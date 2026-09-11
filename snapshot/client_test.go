package snapshot

// Client: the single-tenant port of the edge collector's snapshot lifecycle over the
// GET /snapshot contract (200 frame + etag + x-camada-config; 304 unchanged; 204 nothing
// published -> enforce nothing). Cold = fail open; any error keeps the previous snapshot.

import (
	"reflect"
	"testing"
	"time"

	"github.com/camada/camada-go/internal/testutil"
	"github.com/camada/camada-go/internal/transport"
)

const url = "https://analyst.test/snapshot"

func client(a *testutil.FakeAnalyst, o Options) *Client {
	o.Transport, o.SDK, o.Mode = a.Transport, "@camada/go/0.0.0", "lazy"
	return New(url, "snap-test", o)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition never held")
}

func TestColdClientFailsOpen(t *testing.T) {
	c := client(testutil.NewFakeAnalyst(t), Options{})
	v := c.Verdict(MatchInput{IP: testutil.BlockedIP})
	if v.Reason != "cold" || v.Block || v.Challenge || v.Allowed {
		t.Fatalf("%+v", v)
	}
}

func TestLoadsAndEnforcesWithTheContractHeaders(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	c := client(a, Options{})
	c.Refresh()
	if !c.Verdict(MatchInput{IP: testutil.BlockedIP}).Block {
		t.Fatal("not enforcing")
	}
	req := a.Snapshots()[0]
	if req.Headers["authorization"] != "Bearer snap-test" || req.Headers["x-camada-sdk"] != "@camada/go/0.0.0" || req.Headers["x-camada-snapshot"] != "5" {
		t.Fatalf("headers %v", req.Headers)
	}
	if _, ok := req.Headers["if-none-match"]; ok {
		t.Fatal("if-none-match on the first poll")
	}
	if _, ok := req.Headers["accept-encoding"]; ok {
		t.Fatal("accept-encoding is net/http's to set (transparent gzip)")
	}
	cfg := c.Config()
	if cfg == nil || cfg.Tenant != "acme" || !cfg.BeaconOn() || *cfg.Sample != 1 || cfg.TrustedProxy.Mode != "none" || *cfg.PollSeconds != 30 {
		t.Fatalf("config %+v", cfg)
	}
}

func Test304RepeatsConfigAndKeepsTheSnapshot(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	c := client(a, Options{})
	c.Refresh()
	a.SetConfig("beacon", false)
	c.Refresh()
	if a.Snapshots()[1].Headers["if-none-match"] != a.Etag() {
		t.Fatal("no etag on the second poll")
	}
	if !c.Verdict(MatchInput{IP: testutil.BlockedIP}).Block || c.Config().BeaconOn() {
		t.Fatal("304 lost the snapshot or the config")
	}
}

func Test204MeansNothingPublishedAndNotCold(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	a.SnapshotStatus = 204
	c := client(a, Options{})
	c.Refresh()
	v := c.Verdict(MatchInput{IP: testutil.BlockedIP})
	if v.Reason != "" || v.Block {
		t.Fatalf("%+v", v)
	}
}

func TestErrorsKeepWhatWeHave(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	c := client(a, Options{})
	c.Refresh()
	for _, status := range []int{401, 500} {
		a.Update(func(a *testutil.FakeAnalyst) { a.SnapshotStatus = status })
		c.Refresh()
		if !c.Verdict(MatchInput{IP: testutil.BlockedIP}).Block {
			t.Fatalf("%d lost the snapshot", status)
		}
	}
	a.Update(func(a *testutil.FakeAnalyst) { a.SnapshotStatus, a.SnapshotDown = 0, true })
	c.Refresh()
	if !c.Verdict(MatchInput{IP: testutil.BlockedIP}).Block {
		t.Fatal("a dead analyst lost the snapshot")
	}
}

func TestCorruptBodyKeepsThePreviousSnapshot(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	c := client(a, Options{})
	c.Refresh()
	good := a.Transport
	c.Transport = func(req transport.Request) transport.Response {
		r := good(req)
		r.Headers["etag"] = `"other"`
		r.Body = append([]byte{5, 0, 0, 0, 'j', 'u', 'n', 'k', '!'}, make([]byte, 10)...)
		r.Status = 200
		return r
	}
	c.Refresh()
	if !c.Verdict(MatchInput{IP: testutil.BlockedIP}).Block {
		t.Fatal("corrupt body replaced the snapshot")
	}
}

func TestSameVersionNewEtagReparses(t *testing.T) {
	// the server ships v3/v4/v5 bodies of one publish under the same meta.version and different etags
	a := testutil.NewFakeAnalyst(t)
	c := client(a, Options{})
	c.Refresh()
	if c.Verdict(MatchInput{IP: testutil.ChallengedIP}).Challenge { // v3 has no challenge side
		t.Fatal("v3 challenged")
	}
	a.Update(func(a *testutil.FakeAnalyst) { a.Container = "v4" })
	c.Refresh()
	if !c.Verdict(MatchInput{IP: testutil.ChallengedIP}).Challenge {
		t.Fatal("the v4 body under a new etag was not parsed")
	}
}

func TestSnapshotVersionHeaderFollowsTheOption(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	client(a, Options{SnapshotVersion: 4}).Refresh()
	client(a, Options{SnapshotVersion: 3}).Refresh()
	if got := a.SnapshotVersionList(); !reflect.DeepEqual(got, []string{"4", ""}) {
		t.Fatalf("%v", got)
	}
}

func TestServerSteersTheCadenceUnlessPinned(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	a.SetConfig("poll_seconds", 7)
	c := client(a, Options{})
	c.Refresh()
	if c.RefreshInterval() != 7*time.Second {
		t.Fatalf("got %v", c.RefreshInterval())
	}
	a.SetConfig("poll_seconds", 1) // below the 5 s floor: ignored
	c.Refresh()
	if c.RefreshInterval() != 7*time.Second {
		t.Fatalf("floor: got %v", c.RefreshInterval())
	}
	pinned := client(a, Options{Refresh: 11 * time.Second})
	pinned.Refresh()
	if pinned.RefreshInterval() != 11*time.Second {
		t.Fatalf("pinned: got %v", pinned.RefreshInterval())
	}
}

func TestNonFinitePollSecondsIsIgnored(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	c := client(a, Options{})
	before := c.RefreshInterval()
	a.Update(func(a *testutil.FakeAnalyst) {
		a.Config["poll_seconds"] = 1e300 // beyond any timer; and JSON's 1e999 is not even a float64
		a.Config["beacon"] = false
	})
	c.Refresh()
	if c.RefreshInterval() != before {
		t.Fatalf("got %v", c.RefreshInterval())
	}
	if c.Config().BeaconOn() {
		t.Fatal("the rest of the config must still apply")
	}
}

func TestEnsureFreshIsOffPathAndSingleInFlight(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	c := client(a, Options{})
	c.EnsureFresh()
	c.EnsureFresh()
	waitFor(t, func() bool { return c.Verdict(MatchInput{IP: "0.0.0.0"}).Reason != "cold" })
	if !c.Verdict(MatchInput{IP: testutil.BlockedIP}).Block || len(a.Snapshots()) != 1 {
		t.Fatalf("polls %d", len(a.Snapshots()))
	}
	c.EnsureFresh() // fresh: no new poll
	time.Sleep(20 * time.Millisecond)
	if len(a.Snapshots()) != 1 {
		t.Fatal("polled while fresh")
	}
}

func TestTimerModePollsOnItsOwnAndStops(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	c := New(url, "snap-test", Options{Transport: a.Transport, Mode: "timer", Refresh: 20 * time.Millisecond})
	c.Start()
	waitFor(t, func() bool { return len(a.Snapshots()) >= 3 })
	c.Stop()
	time.Sleep(30 * time.Millisecond)
	n := len(a.Snapshots())
	time.Sleep(50 * time.Millisecond)
	if len(a.Snapshots()) != n {
		t.Fatal("polled after stop")
	}
}

func TestStopIsIdempotentAndStartAfterStopIsANoOp(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	c := New(url, "snap-test", Options{Transport: a.Transport, Mode: "timer", Refresh: 20 * time.Millisecond})
	c.Start()
	c.Stop()
	c.Stop()
	c.Start()
	time.Sleep(60 * time.Millisecond)
	if n := len(a.Snapshots()); n > 2 {
		t.Fatalf("a stopped client kept polling: %d", n)
	}
}
