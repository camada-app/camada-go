package snapshot

// Snapshot poll pacing (camada-all-pbv9): a failed poll (any status but 200/204/304, or no
// answer) keeps the blocks and gates the next self-initiated poll until now + nextPollDelay.
// Driven by camada-core's shared fixture poll/backoff.json.

import (
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/camada-app/camada-go/internal/testutil"
	"github.com/camada-app/camada-go/internal/transport"
)

type pacingFixture struct {
	BlockedIP string `json:"blockedIp"`
	Delay     []struct {
		Name               string   `json:"name"`
		Status             int      `json:"status"`
		RetryAfter         *string  `json:"retryAfter"`
		RefreshSeconds     float64  `json:"refreshSeconds"`
		ExpectDelaySeconds *float64 `json:"expectDelaySeconds"`
	} `json:"delay"`
	Timelines []struct {
		Name           string  `json:"name"`
		RefreshSeconds float64 `json:"refreshSeconds"`
		ClockBase      float64 `json:"clockBase"`
		Steps          []struct {
			T       float64 `json:"t"`
			Poll    bool    `json:"poll"`
			Respond struct {
				Status     int     `json:"status"`
				RetryAfter *string `json:"retryAfter"`
			} `json:"respond"`
			After struct {
				Cold    bool `json:"cold"`
				Blocked bool `json:"blocked"`
			} `json:"after"`
		} `json:"steps"`
	} `json:"timelines"`
}

func secs(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

func TestNextPollDelay(t *testing.T) {
	var fx pacingFixture
	testutil.ReadJSON(t, "poll/backoff.json", &fx)
	if len(fx.Delay) == 0 {
		t.Fatal("fixture has no delay cases")
	}
	for _, c := range fx.Delay {
		ra := ""
		if c.RetryAfter != nil {
			ra = *c.RetryAfter
		}
		got, paced := nextPollDelay(c.Status, ra, c.RefreshSeconds)
		if c.ExpectDelaySeconds == nil {
			if paced {
				t.Errorf("%s: paced, want not paced", c.Name)
			}
			continue
		}
		if !paced || math.Abs(got-*c.ExpectDelaySeconds) > 1e-9 {
			t.Errorf("%s: got %v/%v, want %v", c.Name, got, paced, *c.ExpectDelaySeconds)
		}
	}
}

func TestPollTimelines(t *testing.T) {
	var fx pacingFixture
	testutil.ReadJSON(t, "poll/backoff.json", &fx)
	if len(fx.Timelines) == 0 {
		t.Fatal("fixture has no timelines")
	}
	for _, tl := range fx.Timelines {
		t.Run(tl.Name, func(t *testing.T) {
			a := testutil.NewFakeAnalyst(t)
			var reply struct {
				status int
				ra     string
			}
			c := New(url, "t", Options{Refresh: secs(tl.RefreshSeconds), Mode: "lazy", Transport: func(r transport.Request) transport.Response {
				if reply.status == 200 {
					return a.Transport(r)
				}
				h := map[string]string{}
				if reply.ra != "" {
					h["retry-after"] = reply.ra
				}
				if reply.status != 204 && reply.status != 304 {
					h["x-camada-config"] = `{"tenant":"x","poll_seconds":7}` // a failed answer's config is not read
				}
				return transport.Response{Status: reply.status, Headers: h, Body: []byte{}}
			}})
			var now time.Duration
			c.now = func() time.Duration { return now }
			for _, s := range tl.Steps {
				now = secs(tl.ClockBase + s.T)
				if c.due() != s.Poll {
					t.Fatalf("t=%v: due=%v want %v", s.T, c.due(), s.Poll)
				}
				if !s.Poll {
					continue
				}
				reply.status, reply.ra = s.Respond.Status, ""
				if s.Respond.RetryAfter != nil {
					reply.ra = *s.Respond.RetryAfter
				}
				c.Refresh()
				v := c.Verdict(MatchInput{IP: fx.BlockedIP})
				if (v.Reason == "cold") != s.After.Cold || v.Block != s.After.Blocked {
					t.Fatalf("t=%v: cold=%v blocked=%v want %+v", s.T, v.Reason == "cold", v.Block, s.After)
				}
			}
			if cfg := c.Config(); cfg != nil && cfg.PollSeconds != nil && *cfg.PollSeconds == 7 {
				t.Fatal("read x-camada-config from a failed answer")
			}
		})
	}
}

func TestTransportPanicIsAFailedPollToo(t *testing.T) {
	var polls atomic.Int32
	c := New(url, "t", Options{Refresh: 30 * time.Second, Mode: "lazy", Transport: func(transport.Request) transport.Response {
		polls.Add(1)
		panic("boom")
	}})
	var now time.Duration = 1000 * time.Second
	c.now = func() time.Duration { return now }
	c.Refresh()
	if c.due() {
		t.Fatal("due right after a failed poll")
	}
	now += 5 * time.Second
	if !c.due() {
		t.Fatal("not due after the 5 s floor")
	}
}

// F2: loadedAt must be monotonic, so a wall-clock step cannot stall polling.
func TestStaleUsesTheMonotonicClock(t *testing.T) {
	c := New(url, "t", Options{Refresh: 30 * time.Second, Mode: "lazy"})
	var now time.Duration = 1000 * time.Second
	c.now = func() time.Duration { return now }
	c.loadedAt.Store(int64(now))
	if c.Stale() {
		t.Fatal("fresh client stale")
	}
	now += 28 * time.Second
	if !c.Stale() {
		t.Fatal("not stale after 0.9 x refresh")
	}
}

// R1-S1: a request that read "due" while a poll was failing must not start a second poll
// once it gets the slot.
func TestEnsureFreshRechecksDueAfterTheSlot(t *testing.T) {
	var polls atomic.Int32
	c := New(url, "t", Options{Refresh: 30 * time.Second, Mode: "lazy", Transport: func(transport.Request) transport.Response {
		polls.Add(1)
		return transport.Response{Status: 503, Headers: map[string]string{}}
	}})
	var now time.Duration = 1000 * time.Second
	c.now = func() time.Duration { return now }
	hooked := false
	c.afterDueCheck = func() {
		if !hooked {
			hooked = true
			c.Refresh() // the competing poll fails and gates before this request gets the slot
		}
	}
	c.EnsureFresh()
	c.loading.Lock() // join a background load, if one was wrongly started
	c.loading.Unlock()
	if n := polls.Load(); n != 1 {
		t.Fatalf("polls = %d, want 1", n)
	}
}

// Request path under a closed gate: one poll per retry-after, not one per request.
func TestEnsureFreshHonoursTheGate(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	var polls atomic.Int32
	failing := false
	c := New(url, "t", Options{Refresh: 60 * time.Second, Mode: "lazy", Transport: func(r transport.Request) transport.Response {
		polls.Add(1)
		if !failing {
			return a.Transport(r)
		}
		return transport.Response{Status: 503, Headers: map[string]string{"retry-after": "30"}}
	}})
	var now time.Duration = 1000 * time.Second
	c.now = func() time.Duration { return now }
	ensure := func() {
		c.EnsureFresh()
		c.loading.Lock()
		c.loading.Unlock()
	}
	ensure() // warm: 200
	if polls.Load() != 1 {
		t.Fatalf("warm polls = %d", polls.Load())
	}
	failing = true
	now += 55 * time.Second // stale (> 0.9 x 60)
	for i := 0; i < 5; i++ {
		ensure()
	}
	if n := polls.Load(); n != 2 {
		t.Fatalf("polls under a closed gate = %d, want 2 (warm + one failure)", n)
	}
	now += 29 * time.Second
	ensure()
	if n := polls.Load(); n != 2 {
		t.Fatalf("polled before retry-after: %d", n)
	}
	now += 1 * time.Second
	ensure()
	if n := polls.Load(); n != 3 {
		t.Fatalf("polls after +30 s = %d, want 3", n)
	}
}

// R1-N4: the default clock is monotonic-based (small offset from the client's birth, not a UnixNano).
func TestDefaultClockIsMonotonicBased(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	c := New(url, "t", Options{Refresh: 30 * time.Second, Mode: "lazy", Transport: a.Transport})
	c.Refresh()
	loaded := c.loadedAt.Load()
	if loaded <= 0 || loaded >= int64(time.Hour) {
		t.Fatalf("loadedAt = %d, want in (0, 1h)", loaded)
	}
}

// R1-N5: a struct-literal client has no clock seam set and must not panic.
func TestStructLiteralClientDoesNotPanic(t *testing.T) {
	c := &Client{URL: url, Token: "t"}
	if !c.Stale() || !c.due() {
		t.Fatal("never-loaded literal client should be stale and due")
	}
	c.loadedAt.Store(int64(c.clock()))
	c.refresh.Store(int64(30 * time.Second))
	if c.Stale() {
		t.Fatal("just-loaded literal client stale")
	}
}

// A body the transport cannot read is no answer: no headers, so no retry-after is honoured.
func TestUnreadableBodyHasNoHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(503)
		_, _ = w.Write([]byte("short")) // promises 100 bytes, sends 5: the read fails
	}))
	defer srv.Close()
	res := transport.HTTP(transport.Request{Method: "GET", URL: srv.URL, Timeout: 2 * time.Second})
	if res.Status != 0 || len(res.Headers) != 0 {
		t.Fatalf("got status %d headers %v, want no answer and no headers", res.Status, res.Headers)
	}
}
