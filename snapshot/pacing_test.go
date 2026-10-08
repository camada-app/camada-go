package snapshot

// Snapshot poll pacing (camada-all-pbv9): a failed poll (any status but 200/204/304, or no
// answer) keeps the blocks and gates the next self-initiated poll until now + nextPollDelay.
// Driven by camada-core's shared fixture poll/backoff.json.

import (
	"math"
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
				if c.Due() != s.Poll {
					t.Fatalf("t=%v: due=%v want %v", s.T, c.Due(), s.Poll)
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
	if c.Due() {
		t.Fatal("due right after a failed poll")
	}
	now += 5 * time.Second
	if !c.Due() {
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
