package snapshot

// Client: the single-tenant port of the edge collector's snapshot lifecycle over the
// GET /snapshot contract (ported from @camada/core src/snapshot/client.ts):
//
//	200  [u32 LE meta-length][meta JSON][BLK container] + etag + x-camada-config
//	304  nothing changed; config header repeated (config refreshes every poll for free)
//	204  authenticated, no snapshot published -> enforce nothing, fail open
//
// Semantics ported exactly: single-in-flight load; loadedAt stamped even on 204 (retry per
// poll cadence, not per request); any error keeps the previous snapshot; cold = fail open.
// Timer mode runs one goroutine per client; lazy mode kicks a goroutine from EnsureFresh() so
// the request path never waits on the network. The matcher lives behind an atomic pointer,
// so a request reads the snapshot without a lock while a poll swaps in the next one.

import (
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/camada-app/camada-go/internal/config"
	"github.com/camada-app/camada-go/internal/guarded"
	"github.com/camada-app/camada-go/internal/transport"
)

const (
	DefaultRefresh         = 30 * time.Second
	DefaultSnapshotVersion = 5 // asks for the custom rules too; 4 the sides only; 3 opts out of both
	defaultTimeout         = 3 * time.Second
)

// Cold is the verdict before the first poll lands: fail open, mirrors the collector.
var Cold = MatchResult{Reason: "cold"}

// None is the verdict when nothing is published.
var None = MatchResult{}

// Options tune a Client; the zero value is the production default.
type Options struct {
	Refresh         time.Duration       // leave 0 and the server's poll_seconds steers it; set it and it is pinned
	Timeout         time.Duration       // per poll; 3 s
	Mode            string              // "timer" (default) | "lazy"
	Transport       transport.Transport // nil = net/http
	SDK             string              // "<package>/<version>": sent as x-camada-sdk on every poll (SDK-03)
	SnapshotVersion int                 // 0 = DefaultSnapshotVersion
}

// Client keeps one tenant's snapshot fresh and answers verdicts from it.
type Client struct {
	URL, Token      string
	Timeout         time.Duration
	Mode            string
	Transport       transport.Transport
	SDK             string
	SnapshotVersion int

	matcher  atomic.Pointer[Matcher]
	config   atomic.Pointer[config.RemoteConfig]
	refresh  atomic.Int64 // nanoseconds
	loadedAt atomic.Int64 // unix nanoseconds; 0 = cold
	pinned   bool
	etag     string     // only touched under loading
	loading  sync.Mutex // TryLock keeps one refresh in flight
	mu       sync.Mutex // start/stop state
	stop     chan struct{}
	started  bool
	stopped  bool
}

// New builds a client; nothing polls until Start (timer) or EnsureFresh (lazy).
func New(url, token string, o Options) *Client {
	c := &Client{URL: url, Token: token, Timeout: o.Timeout, Mode: o.Mode, Transport: o.Transport, SDK: o.SDK, SnapshotVersion: o.SnapshotVersion}
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	if c.Mode == "" {
		c.Mode = "timer"
	}
	if c.Transport == nil {
		c.Transport = transport.HTTP
	}
	if c.SnapshotVersion == 0 {
		c.SnapshotVersion = DefaultSnapshotVersion
	}
	refresh := o.Refresh
	if refresh > 0 {
		c.pinned = true
	} else {
		refresh = DefaultRefresh
	}
	c.refresh.Store(int64(refresh))
	c.stop = make(chan struct{})
	return c
}

// Start kicks the first poll and, in timer mode, the poll goroutine.
func (c *Client) Start() {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.EnsureFresh()
	if c.Mode != "timer" || c.started {
		c.mu.Unlock()
		return
	}
	c.started = true
	stop := c.stop
	c.mu.Unlock()
	go c.run(stop)
}

func (c *Client) run(stop chan struct{}) {
	for {
		timer := time.NewTimer(c.RefreshInterval())
		select {
		case <-timer.C:
			c.EnsureFresh()
		case <-stop:
			timer.Stop()
			return
		}
	}
}

// Stop ends the poll goroutine; idempotent. A stopped client never polls again.
func (c *Client) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		close(c.stop)
	}
}

// RefreshInterval is the current poll cadence (server-steered unless pinned).
func (c *Client) RefreshInterval() time.Duration { return time.Duration(c.refresh.Load()) }

// Config is the last x-camada-config the analyst sent; nil before the first poll.
func (c *Client) Config() *config.RemoteConfig { return c.config.Load() }

// Matcher is the current matcher; nil while cold or when nothing is published.
func (c *Client) Matcher() *Matcher { return c.matcher.Load() }

// Stale is 0.9 x refresh so a timer tick arriving at ~refresh-ε still refreshes; a
// full-interval comparison makes every other tick a no-op (effective cadence 2x).
func (c *Client) Stale() bool {
	loaded := c.loadedAt.Load()
	return loaded == 0 || time.Since(time.Unix(0, loaded)) > time.Duration(float64(c.refresh.Load())*0.9)
}

// EnsureFresh kicks a refresh when stale; never blocks the request path, never panics.
func (c *Client) EnsureFresh() {
	if !c.Stale() || !c.loading.TryLock() {
		return
	}
	go c.loadLocked()
}

// Refresh is one synchronous poll (single in-flight): what the goroutines call, and what tests
// and warm-ups call directly. A no-op while another poll holds the lock.
func (c *Client) Refresh() {
	if !c.loading.TryLock() {
		return
	}
	c.loadLocked()
}

func (c *Client) loadLocked() {
	defer c.loading.Unlock()
	defer func() {
		if r := recover(); r != nil { // a poll that can never succeed must not be silent, nor fatal
			guarded.LogRateLimited(r)
		}
	}()
	if err := c.load(); err != nil {
		guarded.LogRateLimited(err)
	}
}

func (c *Client) load() error {
	headers := map[string]string{"authorization": "Bearer " + c.Token}
	if c.etag != "" {
		headers["if-none-match"] = c.etag
	}
	if c.SDK != "" {
		headers["x-camada-sdk"] = c.SDK
	}
	if c.SnapshotVersion > 3 {
		headers["x-camada-snapshot"] = strconv.Itoa(c.SnapshotVersion) // a tenant without that container is answered with the next one down
	}
	res := c.Transport(transport.Request{Method: "GET", URL: c.URL, Headers: headers, Timeout: c.Timeout})
	if res.Status != 200 && res.Status != 204 && res.Status != 304 {
		return nil // 401/5xx/network: keep what we have
	}
	// Stamped on the way out, corrupt body included (retry per poll cadence, not per request), and
	// after the matcher swap: "not cold" must never be observable before the snapshot is in place.
	defer c.loadedAt.Store(time.Now().UnixNano())
	c.readConfig(res.Headers["x-camada-config"])
	if res.Status == 304 {
		return nil
	}
	if res.Status == 204 { // no snapshot published: enforce nothing
		c.matcher.Store(nil)
		c.etag = ""
		return nil
	}
	body := res.Body
	if len(body) < 4 {
		return errors.New("camada: truncated snapshot frame")
	}
	metaLen := int(binary.LittleEndian.Uint32(body))
	if metaLen < 0 || 4+metaLen > len(body) {
		return errors.New("camada: truncated snapshot frame")
	}
	meta, err := DecodeMeta(body[4 : 4+metaLen])
	if err != nil {
		return err
	}
	// The server ships the v3, v4 and v5 bodies of one publish under the SAME meta.version and
	// different etags, so version alone cannot say "nothing changed".
	etag := res.Headers["etag"]
	if m := c.matcher.Load(); m != nil && meta.Version == m.Snap.Version && etag != "" && etag == c.etag {
		return nil
	}
	snap, err := ParseSnapshot(body[4+metaLen:], meta) // errors on corrupt data -> previous kept
	if err != nil {
		return err
	}
	c.matcher.Store(NewMatcher(snap))
	c.etag = etag
	return nil
}

func (c *Client) readConfig(raw string) {
	if raw == "" {
		return
	}
	cfg := config.ParseRemoteConfig(raw)
	if cfg == nil {
		return // keep the previous config
	}
	c.config.Store(cfg)
	// the server steers the poll cadence per tenant (its cost lever) unless the client pinned one
	if c.pinned || cfg.PollSeconds == nil {
		return
	}
	secs := *cfg.PollSeconds
	if math.IsNaN(secs) || math.IsInf(secs, 0) || secs < 5 || secs > float64(math.MaxInt64)/float64(time.Second) {
		return
	}
	c.refresh.Store(int64(secs * float64(time.Second)))
}

// Verdict matches one request. Cold (never loaded) and no-snapshot both fail open, mirroring the edge collector.
func (c *Client) Verdict(i MatchInput) MatchResult {
	if c.loadedAt.Load() == 0 {
		return Cold
	}
	m := c.matcher.Load()
	if m == nil {
		return None
	}
	return m.Match(i)
}
