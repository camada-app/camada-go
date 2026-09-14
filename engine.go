// Package camada is camada for Go: inline enforcement of your tenant snapshot (ordered custom
// rules, then allow, block, challenge), a first-party proof-of-work challenge and beacon,
// app-context events, and batched wire events shipped off the request path. Fails open by design.
//
// Quickstart (env: CAMADA_KEY, plus CAMADA_INGEST_URL in dev):
//
//	mux := http.NewServeMux()
//	http.ListenAndServe(":8080", camada.Handler(mux))
//
// The engine here is the host-neutral request handling the net/http adapter (handler.go)
// delegates to — the Go twin of camada-python's engine.py. An adapter turns its request into a
// Req, asks WantsBody and reads at most that many bytes, then calls Handle: an Answer means
// camada fully answered the request (block, challenge, verify, beacon endpoints); a Passed means
// run the app, stamp the rid header and session cookie on its response, and call
// OnFinish(status) once when it is done. Everything runs inside the fail-open envelope: a
// camada bug must never 5xx the customer, and CAMADA_DISABLED=1 bypasses the SDK entirely.
package camada

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/camada-app/camada-go/challenge"
	"github.com/camada-app/camada-go/events"
	"github.com/camada-app/camada-go/internal/beacon"
	"github.com/camada-app/camada-go/internal/guarded"
	"github.com/camada-app/camada-go/snapshot"
)

// Header is one request or response header; request names arrive lower-cased.
type Header = events.Header

// Req is what an adapter hands the engine. Header names are lower-cased; the list keeps the
// order the host gave (net/http normalises headers into a map, so handler.go sorts them).
type Req struct {
	Method      string
	Path        string // no query
	Query       string // with the leading '?', or ""
	Host        string
	HTTPVersion string // "1.1", "2.0"; "" when unknown
	Peer        string // the socket peer the host vouches for; "" when there is none
	HTTPS       bool
	Headers     []Header
	Route       string // the matched route pattern, when the host knows it at finish time
}

// Header joins a header the client repeated the way node:http does it: cookies with "; "
// (HTTP/2 clients split them into several fields; cookieValue looks for "; name="), the rest
// with ", ". ok is false when the request does not carry it.
func (r *Req) Header(name string) (string, bool) {
	var vals []string
	for _, h := range r.Headers {
		if h.Name == name {
			vals = append(vals, h.Value)
		}
	}
	if vals == nil {
		return "", false
	}
	sep := ", "
	if name == "cookie" {
		sep = "; "
	}
	return strings.Join(vals, sep), true
}

func (r *Req) header(name string) string {
	v, _ := r.Header(name)
	return v
}

// Answer: camada answered the request; the adapter writes exactly this.
type Answer struct {
	Status  int
	Headers []Header
	Body    []byte
}

// Ctx is the per-request context the app helpers read (ScriptTag, Track, ServeChallenge).
type Ctx struct {
	RID        string
	SID        string
	IP         string // "" when the client could not be identified
	req        *Req
	engine     *Camada
	challenged atomic.Bool
}

// Passed: run the app. RID/SetCookie ride the response; Ctx is stored on the host request;
// OnFinish(status) is called once at the end. The inert Passed has every field zero.
type Passed struct {
	RID       string
	SetCookie string
	Ctx       *Ctx
	OnFinish  func(status int)
}

var inert = &Passed{}

func cookieValue(cookie, name string) (string, bool) {
	src := "; " + cookie
	i := strings.Index(src, "; "+name+"=")
	if i == -1 {
		return "", false
	}
	start := i + len(name) + 3
	if j := strings.IndexByte(src[start:], ';'); j != -1 {
		return src[start : start+j], true
	}
	return src[start:], true
}

func uuid4() string {
	var b [16]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		panic(err) // the OS entropy source failed: the fail-open envelope turns this into an inert request
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// Options configure New; everything credential-shaped comes from the environment.
type Options struct {
	Env             map[string]string // where CAMADA_* are read from; nil = the process environment
	Transport       Transport         // the HTTP func that reaches the analyst (tests inject a fake)
	Refresh         time.Duration     // poll cadence; 0 = server-steered, set = pinned
	ScriptPath      string            // the beacon script endpoint; default /_cam/b.js
	FPPath          string            // the beacon post endpoint; default /_cam/fp (same directory as ScriptPath)
	Challenge       *bool             // serve the proof-of-work page for challenge verdicts; nil = true (CAMADA_CHALLENGE=0 also off)
	ChallengePath   string            // where the page posts its solution; default /__camada/challenge
	SnapshotVersion int               // 5 (default) asks for your custom rules; 4 the sides only; 3 opts out of both
}

// Camada is the engine: one per process, built from the environment.
type Camada struct {
	ScriptPath, FPPath, ChallengePath string
	Env                               *Env             // nil when unconfigured: the engine is inert
	Snap                              *snapshot.Client // nil when inert or killed at boot
	Queue                             *events.Queue
	Kit                               *challenge.Kit

	getenv      func(string) string
	challengeOn bool
	decide      func(req *Req, body []byte) (*Answer, *Passed)
}

// New builds an engine eagerly: the snapshot poll starts now (timer mode) and the request that
// arrives first is answered cold unless you wait for the boot poll (see the README's warm-up).
func New(o Options) *Camada {
	getenv := os.Getenv
	if o.Env != nil {
		env := o.Env
		getenv = func(k string) string { return env[k] }
	}
	c := &Camada{
		ScriptPath: o.ScriptPath, FPPath: o.FPPath, ChallengePath: o.ChallengePath,
		getenv: getenv,
	}
	c.decide = c.decideRequest
	if c.ScriptPath == "" {
		c.ScriptPath = ScriptPath
	}
	if c.FPPath == "" {
		c.FPPath = FPPath
	}
	if c.ChallengePath == "" {
		c.ChallengePath = ChallengePath
	}
	c.challengeOn = (o.Challenge == nil || *o.Challenge) && getenv("CAMADA_CHALLENGE") != "0"
	c.Env = resolveEnv(getenv)
	if c.Env == nil {
		guarded.LogRateLimited("CAMADA_KEY (or CAMADA_TOKEN + CAMADA_SNAPSHOT_TOKEN) not set — camada is inactive")
		return c
	}
	if getenv(KillSwitchEnv) == "1" {
		return c // killed at boot: no goroutines, no requests, truly silent
	}
	mode := "timer"
	if c.Env.Serverless {
		mode = "lazy"
	}
	c.Snap = snapshot.New(c.Env.SnapshotURL, c.Env.SnapToken, snapshot.Options{
		Refresh: o.Refresh, Mode: mode, Transport: o.Transport, SDK: SDKID, SnapshotVersion: o.SnapshotVersion,
	})
	c.Queue = events.NewQueue(c.Env.IngestURL, c.Env.IngestToken, events.QueueOptions{Transport: o.Transport, SDK: SDKID})
	c.Kit = challenge.New(c.Env.Secret)
	c.Snap.Start()
	return c
}

// Disabled is true when unconfigured or when CAMADA_DISABLED=1 (read per request).
func (c *Camada) Disabled() bool {
	return c.Env == nil || c.Snap == nil || c.getenv(KillSwitchEnv) == "1"
}

// NowMS is the engine's clock in milliseconds since the epoch.
func (c *Camada) NowMS() int64 { return events.NowMS() }

func (c *Camada) trustedProxy() *TrustedProxy {
	if c.Env != nil && c.Env.TrustedProxy != nil {
		return c.Env.TrustedProxy // explicit local override wins
	}
	if cfg := c.Snap.Config(); cfg != nil {
		return cfg.TrustedProxy
	}
	return nil
}

func (c *Camada) beaconEnabled() bool {
	return c.Snap != nil && c.Snap.Config().BeaconOn()
}

func (c *Camada) ip(req *Req) string {
	return ResolveClientIP(req.Peer, req.header("x-forwarded-for"), c.trustedProxy())
}

// ---- the adapter contract ----

// WantsBody is the byte cap to read the body under, when camada itself may answer this request.
func (c *Camada) WantsBody(method, path string) (int, bool) {
	if c.Disabled() || method != "POST" {
		return 0, false
	}
	if path == c.FPPath && c.beaconEnabled() {
		return FPMax, true
	}
	if path == c.ChallengePath && c.challengeOn {
		return BodyMax, true
	}
	return 0, false
}

// Handle decides one request; exactly one of the results is non-nil, and it never panics.
// `body` is the request body when WantsBody asked for one; nil when the adapter refused to read
// it (declared or actual size over the cap) or was not asked; []byte{} when it was empty.
func (c *Camada) Handle(req *Req, body []byte) (a *Answer, p *Passed) {
	defer func() {
		if r := recover(); r != nil { // a camada bug costs the join, never the request
			guarded.LogRateLimited(r)
			a, p = nil, inert
		}
	}()
	return c.decide(req, body)
}

func (c *Camada) decideRequest(req *Req, body []byte) (*Answer, *Passed) {
	if c.Disabled() {
		return nil, inert
	}
	t0 := time.Now()
	c.Snap.EnsureFresh()
	ip := c.ip(req)

	// Enforce before anything else, beacon endpoints included — fail open while cold. The
	// custom rules read the user agent and the request headers (§D3).
	v := c.Snap.Verdict(snapshot.MatchInput{IP: ip, Path: req.Path, UA: req.header("user-agent"), Header: req.Header})
	if v.Block {
		headers := []Header{hdr("content-type", "text/plain"), hdr("x-block-reason", v.Reason), hdr("x-block-version", v.Version)}
		if v.Rule != "" {
			headers = append(headers, hdr("x-block-rule", v.Rule)) // a custom rule blocked: name it, so the customer knows which row to edit
		}
		ev := c.event(req, uuid4(), "", false, ip)
		ev["st"] = 403 // blocked requests always ship: silent expiry makes blocks oscillate
		ev["blk"] = v.Reason
		if v.Rule != "" {
			ev["rl"] = v.Rule
		}
		c.Queue.Push(ev)
		return &Answer{403, headers, []byte("Forbidden")}, nil
	}
	// `warn` passes the request and only marks its event (below, on finish); a skip passes
	// with nothing stamped at all — it is the absence of enforcement.

	// A challenge needs a resolved client IP: the nonce and the _cch cookie are bound to it,
	// so without one a single solve would mint a cookie every unidentified client could
	// present. No ip -> no challenge (fail open), the same stance ip rules take.
	if c.challengeOn && ip != "" {
		// The verify endpoint answers first: a challenged client must be able to reach it.
		if req.Method == "POST" && req.Path == c.ChallengePath {
			return c.verify(req, body, ip), nil
		}
		if v.Challenge && !c.challengePassed(req, ip) {
			sid, _ := cookieValue(req.header("cookie"), SessionCookie)
			return c.serveChallenge(req, ip, sid), nil
		}
	}

	if c.beaconEnabled() {
		if req.Method == "GET" && req.Path == c.ScriptPath {
			return &Answer{200, []Header{hdr("content-type", "application/javascript"), hdr("cache-control", "public, max-age=3600")}, []byte(beacon.JS())}, nil
		}
		if req.Method == "POST" && req.Path == c.FPPath {
			return c.relayBeacon(body, ip), nil
		}
	}

	rid := uuid4()
	sid, hadSession := cookieValue(req.header("cookie"), SessionCookie)
	newSession := !hadSession || sid == ""
	setCookie := ""
	if newSession {
		sid = uuid4()
		setCookie = SessionCookie + "=" + sid + "; Path=/; Max-Age=" + strconv.Itoa(SessionMaxAge) + "; HttpOnly; SameSite=Lax"
		if req.HTTPS || req.header("x-forwarded-proto") == "https" {
			setCookie += "; Secure"
		}
	}
	ctx := &Ctx{RID: rid, SID: sid, IP: ip, req: req, engine: c}

	cfg := c.Snap.Config()
	excluded := false
	sample := 1.0
	if cfg != nil {
		for _, x := range cfg.Exclude {
			if strings.HasPrefix(req.Path, x) {
				excluded = true
			}
		}
		if cfg.Sample != nil {
			sample = *cfg.Sample
		}
	}
	sampled := rand.Float64() < sample // sampling, not crypto
	warnRule := ""
	if v.Warn {
		warnRule = v.Rule
	}

	onFinish := func(status int) {
		defer func() {
			if r := recover(); r != nil {
				guarded.LogRateLimited(r)
			}
		}()
		// ServeChallenge may have answered from inside the app, and it already shipped the
		// `blk: "challenge"` row — one request, one event.
		if ctx.challenged.Load() || excluded || !sampled {
			return
		}
		ev := c.event(req, rid, sid, newSession, ip)
		ev["st"], ev["dur"] = status, time.Since(t0).Milliseconds()
		if req.Route != "" {
			ev["rt"] = req.Route
		}
		if warnRule != "" {
			ev["wrn"] = warnRule // §D3: the warn rule that let this request through
		}
		c.Queue.Push(ev)
	}
	return nil, &Passed{RID: rid, SetCookie: setCookie, Ctx: ctx, OnFinish: onFinish}
}

func (c *Camada) event(req *Req, rid, sid string, newSession bool, ip string) map[string]any {
	info := events.RequestInfo{Method: req.Method, Host: req.Host, Path: req.Path, Query: req.Query, Headers: req.Headers, IP: ip, HTTPVersion: req.HTTPVersion}
	return events.BuildWireEvent(info, TAP, rid, sid, newSession, "")
}

// ---- beacon ----

// relayBeacon answers 204, and queues the beacon as a `sig: 1` row with the trusted-proxy-resolved
// client IP: it rides the next event batch. Junk bodies are dropped, never shipped.
func (c *Camada) relayBeacon(body []byte, ip string) *Answer {
	if body == nil {
		return &Answer{413, nil, []byte{}}
	}
	answer := &Answer{204, []Header{hdr("cache-control", "no-store")}, []byte{}}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil || parsed == nil {
		return answer
	}
	parsed["sig"], parsed["tap"] = 1, TAP // ip and tap are the server's word, whatever the body claimed
	parsed["ip"] = nil
	if ip != "" {
		parsed["ip"] = ip
	}
	c.Queue.Push(parsed)
	return answer
}

// ScriptTag is the first-party beacon tag with the request's rid, for HTML templates; "" when
// the beacon is off or the SDK is inert.
func (c *Camada) ScriptTag(ctx *Ctx) string {
	if c.Disabled() || !c.beaconEnabled() {
		return ""
	}
	if ctx != nil && ctx.RID != "" {
		return `<script src="` + c.ScriptPath + `?r=` + ctx.RID + `" async></script>`
	}
	return `<script src="` + c.ScriptPath + `" async></script>`
}

// ---- challenge ----

func (c *Camada) challengePassed(req *Req, ip string) bool {
	cch, _ := cookieValue(req.header("cookie"), challenge.CookieName)
	return c.Kit != nil && c.Kit.TokenValid(ip, c.NowMS(), cch)
}

func (c *Camada) page(ip, to string) *Answer {
	html := challenge.Page(c.Kit.Nonce(ip, c.NowMS()), c.ChallengePath, to, challenge.PowBits)
	headers := []Header{hdr("content-type", "text/html; charset=utf-8"), hdr("cache-control", "no-store"), hdr("x-camada-challenge", "1")}
	return &Answer{403, headers, []byte(html)}
}

// serveChallenge: 403 + the proof-of-work page (HTML navigations) or 403 JSON (everything
// else), plus the `blk: "challenge"` event — a served challenge is reported like a block (contract §D2).
func (c *Camada) serveChallenge(req *Req, ip, sid string) *Answer {
	to := challenge.SafeReturnTo(req.Path + req.Query)
	var answer *Answer
	if challenge.WantsHTML(req.header("accept"), req.header("sec-fetch-dest")) {
		answer = c.page(ip, to)
	} else {
		headers := []Header{hdr("content-type", "application/json"), hdr("cache-control", "no-store"), hdr("x-camada-challenge", "1")}
		answer = &Answer{403, headers, []byte(`{"error":"challenge_required"}`)}
	}
	func() {
		defer func() {
			if r := recover(); r != nil { // the response is decided; telemetry must never undo that
				guarded.LogRateLimited(r)
			}
		}()
		ev := c.event(req, uuid4(), sid, false, ip)
		ev["st"], ev["blk"] = 403, "challenge"
		c.Queue.Push(ev)
	}()
	return answer
}

// verify handles the POST from the challenge page: validate the nonce and the proof of work,
// set _cch, 302 back to the (sanitised, same-site) original URL, and ship `{ st: 200, ch: 1 }`.
func (c *Camada) verify(req *Req, body []byte, ip string) *Answer {
	if body == nil {
		return &Answer{413, nil, []byte{}}
	}
	form := challenge.ParseFormBody(string(body))
	to := challenge.SafeReturnTo(form["to"])
	now := c.NowMS()
	if !c.Kit.Verify(ip, now, form["nonce"], form["solution"]) {
		return c.page(ip, to)
	}
	secure := req.HTTPS || req.header("x-forwarded-proto") == "https"
	cookie := challenge.Cookie(c.Kit.Issue(ip, now), secure)
	headers := []Header{hdr("location", to), hdr("set-cookie", cookie), hdr("cache-control", "no-store")}
	sid, _ := cookieValue(req.header("cookie"), SessionCookie)
	ev := c.event(req, uuid4(), sid, false, ip)
	ev["st"], ev["ch"] = 200, 1 // challenge passed (contract §A3 ingest field)
	c.Queue.Push(ev)
	return &Answer{302, headers, []byte{}}
}

// ServeChallenge serves the challenge for this request on demand — for a route the app wants
// to gate itself. nil when the client already holds a valid _cch (render your own page), or
// when the client cannot be identified (fail open).
func (c *Camada) ServeChallenge(ctx *Ctx) (a *Answer) {
	defer func() {
		if r := recover(); r != nil {
			guarded.LogRateLimited(r)
			a = nil
		}
	}()
	if c.Disabled() || c.Kit == nil || ctx == nil || ctx.req == nil || ctx.IP == "" || c.challengePassed(ctx.req, ctx.IP) {
		return nil
	}
	ctx.challenged.Store(true)
	return c.serveChallenge(ctx.req, ctx.IP, ctx.SID)
}

// ---- app-context events ----

// Track ships an app-context outcome event (login_failed, signup, ...). The identifier is
// HMAC-hashed in-process; the raw value never reaches the queue. Never panics; a no-op when inert.
func (c *Camada) Track(ctx *Ctx, event, user string) {
	defer func() {
		if r := recover(); r != nil {
			guarded.LogRateLimited(r)
		}
	}()
	if c.Disabled() {
		return
	}
	row := map[string]any{"tap": TAP, "et": event, "uid": nil, "rid": nil, "sid": nil, "ip": nil, "ts": c.NowMS()}
	if user != "" {
		row["uid"] = HashUserID(user, c.Env.IngestToken)
	}
	if ctx != nil {
		if ctx.RID != "" {
			row["rid"] = ctx.RID
		}
		if ctx.SID != "" {
			row["sid"] = ctx.SID
		}
		if ctx.IP != "" {
			row["ip"] = ctx.IP
		}
	}
	c.Queue.Push(row)
}

// Stop ends the poll and flush goroutines and drains pending events, for at most 500 ms or
// until ctx is done, whichever comes first. No signal handlers are installed: call it from
// your own shutdown path (`defer cam.Stop(context.Background())`).
func (c *Camada) Stop(ctx context.Context) {
	if c.Snap != nil {
		c.Snap.Stop()
	}
	if c.Queue != nil {
		c.Queue.Stop()
		bounded, cancel := context.WithTimeout(ctx, events.DrainBudget)
		defer cancel()
		c.Queue.Drain(bounded)
	}
}

func hdr(name, value string) Header { return Header{Name: name, Value: value} }
