package camada

// The engine through net/http: inline enforcement, ordered custom rules, the challenge, the
// first-party beacon, request capture, app-context events, and the fail-open envelope. The
// case list mirrors camada-python's test_engine.py (which mirrors camada-node's engine, rules
// and challenge suites).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/camada/camada-go/internal/testutil"
)

func shortCtx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	_ = cancel // the engine's Stop returns well inside the budget; the timer collects itself
	return ctx
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---- inline blocking ----

func TestBlockAnswers403BeforeTheAppAndStillShipsTheEvent(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	h := newHost(t, a, hostOpts{env: map[string]string{"CAMADA_TRUSTED_PROXY": "hops:1"}})
	r := h.call(call{path: "/admin?x=1", headers: xff(testutil.BlockedIP)})
	if r.status != 403 || r.body != "Forbidden" || r.header("x-block-reason") != "ip4" || r.header("x-block-version") != a.Version() {
		t.Fatalf("%+v", r)
	}
	if r.header("content-type") != "text/plain" || r.header("x-block-rule") != "" {
		t.Fatalf("headers %v", r.headers)
	}
	if len(h.seen) != 0 {
		t.Fatal("the app ran")
	}
	evs := h.events()
	if len(evs) != 1 {
		t.Fatalf("events %v", evs)
	}
	ev := evs[0]
	if ev["st"] != 403.0 || ev["blk"] != "ip4" || ev["ip"] != testutil.BlockedIP || ev["p"] != "/admin" || ev["tap"] != "sdk-go" {
		t.Fatalf("%v", ev)
	}
	if _, ok := ev["rl"]; ok {
		t.Fatal("rl without a rule")
	}
}

func TestIgnoresASpoofedXFFWithoutTrustedProxyConfig(t *testing.T) {
	h := newHost(t, testutil.NewFakeAnalyst(t), hostOpts{})
	if h.call(call{path: "/", headers: xff(testutil.BlockedIP)}).status != 200 {
		t.Fatal("spoof honoured")
	}
	if h.call(call{path: "/", peer: testutil.BlockedIP}).status != 403 {
		t.Fatal("the peer was not judged")
	}
}

func TestServerDeliveredTrustedProxyAppliesWhenNoLocalOverride(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	hops1(a)
	h := newHost(t, a, hostOpts{})
	if h.call(call{path: "/", headers: xff(testutil.BlockedIP)}).status != 403 {
		t.Fatal("server config ignored")
	}
}

func TestFailsOpenWhileCold(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	a.SnapshotDown = true
	h := newHost(t, a, hostOpts{cold: true})
	if h.call(call{path: "/", peer: testutil.BlockedIP}).status != 200 || len(h.seen) != 1 {
		t.Fatal("cold did not fall open")
	}
}

func TestHonoursTheAllowSideOverAWiderBlock(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	a.Container = "v4"
	h := newHost(t, a, hostOpts{})
	if h.call(call{path: "/", peer: "10.0.0.9"}).status != 403 || h.call(call{path: "/", peer: testutil.AllowedIP}).status != 200 {
		t.Fatal("allow side")
	}
}

// ---- sdk identity ----

func TestSendsXCamadaSDKOnPollsAndBatches(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	h := newHost(t, a, hostOpts{})
	h.call(call{path: "/"})
	h.events()
	seen := a.SDKHeaderList()
	if len(seen) < 2 {
		t.Fatalf("%v", seen)
	}
	for _, s := range seen {
		if s != SDKID {
			t.Fatalf("%v", seen)
		}
	}
}

func TestAsksForV5ByDefaultAndOptsOutAt3(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	newHost(t, a, hostOpts{})
	newHost(t, a, hostOpts{opts: Options{SnapshotVersion: 3}})
	if got := a.SnapshotVersionList(); got[0] != "5" || got[1] != "" {
		t.Fatalf("%v", got)
	}
}

// ---- capture ----

func TestCapturesOnFinishWithStatusLatencySessionAndRID(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	h := newHost(t, a, hostOpts{handler: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-app", "1")
		w.WriteHeader(201)
		_, _ = w.Write([]byte("made"))
	}})
	r := h.call(call{method: "POST", path: "/things?q=1&token=secret", headers: [][2]string{{"user-agent", "UA/1"}, {"accept", "*/*"}}, body: "{}"})
	if r.status != 201 || r.body != "made" || r.header("x-app") != "1" {
		t.Fatalf("%+v", r)
	}
	rid := r.header("x-rid")
	if len(rid) != 36 {
		t.Fatalf("rid %q", rid)
	}
	cookie := r.header("set-cookie")
	if !strings.HasPrefix(cookie, "_sfp=") || !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "SameSite=Lax") || strings.Contains(cookie, "Secure") {
		t.Fatalf("cookie %q", cookie)
	}
	evs := h.events()
	if len(evs) != 1 {
		t.Fatalf("%v", evs)
	}
	ev := evs[0]
	if ev["rid"] != rid || ev["sid"] != cookiePair(cookie)[5:] || ev["ns"] != 1.0 {
		t.Fatalf("%v", ev)
	}
	if ev["st"] != 201.0 {
		t.Fatalf("st %v", ev["st"])
	}
	if dur, ok := ev["dur"].(float64); !ok || dur < 0 {
		t.Fatalf("dur %v", ev["dur"])
	}
	if ev["m"] != "POST" || ev["p"] != "/things" || ev["q"] != "?q=1&token=~r" || ev["ua"] != "UA/1" || ev["cl"] != "2" {
		t.Fatalf("%v", ev)
	}
	if ev["ip"] != defaultPeer || ev["proto"] != "HTTP/1.1" || ev["h"] != "x.test" {
		t.Fatalf("%v", ev)
	}
	if _, ok := ev["blk"]; ok {
		t.Fatal("blk on a pass")
	}
	if _, ok := ev["wrn"]; ok {
		t.Fatal("wrn on a pass")
	}
}

func TestReusesTheSessionCookieAndMarksHTTPSSecure(t *testing.T) {
	h := newHost(t, testutil.NewFakeAnalyst(t), hostOpts{})
	r := h.call(call{path: "/", headers: [][2]string{{"cookie", "a=1; _sfp=sess-1; b=2"}}, https: true})
	if r.header("set-cookie") != "" {
		t.Fatal("re-minted a session")
	}
	if r2 := h.call(call{path: "/", https: true}); !strings.Contains(r2.header("set-cookie"), "; Secure") {
		t.Fatalf("https: %q", r2.header("set-cookie"))
	}
	if r3 := h.call(call{path: "/", headers: [][2]string{{"x-forwarded-proto", "https"}}}); !strings.Contains(r3.header("set-cookie"), "; Secure") {
		t.Fatalf("x-forwarded-proto: %q", r3.header("set-cookie"))
	}
	ev := h.events()[0]
	if ev["sid"] != "sess-1" || ev["ns"] != 0.0 {
		t.Fatalf("%v", ev)
	}
}

func TestKeepsTheAppsOwnCookies(t *testing.T) {
	h := newHost(t, testutil.NewFakeAnalyst(t), hostOpts{handler: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "app=1; Path=/")
		w.Header().Add("Set-Cookie", "b=2")
	}})
	cookies := h.call(call{path: "/"}).headers.Values("Set-Cookie")
	if len(cookies) != 3 {
		t.Fatalf("%v", cookies)
	}
	joined := strings.Join(cookies, "\n")
	if !strings.Contains(joined, "app=1; Path=/") || !strings.Contains(joined, "b=2") || !strings.Contains(joined, "_sfp=") {
		t.Fatalf("%v", cookies)
	}
}

func TestHonoursExcludeAndSampleAndNeverCapturesCredentials(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	a.SetConfig("exclude", []string{"/health"})
	h := newHost(t, a, hostOpts{})
	h.call(call{path: "/health/live"})
	h.call(call{path: "/api", headers: [][2]string{{"authorization", "Bearer very-secret"}, {"cookie", "s=1; t=2"}}})
	evs := h.events()
	if len(evs) != 1 || evs[0]["p"] != "/api" || evs[0]["auth"] != "Bearer" || evs[0]["ck"] != 2.0 {
		t.Fatalf("%v", evs)
	}
	if s := jsonOf(t, evs[0]); strings.Contains(s, "very-secret") || strings.Contains(s, "s=1") {
		t.Fatalf("credential shipped: %s", s)
	}
	a.SetConfig("sample", 0)
	h.engine.Snap.Refresh()
	h.call(call{path: "/api"})
	if len(h.events()) != 1 {
		t.Fatal("sampled out request shipped")
	}
}

func TestExposesRIDSIDIPToTheApp(t *testing.T) {
	h := newHost(t, testutil.NewFakeAnalyst(t), hostOpts{})
	r := h.call(call{path: "/"})
	ctx := h.ctx(0)
	if ctx == nil || ctx.RID != r.header("x-rid") || ctx.IP != defaultPeer || ctx.SID == "" {
		t.Fatalf("%+v", ctx)
	}
}

func TestAnAppPanicShipsSt500AndPropagates(t *testing.T) {
	h := newHost(t, testutil.NewFakeAnalyst(t), hostOpts{handler: func(w http.ResponseWriter, r *http.Request) { panic("app bug") }})
	func() {
		defer func() {
			if r := recover(); r != "app bug" {
				t.Fatalf("panic %v", r)
			}
		}()
		h.call(call{path: "/crash"})
	}()
	evs := h.events()
	if len(evs) != 1 || evs[0]["p"] != "/crash" || evs[0]["st"] != 500.0 {
		t.Fatalf("%v", evs)
	}
}

// ---- track ----

func TestTrackShipsAnAppContextEventWithAHashedUID(t *testing.T) {
	h := newHost(t, testutil.NewFakeAnalyst(t), hostOpts{handler: func(w http.ResponseWriter, r *http.Request) {
		Track(r, "login_failed", "alice@example.com")
		w.WriteHeader(401)
	}})
	r := h.call(call{method: "POST", path: "/login", body: "x=1"})
	evs := h.events()
	var tracked map[string]any
	for _, e := range evs {
		if e["et"] != nil {
			tracked = e
		}
	}
	if tracked == nil || tracked["et"] != "login_failed" || tracked["tap"] != "sdk-go" || tracked["rid"] != r.header("x-rid") {
		t.Fatalf("%v", tracked)
	}
	if tracked["uid"] != HashUserID("alice@example.com", "tok-test") {
		t.Fatalf("uid %v", tracked["uid"])
	}
	if strings.Contains(jsonOf(t, evs), "alice") {
		t.Fatal("raw identifier shipped")
	}
	if tracked["ip"] != defaultPeer {
		t.Fatalf("%v", tracked)
	}
	if _, ok := tracked["p"]; ok {
		t.Fatal("a track row is not a page row")
	}
}

func TestTrackWithoutAUserAndWithoutContext(t *testing.T) {
	h := newHost(t, testutil.NewFakeAnalyst(t), hostOpts{})
	h.engine.Track(nil, "signup", "")
	evs := h.events()
	if len(evs) != 1 || evs[0]["et"] != "signup" || evs[0]["uid"] != nil || evs[0]["rid"] != nil {
		t.Fatalf("%v", evs)
	}
}

// ---- beacon ----

func TestServesTheScriptAndBatchesFPAsASigRowWithTheResolvedIP(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	hops1(a)
	h := newHost(t, a, hostOpts{})
	js := h.call(call{path: "/_cam/b.js"})
	if js.status != 200 || js.header("content-type") != "application/javascript" || !strings.Contains(js.body, "@camada/browser") {
		t.Fatalf("%+v", js)
	}
	if js.header("cache-control") != "public, max-age=3600" {
		t.Fatalf("cache-control %q", js.header("cache-control"))
	}
	body := jsonOf(t, map[string]any{"sdk": "@camada/browser/0.2.0", "rid": "r-1", "ip": "9.9.9.9", "tap": "proxy", "scr": "1x1"})
	fp := h.call(call{method: "POST", path: "/_cam/fp", headers: [][2]string{{"x-forwarded-for", "198.18.0.5"}, {"content-type", "application/json"}}, body: body})
	if fp.status != 204 || fp.header("cache-control") != "no-store" || len(h.seen) != 0 {
		t.Fatalf("%+v", fp)
	}
	evs := h.events()
	if len(evs) != 1 {
		t.Fatalf("%v", evs)
	}
	row := evs[0]
	if row["sig"] != 1.0 || row["ip"] != "198.18.0.5" || row["tap"] != "sdk-go" || row["scr"] != "1x1" || row["rid"] != "r-1" {
		t.Fatalf("%v", row)
	}
}

func TestDropsJunkBodiesInsteadOfShippingThem(t *testing.T) {
	h := newHost(t, testutil.NewFakeAnalyst(t), hostOpts{})
	for _, junk := range []string{"not json", "[1,2]", "42", ""} {
		if h.call(call{method: "POST", path: "/_cam/fp", body: junk}).status != 204 {
			t.Fatalf("junk %q", junk)
		}
	}
	if len(h.events()) != 0 {
		t.Fatal("junk shipped")
	}
}

func TestRejectsOversizedPostsDeclaredOrActual(t *testing.T) {
	h := newHost(t, testutil.NewFakeAnalyst(t), hostOpts{})
	if h.call(call{method: "POST", path: "/_cam/fp", body: "{}", contentLength: 40000}).status != 413 {
		t.Fatal("declared")
	}
	if h.call(call{method: "POST", path: "/_cam/fp", body: "{" + strings.Repeat(" ", 33000) + "}"}).status != 413 {
		t.Fatal("actual")
	}
	if len(h.events()) != 0 {
		t.Fatal("shipped")
	}
}

func TestFallsThroughToTheAppWhenTheTenantDisabledTheBeacon(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	a.SetConfig("beacon", false)
	h := newHost(t, a, hostOpts{})
	if h.call(call{path: "/_cam/b.js"}).body != "hello" || h.call(call{method: "POST", path: "/_cam/fp", body: "{}"}).body != "hello" {
		t.Fatal("did not fall through")
	}
	if h.engine.ScriptTag(h.ctx(0)) != "" {
		t.Fatal("tag with the beacon off")
	}
}

func TestScriptTagCarriesTheRID(t *testing.T) {
	h := newHost(t, testutil.NewFakeAnalyst(t), hostOpts{})
	r := h.call(call{path: "/"})
	if got := h.engine.ScriptTag(h.ctx(0)); got != `<script src="/_cam/b.js?r=`+r.header("x-rid")+`" async></script>` {
		t.Fatalf("%q", got)
	}
	if got := h.engine.ScriptTag(nil); got != `<script src="/_cam/b.js" async></script>` {
		t.Fatalf("%q", got)
	}
}

func TestEnforcementComesBeforeTheBeaconEndpoints(t *testing.T) {
	h := newHost(t, testutil.NewFakeAnalyst(t), hostOpts{})
	if h.call(call{path: "/_cam/b.js", peer: testutil.BlockedIP}).status != 403 {
		t.Fatal("beacon served to a blocked ip")
	}
}

// ---- rules ----

func v5(t *testing.T) *testutil.FakeAnalyst {
	a := testutil.NewFakeAnalyst(t)
	a.Container = "v5"
	hops1(a)
	return a
}

func TestSkipRuleBeatsTheWiderBlock(t *testing.T) {
	h := newHost(t, v5(t), hostOpts{})
	if h.call(call{path: testutil.SkipPath, headers: xff(testutil.BlockedIP)}).status != 200 {
		t.Fatal("skip lost")
	}
	ev := h.events()[0]
	if _, ok := ev["blk"]; ok {
		t.Fatal("blk")
	}
	if _, ok := ev["wrn"]; ok {
		t.Fatal("wrn")
	}
}

func TestBlocksByRuleWithXBlockRuleAndShipsRL(t *testing.T) {
	h := newHost(t, v5(t), hostOpts{})
	r := h.call(call{path: "/", headers: xff(testutil.RuleBlockedIP)})
	if r.status != 403 || r.header("x-block-reason") != "rule" || r.header("x-block-rule") != "builtin:block" {
		t.Fatalf("%+v", r)
	}
	ev := h.events()[0]
	if ev["blk"] != "rule" || ev["rl"] != "builtin:block" {
		t.Fatalf("%v", ev)
	}
}

func TestBlocksByPathUAAndHeaderRules(t *testing.T) {
	h := newHost(t, v5(t), hostOpts{})
	if h.call(call{path: testutil.RuleBlockedPath}).header("x-block-rule") != "cr_00000000000c" {
		t.Fatal("path rule")
	}
	if h.call(call{path: "/", headers: [][2]string{{"user-agent", testutil.BlockedUA}}}).status != 403 {
		t.Fatal("ua rule")
	}
	if h.call(call{path: "/", headers: [][2]string{{strings.ToUpper(testutil.BlockedHeader), testutil.BlockedHeaderValue}}}).status != 403 { // any spelling
		t.Fatal("header rule")
	}
	if h.call(call{path: "/", headers: [][2]string{{testutil.BlockedHeader, "other"}}}).status != 200 || h.call(call{path: "/"}).status != 200 {
		t.Fatal("over-blocked")
	}
}

func TestWarnPassesAndStampsWrn(t *testing.T) {
	h := newHost(t, v5(t), hostOpts{})
	if h.call(call{path: "/", headers: [][2]string{{"user-agent", testutil.WarnUA}}}).status != 200 {
		t.Fatal("warn blocked")
	}
	ev := h.events()[0]
	if ev["wrn"] != "cr_00000000000e" || ev["st"] != 200.0 {
		t.Fatalf("%v", ev)
	}
}

func TestStillEnforcesAgainstAnAnalystThatOnlyPublishesV3(t *testing.T) {
	a := v5(t)
	a.Container = "v3"
	h := newHost(t, a, hostOpts{})
	if h.call(call{path: "/", headers: xff(testutil.BlockedIP)}).status != 403 {
		t.Fatal("v3 block lost")
	}
	if h.call(call{path: "/", headers: [][2]string{{"user-agent", testutil.BlockedUA}}}).status != 200 { // a rule-only signal: v3 carries no rules
		t.Fatal("v3 blocked by a rule it cannot carry")
	}
}

// ---- challenge ----

func v4(t *testing.T) *testutil.FakeAnalyst {
	a := testutil.NewFakeAnalyst(t)
	a.Container = "v4"
	return a
}

func TestServesThePageForAnHTMLNavigationAndShipsBlkChallenge(t *testing.T) {
	h := newHost(t, v4(t), hostOpts{})
	r := h.call(call{path: "/account?tab=1", headers: htmlNav, peer: testutil.ChallengedIP})
	if r.status != 403 || r.header("content-type") != "text/html; charset=utf-8" || r.header("x-camada-challenge") != "1" || r.header("cache-control") != "no-store" {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.body, `action="/__camada/challenge"`) || !strings.Contains(r.body, `name="to" value="/account?tab=1"`) {
		t.Fatal("page")
	}
	if len(h.seen) != 0 {
		t.Fatal("the app ran")
	}
	ev := h.events()[0]
	if ev["st"] != 403.0 || ev["blk"] != "challenge" || ev["p"] != "/account" {
		t.Fatalf("%v", ev)
	}
}

func TestAnswersJSONForANonHTMLRequest(t *testing.T) {
	h := newHost(t, v4(t), hostOpts{})
	r := h.call(call{path: "/api", headers: [][2]string{{"accept", "application/json"}}, peer: testutil.ChallengedIP})
	if r.status != 403 || r.header("content-type") != "application/json" || r.body != `{"error":"challenge_required"}` {
		t.Fatalf("%+v", r)
	}
	r2 := h.call(call{path: "/api", headers: [][2]string{{"accept", "text/html"}, {"sec-fetch-dest", "empty"}}, peer: testutil.ChallengedIP})
	if r2.header("content-type") != "application/json" {
		t.Fatal("a fetch got the page")
	}
}

func TestBlocksOutrightRatherThanChallengingABlockedIP(t *testing.T) {
	h := newHost(t, v4(t), hostOpts{})
	r := h.call(call{path: "/", headers: htmlNav, peer: testutil.BlockedIP})
	if r.status != 403 || r.header("x-camada-challenge") != "" {
		t.Fatalf("%+v", r)
	}
}

func TestVerifySetsCchRedirectsBackAndShipsCh1(t *testing.T) {
	h := newHost(t, v4(t), hostOpts{})
	page := h.call(call{path: "/back?x=1", headers: htmlNav, peer: testutil.ChallengedIP}).body
	nonce := nonceOf(t, page)
	form := "nonce=" + nonce + "&solution=" + testutil.Solve(nonce) + "&to=%2Fback%3Fx%3D1"
	r := h.call(call{method: "POST", path: "/__camada/challenge", headers: [][2]string{{"content-type", "application/x-www-form-urlencoded"}}, body: form, peer: testutil.ChallengedIP})
	if r.status != 302 || r.header("location") != "/back?x=1" || r.header("cache-control") != "no-store" {
		t.Fatalf("%+v", r)
	}
	cookie := r.header("set-cookie")
	if !strings.HasPrefix(cookie, "_cch=") || !strings.Contains(cookie, "HttpOnly") {
		t.Fatalf("cookie %q", cookie)
	}
	evs := h.events()
	last := evs[len(evs)-1]
	if last["st"] != 200.0 || last["ch"] != 1.0 || last["p"] != "/__camada/challenge" {
		t.Fatalf("%v", last)
	}
	// the holder of a valid _cch passes; a cookie minted for another ip does not
	pair := cookiePair(cookie)
	if h.call(call{path: "/back", headers: append(htmlNav, [2]string{"cookie", pair}), peer: testutil.ChallengedIP}).status != 200 {
		t.Fatal("holder challenged")
	}
	if h.call(call{path: "/back", headers: append(htmlNav, [2]string{"cookie", pair}), peer: "192.0.2.21"}).status != 200 { // not challenged at all
		t.Fatal("neighbour challenged")
	}
	forged := "_cch=" + strings.Replace(pair[5:], "0", "1", 1)
	if h.call(call{path: "/back", headers: append(htmlNav, [2]string{"cookie", forged}), peer: testutil.ChallengedIP}).status != 403 {
		t.Fatal("forged cookie passed")
	}
}

func TestWrongSolutionOrForgedNonceReservesThePage(t *testing.T) {
	h := newHost(t, v4(t), hostOpts{})
	nonce := nonceOf(t, h.call(call{path: "/", headers: htmlNav, peer: testutil.ChallengedIP}).body)
	r := h.call(call{method: "POST", path: "/__camada/challenge", body: "nonce=" + nonce + "&solution=1&to=%2F", peer: testutil.ChallengedIP})
	if r.status != 403 || r.header("set-cookie") != "" || !strings.Contains(r.body, "camada-f") {
		t.Fatalf("%+v", r)
	}
	forged := strings.Repeat("f", 32)
	r = h.call(call{method: "POST", path: "/__camada/challenge", body: "nonce=" + forged + "&solution=" + testutil.Solve(forged) + "&to=%2F", peer: testutil.ChallengedIP})
	if r.status != 403 || r.header("set-cookie") != "" {
		t.Fatalf("%+v", r)
	}
}

func TestNeverRedirectsOffSite(t *testing.T) {
	h := newHost(t, v4(t), hostOpts{})
	nonce := h.engine.Kit.Nonce(testutil.ChallengedIP, h.engine.NowMS())
	r := h.call(call{method: "POST", path: "/__camada/challenge", body: "nonce=" + nonce + "&solution=" + testutil.Solve(nonce) + "&to=" + url.QueryEscape("https://evil"), peer: testutil.ChallengedIP})
	if r.status != 302 || r.header("location") != "/" {
		t.Fatalf("%+v", r)
	}
}

func TestRefusesAnOversizedVerifyBody(t *testing.T) {
	h := newHost(t, v4(t), hostOpts{})
	if h.call(call{method: "POST", path: "/__camada/challenge", body: "a=" + strings.Repeat("b", 5000), peer: testutil.ChallengedIP}).status != 413 {
		t.Fatal("accepted")
	}
}

func TestNoIPMeansNoChallenge(t *testing.T) {
	h := newHost(t, v4(t), hostOpts{})
	if h.call(call{path: "/", headers: htmlNav, peer: "-"}).status != 200 {
		t.Fatal("challenged without an ip")
	}
}

func TestChallengeSwitchedOffByEnvOrOption(t *testing.T) {
	a := v4(t)
	if newHost(t, a, hostOpts{env: map[string]string{"CAMADA_CHALLENGE": "0"}}).call(call{path: "/", headers: htmlNav, peer: testutil.ChallengedIP}).status != 200 {
		t.Fatal("env")
	}
	off := false
	if newHost(t, a, hostOpts{opts: Options{Challenge: &off}}).call(call{path: "/", headers: htmlNav, peer: testutil.ChallengedIP}).status != 200 {
		t.Fatal("option")
	}
}

func TestServeChallengeOnDemand(t *testing.T) {
	h := newHost(t, v4(t), hostOpts{handler: func(w http.ResponseWriter, r *http.Request) {
		if ServeChallenge(w, r) {
			return
		}
		_, _ = w.Write([]byte("secret page"))
	}})
	r := h.call(call{path: "/challenge-me", headers: htmlNav})
	if r.status != 403 || !strings.Contains(r.body, "camada-f") {
		t.Fatalf("%+v", r)
	}
	evs := h.events()
	if len(evs) != 1 || evs[0]["blk"] != "challenge" { // one request, one event
		t.Fatalf("%v", evs)
	}
	nonce := nonceOf(t, r.body)
	ok := h.call(call{method: "POST", path: "/__camada/challenge", body: "nonce=" + nonce + "&solution=" + testutil.Solve(nonce) + "&to=%2Fchallenge-me"})
	pair := cookiePair(ok.header("set-cookie"))
	if h.call(call{path: "/challenge-me", headers: append(htmlNav, [2]string{"cookie", pair})}).body != "secret page" {
		t.Fatal("holder still challenged")
	}
}

// ---- fail open ----

func TestKeepsServingWhenIngestIsDown(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	a.IngestDown = true
	h := newHost(t, a, hostOpts{})
	if h.call(call{path: "/"}).status != 200 {
		t.Fatal("5xx")
	}
	if len(h.events()) != 0 || h.engine.Queue.Dropped() != 1 {
		t.Fatalf("dropped %d", h.engine.Queue.Dropped())
	}
}

func TestDisabledBypassesTheSDKEntirely(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	h := newHost(t, a, hostOpts{env: map[string]string{"CAMADA_DISABLED": "1"}, cold: true})
	if h.engine.Snap != nil || !h.engine.Disabled() {
		t.Fatal("built a client under the kill switch")
	}
	r := h.call(call{path: "/", peer: testutil.BlockedIP})
	if r.status != 200 || r.header("x-rid") != "" || len(a.Snapshots()) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestKillSwitchIsReadPerRequest(t *testing.T) {
	env := map[string]string{}
	for k, v := range testEnv {
		env[k] = v
	}
	a := testutil.NewFakeAnalyst(t)
	e := New(Options{Env: env, Transport: a.Transport})
	t.Cleanup(func() { e.Stop(shortCtx()) })
	loaded(t, e)
	h := &host{t: t, a: a, engine: e, app: e.Handler(http.HandlerFunc(hello))}
	if h.call(call{path: "/", peer: testutil.BlockedIP}).status != 403 {
		t.Fatal("not enforcing")
	}
	env["CAMADA_DISABLED"] = "1"
	if r := h.call(call{path: "/", peer: testutil.BlockedIP}); r.status != 200 || r.header("x-rid") != "" {
		t.Fatalf("%+v", r)
	}
}

func TestStaysInertWithoutCredentials(t *testing.T) {
	h := newHost(t, testutil.NewFakeAnalyst(t), hostOpts{env: map[string]string{"CAMADA_KEY": ""}, cold: true})
	if h.engine.Env != nil {
		t.Fatal("configured from nothing")
	}
	if h.call(call{path: "/", peer: testutil.BlockedIP}).status != 200 {
		t.Fatal("blocked while inert")
	}
	if h.engine.ScriptTag(nil) != "" || h.engine.ServeChallenge(nil) != nil {
		t.Fatal("helpers active while inert")
	}
	h.engine.Track(nil, "x", "")
}

func TestACamadaBugCostsTheJoinNotTheRequest(t *testing.T) {
	h := newHost(t, testutil.NewFakeAnalyst(t), hostOpts{})
	h.engine.decide = func(*Req, []byte) (*Answer, *Passed) { panic("sdk bug") }
	r := h.call(call{path: "/", peer: testutil.BlockedIP})
	if r.status != 200 || r.body != "hello" {
		t.Fatalf("%+v", r)
	}
}

// ---- small parts ----

func TestCookieValueFindsTheNamedCookieOnly(t *testing.T) {
	for _, c := range []struct {
		cookie, name, want string
		ok                 bool
	}{
		{"a=1; _sfp=abc; b=2", "_sfp", "abc", true},
		{"_sfp=abc", "_sfp", "abc", true},
		{"x_sfp=zzz; b=2", "_sfp", "", false},
		{"", "_sfp", "", false},
	} {
		got, ok := cookieValue(c.cookie, c.name)
		if got != c.want || ok != c.ok {
			t.Errorf("cookieValue(%q, %q) = %q,%v", c.cookie, c.name, got, ok)
		}
	}
}

func TestReqHeaderJoinsRepeatedFields(t *testing.T) {
	req := &Req{Headers: []Header{hdr("cookie", "a=1"), hdr("accept", "text/html"), hdr("cookie", "b=2"), hdr("accept", "*/*")}}
	if v, _ := req.Header("cookie"); v != "a=1; b=2" {
		t.Fatalf("cookie %q", v)
	}
	if v, _ := req.Header("accept"); v != "text/html, */*" {
		t.Fatalf("accept %q", v)
	}
}

func TestUUID4Shape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		u := uuid4()
		if len(u) != 36 || u[14] != '4' || !strings.ContainsRune("89ab", rune(u[19])) || seen[u] {
			t.Fatalf("%q", u)
		}
		seen[u] = true
	}
}

func TestWantsBodyOnlyForTheEndpointsCamadaAnswers(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	h := newHost(t, a, hostOpts{})
	for _, c := range []struct {
		method, path string
		cap          int
		ok           bool
	}{
		{"POST", "/_cam/fp", FPMax, true},
		{"POST", "/__camada/challenge", BodyMax, true},
		{"GET", "/_cam/fp", 0, false},
		{"POST", "/login", 0, false},
	} {
		if got, ok := h.engine.WantsBody(c.method, c.path); got != c.cap || ok != c.ok {
			t.Errorf("WantsBody(%s %s) = %d,%v", c.method, c.path, got, ok)
		}
	}
	a.SetConfig("beacon", false)
	h.engine.Snap.Refresh()
	if _, ok := h.engine.WantsBody("POST", "/_cam/fp"); ok {
		t.Fatal("beacon off still reads the body")
	}
	off := newHost(t, a, hostOpts{env: map[string]string{"CAMADA_CHALLENGE": "0"}})
	if _, ok := off.engine.WantsBody("POST", "/__camada/challenge"); ok {
		t.Fatal("challenge off still reads the body")
	}
}

func TestStopDrainsThePendingBatch(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	h := newHost(t, a, hostOpts{})
	h.call(call{path: "/"})
	if len(a.AllEvents()) != 0 {
		t.Fatal("shipped before the interval")
	}
	h.engine.Stop(context.Background())
	if evs := a.AllEvents(); len(evs) != 1 || evs[0]["p"] != "/" {
		t.Fatalf("%v", evs)
	}
}

func TestServerlessModeRefreshesFromTheRequestPath(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	h := newHost(t, a, hostOpts{env: map[string]string{"CAMADA_SERVERLESS": "1"}})
	if h.engine.Snap.Mode != "lazy" {
		t.Fatalf("mode %q", h.engine.Snap.Mode)
	}
	if h.call(call{path: "/", peer: testutil.BlockedIP}).status != 403 {
		t.Fatal("not enforcing")
	}
	pinned := newHost(t, a, hostOpts{opts: Options{Refresh: 7 * time.Second}})
	if pinned.engine.Snap.RefreshInterval() != 7*time.Second {
		t.Fatal("refresh not handed to the client")
	}
}
