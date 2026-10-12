package camada

// What only the net/http adapter can show: the request mapping, a body camada read being put
// back, the recorder's status and stamps, the route pattern, and the lazy default engine.

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/camada-app/camada-go/internal/guarded"
	"github.com/camada-app/camada-go/internal/testutil"
	"github.com/camada-app/camada-go/snapshot"
)

func TestRequestMapping(t *testing.T) {
	r := httptest.NewRequest("PUT", "http://h/a?x=1", strings.NewReader("abc"))
	r.RemoteAddr = "[::ffff:1.2.3.4]:9"
	r.Header.Set("X-Forwarded-For", "5.6.7.8")
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Add("Cookie", "a=1")
	r.Header.Add("Cookie", "b=2")
	req := reqFromHTTP(r)
	if req.Method != "PUT" || req.Path != "/a" || req.Query != "?x=1" || req.Host != "h" || req.HTTPVersion != "1.1" || req.Peer != "::ffff:1.2.3.4" || req.HTTPS {
		t.Fatalf("%+v", req)
	}
	if v, _ := req.Header("x-forwarded-for"); v != "5.6.7.8" {
		t.Fatal("xff")
	}
	if v, _ := req.Header("cookie"); v != "a=1; b=2" { // HTTP/2 clients split cookies into several fields
		t.Fatalf("cookie %q", v)
	}
	if v, _ := req.Header("content-type"); v != "text/plain" {
		t.Fatal("content-type")
	}
	if _, ok := req.Header("x-none"); ok {
		t.Fatal("absent header present")
	}
	// the matcher reads the path still percent-encoded: %2F must stay distinct from a separator
	if p := reqFromHTTP(httptest.NewRequest("GET", "http://h/%62locked%2Fpath", nil)).Path; p != "/%62locked%2Fpath" {
		t.Fatalf("raw path %q", p)
	}
}

// C6 v3 peer table, net/http: a unix-socket listener is no peer (the cidrs walk runs over XFF alone); a RemoteAddr
// SplitHostPort cannot split, or "@", on a TCP listener could not be read and resolves to no ip. A request with no
// local address at all (a Lambda/API Gateway shim, http.NewRequest) has no socket: "" is no peer and walks, and any
// other unsplittable RemoteAddr is passed as-is (a bare ip is the peer; anything else fails validation).
func TestPeerRuleUnixListenerAndUnreadablePeer(t *testing.T) {
	cfg := &TrustedProxy{Mode: "cidrs", CIDRs: []string{"172.64.0.0/13"}}
	resolveWith := func(r *http.Request, c *TrustedProxy) string { return reqIP(reqFromHTTP(r), c) }
	resolve := func(r *http.Request) string { return resolveWith(r, cfg) }
	mk := func(remote string, local net.Addr) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", "198.51.100.9, 172.64.1.1")
		if local != nil {
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, local))
		}
		return r
	}
	unix := &net.UnixAddr{Name: "/run/app.sock", Net: "unix"}
	tcp := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	for _, remote := range []string{"@", "", "/run/app.sock"} {
		if got := resolve(mk(remote, unix)); got != "198.51.100.9" {
			t.Errorf("unix listener, RemoteAddr %q: got %q", remote, got)
		}
		if req := reqFromHTTP(mk(remote, unix)); req.Peer != "" || req.PeerUnreadable {
			t.Errorf("unix listener, RemoteAddr %q: %+v", remote, req)
		}
	}
	for _, remote := range []string{"@", "", "/run/app.sock", "198.51.100.7", "[fe80::1%eth0]:1"} {
		if got := resolve(mk(remote, tcp)); got != "" {
			t.Errorf("tcp listener, RemoteAddr %q: got %q", remote, got)
		}
	}
	// no local address: no socket concept
	for remote, want := range map[string]string{
		"":                 "198.51.100.9", // no peer: walks XFF
		"198.51.100.7":     "198.51.100.7", // a bare ip from the platform is the peer (not trusted: the client)
		"172.64.1.1":       "198.51.100.9", // a bare trusted ip walks
		"@":                "",             // garbage fails validation
		"/run/app.sock":    "",
		"[fe80::1%eth0]:1": "",
	} {
		if got := resolve(mk(remote, nil)); got != want {
			t.Errorf("no local address, RemoteAddr %q: got %q want %q", remote, got, want)
		}
		if req := reqFromHTTP(mk(remote, nil)); req.PeerUnreadable {
			t.Errorf("no local address, RemoteAddr %q: unreadable", remote)
		}
	}
	for _, c := range []*TrustedProxy{{Mode: "vercel"}, {Mode: "hops", Hops: 1}} {
		if got := resolveWith(mk("", nil), c); got != "172.64.1.1" {
			t.Errorf("no local address, RemoteAddr \"\", %s: got %q", c.Mode, got)
		}
		if got := resolveWith(mk("", tcp), c); got != "" {
			t.Errorf("tcp listener, RemoteAddr \"\", %s: got %q", c.Mode, got)
		}
	}
	if got := resolve(mk("172.64.1.1:443", tcp)); got != "198.51.100.9" { // a trusted peer still walks
		t.Errorf("trusted peer: got %q", got)
	}
	if got := resolve(mk("203.0.113.5:443", tcp)); got != "203.0.113.5" { // a direct hit is the client
		t.Errorf("direct hit: got %q", got)
	}
}

// A middleware (chi's RealIP, gorilla's ProxyHeaders) that rewrote RemoteAddr to a bare ip on a TCP listener: no ip,
// and one warning line naming the cause, rate-limited.
func TestBareIPRemoteAddrOnATCPListenerWarnsOnce(t *testing.T) {
	var buf strings.Builder
	SetLogger(log.New(&buf, "", 0))
	t.Cleanup(func() { SetLogger(log.Default()) })
	guarded.Reset()
	tcp := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "198.51.100.7"
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, net.Addr(tcp)))
		if got := reqIP(reqFromHTTP(r), nil); got != "" {
			t.Fatalf("ip %q", got)
		}
	}
	out := buf.String()
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, "RemoteAddr") || !strings.Contains(out, "198.51.100.7") {
		t.Fatalf("log %q", out)
	}
}

func TestABodyCamadaReadIsPutBackForTheApp(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	a.SetConfig("beacon", false)
	e := engineWith(t, a, nil, Options{})
	loaded(t, e)
	var got []string
	app := e.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, string(b))
		_, _ = w.Write([]byte("ok"))
	}))
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/_cam/fp", strings.NewReader("{}"))
	r.RemoteAddr = defaultPeer + ":1"
	app.ServeHTTP(rec, r)
	if rec.Body.String() != "ok" || len(got) != 1 || got[0] != "{}" {
		t.Fatalf("%q %v", rec.Body.String(), got)
	}
}

func TestABodyOverTheCapReachesTheAppWhole(t *testing.T) {
	// no ip -> camada never answers the verify endpoint, so the app gets the request with its full body
	e := engineWith(t, testutil.NewFakeAnalyst(t), nil, Options{})
	loaded(t, e)
	big := strings.Repeat("x", 70_000)
	var got []string
	app := e.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, string(b))
		_, _ = w.Write([]byte("ok"))
	}))
	for _, chunked := range []bool{false, true} { // declared over the cap, and over it only once read
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/__camada/challenge", strings.NewReader(big))
		r.RemoteAddr = ""
		if chunked {
			r.ContentLength = -1
		}
		app.ServeHTTP(rec, r)
		if rec.Body.String() != "ok" || len(got) != 1 || got[0] != big {
			t.Fatalf("chunked=%v: %q len %d", chunked, rec.Body.String(), len(got))
		}
		got = nil
	}
}

func TestRoutePatternReachesTheEvent(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	e := engineWith(t, a, nil, Options{})
	loaded(t, e)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /items/{id}", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(r.PathValue("id"))) })
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/items/7", nil)
	r.RemoteAddr = defaultPeer + ":1"
	e.Handler(mux).ServeHTTP(rec, r)
	if rec.Body.String() != "7" {
		t.Fatal("route")
	}
	e.Queue.Flush()
	if ev := a.AllEvents()[0]; ev["rt"] != "GET /items/{id}" {
		t.Fatalf("%v", ev)
	}
}

func TestStreamingResponsesFlushAndFinishOnce(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	e := engineWith(t, a, nil, Options{})
	loaded(t, e)
	app := e.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		for _, part := range []string{"a", "b", "c"} {
			_, _ = w.Write([]byte(part))
			http.NewResponseController(w).Flush()
		}
	}))
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/s", nil)
	r.RemoteAddr = defaultPeer + ":1"
	app.ServeHTTP(rec, r)
	if rec.Body.String() != "abc" || !rec.Flushed || rec.Header().Get("x-rid") == "" {
		t.Fatalf("%q flushed %v", rec.Body.String(), rec.Flushed)
	}
	e.Queue.Flush()
	evs := a.AllEvents()
	if len(evs) != 1 || evs[0]["p"] != "/s" || evs[0]["st"] != 200.0 {
		t.Fatalf("%v", evs)
	}
}

func TestStampsSurviveAnAppThatResetsTheCookieHeader(t *testing.T) {
	e := engineWith(t, testutil.NewFakeAnalyst(t), nil, Options{})
	loaded(t, e)
	app := e.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "app=1") // Set, not Add: wipes what was there
		w.WriteHeader(204)
	}))
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = defaultPeer + ":1"
	app.ServeHTTP(rec, r)
	cookies := rec.Header().Values("Set-Cookie")
	if rec.Code != 204 || len(cookies) != 2 || rec.Header().Get("x-rid") == "" {
		t.Fatalf("%d %v", rec.Code, cookies)
	}
}

func TestFromRequestIsNilOutsideTheMiddleware(t *testing.T) {
	if FromRequest(httptest.NewRequest("GET", "/", nil)) != nil {
		t.Fatal("ctx from nowhere")
	}
}

func TestWrapsTheDefaultEngineLazily(t *testing.T) {
	resetDefault()
	t.Cleanup(resetDefault)
	t.Setenv("CAMADA_DISABLED", "1")
	t.Setenv("CAMADA_KEY", "a.b")
	if defaultEngine != nil {
		t.Fatal("built before the first request")
	}
	rec := httptest.NewRecorder()
	Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("x")) })).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Body.String() != "x" || !Default().Disabled() {
		t.Fatal("default engine")
	}
}

func TestConfigureReplacesAndStopsTheDefault(t *testing.T) {
	resetDefault()
	t.Cleanup(resetDefault)
	a := testutil.NewFakeAnalyst(t)
	first := Configure(Options{Env: testEnv, Transport: a.Transport})
	loaded(t, first)
	second := Configure(Options{Env: map[string]string{"CAMADA_KEY": ""}})
	if Default() != second || second.Env != nil {
		t.Fatal("not replaced")
	}
	time.Sleep(20 * time.Millisecond)
	n := len(a.Snapshots())
	time.Sleep(50 * time.Millisecond)
	if len(a.Snapshots()) != n {
		t.Fatal("the old engine kept polling")
	}
}

func TestAHijackedConnectionReports101(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	e := engineWith(t, a, nil, Options{})
	loaded(t, e)
	srv := httptest.NewServer(e.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: close\r\n\r\n")
		_ = rw.Flush()
		_ = conn.Close()
	})))
	defer srv.Close()
	res, err := http.Get(srv.URL + "/ws")
	if err == nil {
		res.Body.Close()
	}
	// the client sees EOF as soon as the conn closes, but the event is enqueued by the handler's
	// deferred finish, which runs after that: wait for it rather than assume it already landed
	var evs []map[string]any
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		e.Queue.Flush()
		if evs = a.AllEvents(); len(evs) > 0 {
			break
		}
	}
	if len(evs) != 1 || evs[0]["p"] != "/ws" || evs[0]["st"] != 101.0 {
		t.Fatalf("%v", evs)
	}
}

func TestEarlyHintsAreNotTheFinalStatus(t *testing.T) {
	// 103 Early Hints, then the real answer: the event and the response both carry the final one
	a := testutil.NewFakeAnalyst(t)
	e := engineWith(t, a, nil, Options{})
	loaded(t, e)
	srv := httptest.NewServer(e.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</app.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})))
	defer srv.Close()
	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	rid := res.Header.Get("x-rid")
	if res.StatusCode != 200 || rid == "" {
		t.Fatalf("%d %v", res.StatusCode, res.Header)
	}
	e.Queue.Flush()
	if evs := a.AllEvents(); len(evs) != 1 || evs[0]["st"] != 200.0 || evs[0]["rid"] != rid {
		t.Fatalf("%v", evs)
	}
}

func TestInterimEarlyHintsCarryNoRidOrCookie(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	e := engineWith(t, a, nil, Options{})
	loaded(t, e)
	srv := httptest.NewServer(e.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</app.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("X-App", "1")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})))
	defer srv.Close()
	var hints http.Header
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
		hints = http.Header(h)
		return nil
	}}
	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	res, err := http.DefaultClient.Do(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if hints.Get("Link") == "" || hints.Get("X-Rid") != "" || hints.Get("Set-Cookie") != "" {
		t.Fatalf("103: %v", hints)
	}
	if res.StatusCode != 200 || res.Header.Get("X-Rid") == "" || res.Header.Get("X-App") != "1" || res.Header.Get("Link") == "" {
		t.Fatalf("final: %d %v", res.StatusCode, res.Header)
	}
}

func TestA101CarriesNoRid(t *testing.T) {
	// a websocket library that answers the handshake with WriteHeader(101) before it hijacks
	a := testutil.NewFakeAnalyst(t)
	e := engineWith(t, a, nil, Options{})
	loaded(t, e)
	app := e.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Upgrade", "websocket")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ws", nil)
	r.RemoteAddr = defaultPeer + ":1"
	app.ServeHTTP(rec, r)
	if rec.Code != 101 || rec.Header().Get("x-rid") != "" || rec.Header().Get("Upgrade") != "websocket" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	e.Queue.Flush()
	if evs := a.AllEvents(); len(evs) != 1 || evs[0]["st"] != 101.0 || evs[0]["rid"] == nil {
		t.Fatalf("%v", evs)
	}
}

func TestTheReadmeWarmUpWaitsForTheBootPoll(t *testing.T) {
	// The README's startup recipe: Default() has already kicked the boot poll, so a plain Refresh()
	// finds the lock held and returns cold; waiting on Verdict() until it is not cold is what warms it.
	resetDefault()
	t.Cleanup(resetDefault)
	a := testutil.NewFakeAnalyst(t)
	cam := Configure(Options{Env: testEnv, Transport: a.Transport})
	t.Cleanup(func() { cam.Stop(shortCtx()) })
	if cam.Snap == nil {
		t.Fatal("no client")
	}
	deadline := time.Now().Add(5 * time.Second)
	for cam.Snap.Verdict(snapshot.MatchInput{IP: "0.0.0.0"}).Reason == "cold" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !cam.Snap.Verdict(snapshot.MatchInput{IP: testutil.BlockedIP}).Block {
		t.Fatal("still cold after the warm-up")
	}
}
