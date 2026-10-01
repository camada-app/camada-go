package camada

// What only the net/http adapter can show: the request mapping, a body camada read being put
// back, the recorder's status and stamps, the route pattern, and the lazy default engine.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "/var/run/app.sock"
	if reqFromHTTP(r2).Peer != "/var/run/app.sock" { // a unix socket: the raw string, which is no ip
		t.Fatal("unix peer")
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
	e.Queue.Flush()
	evs := a.AllEvents()
	if len(evs) != 1 || evs[0]["p"] != "/ws" || evs[0]["st"] != 101.0 {
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
