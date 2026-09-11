package camada

// The driver that runs the SDK through net/http without a listening socket: an httptest
// recorder and a ServeMux app, so r.Pattern and RemoteAddr behave as they do in production.

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/camada/camada-go/internal/testutil"
	"github.com/camada/camada-go/snapshot"
)

var testEnv = map[string]string{"CAMADA_KEY": "tok-test.snap-test", "CAMADA_INGEST_URL": "https://analyst.test"}

const defaultPeer = "172.16.0.9" // a peer no golden container lists (10.0.0.0/8 is blocked in all of them)

type call struct {
	method, path  string
	headers       [][2]string
	body          string
	peer          string // "" = defaultPeer; "-" = no peer at all (a unix socket)
	https         bool
	contentLength int // override the declared length; 0 = actual
}

type reply struct {
	status  int
	headers http.Header
	body    string
}

func (r reply) header(name string) string { return r.headers.Get(name) }

func engineWith(t *testing.T, a *testutil.FakeAnalyst, env map[string]string, o Options) *Camada {
	t.Helper()
	merged := map[string]string{}
	for k, v := range testEnv {
		merged[k] = v
	}
	for k, v := range env {
		merged[k] = v
	}
	o.Env, o.Transport = merged, a.Transport
	e := New(o)
	t.Cleanup(func() { e.Stop(shortCtx()) })
	return e
}

func loaded(t *testing.T, e *Camada) {
	t.Helper()
	if e.Snap == nil {
		t.Fatal("no snapshot client")
	}
	for i := 0; i < 400; i++ {
		if e.Snap.Verdict(snapshot.MatchInput{IP: "0.0.0.0"}).Reason != "cold" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("snapshot never loaded")
}

func hello(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "text/plain")
	_, _ = w.Write([]byte("hello"))
}

// host is one engine + one net/http app per test, loaded unless asked otherwise.
type host struct {
	t      *testing.T
	a      *testutil.FakeAnalyst
	engine *Camada
	app    http.Handler
	seen   []*http.Request
}

type hostOpts struct {
	env     map[string]string
	handler http.HandlerFunc
	cold    bool
	opts    Options
}

func newHost(t *testing.T, a *testutil.FakeAnalyst, ho hostOpts) *host {
	t.Helper()
	h := &host{t: t, a: a, engine: engineWith(t, a, ho.env, ho.opts)}
	handler := ho.handler
	if handler == nil {
		handler = hello
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h.seen = append(h.seen, r)
		handler(w, r)
	})
	h.app = h.engine.Handler(mux)
	if !ho.cold && h.engine.Snap != nil {
		loaded(t, h.engine)
	}
	return h
}

func (h *host) request(c call) *http.Request {
	if c.method == "" {
		c.method = "GET"
	}
	r := httptest.NewRequest(c.method, "http://x.test"+c.path, strings.NewReader(c.body))
	r.Host = "x.test"
	switch c.peer {
	case "":
		r.RemoteAddr = defaultPeer + ":12345"
	case "-":
		r.RemoteAddr = ""
	default:
		r.RemoteAddr = c.peer + ":12345"
	}
	if c.https {
		r.TLS = &tls.ConnectionState{}
	}
	for _, kv := range c.headers {
		r.Header.Add(kv[0], kv[1])
	}
	if c.contentLength != 0 {
		r.ContentLength = int64(c.contentLength)
		r.Header.Set("Content-Length", strconv.Itoa(c.contentLength))
	} else if c.method == "POST" || c.body != "" {
		r.Header.Set("Content-Length", strconv.Itoa(len(c.body)))
	}
	return r
}

func (h *host) call(c call) reply {
	rec := httptest.NewRecorder()
	h.app.ServeHTTP(rec, h.request(c))
	res := rec.Result()
	body, _ := io.ReadAll(res.Body)
	return reply{status: res.StatusCode, headers: res.Header, body: string(body)}
}

func (h *host) events() []map[string]any {
	h.engine.Queue.Flush()
	return h.a.AllEvents()
}

func (h *host) ctx(i int) *Ctx { return FromRequest(h.seen[i]) }

func xff(addr string) [][2]string { return [][2]string{{"x-forwarded-for", addr}} }

func hops1(a *testutil.FakeAnalyst) {
	a.SetConfig("trusted_proxy", map[string]any{"mode": "hops", "hops": 1})
}

var htmlNav = [][2]string{{"accept", "text/html,*/*"}, {"sec-fetch-dest", "document"}}

func nonceOf(t *testing.T, page string) string {
	t.Helper()
	_, after, ok := strings.Cut(page, `name="nonce" value="`)
	if !ok {
		t.Fatal("no nonce in the page")
	}
	nonce, _, _ := strings.Cut(after, `"`)
	return nonce
}

func cookiePair(setCookie string) string {
	pair, _, _ := strings.Cut(setCookie, ";")
	return pair
}
