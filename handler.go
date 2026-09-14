package camada

// The net/http adapter: `http.ListenAndServe(":8080", camada.Handler(mux))`. It builds the Req,
// reads a capped body when the engine may answer the request, writes an Answer, or runs the
// app with the rid header and session cookie stamped on its response and OnFinish fired
// exactly once — after the last byte, on a panic (as 500, then re-panicked unchanged), or on
// a hijack (101). r.Pattern (Go 1.23) is the route the event reports.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/camada-app/camada-go/internal/guarded"
)

type ctxKey struct{}

// Handler wraps an http.Handler with the default engine, built from the environment on the
// first request (so nothing polls before the app serves).
func Handler(next http.Handler) http.Handler { return &handler{next: next} }

// Handler wraps an http.Handler with this engine.
func (c *Camada) Handler(next http.Handler) http.Handler { return &handler{engine: c, next: next} }

// FromRequest is the camada context of a request the middleware ran for; nil otherwise.
func FromRequest(r *http.Request) *Ctx {
	ctx, _ := r.Context().Value(ctxKey{}).(*Ctx)
	return ctx
}

// ScriptTag is the first-party beacon tag for this request's HTML ("" when the beacon is off).
func ScriptTag(r *http.Request) string {
	ctx := FromRequest(r)
	return engineFor(ctx).ScriptTag(ctx)
}

// Track ships an app-context outcome event for this request; user (an email, an account id)
// is HMAC-hashed in-process and may be "". Never panics. Outside the middleware the outcome
// still ships, with no rid/sid/ip to join on (and the default engine is built if it was not yet).
func Track(r *http.Request, event, user string) {
	ctx := FromRequest(r)
	engineFor(ctx).Track(ctx, event, user)
}

// ServeChallenge writes the proof-of-work page (or 403 JSON) for a route you gate yourself
// and reports true; false — write your own response — once the browser holds a valid _cch,
// or when the client cannot be identified (fail open).
func ServeChallenge(w http.ResponseWriter, r *http.Request) bool {
	ctx := FromRequest(r)
	a := engineFor(ctx).ServeChallenge(ctx)
	if a == nil {
		return false
	}
	writeAnswer(w, a)
	return true
}

type handler struct {
	engine *Camada
	next   http.Handler
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	eng := h.engine
	if eng == nil {
		eng = Default()
	}
	req, body, ok := prepare(eng, r)
	if !ok {
		h.next.ServeHTTP(w, r)
		return
	}
	a, p := eng.Handle(req, body)
	if a != nil {
		writeAnswer(w, a)
		return
	}
	h.run(w, r, p)
}

// prepare builds the Req and reads the capped body inside the fail-open envelope: ok is false
// when camada itself failed, and the app then runs untouched.
func prepare(eng *Camada, r *http.Request) (req *Req, body []byte, ok bool) {
	defer func() {
		if rec := recover(); rec != nil {
			guarded.LogRateLimited(rec)
			req, body, ok = nil, nil, false
		}
	}()
	req = reqFromHTTP(r)
	if limit, wants := eng.WantsBody(req.Method, req.Path); wants {
		body = readBody(r, limit)
	}
	return req, body, true
}

func reqFromHTTP(r *http.Request) *Req {
	headers := make([]Header, 0, len(r.Header)+1)
	if r.Host != "" {
		headers = append(headers, hdr("host", r.Host)) // net/http lifts Host out of the map
	}
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names) // a map has no wire order; sorted is at least stable
	for _, name := range names {
		for _, v := range r.Header[name] {
			headers = append(headers, hdr(strings.ToLower(name), v))
		}
	}
	query := ""
	if r.URL.RawQuery != "" {
		query = "?" + r.URL.RawQuery
	}
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host // "1.2.3.4:56" and "[::1]:56"; a unix socket stays as it is (no ip)
	}
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	return &Req{
		Method:      r.Method,
		Path:        path,
		Query:       query,
		Host:        r.Host,
		HTTPVersion: strconv.Itoa(r.ProtoMajor) + "." + strconv.Itoa(r.ProtoMinor),
		Peer:        peer,
		HTTPS:       r.TLS != nil,
		Headers:     headers,
	}
}

// readBody reads at most `limit` bytes, or nil when the declared or actual size exceeds it.
// Whatever was read is put back so an app the request falls through to still sees its whole body.
func readBody(r *http.Request, limit int) []byte {
	if r.ContentLength > int64(limit) {
		return nil
	}
	if r.Body == nil {
		return []byte{}
	}
	read, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(read), r.Body), r.Body}
	if err != nil || len(read) > limit {
		return nil
	}
	return read // io.ReadAll never returns nil: an empty body is []byte{}
}

func writeAnswer(w http.ResponseWriter, a *Answer) {
	h := w.Header()
	for _, kv := range a.Headers {
		h.Add(kv.Name, kv.Value)
	}
	h.Set("Content-Length", strconv.Itoa(len(a.Body)))
	w.WriteHeader(a.Status)
	_, _ = w.Write(a.Body)
}

func (h *handler) run(w http.ResponseWriter, r *http.Request, p *Passed) {
	if p.Ctx != nil {
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, p.Ctx))
	}
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK, rid: p.RID, cookie: p.SetCookie}
	rec.stamp() // before the app: a handler that never writes still answers with them
	finished := false
	finish := func(status int) {
		if finished || p.OnFinish == nil {
			return
		}
		finished = true
		if p.Ctx != nil && p.Ctx.req != nil {
			p.Ctx.req.Route = r.Pattern // set by the ServeMux the app routed through, if any
		}
		p.OnFinish(status)
	}
	defer func() {
		if err := recover(); err != nil {
			finish(http.StatusInternalServerError) // the app panicked: net/http will answer 500 (or drop the connection)
			panic(err)
		}
		finish(rec.status)
	}()
	h.next.ServeHTTP(rec, r)
}

// statusRecorder remembers the status the app wrote and keeps the rid/cookie stamps on the
// response even when the app replaced the header map's values.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
	rid    string
	cookie string
}

func (s *statusRecorder) stamp() {
	h := s.Header()
	if s.rid != "" && h.Get("X-Rid") == "" {
		h.Set("X-Rid", s.rid)
	}
	if s.cookie != "" {
		for _, c := range h.Values("Set-Cookie") {
			if c == s.cookie {
				return
			}
		}
		h.Add("Set-Cookie", s.cookie)
	}
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.wrote = true
		s.status = code
		s.stamp()
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Flush() {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack hands the connection over (websockets); the event then reports 101.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("camada: the underlying ResponseWriter does not support hijacking")
	}
	conn, rw, err := hj.Hijack()
	if err == nil {
		s.wrote, s.status = true, http.StatusSwitchingProtocols
	}
	return conn, rw, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
