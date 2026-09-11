// Package transport is the one HTTP seam. The engine, the snapshot client and the event queue
// speak to the analyst through a Transport func, so tests inject an in-process fake and
// production uses net/http. A transport never panics: a network failure is a status-0
// response, which every caller treats as "keep what we have".
package transport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// Request is one call to the analyst.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Timeout time.Duration
}

// Response is what came back; Status 0 when the request never got an answer.
type Response struct {
	Status  int
	Headers map[string]string // lower-cased names; repeated values joined with ", "
	Body    []byte
}

// Transport performs one Request.
type Transport func(Request) Response

// client shares the default transport (connection pool); per-call deadlines ride the context.
// Accept-Encoding is left to net/http, which then decodes gzip transparently (GET /snapshot
// ships ~5 MB that gzips to a few KB).
var client = &http.Client{}

// HTTP is the production transport over net/http.
func HTTP(req Request) (res Response) {
	defer func() {
		if recover() != nil {
			res = Response{Headers: map[string]string{}}
		}
	}()
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var body io.Reader
	if req.Body != nil {
		body = bytes.NewReader(req.Body)
	}
	r, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return Response{Headers: map[string]string{}}
	}
	for k, v := range req.Headers {
		r.Header.Set(k, v)
	}
	resp, err := client.Do(r)
	if err != nil {
		return Response{Headers: map[string]string{}}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return Response{Headers: map[string]string{}} // a body we cannot read is no answer at all
	}
	headers := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		headers[strings.ToLower(k)] = strings.Join(vs, ", ")
	}
	return Response{Status: resp.StatusCode, Headers: headers, Body: data}
}
