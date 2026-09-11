package camada

import (
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPTransportGunzipsAndNeverPanics(t *testing.T) {
	payload := []byte("\x03\x00\x00\x00{}}BLK")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, set := r.Header["Accept-Encoding"]; set && r.Header.Get("Accept-Encoding") == "" {
			t.Error("the SDK must not override Accept-Encoding")
		}
		w.Header().Set("etag", `"z"`)
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("content-encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = gz.Write(payload)
			_ = gz.Close()
			return
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	r := HTTPTransport(HTTPRequest{Method: "GET", URL: srv.URL + "/snapshot", Headers: map[string]string{"authorization": "Bearer x"}, Timeout: 2 * time.Second})
	if r.Status != 200 || string(r.Body) != string(payload) || r.Headers["etag"] != `"z"` {
		t.Fatalf("status %d body %q headers %v", r.Status, r.Body, r.Headers)
	}
	if _, still := r.Headers["content-encoding"]; still {
		t.Fatal("content-encoding must go with the decoding")
	}
	dead := HTTPTransport(HTTPRequest{Method: "GET", URL: "http://127.0.0.1:1/snapshot", Timeout: 200 * time.Millisecond})
	if dead.Status != 0 {
		t.Fatalf("dead port answered %d", dead.Status)
	}
	if HTTPTransport(HTTPRequest{Method: "GET", URL: "://bad"}).Status != 0 {
		t.Fatal("a bad URL must be a status-0 answer")
	}
}
