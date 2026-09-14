// Package events builds the wire events and ships them in batches. build.go reproduces the
// collector's record() (edge-analyst workers/collector/edge-collector.js) from a normalized
// request, so events are comparable across taps. HDRS bit order is pinned by the shared fixture
// (hdrs.json) — never reorder.
package events

import (
	"regexp"
	"strings"
	"time"

	"github.com/camada-app/camada-go/internal/redact"
)

// HDRS is the header-presence bitmask order, pinned by camada-core/test/fixtures/blk3/hdrs.json.
var HDRS = [28]string{
	"accept", "accept-language", "accept-encoding", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
	"sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "dnt",
	"cache-control", "pragma", "referer", "origin", "cookie", "authorization", "x-requested-with", "content-type",
	"via", "x-forwarded-for", "priority", "sec-purpose", "save-data", "te", "if-modified-since", "if-none-match",
}

var hdrBit = func() map[string]int {
	m := make(map[string]int, len(HDRS))
	for i, n := range HDRS {
		m[n] = 1 << i
	}
	return m
}()

// A schemeless header (`Authorization: <raw token>`) has no safe prefix: the first "word" IS
// the credential. Only a real auth-scheme token followed by a space ever ships.
var schemeRE = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,16}$")

// Header is one request header in wire order; the name may carry any case.
type Header struct {
	Name, Value string
}

// RequestInfo is the normalized request the event is built from.
type RequestInfo struct {
	Method      string
	Host        string
	Path        string
	Query       string   // includes the leading '?', or empty
	Headers     []Header // in the order the host gives them
	IP          string   // already resolved via trusted-proxy config; "" when unknown
	HTTPVersion string   // e.g. "1.1"
}

// AuthScheme is the auth scheme of an Authorization value, never the credential.
func AuthScheme(value string) string {
	sp := strings.IndexByte(value, ' ')
	if sp <= 0 {
		return ""
	}
	if scheme := value[:sp]; schemeRE.MatchString(scheme) {
		return scheme
	}
	return ""
}

// NowMS is the wire timestamp: milliseconds since the epoch.
func NowMS() int64 { return time.Now().UnixMilli() }

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// BuildWireEvent is the mutable wire event; the caller fills st/dur on response-finish before
// enqueueing. A "" sid or ip ships as null.
func BuildWireEvent(r RequestInfo, tap, rid, sid string, newSession bool, ja4 string) map[string]any {
	mask, hn, hb := 0, 0, 0
	cookie := ""
	names := make([]string, 0, len(r.Headers))
	first := make(map[string]string, len(r.Headers))
	for _, h := range r.Headers {
		k := strings.ToLower(h.Name)
		hn++
		hb += len(h.Name) + len(h.Value)
		names = append(names, k)
		if _, seen := first[k]; !seen {
			first[k] = h.Value
		}
		mask |= hdrBit[k]
		if k == "cookie" {
			if cookie != "" {
				cookie += "; " + h.Value
			} else {
				cookie = h.Value
			}
		}
	}
	h := func(name string) any {
		v, ok := first[name]
		if !ok {
			return nil
		}
		return v
	}
	qn := 0
	if len(r.Query) > 1 {
		for _, p := range strings.Split(r.Query[1:], "&") {
			if p != "" {
				qn++
			}
		}
	}
	ns := 0
	if newSession {
		ns = 1
	}
	ck := 0
	if cookie != "" {
		ck = strings.Count(cookie, ";") + 1
	}
	var proto any
	if r.HTTPVersion != "" {
		proto = "HTTP/" + r.HTTPVersion
	}
	ev := map[string]any{
		"tap": tap, "rid": rid, "sid": nullable(sid), "ns": ns, "ts": NowMS(),
		"ip":    nullable(r.IP),
		"proto": proto,
		"m":     r.Method, "h": r.Host, "p": r.Path, "q": truncRunes(redact.ScrubQuery(r.Query), 512), "qn": qn,
		"ct": h("content-type"), "cl": h("content-length"),
		"ua": h("user-agent"), "chua": h("sec-ch-ua"), "chmob": h("sec-ch-ua-mobile"), "chplat": h("sec-ch-ua-platform"),
		"acc": h("accept"), "lang": h("accept-language"), "fs": h("sec-fetch-site"), "fm": h("sec-fetch-mode"),
		"fd": h("sec-fetch-dest"), "fu": h("sec-fetch-user"), "ref": h("referer"), "org": h("origin"),
		"xrw":  h("x-requested-with"),
		"auth": nullable(AuthScheme(first["authorization"])), // scheme only, never the credential
		"hm":   mask, "hn": hn, "hb": hb, "ck": ck,
		"hord": truncRunes(strings.Join(names, ","), 2048), // header order as this host reports it
	}
	if ja4 != "" {
		ev["ja4"] = ja4
	}
	ev["st"] = nil
	ev["dur"] = nil // 'dur': the collector wire already claims 'lat' for latitude
	return ev
}
