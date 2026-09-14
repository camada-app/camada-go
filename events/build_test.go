package events

// The wire event reproduces the collector's record(); HDRS bit order is pinned by the shared
// fixture (hdrs.json) — here the derived counters and the credential rules.

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/camada-app/camada-go/internal/testutil"
)

func req(headers []Header, query, ip string) RequestInfo {
	return RequestInfo{Method: "GET", Host: "x.test", Path: "/p", Query: query, Headers: headers, IP: ip, HTTPVersion: "1.1"}
}

func TestAuthSchemeOnlyEverShipsAScheme(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"Bearer abc.def", "Bearer"}, {"Basic dXNlcjpwYXNz", "Basic"}, {"rawtoken", ""}, {" Bearer x", ""},
		{strings.Repeat("a", 17) + " x", ""}, {"", ""},
	} {
		if got := AuthScheme(c.in); got != c.want {
			t.Errorf("AuthScheme(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func bit(name string) int {
	for i, h := range HDRS {
		if h == name {
			return 1 << i
		}
	}
	panic(name)
}

func TestEventFieldsAndCounters(t *testing.T) {
	headers := []Header{{"Accept", "text/html"}, {"Cookie", "a=1; b=2"}, {"Authorization", "Bearer t"}, {"Accept", "*/*"}, {"User-Agent", "ua"}}
	ev := BuildWireEvent(req(headers, "?x=1&token=t&&y", "1.2.3.4"), "sdk-go", "r1", "s1", true, "")
	want := map[string]any{
		"tap": "sdk-go", "rid": "r1", "sid": "s1", "ns": 1, "m": "GET", "h": "x.test", "p": "/p", "proto": "HTTP/1.1",
		"q": "?x=1&token=~r&&y", "qn": 3, "acc": "text/html", "auth": "Bearer", "ck": 2, "hn": 5, "ua": "ua",
		"hord": "accept,cookie,authorization,accept,user-agent", "hm": bit("accept") | bit("cookie") | bit("authorization"),
	}
	hb := 0
	for _, h := range headers {
		hb += len(h.Name) + len(h.Value)
	}
	want["hb"] = hb
	for k, v := range want {
		if !reflect.DeepEqual(ev[k], v) {
			t.Errorf("%s = %#v want %#v", k, ev[k], v)
		}
	}
	if ev["st"] != nil || ev["dur"] != nil {
		t.Fatal("st/dur must start unset")
	}
	if _, ok := ev["ts"].(int64); !ok {
		t.Fatalf("ts %T", ev["ts"])
	}
	if _, ok := ev["ja4"]; ok {
		t.Fatal("ja4 without a fingerprint")
	}
}

func TestEventWithoutHeadersOrIP(t *testing.T) {
	ev := BuildWireEvent(req(nil, "", ""), "sdk-go", "r", "", false, "")
	for k, v := range map[string]any{"ip": nil, "sid": nil, "ns": 0, "hm": 0, "hn": 0, "hb": 0, "ck": 0, "hord": "", "qn": 0, "q": "", "acc": nil, "auth": nil} {
		if !reflect.DeepEqual(ev[k], v) {
			t.Errorf("%s = %#v want %#v", k, ev[k], v)
		}
	}
}

func TestHordAndQueryAreCapped(t *testing.T) {
	var headers []Header
	for i := 0; i < 1000; i++ {
		headers = append(headers, Header{"x-" + strconv.Itoa(i), "v"})
	}
	ev := BuildWireEvent(req(headers, "?"+strings.Repeat("a", 600), "1.2.3.4"), "sdk-go", "r", "", false, "")
	if len(ev["hord"].(string)) != 2048 || len(ev["q"].(string)) != 512 {
		t.Fatalf("hord %d q %d", len(ev["hord"].(string)), len(ev["q"].(string)))
	}
}

func TestJA4RidesWhenKnown(t *testing.T) {
	if BuildWireEvent(req(nil, "", ""), "sdk-go", "r", "", false, "t13d")["ja4"] != "t13d" {
		t.Fatal("ja4 dropped")
	}
}

type hdrsFixture struct {
	Hdrs  []string `json:"hdrs"`
	Cases []struct {
		Names []string `json:"names"`
		HM    int      `json:"hm"`
	} `json:"cases"`
}

func TestHdrsBitmaskPinsTheExactHeaderOrder(t *testing.T) {
	var fx hdrsFixture
	testutil.ReadJSON(t, "blk3/hdrs.json", &fx)
	if !reflect.DeepEqual(HDRS[:], fx.Hdrs) {
		t.Fatalf("HDRS drifted from hdrs.json:\n%v\n%v", HDRS, fx.Hdrs)
	}
	for _, c := range fx.Cases {
		var headers []Header
		for _, n := range c.Names {
			headers = append(headers, Header{n, "v"})
		}
		ev := BuildWireEvent(RequestInfo{Method: "GET", Host: "x.test", Path: "/", Headers: headers, IP: "1.2.3.4"}, "sdk-node", "r", "", false, "")
		if ev["hm"] != c.HM {
			t.Errorf("%s: hm %v want %d", strings.Join(c.Names, "+"), ev["hm"], c.HM)
		}
	}
}
