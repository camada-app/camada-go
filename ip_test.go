package camada

// Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer:
// raw X-Forwarded-For is attacker-writable and never trusted without explicit configuration.

import (
	"reflect"
	"testing"
)

func TestSocketPeerWithoutConfigEvenWhenXFFIsPresent(t *testing.T) {
	if got := ResolveClientIP("10.0.0.1", "203.0.113.66", nil); got != "10.0.0.1" {
		t.Fatalf("got %q", got)
	}
	if got := ResolveClientIP("10.0.0.1", "203.0.113.66", &TrustedProxy{Mode: "none"}); got != "10.0.0.1" {
		t.Fatalf("got %q", got)
	}
}

func TestV4MappedPeerIsUnwrapped(t *testing.T) {
	if got := ResolveClientIP("::ffff:10.0.0.1", "", nil); got != "10.0.0.1" {
		t.Fatalf("got %q", got)
	}
	if got := ResolveClientIP("", "1.2.3.4", nil); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestHopsCountsFromTheRight(t *testing.T) {
	cfg := &TrustedProxy{Mode: "hops", Hops: 1}
	if got := ResolveClientIP("10.0.0.1", "203.0.113.66, 198.51.100.7", cfg); got != "198.51.100.7" {
		t.Fatalf("hops:1 got %q", got)
	}
	if got := ResolveClientIP("10.0.0.1", "203.0.113.66, 198.51.100.7", &TrustedProxy{Mode: "hops", Hops: 2}); got != "203.0.113.66" {
		t.Fatalf("hops:2 got %q", got)
	}
	if got := ResolveClientIP("10.0.0.1", "203.0.113.66", &TrustedProxy{Mode: "hops", Hops: 2}); got != "10.0.0.1" { // out of range: the peer
		t.Fatalf("out of range got %q", got)
	}
}

func TestVercelTakesTheRightmostEntry(t *testing.T) {
	if got := ResolveClientIP("10.0.0.1", "spoof, 203.0.113.66", &TrustedProxy{Mode: "vercel"}); got != "203.0.113.66" {
		t.Fatalf("got %q", got)
	}
}

func TestCidrsSkipsTrustedProxiesFromTheRight(t *testing.T) {
	cfg := &TrustedProxy{Mode: "cidrs", CIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}}
	for _, c := range []struct{ xff, want string }{
		{"203.0.113.66, 10.1.2.3, 10.9.9.9", "203.0.113.66"},
		{"203.0.113.66, 2001:db8::5", "203.0.113.66"},
		{"10.1.2.3", "10.0.0.1"},            // everything trusted: the peer
		{"not-an-ip, 10.1.2.3", "10.0.0.1"}, // candidate must parse
	} {
		if got := ResolveClientIP("10.0.0.1", c.xff, cfg); got != c.want {
			t.Errorf("xff %q: got %q want %q", c.xff, got, c.want)
		}
	}
}

func TestEnvStringForms(t *testing.T) {
	for _, c := range []struct {
		in   string
		want *TrustedProxy
	}{
		{"", nil},
		{"none", &TrustedProxy{Mode: "none"}},
		{"vercel", &TrustedProxy{Mode: "vercel"}},
		{"hops:2", &TrustedProxy{Mode: "hops", Hops: 2}},
		{"hops:0", nil},
		{"cidrs:10.0.0.0/8, 192.0.2.0/24", &TrustedProxy{Mode: "cidrs", CIDRs: []string{"10.0.0.0/8", "192.0.2.0/24"}}},
		{"cidrs:", nil},
		{"bogus", nil},
	} {
		if got := ParseTrustedProxyEnv(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseTrustedProxyEnv(%q) = %+v want %+v", c.in, got, c.want)
		}
	}
}
