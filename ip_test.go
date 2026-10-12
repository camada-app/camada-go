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

// camada-all-0vho: an X-Forwarded-For entry may carry a port (Azure Application Gateway writes `ip:port`).
func TestXFFEntriesWithAPortResolveToTheAddress(t *testing.T) {
	hops1 := &TrustedProxy{Mode: "hops", Hops: 1}
	azure := &TrustedProxy{Mode: "cidrs", CIDRs: []string{"169.254.0.0/16"}}
	for _, c := range []struct {
		xff  string
		cfg  *TrustedProxy
		want string
	}{
		{"203.0.113.66:51234", hops1, "203.0.113.66"},
		{"[2001:db8::66]:51234", hops1, "2001:db8::66"},
		{"[2001:db8::66]", hops1, "2001:db8::66"},
		{"2001:db8::66:8080", hops1, "2001:db8::66:8080"}, // a bare v6 is never split
		{"203.0.113.66:51234", &TrustedProxy{Mode: "vercel"}, "203.0.113.66"},
		{"203.0.113.66:51234", azure, "203.0.113.66"},
		{"203.0.113.66, 169.254.1.1:5000", azure, "203.0.113.66"}, // the trust test sees the address
	} {
		if got := ResolveClientIP("169.254.130.1", c.xff, c.cfg); got != c.want {
			t.Errorf("xff %q: got %q want %q", c.xff, got, c.want)
		}
	}
}

func TestMalformedPortEntriesFallBackToThePeer(t *testing.T) {
	for _, bad := range []string{"203.0.113.66:", "203.0.113.66:abc", "203.0.113.66:123456", "203.0.113.66:80:90", "[2001:db8::66:51234",
		"[2001:db8::66]:", "[2001:db8::66]x", "[203.0.113.66]:80", "[]:80", "not-an-ip:80", "203.0.113.256:80"} {
		if got := ResolveClientIP("169.254.130.1", bad, &TrustedProxy{Mode: "hops", Hops: 1}); got != "169.254.130.1" {
			t.Errorf("xff %q: got %q", bad, got)
		}
	}
}

// camada-all-yfc6 (D1): in cidrs mode the chain is [...xff, peer]. A peer outside every trusted range is the client and
// its XFF is ignored; a loopback peer is a local front end (App Engine's is always 127.0.0.1) and counts as a trusted hop.
var cfPreset = []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
	"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
	"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"}

func TestTrialsightsAppEngineBehindCloudflareStillResolvesTheClient(t *testing.T) {
	// the Trialsights shape: the peer is App Engine's local front end, Google appends 169.254.1.1, Cloudflare's edge
	// sits in front of that, and the leftmost entry is client-written
	cfg := &TrustedProxy{Mode: "cidrs", CIDRs: append(append([]string{}, cfPreset...), "169.254.0.0/16")}
	for _, xff := range []string{"6.6.6.6, 198.51.100.9, 172.64.1.1, 169.254.1.1", "6.6.6.6, 198.51.100.9, 169.254.1.1"} {
		if got := ResolveClientIP("127.0.0.1", xff, cfg); got != "198.51.100.9" {
			t.Errorf("xff %q: got %q", xff, got)
		}
	}
}

func TestCidrsDirectHitFromAnUntrustedPeerIgnoresXFF(t *testing.T) {
	cf := &TrustedProxy{Mode: "cidrs", CIDRs: cfPreset}
	for _, xff := range []string{"203.0.113.66", "8.8.8.8", "8.8.8.8, 172.64.1.1"} {
		for _, peer := range []string{"203.0.113.200", "::ffff:203.0.113.200", "::FFFF:203.0.113.200"} {
			if got := ResolveClientIP(peer, xff, cf); got != "203.0.113.200" {
				t.Errorf("peer %q xff %q: got %q", peer, xff, got)
			}
		}
	}
	if got := ResolveClientIP("2001:db8::99", "198.51.100.9", cf); got != "2001:db8::99" {
		t.Errorf("v6 peer: got %q", got)
	}
	if got := ResolveClientIP("172.64.1.1", "1.2.3.4, 198.51.100.9", cf); got != "198.51.100.9" { // a trusted peer still walks
		t.Errorf("trusted peer: got %q", got)
	}
}

func TestLoopbackPeerIsATrustedHopOnlyAsThePeer(t *testing.T) {
	cf := &TrustedProxy{Mode: "cidrs", CIDRs: cfPreset}
	for _, peer := range []string{"127.0.0.1", "127.5.6.7", "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1"} {
		if got := ResolveClientIP(peer, "198.51.100.9, 172.64.1.1", cf); got != "198.51.100.9" {
			t.Errorf("peer %q: got %q", peer, got)
		}
	}
	if got := ResolveClientIP("127.0.0.1", "8.8.8.8", cf); got != "8.8.8.8" { // D1's accepted trade-off
		t.Errorf("front end: got %q", got)
	}
	if got := ResolveClientIP("172.64.1.1", "127.0.0.1", cf); got != "127.0.0.1" { // a loopback XFF entry is untrusted
		t.Errorf("loopback entry: got %q", got)
	}
}

func TestNoPeerKeepsThePlainWalk(t *testing.T) {
	cf := &TrustedProxy{Mode: "cidrs", CIDRs: cfPreset}
	if got := ResolveClientIP("", "1.2.3.4, 198.51.100.9, 172.64.1.1", cf); got != "198.51.100.9" {
		t.Errorf("got %q", got)
	}
	if got := ResolveClientIP("", "172.64.1.1", cf); got != "" {
		t.Errorf("all trusted: got %q", got)
	}
	if got := ResolveClientIP("@", "198.51.100.9, 172.64.1.1", cf); got != "198.51.100.9" { // a unix-socket peer: a local proxy
		t.Errorf("unix socket peer: got %q", got)
	}
}
