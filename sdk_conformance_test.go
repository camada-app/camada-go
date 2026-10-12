package camada

// C6 sdk-conformance: the language-neutral cases every server SDK runs (camada-core test/fixtures/ip/resolve.json and
// redact/referer.json), so the XFF-port (0vho), peer-first cidrs (yfc6) and Referer-scrub (ijsa) semantics cannot
// drift from core. A missing fixture fails by name; no case is skipped.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/camada-app/camada-go/events"
	"github.com/camada-app/camada-go/internal/testutil"
)

func TestConformanceResolveClientIP(t *testing.T) {
	var fx struct {
		Version int                      `json:"version"`
		Configs map[string]*TrustedProxy `json:"configs"`
		Cases   []struct {
			ID     string  `json:"id"`
			Config string  `json:"config"`
			Peer   *string `json:"peer"`
			XFF    *string `json:"xff"`
			Expect *string `json:"expect"`
		} `json:"cases"`
	}
	testutil.ReadJSON(t, "ip/resolve.json", &fx)
	if fx.Version != 1 || len(fx.Cases) == 0 {
		t.Fatalf("ip/resolve.json: version %d, %d cases", fx.Version, len(fx.Cases))
	}
	str := func(p *string) string { // null is "" in this SDK: no peer, no header, no address
		if p == nil {
			return ""
		}
		return *p
	}
	for _, c := range fx.Cases {
		t.Run(c.ID, func(t *testing.T) {
			cfg, ok := fx.Configs[c.Config]
			if !ok {
				t.Fatalf("unknown config %q", c.Config)
			}
			if got := ResolveClientIP(str(c.Peer), str(c.XFF), cfg); got != str(c.Expect) {
				t.Errorf("peer %v xff %v: got %q want %q", str(c.Peer), str(c.XFF), got, str(c.Expect))
			}
		})
	}
}

func TestConformanceRefererRedaction(t *testing.T) {
	var fx struct {
		Version int `json:"version"`
		Cases   []struct {
			ID      string   `json:"id"`
			Referer *string  `json:"referer"`
			Ref     *string  `json:"ref"`
			Absent  []string `json:"absent"`
		} `json:"cases"`
	}
	testutil.ReadJSON(t, "redact/referer.json", &fx)
	if fx.Version != 1 || len(fx.Cases) == 0 {
		t.Fatalf("redact/referer.json: version %d, %d cases", fx.Version, len(fx.Cases))
	}
	for _, c := range fx.Cases {
		t.Run(c.ID, func(t *testing.T) {
			headers := []events.Header{{Name: "User-Agent", Value: "ua"}}
			if c.Referer != nil {
				headers = append(headers, events.Header{Name: "Referer", Value: *c.Referer})
			}
			info := events.RequestInfo{Method: "GET", Host: "x.test", Path: "/api/me", Headers: headers, IP: "1.2.3.4", HTTPVersion: "1.1"}
			ev := events.BuildWireEvent(info, "sdk-go", "r", "", false, "")
			var want any
			if c.Ref != nil {
				want = *c.Ref
			}
			if ev["ref"] != want {
				t.Errorf("ref = %#v want %#v", ev["ref"], want)
			}
			var buf strings.Builder
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false) // the secret must not hide behind \u0026
			if err := enc.Encode(ev); err != nil {
				t.Fatal(err)
			}
			wire := buf.String()
			for _, secret := range c.Absent {
				if strings.Contains(wire, secret) {
					t.Errorf("%q shipped: %s", secret, wire)
				}
			}
		})
	}
}
