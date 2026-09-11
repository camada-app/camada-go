// Package config holds the configuration shapes shared by the snapshot client and the engine:
// ParseKey splits CAMADA_KEY, and RemoteConfig is what GET /snapshot hands back in
// x-camada-config (whitelisted server-side).
package config

import (
	"encoding/json"
	"strconv"
	"strings"
)

// TrustedProxy mirrors the server-validated tenant config (edge-analyst src/tenant-config.js):
// {mode: none} | {mode: hops, hops: N} | {mode: cidrs, cidrs: [...]} | {mode: vercel}.
type TrustedProxy struct {
	Mode  string   `json:"mode"`
	Hops  int      `json:"hops,omitempty"`
	CIDRs []string `json:"cidrs,omitempty"`
}

// RemoteConfig is the parsed x-camada-config header. Pointer fields are nil when the server
// left them out, so a missing key never reads as false or zero.
type RemoteConfig struct {
	Tenant       string        `json:"tenant"`
	Beacon       *bool         `json:"beacon"`
	Sample       *float64      `json:"sample"`
	Exclude      []string      `json:"exclude"`
	TrustedProxy *TrustedProxy `json:"trusted_proxy"`
	PollSeconds  *float64      `json:"poll_seconds"`
}

// BeaconOn is true unless the tenant switched the beacon off.
func (c *RemoteConfig) BeaconOn() bool { return c == nil || c.Beacon == nil || *c.Beacon }

// ParseKey splits CAMADA_KEY, `<ingest_token>.<snap_token>` (printed by reconcile instructions and seed).
func ParseKey(key string) (ingest, snap string, ok bool) {
	dot := strings.IndexByte(key, '.')
	if dot <= 0 || dot == len(key)-1 {
		return "", "", false
	}
	return key[:dot], key[dot+1:], true
}

// ParseTrustedProxyEnv reads CAMADA_TRUSTED_PROXY: none | vercel | hops:N | cidrs:a,b. Unset or
// malformed returns nil, which callers treat as "defer to the server-delivered tenant config",
// never as trust.
func ParseTrustedProxyEnv(v string) *TrustedProxy {
	switch {
	case v == "":
		return nil
	case v == "none":
		return &TrustedProxy{Mode: "none"}
	case v == "vercel":
		return &TrustedProxy{Mode: "vercel"}
	case strings.HasPrefix(v, "hops:"):
		hops, err := strconv.Atoi(v[5:])
		if err != nil || hops < 1 {
			return nil
		}
		return &TrustedProxy{Mode: "hops", Hops: hops}
	case strings.HasPrefix(v, "cidrs:"):
		var cidrs []string
		for _, c := range strings.Split(v[6:], ",") {
			if c = strings.TrimSpace(c); c != "" {
				cidrs = append(cidrs, c)
			}
		}
		if len(cidrs) == 0 {
			return nil
		}
		return &TrustedProxy{Mode: "cidrs", CIDRs: cidrs}
	}
	return nil
}

// ParseRemoteConfig reads the x-camada-config header; anything but a JSON object is nil
// (callers keep the previous config). A number JSON admits but a float64 cannot hold (1e999) is
// read as absent rather than failing the whole header.
func ParseRemoteConfig(raw string) *RemoteConfig {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &probe); err != nil || probe == nil {
		return nil
	}
	cfg := &RemoteConfig{}
	read(probe, "tenant", &cfg.Tenant)
	read(probe, "beacon", &cfg.Beacon)
	read(probe, "sample", &cfg.Sample)
	read(probe, "exclude", &cfg.Exclude)
	read(probe, "trusted_proxy", &cfg.TrustedProxy)
	read(probe, "poll_seconds", &cfg.PollSeconds)
	return cfg
}

// read decodes one key into dst only when it decodes cleanly, so a junk value leaves the
// field absent instead of half-set.
func read[T any](probe map[string]json.RawMessage, key string, dst *T) {
	raw, ok := probe[key]
	if !ok {
		return
	}
	var v T
	if json.Unmarshal(raw, &v) == nil {
		*dst = v
	}
}
