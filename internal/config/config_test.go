package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestResolveTokenHash(t *testing.T) {
	on, off := true, false
	for _, c := range []struct {
		option *bool
		env    string
		want   bool
	}{
		{nil, "", false},
		{nil, "1", true},
		{nil, "true", false},
		{nil, " 1", false},
		{&off, "1", false},
		{&on, "0", true},
	} {
		if got := ResolveTokenHash(c.option, c.env); got != c.want {
			t.Errorf("option %v, env %q: got %t, want %t", c.option, c.env, got, c.want)
		}
	}
}

func TestResolveTokenHeader(t *testing.T) {
	for _, c := range []struct {
		option, env, want string
		valid             bool
	}{
		{"", "", "", true},
		{"", "X-Env-Key", "x-env-key", true},
		{"X-Option-Key", "X-Env-Key", "x-option-key", true},
		{"X-Key\n", "X-Env-Key", "", false},
		{"X-Key", "X-Env-Key", "", false},
		{"X_Key", "X-Env-Key", "", false},
		{"AUTHORIZATION", "X-Env-Key", "", false},
		{"Cookie", "X-Env-Key", "", false},
		{"Set-Cookie", "X-Env-Key", "", false},
		{"", "Cookie", "", false},
		{strings.Repeat("Z", 64), "", strings.Repeat("z", 64), true},
		{strings.Repeat("z", 65), "X-Env-Key", "", false},
	} {
		if got, valid := ResolveTokenHeader(c.option, c.env); got != c.want || valid != c.valid {
			t.Errorf("option %q, env %q: got (%q, %t), want (%q, %t)", c.option, c.env, got, valid, c.want, c.valid)
		}
	}
}

func TestParseRemoteConfigReadsTheWhitelistedShape(t *testing.T) {
	cfg := ParseRemoteConfig(`{"tenant":"acme","beacon":false,"sample":0.5,"exclude":["/health"],"trusted_proxy":{"mode":"hops","hops":2},"poll_seconds":45}`)
	if cfg == nil || cfg.Tenant != "acme" || cfg.BeaconOn() || *cfg.Sample != 0.5 || !reflect.DeepEqual(cfg.Exclude, []string{"/health"}) || *cfg.PollSeconds != 45 {
		t.Fatalf("%+v", cfg)
	}
	if !reflect.DeepEqual(cfg.TrustedProxy, &TrustedProxy{Mode: "hops", Hops: 2}) {
		t.Fatalf("%+v", cfg.TrustedProxy)
	}
}

func TestParseRemoteConfigAbsentKeysAreNotFalseOrZero(t *testing.T) {
	cfg := ParseRemoteConfig(`{}`)
	if cfg == nil || !cfg.BeaconOn() || cfg.Sample != nil || cfg.PollSeconds != nil || cfg.TrustedProxy != nil {
		t.Fatalf("%+v", cfg)
	}
}

func TestParseRemoteConfigKeepsWhatItCanRead(t *testing.T) {
	// one junk field never costs the rest; a number beyond float64 reads as absent
	cfg := ParseRemoteConfig(`{"beacon":"yes","sample":1,"poll_seconds":1e999}`)
	if cfg == nil || cfg.Beacon != nil || *cfg.Sample != 1 || cfg.PollSeconds != nil {
		t.Fatalf("%+v", cfg)
	}
	for _, raw := range []string{"", "null", "[1]", "42", "{"} {
		if ParseRemoteConfig(raw) != nil {
			t.Errorf("%q parsed", raw)
		}
	}
}
