package config

import (
	"reflect"
	"testing"
)

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
