package camada

import (
	"reflect"
	"testing"
)

func TestResolveEnvFromTheKey(t *testing.T) {
	env := ResolveEnv(map[string]string{"CAMADA_KEY": "tok.snap", "CAMADA_INGEST_URL": "http://localhost:8787/"})
	want := &Env{IngestToken: "tok", SnapToken: "snap", Secret: "tok.snap", IngestURL: "http://localhost:8787", SnapshotURL: "http://localhost:8787/snapshot"}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("%+v", env)
	}
}

func TestResolveEnvFromTheTokenPair(t *testing.T) {
	env := ResolveEnv(map[string]string{"CAMADA_TOKEN": "tok", "CAMADA_SNAPSHOT_TOKEN": "snap", "CAMADA_SNAPSHOT_URL": "http://s/x", "CAMADA_SERVERLESS": "1", "CAMADA_TRUSTED_PROXY": "hops:2"})
	if env == nil || env.IngestToken != "tok" || env.SnapToken != "snap" || env.Secret != "tok.snap" || env.IngestURL != DefaultIngestURL || env.SnapshotURL != "http://s/x" || !env.Serverless {
		t.Fatalf("%+v", env)
	}
	if !reflect.DeepEqual(env.TrustedProxy, &TrustedProxy{Mode: "hops", Hops: 2}) {
		t.Fatalf("%+v", env.TrustedProxy)
	}
}

func TestResolveEnvIsNilWithoutBothTokens(t *testing.T) {
	for _, env := range []map[string]string{{}, {"CAMADA_KEY": "nodot"}, {"CAMADA_TOKEN": "tok"}, {"CAMADA_SNAPSHOT_TOKEN": "snap"}} {
		if ResolveEnv(env) != nil {
			t.Fatalf("%v resolved", env)
		}
	}
}
