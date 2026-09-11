package camada

// Environment wiring. The two-line quickstart depends on this doing the right thing:
//
//	CAMADA_KEY=<ingest_token>.<snap_token>   (printed by `reconcile instructions` and seed)
//	CAMADA_INGEST_URL / CAMADA_SNAPSHOT_URL  (dev: http://localhost:8787[/snapshot])
//	CAMADA_DISABLED=1                        kill switch, checked at boot and per request
//	CAMADA_SERVERLESS=1                      lazy snapshot mode (no poll goroutine)
//	CAMADA_TRUSTED_PROXY                     local override: none | vercel | hops:N | cidrs:a,b
//	CAMADA_CHALLENGE=0                       do not enforce challenge verdicts

import "strings"

// DefaultIngestURL is a PLACEHOLDER default, the same one @camada/node and camada-python carry —
// confirm the production ingest domain before any release.
const DefaultIngestURL = "https://in.camada.dev"

// Env is the resolved configuration; credentials come from the environment only.
type Env struct {
	IngestToken  string
	SnapToken    string
	Secret       string // HMAC key for the challenge nonce/cookie — never leaves the process
	IngestURL    string
	SnapshotURL  string
	Serverless   bool
	TrustedProxy *TrustedProxy // nil = defer to server-delivered config
}

// ResolveEnv reads the CAMADA_* variables from a map (tests, or an app's own config); nil (the
// SDK stays inert, one log line) rather than an error on bad config.
func ResolveEnv(env map[string]string) *Env {
	return resolveEnv(func(k string) string { return env[k] })
}

func resolveEnv(get func(string) string) *Env {
	ingestToken, snapToken, ok := ParseKey(get("CAMADA_KEY"))
	if !ok {
		ingestToken, snapToken = get("CAMADA_TOKEN"), get("CAMADA_SNAPSHOT_TOKEN")
	}
	if ingestToken == "" || snapToken == "" {
		return nil
	}
	ingestURL := get("CAMADA_INGEST_URL")
	if ingestURL == "" {
		ingestURL = DefaultIngestURL
	}
	ingestURL = strings.TrimRight(ingestURL, "/")
	snapshotURL := get("CAMADA_SNAPSHOT_URL")
	if snapshotURL == "" {
		snapshotURL = ingestURL + "/snapshot"
	}
	secret := get("CAMADA_KEY")
	if secret == "" {
		secret = ingestToken + "." + snapToken
	}
	return &Env{
		IngestToken: ingestToken, SnapToken: snapToken, Secret: secret,
		IngestURL: ingestURL, SnapshotURL: snapshotURL,
		Serverless:   get("CAMADA_SERVERLESS") == "1",
		TrustedProxy: ParseTrustedProxyEnv(get("CAMADA_TRUSTED_PROXY")),
	}
}
