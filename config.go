package camada

import "github.com/camada/camada-go/internal/config"

// TrustedProxy is the tenant's trusted-proxy config: {mode: none} | {mode: hops, hops: N} |
// {mode: cidrs, cidrs: [...]} | {mode: vercel}. CAMADA_TRUSTED_PROXY overrides it locally.
type TrustedProxy = config.TrustedProxy

// RemoteConfig is what GET /snapshot hands back in x-camada-config (whitelisted server-side).
type RemoteConfig = config.RemoteConfig

// ParseKey splits CAMADA_KEY, `<ingest_token>.<snap_token>`; ok is false without both halves.
func ParseKey(key string) (ingest, snap string, ok bool) { return config.ParseKey(key) }

// ParseTrustedProxyEnv reads CAMADA_TRUSTED_PROXY: none | vercel | hops:N | cidrs:a,b. Unset or
// malformed is nil — defer to the server-delivered config, never trust.
func ParseTrustedProxyEnv(v string) *TrustedProxy { return config.ParseTrustedProxyEnv(v) }
