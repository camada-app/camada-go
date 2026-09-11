package camada

import "time"

// Tap identifier this SDK claims on the wire. The server validates against its own enum and
// derives the capability mask itself (edge-analyst src/capabilities.js): an SDK can never grant
// itself capability bits, only name its position — and an unknown name is silently read as a
// proxy, so this literal is load-bearing.
const TAP = "sdk-go"

const DefaultRefresh = 30 * time.Second

// 5 carries the tenant's ordered custom rules (§D3); a tenant without one is answered with the next container down.
const DefaultSnapshotVersion = 5

const KillSwitchEnv = "CAMADA_DISABLED"

const (
	ScriptPath    = "/_cam/b.js"
	FPPath        = "/_cam/fp"
	FPMax         = 32 * 1024 // matches the server's /fp cap: never accept what ingest will 413
	ChallengePath = "/__camada/challenge"
	BodyMax       = 4 * 1024 // the verify form is ~120 bytes; anything larger is not ours

	SessionCookie = "_sfp"  // same cookie as the edge collector: sid/ns comparable across taps
	SessionMaxAge = 2592000 // 30 days
)
