# camada-go

camada for Go: enforces the tenant snapshot inline (your ordered custom rules, then allow,
block, challenge), serves a first-party proof-of-work challenge page and beacon, records the
outcomes your handlers know (`Track`), and ships wire events in batches off the request path.
One module, one public package, a `net/http` middleware — `http.ListenAndServe(":8080",
camada.Handler(mux))` — that any router built on `http.Handler` sits behind. Fails open by
design: a camada outage or bug never 5xxes your app.

Not yet tagged — use it from a sibling checkout with a `replace` directive, as
[`camada-go-example`](../camada-go-example) does; publishing is one decision with the npm
packages (SDK-G01). Go 1.23 or newer, no dependencies outside the standard library.

## Quickstart

```go
import "github.com/camada/camada-go"

mux := http.NewServeMux()
mux.HandleFunc("GET /{$}", home)
http.ListenAndServe(":8080", camada.Handler(mux))   // outermost, so camada answers before routing
```

Env (printed by camada onboarding / `npm run seed` in dev):

```
CAMADA_KEY=<ingest_token>.<snap_token>
CAMADA_INGEST_URL=http://localhost:8787        # dev only; defaults to production ingest
```

`camada.Handler` shares one lazy engine (`camada.Default()`) built from the environment on the
first request. That build starts the snapshot poll on a goroutine and never blocks, so the
request that triggered it is answered cold: it passes (fail open), and so does anything else
that arrives before that first poll lands (a few hundred milliseconds against a local analyst;
snapshot-size and network bound). To enforce from request 1, build the engine eagerly at startup
and wait for the boot poll — `Snap.Refresh()` alone is not it, the boot poll already holds the
single-in-flight lock:

```go
import "github.com/camada/camada-go/snapshot"

cam := camada.Default()   // builds the engine; the boot poll is already running on its goroutine
if cam.Snap != nil {      // nil when CAMADA_KEY is unset or CAMADA_DISABLED=1
	deadline := time.Now().Add(5 * time.Second)
	for cam.Snap.Verdict(snapshot.MatchInput{IP: "0.0.0.0"}).Reason == "cold" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)   // bounded: an unreachable analyst leaves it cold, and the app still fails open
	}
}
defer cam.Stop(context.Background())   // drains the last event batch, at most 500 ms
```

Without `CAMADA_KEY` the engine is inert (one log line, no requests, no enforcement). An app that
reads its own config builds the engine itself and hands it in:

```go
cam := camada.New(camada.Options{Env: map[string]string{"CAMADA_KEY": myKey, "CAMADA_INGEST_URL": myIngest}})
http.ListenAndServe(":8080", cam.Handler(mux))
```

## What it does per request

1. Keeps the snapshot fresh. A Go server is a long-lived process, so the default is one poll
   goroutine at the cadence your tenant config sets (`poll_seconds`), with ETag/304 and gzip on
   the wire. `CAMADA_SERVERLESS=1` drops the poll goroutine: each request checks staleness, and a
   stale one kicks a single refresh off the request path.
   Every poll and event batch carries `x-camada-sdk: @camada/go/<version>`, and polls ask for
   snapshot v5 (`x-camada-snapshot: 5`) — the container that carries your ordered custom rules.
2. Resolves the client from the socket peer (`r.RemoteAddr`), combined with `X-Forwarded-For`
   only under your tenant's trusted-proxy config (or `CAMADA_TRUSTED_PROXY` locally). A forwarded
   header on its own is never the ip: any caller can set it. Nothing needs disabling for proxies —
   `net/http` never rewrites the peer — so a reverse proxy in front of the app is declared, not
   inferred.
3. Enforces before anything else, beacon endpoints included: your ordered custom rules first (first
   match wins; they read ip, path, user-agent and request headers), then allow → block → challenge.
   A block answers `403 Forbidden` with `x-block-reason`, `x-block-version` and, when a rule
   decided, `x-block-rule`; its event ships with `blk` (and `rl`). A `warn` rule passes and stamps
   `wrn`; a `skip` rule passes with nothing stamped. Cold (no snapshot yet) passes: fail open.
4. Challenge: a `challenge` verdict gets the self-contained proof-of-work page (or 403 JSON for a
   non-HTML request); `POST /__camada/challenge` verifies the solution, sets `_cch` (bound to the
   ip, one hour) and 302s back. A request whose ip cannot be resolved is never challenged.
5. Serves the beacon: `GET /_cam/b.js` (the `@camada/browser` build, embedded) and `POST /_cam/fp`
   (≤ 32 KB, relayed onto the event batch as a `sig: 1` row with the ip camada resolved). Both
   fall through to your app when the tenant switched the beacon off.
6. Runs your app with `X-Rid` and the `_sfp` session cookie on its response, and when the response
   is done ships one redacted event: method, host, path, scrubbed query, status, latency, route
   pattern (`r.Pattern`), header names/sizes, the auth scheme (never the credential), cookie count
   (never values). A panic in your handler ships as `st: 500` and propagates unchanged (net/http
   answers as it always does); a hijacked connection ships as `st: 101`.

## Options

`camada.New(camada.Options{...})`; everything credential-shaped comes from the environment.

| option | default | meaning |
|---|---|---|
| `Env` | the process environment | where `CAMADA_*` are read from (a `map[string]string`) |
| `Transport` | net/http | the `func(HTTPRequest) HTTPResponse` that reaches the analyst (tests inject a fake) |
| `Refresh` | server-steered | poll cadence; set, it is pinned |
| `Challenge` | `nil` (= true) | serve the proof-of-work page for challenge verdicts (`CAMADA_CHALLENGE=0` too) |
| `ChallengePath` | `/__camada/challenge` | where the page posts its solution |
| `SnapshotVersion` | `5` | 4 drops your custom rules; 3 the allow/challenge sides too |
| `ScriptPath` / `FPPath` | `/_cam/b.js` / `/_cam/fp` | the beacon endpoints; keep them in one directory |

Env: `CAMADA_KEY` (or `CAMADA_TOKEN` + `CAMADA_SNAPSHOT_TOKEN`), `CAMADA_INGEST_URL`,
`CAMADA_SNAPSHOT_URL`, `CAMADA_TRUSTED_PROXY` (`none | vercel | hops:N | cidrs:a,b`),
`CAMADA_SERVERLESS=1`, `CAMADA_CHALLENGE=0`, and the kill switch `CAMADA_DISABLED=1` (checked per
request; set at boot, no goroutines start at all).

## The first-party beacon

```go
fmt.Fprintf(w, "<html><head>%s</head>…", camada.ScriptTag(r))
```

The tag is `<script src="/_cam/b.js?r=<rid>" async>`, so the beacon joins the page view that
served it. Move both paths with `ScriptPath` / `FPPath` when `/_cam/` is not yours; the script
derives the post path from its own URL, so the two must share a directory.

## App-context events

```go
camada.Track(r, "login_failed", email)   // "" when there is no identifier
```

The identifier is HMAC-hashed in-process with your ingest token; the raw value never reaches the
queue. `Track` never panics. Outside the middleware (a request it did not run for) the outcome
still ships, with no `rid`/`sid`/`ip` to join on — and it builds the default engine if nothing
has yet. The event name is free-form; the analyst's app-context rules read this vocabulary:

| event | when |
|---|---|
| `login_failed` / `login_succeeded` | a login attempt settled; pass the user so attempts per account can be counted |
| `signup` | an account was created |
| `password_reset` | a reset was requested |
| `mfa_failed` | a second factor was rejected |
| `payment_failed` / `payment_succeeded` | a payment authorisation settled |
| `coupon_failed` | a promo/voucher code was rejected |

A route you gate yourself: `if camada.ServeChallenge(w, r) { return }` writes the page (or 403
JSON) until the browser holds a valid `_cch`, then reports false so you render your own.
`camada.FromRequest(r)` exposes the request's `RID`, `SID` and resolved `IP`.

## What this tap can see

`sdk-go` is an in-app tap: status, latency, session, route pattern, the beacon's browser
signals and your outcomes. `net/http` parses headers into a map, so the event's header order
(`hord`) is the sorted name list, not the wire's; the analyst knows what this tap can see and
never scores the absence of header order, ASN, country or a TLS fingerprint against a request;
ASN and country it resolves itself. Enforcement at this position covers ip, path, user-agent and
header conditions — ASN, country and TLS entries fail open in-app. `matches` patterns are JS
regexes read by Go's RE2 (`(?<name>` is native, `[^]` and `\cX` are translated, `\d`/`\w`/`\b`
are ASCII as JS reads them); a spelling RE2 rejects — lookaround, backreferences — never matches
here, while it does at the edge.

Not yet in this SDK: the TLS fingerprint (`ja4`). A Go server terminating TLS itself could read
the ClientHello through `tls.Config.GetConfigForClient`; the event builder already carries the
field, always empty, until that lands.

## Deploying it

- Every process polls its own snapshot (about 5 MB resident) and flushes its own batches; the
  tenant's `poll_seconds` keeps the cadence honest across a fleet.
- Pending events drain when you call `Stop` (`defer cam.Stop(ctx)` in `main`), within half a
  second. No signal handlers are installed — an app owns its own shutdown — so a process killed
  without one drops its last batch.
- Serverless: `CAMADA_SERVERLESS=1`. A cold invocation fails open and catches up on the next one.
- Behind a reverse proxy or load balancer, declare it: `CAMADA_TRUSTED_PROXY=hops:1` (or the
  tenant config) is what makes `X-Forwarded-For` count.

## Fail open

Every entry point runs inside the fail-open envelope: a dead ingest drops telemetry (logged at
most once a minute, through `log.Default()` or the logger you pass to `camada.SetLogger`), a
corrupt snapshot keeps the previous one, a bug in the package costs the request its join, never
its response. `CAMADA_DISABLED=1` bypasses everything.

## Development

```
gofmt -l . | (! grep .) && go vet ./... && go test ./...
```

The suite reads the golden snapshot fixtures from the `camada-core` sibling checkout
(`CAMADA_FIXTURES_DIR` overrides) and pins the embedded beacon to
`camada-browser/dist/auto.global.js` (`CAMADA_BROWSER_DIST` overrides; `npm run build` there
first, then `go run ./scripts/sync-beacon` after a beacon release). Both fail by name when the
checkout is missing rather than skipping.

[`camada-go-example`](../camada-go-example) is the hand-test bench (net/http on :3003), and
`node scripts/e2e-sdk-go.mjs` in `camada/edge-analyst` drives it against a seeded local analyst
over real HTTP, cold first request included.
