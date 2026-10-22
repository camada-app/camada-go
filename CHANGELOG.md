# Changelog

## Unreleased

- feat: the first-party beacon relay (/_cam/fp) stamps `rts`, its own clock in epoch ms, on the sig:1 row (overwriting any browser-supplied `rts`), so the analyst can place the beacon on the same clock as the request rows. (camada-all-wd3b)
- fix: a signalled response (`x-camada-challenge: 1`) now also sets `cdn-cache-control`, `surrogate-control`, `cloudflare-cdn-cache-control`, `vercel-cdn-cache-control` and `netlify-cdn-cache-control` to `no-store`, overriding the app's. CDNs read those ahead of `cache-control`, so an app-set one could still let a shared cache keep the per-client copy. (camada-all-1zlg)
- feat: a non-HTML request (fetch/XHR/API) under a `challenge` row no longer gets a 403 JSON `challenge_required`: it passes to the app with `x-camada-challenge: 1` and `cache-control: no-store` (replacing the app's own), and its normal event ships with `chs: 1` even when the path is excluded or the request is sampled out. A page load still gets the challenge page. `ServeChallenge` returns false for a non-HTML request and signals it the same way. New `Ctx.Signalled`. (camada-all-7cgs)
- fix (security): the first-party beacon relay (/_cam/fp) drops SDK-attested keys (tlsx, ja4, asn, cc, sid, ns, st, dur, rt, blk, rl, wrn, chs, ch, et, uid) from the visitor's body before queuing the sig:1 row, so a visitor cannot forge them; the analyst joins those from the request row. (camada-all-q617)

## 0.1.5 (2026-10-19)

- fix (security): a custom-rule `matches` regex never runs on a ua, header or path value over 2048 chars (UTF-16 units): over-cap fails closed, a hit for block/challenge/warn and a miss for skip/allow, never truncated (truncation would fail a deny rule open). (camada-all-q980)
- fix (security): control characters never reach the matcher alone: a ua/header value carrying `[\x00-\x1f\x7f]` is tested raw and stripped for deny rules (a pattern that targets `\t` or `\x00` still fires), and never matches a skip/allow rule, so stripping cannot widen an exemption such as `^partner-[a-z]+$` on `partner-acme\n`. The raw path form %-encodes the same characters. (camada-all-q980, camada-all-wh9m)
- test: the shared blk5 conformance vectors (RC01-RC47, contract regex-cap-sdk v3) run against `../camada-core/test/fixtures`.

## 0.1.4 (2026-10-12)

- fix: a block 403 (ip/path/asn/country/tls/rule) sends `Cache-Control: no-store` and replaces a `Cache-Control` a middleware already set on the response, so a shared cache or CDN no longer keeps one visitor's block for others. The challenge answers replace an upstream `Cache-Control` the same way. (camada-all-8lp6)
- fix (security): under trusted proxy `cidrs` (also the dashboard's Cloudflare option) `X-Forwarded-For` is no longer believed from a socket peer that is not a trusted proxy: such a peer is the client. Before this, anyone reaching the origin directly could pick their own client ip, slip past an ip block or get another ip blocked. A loopback peer (127.0.0.0/8, `::1`, `::ffff:127.x.x.x`) counts as a trusted hop; with no peer the walk is unchanged. (camada-all-yfc6)
- fix: `X-Forwarded-For` entries with a port (`203.0.113.66:51234`, `[2001:db8::66]:51234`, as Azure Application Gateway writes them) resolve to the address in every mode instead of falling back to the proxy's ip. (camada-all-0vho)
- fix: `ref` no longer ships the Referer verbatim: its query and fragment go through the query scrub (`~r`). New `ScrubURL`. (camada-all-ijsa)
- fix: the challenge page sends its own `Content-Security-Policy` (its inline solver and style by hash) and replaces a policy already on the response, so a strict app CSP no longer blocks the solver; the solver reads the nonce from the form. New `challenge.PageCSP`. (camada-all-y38o)
- fix (security): the resolved ip is always a valid address or none (C6 v3). A `RemoteAddr` that `net.SplitHostPort` cannot split, or `@`, on a TCP listener gives no ip and never the `X-Forwarded-For` walk; only a unix-socket listener walks `X-Forwarded-For` alone. `X-Forwarded-For` entries are trimmed of SP/HTAB only, `::ffff:a.b.c.d` entries are unmapped, IPv6 with a single leading/trailing `:` or an embedded dotted quad is invalid, and a non-ip entry is never a trusted hop.
- fix (security): the query scrub (`q`, and `ref`'s query and fragment) percent-decodes names and values (bytewise, up to 4 passes, no `+`) before testing, tests bare parts, and replaces a value whose nested query carries a credential segment; attack payloads such as `q=1' or '1'='1` stay visible. Name matching is ASCII-only.
- fix: the challenge page CSP no longer carries `form-action 'self'`, which blocked a post-solve redirect to another origin.
- fix: a request with no `http.LocalAddrContextKey` (Lambda / API Gateway adapters, `http.NewRequest`) has no socket: a `RemoteAddr` of `""` is no peer and walks `X-Forwarded-For` as before, and a bare ip is the peer. Only a TCP listener's unsplittable `RemoteAddr` is an unreadable peer.
- docs: mount `camada.Handler` outside chi's `middleware.RealIP` and gorilla's `handlers.ProxyHeaders`. Both rewrite `RemoteAddr` to a bare ip, which on a TCP listener leaves camada with no ip (blocks and challenges fail open); camada now logs a rate-limited warning when it sees one.
- chore: beacon re-synced to `@camada/browser` 0.3.2.
- test: the shared C6 v3 conformance cases (`ip/resolve.json`, `redact/referer.json`, `redact/query.json`) run in `sdk_conformance_test.go`.

## 0.1.3 (2026-10-09)

- fix: a snapshot poll answered with anything but 200/204/304, or not answered, no longer retries back to back. The blocks are kept and the next self-initiated poll waits `max(Retry-After, 5 s)`, capped at the refresh interval.
- fix: the snapshot staleness clock is monotonic, so a wall-clock step no longer stalls polling.

## 0.1.2 (2026-10-04)

- fix: an interim 1xx response (103 Early Hints) no longer carries x-rid or the `_sfp` Set-Cookie; the final response still does.
