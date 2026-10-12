# Changelog

## Unreleased

- fix (security): under trusted proxy `cidrs` (also the dashboard's Cloudflare option) `X-Forwarded-For` is no longer believed from a socket peer that is not a trusted proxy: such a peer is the client. Before this, anyone reaching the origin directly could pick their own client ip, slip past an ip block or get another ip blocked. A loopback peer (127.0.0.0/8, `::1`, `::ffff:127.x.x.x`) counts as a trusted hop; with no peer the walk is unchanged. (camada-all-yfc6)
- fix: `X-Forwarded-For` entries with a port (`203.0.113.66:51234`, `[2001:db8::66]:51234`, as Azure Application Gateway writes them) resolve to the address in every mode instead of falling back to the proxy's ip. (camada-all-0vho)
- fix: `ref` no longer ships the Referer verbatim: its query and fragment go through the query scrub (`~r`). New `ScrubURL`. (camada-all-ijsa)
- fix: the challenge page sends its own `Content-Security-Policy` (its inline solver and style by hash) and replaces a policy already on the response, so a strict app CSP no longer blocks the solver; the solver reads the nonce from the form. New `challenge.PageCSP`. (camada-all-y38o)
- test: the shared C6 conformance cases (`ip/resolve.json`, `redact/referer.json`) run in `sdk_conformance_test.go`.

## 0.1.3 (2026-10-09)

- fix: a snapshot poll answered with anything but 200/204/304, or not answered, no longer retries back to back. The blocks are kept and the next self-initiated poll waits `max(Retry-After, 5 s)`, capped at the refresh interval.
- fix: the snapshot staleness clock is monotonic, so a wall-clock step no longer stalls polling.

## 0.1.2 (2026-10-04)

- fix: an interim 1xx response (103 Early Hints) no longer carries x-rid or the `_sfp` Set-Cookie; the final response still does.
