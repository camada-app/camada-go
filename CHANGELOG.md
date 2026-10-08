# Changelog

## Unreleased

- fix: a snapshot poll answered with anything but 200/204/304, or not answered, no longer retries back to back. The blocks are kept and the next self-initiated poll waits `max(Retry-After, 5 s)`, capped at the refresh interval.
- fix: the snapshot staleness clock is monotonic, so a wall-clock step no longer stalls polling.

## 0.1.2 (2026-10-04)

- fix: an interim 1xx response (103 Early Hints) no longer carries x-rid or the `_sfp` Set-Cookie; the final response still does.
