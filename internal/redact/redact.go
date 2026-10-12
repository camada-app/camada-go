// Package redact is redaction, non-configurable-off. The SDK never ships: Authorization/Cookie
// values (scheme only, events/build.go), body field values (shape only), query params that look
// like credentials, or raw user identifiers (HMAC-hashed here, inside the SDK, before anything
// reaches the queue). Ported from @camada/core src/redact.ts.
package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Exact patterns of C6 v3. Matching is ASCII-only: RE2's (?i) folds Unicode (U+212A Kelvin K matches k, U+017F
// matches s), so the name test is the lowercase-A-Z-then-substring form and hex spells out [a-fA-F0-9]. RE2 without
// (?m) anchors `$` at the true end of the text. Decoding is bytewise, so a decoded string may hold any byte; every
// pattern is pure ASCII, so a byte >= 0x80 never matches.
var (
	jwtRE = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`) // prefix match: anything may follow
	hexRE = regexp.MustCompile(`^[a-fA-F0-9]{32,}$`)
	b64RE = regexp.MustCompile(`^[A-Za-z0-9+/_-]{40,}={0,2}$`)

	nameWords = []string{"pass", "tok", "secret", "key", "auth", "sess", "sig", "code", "jwt", "bearer", "credential"}
)

// Allowlist names query params that are never scrubbed by name — additions only, never narrowing.
var Allowlist = []string{"plan", "role", "locale", "ab_variant"}

func suspectValue(v string) bool {
	return jwtRE.MatchString(v) || hexRE.MatchString(v) || b64RE.MatchString(v)
}

// nameHit is core's NAME_RE (`pass(word)?|tok(en)?|secret|key|api[-_]?key|auth|sess(ion)?|sig(nature)?|code|jwt|
// bearer|credential`, unanchored, case-insensitive) in its ASCII-only form: lowercase A-Z, then a substring test.
func nameHit(n string) bool {
	b := []byte(n)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	lower := string(b)
	for _, w := range nameWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// hasEscape reports a `%` followed by two ASCII hex digits.
func hasEscape(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == '%' {
			if _, ok := unhex(s[i+1]); ok {
				if _, ok := unhex(s[i+2]); ok {
					return true
				}
			}
		}
	}
	return false
}

// decodeOnce replaces every `%HH` (ASCII hex) with that byte; any other `%` stays, `+` stays. Never rescans its output.
func decodeOnce(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// decodeAll is percent-decoding that never fails loudly: bytewise, up to 4 passes, so double (or triple) encoding
// cannot hide a name or a nested query. Text that still holds a `%HH` after 4 passes returns ok=false, which the
// caller scrubs. The cap keeps a crafted `%252525…` linear. Only ever used to TEST a part; the output keeps the raw text.
func decodeAll(s string) (string, bool) {
	for i := 0; i < 4 && hasEscape(s); i++ {
		s = decodeOnce(s)
	}
	return s, !hasEscape(s)
}

// credSegment is one `name=value` or bare segment of a decoded nested value (no further decoding, no recursion).
func credSegment(seg string) bool {
	name, value, hasEq := strings.Cut(seg, "=")
	if !hasEq {
		return suspectValue(seg)
	}
	return nameHit(name) || suspectValue(value)
}

// nestedCred: a decoded value that carries a nested query (`?`, `&` or `=`) is a credential when any of its
// `[?&]`-separated segments is one (C6 v3). `q=a=b` or `q=1' or '1'='1` is not; `next=/r?token=x` is.
func nestedCred(d string) bool {
	if !strings.ContainsAny(d, "?&=") {
		return false
	}
	start := 0
	for i := 0; i <= len(d); i++ {
		if i == len(d) || d[i] == '?' || d[i] == '&' {
			if credSegment(d[start:i]) {
				return true
			}
			start = i + 1
		}
	}
	return false
}

// ScrubQuery replaces credential-looking query parts with ~r, preserving structure and order (C6 v3). The string is
// split on `&`, never URL-parsed. Each part's name and value are percent-decoded (decodeAll) before testing; the
// output keeps the raw text. `name=value` -> `name=~r` when the name looks like a credential, the value looks like
// one, or the value holds a nested query with a credential segment (replaced whole, so payloads like
// `q=1' or '1'='1` stay visible to the scorer). A bare part -> `~r` when it looks like a credential value or holds a
// credential segment. Either half still encoded after 4 decode passes counts as a credential.
func ScrubQuery(query string) string {
	if len(query) <= 1 {
		return query
	}
	lead := ""
	if query[0] == '?' {
		lead, query = "?", query[1:]
	}
	parts := strings.Split(query, "&")
	for i, p := range parts {
		name, value, hasEq := strings.Cut(p, "=")
		if !hasEq {
			if d, ok := decodeAll(p); !ok || suspectValue(d) || nestedCred(d) {
				parts[i] = "~r"
			}
			continue
		}
		dn, okn := decodeAll(name)
		dv, okv := decodeAll(value)
		if !okn || !okv || nameHit(dn) || suspectValue(dv) || nestedCred(dv) {
			parts[i] = name + "=~r"
		}
	}
	return lead + strings.Join(parts, "&")
}

// ScrubURL is a URL (a Referer) with its query and fragment run through ScrubQuery (camada-all-ijsa); the scheme,
// host and path are kept as they are. The path is left alone on purpose: it gets the same treatment as the request's
// own path `p` (none). A same-origin Referer's path already shipped as `p` on that page's own event, and a
// cross-origin one carries only the origin under the browsers' default Referrer-Policy.
func ScrubURL(url string) string {
	head, frag, hasFrag := strings.Cut(url, "#")
	if q := strings.IndexByte(head, '?'); q != -1 {
		head = head[:q] + ScrubQuery(head[q:])
	}
	if hasFrag {
		return head + "#" + ScrubQuery(frag)
	}
	return head
}

// BodyShape is the body's shape only: field names and sizes, never values. One level deep; nil
// when the body is not an object.
func BodyShape(obj any) map[string]int {
	m, ok := obj.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]int, len(m))
	for k, v := range m {
		switch x := v.(type) {
		case string:
			out[k] = utf8.RuneCountInString(x)
		case nil:
			out[k] = 0
		default:
			b, err := json.Marshal(x)
			if err != nil {
				out[k] = 0
			} else {
				out[k] = len(b)
			}
		}
	}
	return out
}

// HashUserID is a stable per-tenant pseudonym: HMAC-SHA256 keyed by the ingest token, labelled so
// the hash can never double as anything else, truncated to 32 hex chars. The raw identifier never leaves.
func HashUserID(userID, ingestToken string) string {
	m := hmac.New(sha256.New, []byte(ingestToken))
	m.Write([]byte("uid:" + userID))
	return hex.EncodeToString(m.Sum(nil))[:32]
}
