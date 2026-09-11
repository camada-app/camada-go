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

var (
	nameRE = regexp.MustCompile(`(?i)(pass(word)?|tok(en)?|secret|key|api[-_]?key|auth|sess(ion)?|sig(nature)?|code|jwt|bearer|credential)`)
	jwtRE  = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`)
	hexRE  = regexp.MustCompile(`(?i)^[a-f0-9]{32,}$`)
	b64RE  = regexp.MustCompile(`^[A-Za-z0-9+/_-]{40,}={0,2}$`)
)

// Allowlist names query params that are never scrubbed by name — additions only, never narrowing.
var Allowlist = []string{"plan", "role", "locale", "ab_variant"}

func suspectValue(v string) bool {
	return jwtRE.MatchString(v) || hexRE.MatchString(v) || b64RE.MatchString(v)
}

// ScrubQuery replaces credential-looking query values with ~r, preserving structure and order.
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
		eq := strings.IndexByte(p, '=')
		if eq == -1 {
			continue
		}
		name, value := p[:eq], p[eq+1:]
		if nameRE.MatchString(name) || suspectValue(value) {
			parts[i] = name + "=~r"
		}
	}
	return lead + strings.Join(parts, "&")
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
