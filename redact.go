package camada

import "github.com/camada-app/camada-go/internal/redact"

// ScrubQuery replaces credential-looking query parts with ~r, preserving structure and order (C6 v3): names and
// values are percent-decoded before testing, a bare part or a value holding a nested query with a credential segment
// is replaced whole, and the output keeps the raw text.
func ScrubQuery(query string) string { return redact.ScrubQuery(query) }

// ScrubURL is a URL (a Referer) with its query and fragment run through ScrubQuery; the path is kept.
func ScrubURL(url string) string { return redact.ScrubURL(url) }

// BodyShape is a decoded JSON body's field names and sizes, never its values; nil for a non-object.
func BodyShape(obj any) map[string]int { return redact.BodyShape(obj) }

// HashUserID is the per-tenant pseudonym track() ships: HMAC-SHA256 under the ingest token, 32 hex chars.
func HashUserID(userID, ingestToken string) string { return redact.HashUserID(userID, ingestToken) }
