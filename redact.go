package camada

import "github.com/camada/camada-go/internal/redact"

// ScrubQuery replaces credential-looking query values with ~r, preserving structure and order.
func ScrubQuery(query string) string { return redact.ScrubQuery(query) }

// BodyShape is a decoded JSON body's field names and sizes, never its values; nil for a non-object.
func BodyShape(obj any) map[string]int { return redact.BodyShape(obj) }

// HashUserID is the per-tenant pseudonym track() ships: HMAC-SHA256 under the ingest token, 32 hex chars.
func HashUserID(userID, ingestToken string) string { return redact.HashUserID(userID, ingestToken) }
