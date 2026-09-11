// Package beacon is the first-party beacon: @camada/browser's dist/auto.global.js vendored by
// `go run ./scripts/sync-beacon` and embedded, so the SDK serves it at /_cam/b.js with no
// runtime file read. beacon_test.go pins it to the sibling build byte for byte.
package beacon

import (
	_ "embed"
	"strings"
)

//go:embed auto.global.js
var js string

//go:embed version.txt
var version string

//go:embed sha256.txt
var sha string

// JS is the beacon script exactly as @camada/browser built it.
func JS() string { return js }

// Version is the @camada/browser version vendored.
func Version() string { return strings.TrimSpace(version) }

// SHA256 is the hex digest of JS, recorded at sync time.
func SHA256() string { return strings.TrimSpace(sha) }
