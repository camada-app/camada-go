// Re-vendors @camada/browser's auto build into internal/beacon (auto.global.js, version.txt,
// sha256.txt), which the SDK embeds and serves at /_cam/b.js with no runtime file read.
//
// Usage: go run ./scripts/sync-beacon [path/to/camada-browser]   (defaults to the sibling checkout)
// Run `npm run build` in camada-browser first; internal/beacon/beacon_test.go fails until the two agree.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	root, err := os.Getwd()
	if err != nil {
		fail(err)
	}
	browser := filepath.Join(filepath.Dir(root), "camada-browser")
	if len(os.Args) > 1 {
		browser = os.Args[1]
	}
	src, err := os.ReadFile(filepath.Join(browser, "dist", "auto.global.js"))
	if err != nil {
		fail(err)
	}
	pkg, err := os.ReadFile(filepath.Join(browser, "package.json"))
	if err != nil {
		fail(err)
	}
	var meta struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(pkg, &meta); err != nil || meta.Version == "" {
		fail(fmt.Errorf("camada-browser/package.json: no version (%v)", err))
	}
	sum := sha256.Sum256(src)
	out := filepath.Join(root, "internal", "beacon")
	for name, data := range map[string][]byte{
		"auto.global.js": src,
		"version.txt":    []byte(meta.Version),
		"sha256.txt":     []byte(hex.EncodeToString(sum[:])),
	} {
		if err := os.WriteFile(filepath.Join(out, name), data, 0o644); err != nil {
			fail(err)
		}
	}
	fmt.Printf("internal/beacon: @camada/browser/%s, %d bytes\n", meta.Version, len(src))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sync-beacon:", err)
	os.Exit(1)
}
