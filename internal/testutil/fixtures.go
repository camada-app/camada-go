// Package testutil holds the test doubles the suite shares: the golden fixture readers and the
// in-process fake analyst. The golden snapshot containers live in the camada-core sibling
// checkout (copied verbatim from edge-analyst, the format owner); the suite fails by name when
// they are missing rather than skipping, the same stance the web/mkt drift guards take.
package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// RepoRoot is the camada-go checkout this file belongs to.
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

// FixturesDir is CAMADA_FIXTURES_DIR, else camada-core/test/fixtures beside this checkout.
func FixturesDir() string {
	if d := os.Getenv("CAMADA_FIXTURES_DIR"); d != "" {
		return d
	}
	return filepath.Join(filepath.Dir(RepoRoot()), "camada-core", "test", "fixtures")
}

// FixturePath fails the test by name when the golden fixture is absent — never skips.
func FixturePath(t testing.TB, rel string) string {
	t.Helper()
	p := filepath.Join(FixturesDir(), rel)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("golden fixture missing: %s (no camada-core checkout? set CAMADA_FIXTURES_DIR)", p)
	}
	return p
}

// ReadBin reads a golden binary fixture.
func ReadBin(t testing.TB, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(FixturePath(t, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

// ReadJSON decodes a golden JSON fixture into v.
func ReadJSON(t testing.TB, rel string, v any) {
	t.Helper()
	if err := json.Unmarshal(ReadBin(t, rel), v); err != nil {
		t.Fatalf("decode %s: %v", rel, err)
	}
}
