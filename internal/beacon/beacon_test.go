package beacon

// The first-party beacon is @camada/browser's auto build, vendored so the package has no
// runtime file reads. It must be byte-for-byte the sibling's dist/auto.global.js; the test
// fails by name (never skips) when that checkout or its build is missing.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/camada/camada-go/internal/testutil"
)

func dist() string {
	if p := os.Getenv("CAMADA_BROWSER_DIST"); p != "" {
		return p
	}
	return filepath.Join(filepath.Dir(testutil.RepoRoot()), "camada-browser", "dist", "auto.global.js")
}

func TestVendoredBeaconMatchesTheSiblingBuild(t *testing.T) {
	src, err := os.ReadFile(dist())
	if err != nil {
		t.Fatalf("beacon build missing: %s (run npm run build in camada-browser, or set CAMADA_BROWSER_DIST)", dist())
	}
	if JS() != string(src) {
		t.Fatal("run `go run ./scripts/sync-beacon` to re-vendor @camada/browser")
	}
	sum := sha256.Sum256(src)
	if SHA256() != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha256.txt %s != %s", SHA256(), hex.EncodeToString(sum[:]))
	}
}

func TestBeaconNamesItsOwnVersionAndPostsToFP(t *testing.T) {
	if !strings.Contains(JS(), `"`+Version()+`"`) || !strings.Contains(JS(), "@camada/browser") {
		t.Fatalf("version %q not in the build", Version())
	}
	if !strings.Contains(JS(), `"fp"`) { // derives the POST target from the script URL's final segment
		t.Fatal("no fp segment")
	}
}
