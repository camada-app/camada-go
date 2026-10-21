package camada

// The SDK's wire identity (SDK-03): x-camada-sdk: @camada/go/<version>. One literal in
// version.go is the single source the git tag follows and every sibling drift guard parses.

import (
	"os"
	"regexp"
	"testing"
)

// edge-analyst src/freshness.js sdkId: SDK_RE with a name from SDK_NAMES (exact case); anything else is silently dropped from sdk_versions.
var analystSDKRE = regexp.MustCompile(`^@camada/go/\d+\.\d+\.\d+[A-Za-z0-9.-]*$`)

func TestSDKIDIsTheFamilyWireIdentity(t *testing.T) {
	if SDKID != "@camada/go/"+Version || !analystSDKRE.MatchString(SDKID) || len(SDKID) > 64 {
		t.Fatalf("%q", SDKID)
	}
}

func TestTheVersionLiteralIsWhatTheDriftGuardsRead(t *testing.T) {
	src, err := os.ReadFile("version.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^const Version = "([^"]+)"`).FindSubmatch(src)
	if m == nil || string(m[1]) != Version {
		t.Fatalf("version.go literal %q vs %q", m, Version)
	}
}
