package camada

// Redaction is not configurable off: credential-looking query values become ~r, body values
// never ship, user identifiers are HMAC-hashed inside the SDK.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestScrubQueryByNameAndByValueShape(t *testing.T) {
	jwt := "eyJhbGciOi.eyJzdWIiOi.sig"
	for _, c := range []struct{ in, want string }{
		{"?q=hello&token=abc&x=1", "?q=hello&token=~r&x=1"},
		{"?api_key=k&PASSWORD=p", "?api_key=~r&PASSWORD=~r"},
		{"?t=" + jwt, "?t=~r"},
		{"?h=" + strings.Repeat("a", 32), "?h=~r"},
		{"?b=" + strings.Repeat("A", 40) + "==", "?b=~r"},
		{"?flag&x=1", "?flag&x=1"}, // a bare name is kept as is
	} {
		if got := ScrubQuery(c.in); got != c.want {
			t.Errorf("ScrubQuery(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestScrubQueryKeepsShapeAndEmpties(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", ""},
		{"?", "?"},
		{"a=1&code=2", "a=1&code=~r"}, // no leading ? is fine too
	} {
		if got := ScrubQuery(c.in); got != c.want {
			t.Errorf("ScrubQuery(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestBodyShapeIsNamesAndSizesOnly(t *testing.T) {
	got := BodyShape(map[string]any{"email": "a@b.c", "n": 12.0, "none": nil, "arr": []any{1.0, 2.0}})
	want := map[string]int{"email": 5, "n": 2, "none": 0, "arr": 5}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if BodyShape([]any{1}) != nil || BodyShape("str") != nil {
		t.Fatal("non-objects must have no shape")
	}
}

func TestHashUserIDIsALabelledTruncatedHMAC(t *testing.T) {
	m := hmac.New(sha256.New, []byte("tok"))
	m.Write([]byte("uid:alice@example.com"))
	expected := hex.EncodeToString(m.Sum(nil))[:32]
	if got := HashUserID("alice@example.com", "tok"); got != expected {
		t.Fatalf("got %q want %q", got, expected)
	}
	if len(HashUserID("x", "tok")) != 32 {
		t.Fatal("not 32 hex chars")
	}
}
