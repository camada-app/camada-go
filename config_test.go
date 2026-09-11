package camada

import "testing"

func TestKeySplitsOnTheFirstDot(t *testing.T) {
	for _, c := range []struct{ in, ingest, snap string }{
		{"tok-acme.snap-acme", "tok-acme", "snap-acme"},
		{"a.b.c", "a", "b.c"},
	} {
		ingest, snap, ok := ParseKey(c.in)
		if !ok || ingest != c.ingest || snap != c.snap {
			t.Errorf("ParseKey(%q) = %q,%q,%v", c.in, ingest, snap, ok)
		}
	}
}

func TestKeyRejectsMissingHalves(t *testing.T) {
	for _, bad := range []string{"", "nodot", ".snap", "tok."} {
		if _, _, ok := ParseKey(bad); ok {
			t.Errorf("ParseKey(%q) accepted", bad)
		}
	}
}
