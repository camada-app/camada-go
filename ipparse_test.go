package camada

// Ported from the reference edge-analyst src/blocklist.js parsers: ip4 is not-ok on anything
// unusual; ip6 rejects zone ids and v4-mapped forms. The golden fixtures pin the rest.

import "testing"

func TestIP4DottedQuadToInt(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint32
	}{
		{"203.0.113.66", 203<<24 | 0<<16 | 113<<8 | 66},
		{"255.255.255.255", 0xFFFFFFFF},
		{"0.0.0.0", 0},
	} {
		got, ok := ParseIP4(c.in)
		if !ok || got != c.want {
			t.Errorf("ParseIP4(%q) = %d,%v want %d", c.in, got, ok, c.want)
		}
	}
}

func TestIP4RejectsAnythingUnusual(t *testing.T) {
	for _, bad := range []string{"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1..2.3", "01.2.3.4444", "a.b.c.d", " 1.2.3.4", "1.2.3.4\n"} {
		if _, ok := ParseIP4(bad); ok {
			t.Errorf("ParseIP4(%q) accepted", bad)
		}
	}
}

func TestIP6FullAndCompressedForms(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Words
	}{
		{"2001:db8::1", Words{0x20010DB8, 0, 0, 1}},
		{"::1", Words{0, 0, 0, 1}},
		{"::", Words{0, 0, 0, 0}},
		{"fe80:0:0:0:0:0:0:1", Words{0xFE800000, 0, 0, 1}},
		{"2001:DB8:CAFE::", Words{0x20010DB8, 0xCAFE0000, 0, 0}},
	} {
		got, ok := ParseIP6(c.in)
		if !ok || got != c.want {
			t.Errorf("ParseIP6(%q) = %v,%v want %v", c.in, got, ok, c.want)
		}
	}
}

func TestIP6RejectsZoneIdsMappedV4AndMalformed(t *testing.T) {
	for _, bad := range []string{"fe80::1%eth0", "::ffff:1.2.3.4", "1:2:3:4:5:6:7:8:9", "1::2::3", "12345::", "g::1", "1:2:3:4:5:6:7", ":1::"} {
		if _, ok := ParseIP6(bad); ok {
			t.Errorf("ParseIP6(%q) accepted", bad)
		}
	}
}
