package snapshot

// Container handling the golden cases do not reach: malformed input, the advisory version byte,
// and the rule-compilation rules (drop, never guess).

import (
	"encoding/binary"
	"strings"
	"sync"
	"testing"

	"github.com/camada-app/camada-go/internal/testutil"
)

type section struct {
	typ   uint32
	words []uint32
}

// container builds a tiny BLK container: header then the sections back to back.
func container(magic uint32, sections []section) []byte {
	k := uint32(len(sections))
	header := []uint32{magic, k}
	off := 2 + k*3
	var body []uint32
	for _, s := range sections {
		header = append(header, s.typ, off, uint32(len(s.words)))
		body = append(body, s.words...)
		off += uint32(len(s.words))
	}
	out := make([]byte, 0, 4*(len(header)+len(body)))
	for _, w := range append(header, body...) {
		out = binary.LittleEndian.AppendUint32(out, w)
	}
	return out
}

func v4basic(t *testing.T) ([]byte, *Meta) {
	meta, err := DecodeMeta(testutil.ReadBin(t, "blk3/v4-basic.meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	return testutil.ReadBin(t, "blk3/v4-basic.bin"), meta
}

func le(words ...uint32) []byte {
	var out []byte
	for _, w := range words {
		out = binary.LittleEndian.AppendUint32(out, w)
	}
	return out
}

func TestBadMagicAndTruncationFail(t *testing.T) {
	meta := &Meta{Version: "1"}
	for name, b := range map[string][]byte{
		"not a container":     []byte("nope"),
		"claims 3 sections":   le(0x424C4B35, 3),                               // has none
		"runs past the end":   le(0x424C4B35, 1, 10, 5, 100),                   // section of 100 words at offset 5
		"short fixed section": append(le(0x424C4B35, 1, 3, 5, 2), le(0, 0)...), // idx4 must be 65537 words
	} {
		if _, err := ParseSnapshot(b, meta); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestUnalignedTailIsDroppedNotFatal(t *testing.T) {
	bin, meta := v4basic(t)
	snap, err := ParseSnapshot(append(append([]byte{}, bin...), 1), meta)
	if err != nil || snap.Format != 4 {
		t.Fatalf("err %v format %d", err, snap.Format)
	}
}

func TestParsedSnapshotDoesNotAliasTheBody(t *testing.T) {
	bin, meta := v4basic(t)
	body := append([]byte{}, bin...)
	snap, err := ParseSnapshot(body, meta)
	if err != nil {
		t.Fatal(err)
	}
	for i := range body {
		body[i] = 0 // the transport's buffer is reused; the snapshot must have its own words
	}
	if NewMatcher(snap).Match(MatchInput{IP: "203.0.113.66"}).Reason != "ip4" {
		t.Fatal("snapshot aliased the body")
	}
}

func TestV3MagicStillReadsV4Sections(t *testing.T) {
	// the version byte is advisory: an allow range under a BLK3 magic still allows
	n := uint32(192<<24 | 0<<16 | 2<<8 | 20)
	bin3 := container(0x424C4B33, []section{{10, []uint32{n, n}}})
	snap, err := ParseSnapshot(bin3, &Meta{Version: "x"})
	if err != nil {
		t.Fatal(err)
	}
	r := NewMatcher(snap).Match(MatchInput{IP: "192.0.2.20"})
	if !r.Allowed || r.Reason != "ip4" || snap.Format != 3 {
		t.Fatalf("got %+v format %d", r, snap.Format)
	}
}

func rulesSnapshot(t *testing.T, rules []Rule, sections []section) *Matcher {
	t.Helper()
	snap, err := ParseSnapshot(container(0x424C4B35, sections), &Meta{Version: "v", Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return NewMatcher(snap)
}

func TestUnknownActionAndEmptyRulesAreDropped(t *testing.T) {
	m := rulesSnapshot(t, []Rule{
		{ID: "a", Action: "teleport", Conds: []Cond{{F: "path", Op: "is", V: "/x"}}},
		{ID: "b", Action: "block", Conds: nil},
		{ID: "c", Action: "block", Conds: []Cond{{F: "path", Op: "is", V: "/x"}}},
	}, nil)
	if len(m.Snap.Rules) != 1 || m.Snap.Rules[0].ID != "c" {
		t.Fatalf("rules %+v", m.Snap.Rules)
	}
	if m.Match(MatchInput{Path: "/x"}).Rule != "c" {
		t.Fatal("c did not fire")
	}
}

func TestRegexRE2RejectsNeverMatchesAndNeverPanics(t *testing.T) {
	m := rulesSnapshot(t, []Rule{{ID: "bad", Action: "block", Conds: []Cond{{F: "path", Op: "matches", V: "(?<=a"}}}}, nil)
	if m.Match(MatchInput{Path: "/a"}).Block {
		t.Fatal("a rejected pattern matched")
	}
	snap, err := ParseSnapshot(container(0x424C4B35, nil), &Meta{Version: "v", PathsRegex: []string{"(?<=a", "^/dump$"}})
	if err != nil {
		t.Fatal(err)
	}
	if NewMatcher(snap).Match(MatchInput{Path: "/dump"}).Reason != "path" {
		t.Fatal("the good pattern was lost with the bad one")
	}
}

func TestASNConditionsCompareAsStringsAndUnanswerableFieldsNeverFire(t *testing.T) {
	m := rulesSnapshot(t, []Rule{
		{ID: "asn", Action: "block", Conds: []Cond{{F: "asn", Op: "is_in", V: []any{14061, "7922"}}}},
		{ID: "cc", Action: "block", Conds: []Cond{{F: "country", Op: "is_not", V: "US"}}},
	}, nil)
	if m.Match(MatchInput{ASN: 14061}).Rule != "asn" || m.Match(MatchInput{ASN: 7922}).Rule != "asn" {
		t.Fatal("asn membership")
	}
	if m.Match(MatchInput{ASN: 1}).Rule != "" { // country unanswerable: is_not stays false
		t.Fatal("is_not fired without a country")
	}
	if m.Match(MatchInput{Country: "BR"}).Rule != "cc" {
		t.Fatal("cc did not fire")
	}
}

func TestHeaderGetterThatPanicsOrAnswersNothingReadsAsAbsent(t *testing.T) {
	m := rulesSnapshot(t, []Rule{{ID: "h", Action: "block", Conds: []Cond{{F: "header", Op: "is", Name: "X-Api-Key", V: "k"}}}}, nil)
	boom := func(string) (string, bool) { panic("app bug") }
	if m.Match(MatchInput{Header: boom}).Block {
		t.Fatal("a panicking getter fired the rule")
	}
	if m.Match(MatchInput{Header: func(n string) (string, bool) { return "", false }}).Block {
		t.Fatal("an absent header fired the rule")
	}
	if m.Match(MatchInput{Header: func(n string) (string, bool) { return "k", n == "x-api-key" }}).Rule != "h" {
		t.Fatal("the lower-cased name did not reach the getter")
	}
}

func TestTwoIPConditionsConsumeTwoSectionPairsInOrder(t *testing.T) {
	a, b := uint32(10<<24|1), uint32(10<<24|2)
	m := rulesSnapshot(t,
		[]Rule{{ID: "r", Action: "block", Conds: []Cond{{F: "ip", Op: "is_in", Set: true}, {F: "ip", Op: "not_in", Set: true}}}},
		[]section{{14, []uint32{0, a, a}}, {15, []uint32{0}}, {14, []uint32{0, b, b}}, {15, []uint32{0}}},
	)
	if m.Match(MatchInput{IP: "10.0.0.1"}).Rule != "r" { // in the first, not in the second
		t.Fatal("10.0.0.1 should match")
	}
	if m.Match(MatchInput{IP: "10.0.0.2"}).Rule != "" { // not in the first
		t.Fatal("10.0.0.2 should not match")
	}
}

func TestJSClassSpellings(t *testing.T) {
	for _, c := range []struct {
		pat string
		yes []string
		no  []string
	}{
		{`x[]-\d]y`, nil, []string{"x]-5]y", "x-5]y", "x]y"}},
		{`x[^]-\d]y`, []string{"xz-5]y"}, []string{"x]y"}},
		{`x[]a]y`, nil, []string{"x]y", "xay", "xa]y"}},
		{`x[^]a]y`, []string{"xza]y"}, []string{"xay"}},
		{`(?i)x[]a]y`, nil, []string{"XA]Y"}},
		{`a\[]`, []string{"a[]"}, nil},
		{`x[[:alpha:]]y`, []string{"xa]y", "x[]y", "x:]y"}, []string{"xby", "xay"}},
		{`(?i)x[[:alpha:]]y`, []string{"XA]Y"}, []string{"XBY"}},
		{`x[[:x:]]y`, []string{"x[]y", "x:]y"}, []string{"xby"}},
		{`x[^[:a:]]y`, []string{"xb]y"}, []string{"xa]y", "x[]y", "xby"}},
		{`x[[:a]y|b:]`, []string{"xay", "b:]"}, []string{"xby"}},
		{`x[\[:alpha:]]y`, []string{"xa]y"}, []string{"xby"}},
		{`x[a[]y`, []string{"x[y", "xay"}, []string{"xby"}},
		{`x[[=a=]]y`, []string{"xa]y", "x=]y"}, []string{"xay"}},
	} {
		rx := CompileRegex(c.pat)
		if rx == nil {
			t.Fatalf("%s did not compile", c.pat)
		}
		for _, s := range c.yes {
			if !rx.MatchString(s) {
				t.Errorf("%s should match %q", c.pat, s)
			}
		}
		for _, s := range c.no {
			if rx.MatchString(s) {
				t.Errorf("%s should not match %q", c.pat, s)
			}
		}
	}
}

func TestJSRegexSpellingsAreTranslated(t *testing.T) {
	m := rulesSnapshot(t, []Rule{{ID: "ver", Action: "block", Conds: []Cond{{F: "path", Op: "matches", V: `^/api/(?<ver>v\d+)/`}}}}, nil)
	if m.Match(MatchInput{Path: "/api/v2/dump"}).Rule != "ver" {
		t.Fatal("named group")
	}
	if m.Match(MatchInput{Path: "/api/v٣/dump"}).Rule != "" { // \d is ASCII, as JS reads it
		t.Fatal("\\d matched a non-ASCII digit")
	}
	m2 := rulesSnapshot(t, []Rule{{ID: "any", Action: "block", Conds: []Cond{{F: "ua", Op: "matches", V: `^a[^]b\cJ$`}}}}, nil)
	if m2.Match(MatchInput{UA: "aXb\n"}).Rule != "any" { // v3 (S5): a deny also tests the raw value, which \cJ reads
		t.Fatal("\\cJ must match the raw LF for a deny rule")
	}
	if rx := CompileRegex(`^a[^]b\cJ$`); rx == nil || !rx.MatchString("a\nb\n") {
		t.Fatal("[^] and \\cJ")
	}
	if m2.Match(MatchInput{UA: "ab"}).Rule != "" {
		t.Fatal("matched without the any-char")
	}
	// \uXXXX is a JS (and Python re) code-point escape; RE2 spells it \x{XXXX}
	// (on ua: a path regex runs case-insensitively, contracts §D3 "Path matching")
	m3 := rulesSnapshot(t, []Rule{{ID: "u", Action: "block", Conds: []Cond{{F: "ua", Op: "matches", V: `^/caf\u00e9/[\u0041-\u005A]$`}}}}, nil)
	if m3.Match(MatchInput{UA: "/café/X"}).Rule != "u" {
		t.Fatal("\\uXXXX")
	}
	if m3.Match(MatchInput{UA: "/cafe/X"}).Rule != "" || m3.Match(MatchInput{UA: "/café/x"}).Rule != "" {
		t.Fatal("\\uXXXX matched the wrong code point")
	}
	if CompileRegex(`\u00e`) != nil || CompileRegex(`\u{1F600}`) != nil { // not four hex digits: rejected, as re rejects it
		t.Fatal("a malformed \\u compiled")
	}
	// JS (non-u): \x not followed by two hex digits is the letter x, so \x{02} is "xx", not U+0002
	if rx := CompileRegex(`^bot\x{02}$`); rx == nil || !rx.MatchString("botxx") || rx.MatchString("bot\u0002") {
		t.Fatal("\\x{02} must read as xx")
	}
	if rx := CompileRegex(`^\x41[\xg]$`); rx == nil || !rx.MatchString("Ax") || rx.MatchString("A\x00") {
		t.Fatal("\\xHH stays a byte escape, a bare \\x is x")
	}
}

func TestOneMatcherServesConcurrentRequestsWithoutCrosstalk(t *testing.T) {
	a := uint32(10<<24 | 1)
	m := rulesSnapshot(t,
		[]Rule{{ID: "r", Action: "block", Conds: []Cond{{F: "header", Op: "is", Name: "x-a", V: "1"}, {F: "ip", Op: "is_in", Set: true}}}},
		[]section{{14, []uint32{0, a, a}}, {15, []uint32{0}}},
	)
	header := func(string) (string, bool) { return "1", true }
	var wg sync.WaitGroup
	wrong := [2]int{}
	hammer := func(slot int, ip string, expect bool) {
		defer wg.Done()
		for i := 0; i < 1500; i++ {
			if m.Match(MatchInput{IP: ip, Header: header}).Block != expect {
				wrong[slot]++
			}
		}
	}
	wg.Add(2)
	go hammer(0, "10.0.0.1", true)
	go hammer(1, "10.0.0.2", false)
	wg.Wait()
	if wrong != [2]int{} {
		t.Fatalf("crosstalk: %v", wrong)
	}
}

func capMatcher(t *testing.T, action, field, pattern string) *Matcher {
	t.Helper()
	return rulesSnapshot(t, []Rule{{ID: "r", Action: action, Conds: []Cond{{F: field, Op: "matches", V: pattern}}}}, nil)
}

func TestMatchesOverCapDenyHitsSkipMisses(t *testing.T) {
	for _, action := range []string{"block", "challenge", "warn"} {
		m := capMatcher(t, action, "ua", "^x")
		if got := m.Match(MatchInput{UA: strings.Repeat("a", 2048)}).Rule; got != "" {
			t.Fatalf("%s at the cap: %q", action, got)
		}
		if got := m.Match(MatchInput{UA: strings.Repeat("a", 2049)}).Rule; got != "r" {
			t.Fatalf("%s over the cap: %q", action, got)
		}
	}
	m := rulesSnapshot(t, []Rule{
		{ID: "s", Action: "skip", Conds: []Cond{{F: "ua", Op: "matches", V: "^x"}}},
		{ID: "b", Action: "block", Conds: []Cond{{F: "ua", Op: "contains", V: "x"}}},
	}, nil)
	if got := m.Match(MatchInput{UA: strings.Repeat("x", 2048)}).Rule; got != "s" {
		t.Fatalf("skip at the cap: %q", got)
	}
	if got := m.Match(MatchInput{UA: strings.Repeat("x", 2049)}).Rule; got != "b" {
		t.Fatalf("skip over the cap: %q", got)
	}
}

func TestCapUnitIsUTF16CodeUnits(t *testing.T) {
	m := capMatcher(t, "block", "ua", "^x")
	cases := []struct {
		name string
		ua   string
		want string
	}{
		{"e-acute at cap (4096 bytes)", strings.Repeat("é", 2048), ""},
		{"astral at cap", strings.Repeat("😀", 1024), ""},
		{"astral over cap", strings.Repeat("😀", 1025), "r"},
		{"invalid UTF-8 counts bytes, at cap", strings.Repeat("\xff", 2048), ""},
		{"invalid UTF-8 counts bytes, over cap", strings.Repeat("\xff", 2049), "r"},
	}
	for _, c := range cases {
		if got := m.Match(MatchInput{UA: c.ua}).Rule; got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestControlCharsAreDeletedBeforeMatches(t *testing.T) {
	m := rulesSnapshot(t, []Rule{
		{ID: "ua", Action: "warn", Conds: []Cond{{F: "ua", Op: "matches", V: "Scrapy/[0-9]"}}},
		{ID: "h", Action: "block", Conds: []Cond{{F: "header", Op: "matches", Name: "x-v", V: `^1\.2$`}}},
	}, nil)
	if m.Match(MatchInput{UA: "Scrapy\t/2.11"}).Rule != "ua" || m.Match(MatchInput{UA: "Scr\x00apy/2\x7f.1"}).Rule != "ua" {
		t.Fatal("ua strip")
	}
	hdr := func(n string) (string, bool) { return "1\x7f.2\n", n == "x-v" }
	if m.Match(MatchInput{Header: hdr}).Rule != "h" {
		t.Fatal("header strip")
	}
	if capMatcher(t, "block", "ua", "^a*$").Match(MatchInput{UA: strings.Repeat("a", 2048) + "\t"}).Rule != "r" {
		t.Fatal("strip happens before the cap, and the stripped value matches")
	}
	if capMatcher(t, "block", "ua", "^b").Match(MatchInput{UA: strings.Repeat("a", 2048) + "\t"}).Rule != "r" {
		t.Fatal("v3 (S5): raw 2049 is over the cap, a deny hits")
	}
	c := rulesSnapshot(t, []Rule{{ID: "c", Action: "block", Conds: []Cond{{F: "ua", Op: "contains", V: "curl/"}}}}, nil)
	if c.Match(MatchInput{UA: "cu\x00rl/8"}).Rule != "" {
		t.Fatal("contains reads the raw value")
	}
	if got := stripControl("a\xffb\n\xc3\xa9"); got != "a\xffb\xc3\xa9" {
		t.Fatalf("invalid UTF-8 must survive the strip: %q", got)
	}
}

func TestPathMatchesCap(t *testing.T) {
	m := rulesSnapshot(t, []Rule{
		{ID: "s", Action: "skip", Conds: []Cond{{F: "path", Op: "matches", V: "^/static-mirror/"}}},
		{ID: "b", Action: "block", Conds: []Cond{{F: "path", Op: "matches", V: "^/api/v[0-9]+/dump$"}}},
	}, nil)
	cases := []struct{ path, want string }{
		{"/static-mirror/" + strings.Repeat("a", 2033), "s"},
		{"/static-mirror/" + strings.Repeat("a", 2034), "b"},
		{"/x/" + strings.Repeat("a", 2045), ""},
		{"/x/" + strings.Repeat("a", 2046), "b"},
		{"/x?" + strings.Repeat("q", 3000), ""},
		{"/" + strings.Repeat("%61", 700), "b"},
		{"/static-mirror/" + strings.Repeat("%61", 700), "s"},
		{"/static-mirror/" + strings.Repeat("./", 1100) + "x", "b"},
		{"/" + strings.Repeat("é", 400), "b"},
		{"/api/v2/dump\n", ""},
		{"/api/v2/dump%0A", ""},
	}
	for _, c := range cases {
		if got := m.Match(MatchInput{Path: c.path}).Rule; got != c.want {
			t.Errorf("%.40q: got %q want %q", c.path, got, c.want)
		}
	}
}

func TestS5TwoValueRuleForControlChars(t *testing.T) {
	hdr := func(name, val string) func(string) (string, bool) {
		return func(n string) (string, bool) { return val, n == name }
	}
	if capMatcher(t, "block", "ua", `\t`).Match(MatchInput{UA: "a\tb"}).Rule != "r" {
		t.Fatal("deny \\t must hit the raw value")
	}
	if capMatcher(t, "block", "ua", "sqlmap").Match(MatchInput{UA: "sql\tmap"}).Rule != "r" {
		t.Fatal("deny sqlmap must hit the stripped value")
	}
	hm := rulesSnapshot(t, []Rule{{ID: "h", Action: "block", Conds: []Cond{{F: "header", Op: "matches", Name: "x-v", V: `\t`}}}}, nil)
	if hm.Match(MatchInput{Header: hdr("x-v", "a\tb")}).Rule != "h" {
		t.Fatal("header deny on raw")
	}
	hs := rulesSnapshot(t, []Rule{{ID: "h", Action: "block", Conds: []Cond{{F: "header", Op: "matches", Name: "x-v", V: "sqlmap"}}}}, nil)
	if hs.Match(MatchInput{Header: hdr("x-v", "sql\tmap")}).Rule != "h" {
		t.Fatal("header deny on stripped")
	}
	ms := rulesSnapshot(t, []Rule{
		{ID: "s", Action: "skip", Conds: []Cond{{F: "ua", Op: "matches", V: "^partner-[a-z]+$"}}},
		{ID: "b", Action: "block", Conds: []Cond{{F: "ua", Op: "contains", V: "partner"}}},
	}, nil)
	if ms.Match(MatchInput{UA: "partner-acme"}).Rule != "s" || ms.Match(MatchInput{UA: "partner-acme\n"}).Rule != "b" {
		t.Fatal("ua skip: clean hits, control chars miss")
	}
	mh := rulesSnapshot(t, []Rule{
		{ID: "s", Action: "skip", Conds: []Cond{{F: "header", Op: "matches", Name: "x-p", V: "^partner-[a-z]+$"}}},
		{ID: "b", Action: "block", Conds: []Cond{{F: "header", Op: "contains", Name: "x-p", V: "partner"}}},
	}, nil)
	if mh.Match(MatchInput{Header: hdr("x-p", "partner-acme")}).Rule != "s" || mh.Match(MatchInput{Header: hdr("x-p", "partner-acme\n")}).Rule != "b" {
		t.Fatal("header skip: clean hits, control chars miss")
	}
	over := strings.Repeat("a", 2048) + "\t"
	if capMatcher(t, "block", "ua", "^b").Match(MatchInput{UA: over}).Rule != "r" {
		t.Fatal("raw over cap, stripped under: deny hits")
	}
	mo := rulesSnapshot(t, []Rule{
		{ID: "s", Action: "skip", Conds: []Cond{{F: "ua", Op: "matches", V: "^a+$"}}},
		{ID: "b", Action: "block", Conds: []Cond{{F: "ua", Op: "contains", V: "a"}}},
	}, nil)
	if mo.Match(MatchInput{UA: strings.Repeat("a", 2048)}).Rule != "s" || mo.Match(MatchInput{UA: over}).Rule != "b" {
		t.Fatal("raw over cap, stripped under: skip misses")
	}
}

func TestQuantifierBoundsAboveRE2CapAreDropped(t *testing.T) {
	a := strings.Repeat("a", 1500)
	for _, c := range []struct {
		pat, in string
		want    bool
	}{
		{`^a{1,5000}$`, "a", true},
		{`^a{0,99999999999999999999}$`, "", true},
		{`^a{1,02048}$`, a, true},
		{`^a{1,5000}$`, "", false},
		{`^a{2,5000}$`, "a", false},
		{`^a{3}$`, "aaa", true},
		{`^a{,5000}$`, "a{,5000}", true}, // not a quantifier in JS: literal
		{`^[a{1,5000}]+$`, "5", true},    // inside a class: untouched
		{`^a{1000,5000}$`, strings.Repeat("a", 1000), true},
		{`^a\{1,5000\}$`, "a{1,5000}", true},
	} {
		rx := CompileRegex(c.pat)
		if rx == nil || rx.MatchString(c.in) != c.want {
			t.Errorf("%s on len %d: want %v (rx nil: %v)", c.pat, len(c.in), c.want, rx == nil)
		}
	}
	// no exact RE2 spelling: rejected, the rule fails open
	for _, pat := range []string{`^a{1,1500}$`, `^a{1500}$`, `^a{1500,}$`, `^a{1500,5000}$`, `^a{1,2047}$`, `^a{1001,5000}$`} {
		if CompileRegex(pat) != nil {
			t.Errorf("%s compiled", pat)
		}
	}
}

func TestQuantifiedAssertionFailsOpenAsJSThrows(t *testing.T) {
	for _, pat := range []string{`^*`, `^+`, `^?`, `^{1,5}`, `^{1,5000}`, `a$*`, `\b+`, `\B{2}`, `x\b?`} {
		if CompileRegex(pat) != nil {
			t.Errorf("%s compiled", pat)
		}
	}
	for _, c := range []struct{ pat, in string }{
		{`^{,5}`, "{,5}"}, // not a quantifier in JS: literal
		{`^[$*]+$`, "$*"}, // inside a class
		{`^a\$*$`, "a$$"}, // escaped $ is a literal
		{`(^)*a`, "a"},    // a group is quantifiable
		{`\ba+\b`, "aa"},
	} {
		if rx := CompileRegex(c.pat); rx == nil || !rx.MatchString(c.in) {
			t.Errorf("%s on %q: want match", c.pat, c.in)
		}
	}
}

func TestLeadingZeroCountReadsAsJS(t *testing.T) {
	for _, c := range []struct {
		pat, in string
		want    bool
	}{
		{`^a{02}$`, "aa", true}, {`^a{02}$`, "a{02}", false},
		{`^a{0,03}$`, "aaa", true},
		{`^a{00}b$`, "b", true},
		{`^a{02,}$`, "aaa", true},
		{`^[{02}]+$`, "{02}", true},
		{`^a\{02}$`, "a{02}", true},
	} {
		re := CompileRegex(c.pat)
		if re == nil {
			t.Fatalf("%s: did not compile", c.pat)
		}
		if got := re.MatchString(c.in); got != c.want {
			t.Errorf("%s on %q = %v, want %v", c.pat, c.in, got, c.want)
		}
	}
	for _, p := range []string{`a{01001}`, `a{0,01001}`} {
		if CompileRegex(p) != nil {
			t.Errorf("%s compiled, want nil", p)
		}
	}
}

func metaRegexMatcher(t *testing.T, pats ...string) *Matcher {
	t.Helper()
	snap, err := ParseSnapshot(container(0x424C4B35, nil), &Meta{Version: "v", PathsRegex: pats})
	if err != nil {
		t.Fatal(err)
	}
	return NewMatcher(snap)
}

func TestMetaPathsRegexIsCaseInsensitive(t *testing.T) {
	m := metaRegexMatcher(t, "^/DUMP$")
	if m.Match(MatchInput{Path: "/dump"}).Reason != "path" {
		t.Fatal("/dump not blocked")
	}
	if m.Match(MatchInput{Path: "/dumpx"}).Block {
		t.Fatal("/dumpx blocked")
	}
}

func TestMetaPathsRegexRefusedPatternNeverMatches(t *testing.T) {
	m := metaRegexMatcher(t, "^/a(?=b)")
	for _, p := range []string{"/ab", "/a"} {
		if m.Match(MatchInput{Path: p}).Block {
			t.Fatalf("%s blocked by a refused pattern", p)
		}
	}
}

func TestMetaPathsRegexOverCapPathAnswersDeny(t *testing.T) {
	m := metaRegexMatcher(t, "^/never$")
	if m.Match(MatchInput{Path: "/" + strings.Repeat("a", MaxMatchInput)}).Reason != "path" {
		t.Fatal("over-cap path not blocked")
	}
	if m.Match(MatchInput{Path: "/" + strings.Repeat("a", MaxMatchInput-1)}).Block {
		t.Fatal("at-cap path blocked")
	}
}

// camada-all-07c7: JS (non-u) reads a [ inside a class as text; RE2 reads [:alpha:] there as a POSIX class.
func TestJSClassBracketIsLiteral(t *testing.T) {
	if got, _ := jsToRE2(`x[[:alpha:]]y`); got != `x[\[:alpha:]]y` {
		t.Fatalf("jsToRE2 = %q", got)
	}
}

// camada-all-hgsn: V8 (Annex B) reads \8 and \9 in a class as the literal digits; Go rejects the escape.
func TestJSToRE2ClassEightNine(t *testing.T) {
	for _, c := range []struct {
		pat  string
		in   string
		want bool
	}{
		{`x[\8]y`, "x8y", true}, {`x[\9]y`, "x9y", true}, {`x[\8]y`, "x9y", false},
		{`x[^\8]y`, "x8y", false}, {`x[\8-\9]y`, "x9y", true}, {`x[a\8]y`, "x\\y", false},
	} {
		rx := CompileRegex(c.pat)
		if rx == nil || rx.MatchString(c.in) != c.want {
			t.Errorf("%q on %q: rx=%v, want match=%v", c.pat, c.in, rx, c.want)
		}
	}
}

// camada-all-pcht: a multi-byte character is one class atom (JS reads a code unit, Go a byte), so a range
// ending in one cannot start another; a 4-byte character is a surrogate pair, whose low half is a fresh atom.
func TestJSToRE2ClassMultiByteAtoms(t *testing.T) {
	for _, p := range []string{`x[a-é-\d]y`, `x[a-ж-\w]y`, `x[a-€-\d]y`, `x[é-ж-\d]y`} {
		if got, ok := jsToRE2(p); !ok || got != p {
			t.Errorf("%q: got (%q, %v), want unchanged and ok", p, got, ok)
		}
	}
	for _, p := range []string{`x[a-😀-\d]y`, `[é-\d]`, `[\s-é]`} {
		if _, ok := jsToRE2(p); ok {
			t.Errorf("%q: jsToRE2 ok, want refused", p)
		}
	}
}

// camada-all-z3l0: V8 (Annex B) reads \4xx-\7xx as a two-digit octal escape then a literal digit;
// Go would read three digits (U+0100+). Checked over every BMP code unit.
func TestJsToRE2OctalEscapeThreeDigits(t *testing.T) {
	cases := []struct {
		pat  string
		full string        // the one string outside the one-code-unit sweep that must match
		in   map[rune]bool // code units c for which "x"+c+"y" must match
	}{
		{`x\400y`, "x 0y", nil},
		{`x\777y`, "x?7y", nil},
		{`x[\400]y`, "", map[rune]bool{' ': true, '0': true}},
		{`x[\777]y`, "", map[rune]bool{'?': true, '7': true}},
		// camada-all-fugt: in a class \1..\7 is a legacy octal escape (Go: a backreference), and a bare \c is a backslash then c
		{`x[\1]y`, "", map[rune]bool{1: true}},
		{`x[\1-\3]y`, "", map[rune]bool{1: true, 2: true, 3: true}},
		{`x[\12]y`, "", map[rune]bool{'\n': true}},
		{`x[\c-]y`, "", map[rune]bool{'-': true, '\\': true, 'c': true}},
		{`x[\c-z]y`, "", func() map[rune]bool {
			m := map[rune]bool{'\\': true}
			for c := 'c'; c <= 'z'; c++ {
				m[c] = true
			}
			return m
		}()},
	}
	for _, tc := range cases {
		rx := CompileRegex(tc.pat)
		if rx == nil {
			t.Fatalf("%q: did not compile", tc.pat)
		}
		if tc.full != "" && !rx.MatchString(tc.full) {
			t.Errorf("%q: want match on %q", tc.pat, tc.full)
		}
		for c := rune(0); c <= 0xFFFF; c++ {
			if c >= 0xD800 && c <= 0xDFFF {
				continue
			}
			if got := rx.MatchString("x" + string(c) + "y"); got != tc.in[c] {
				t.Fatalf("%q on U+%04X: got %v, want %v", tc.pat, c, got, tc.in[c])
			}
		}
	}
}

// camada-all-pao7, camada-all-rmn4: [\c_] [\c0] and a legacy octal escape are one class atom, so a - after them
// is a literal and the pattern translates (V8 ground truth from node).
func TestJsToRE2ClassControlAndOctalAtoms(t *testing.T) {
	cases := []struct {
		pat string
		in  map[string]bool
	}{
		{`x[\c_-a-\d]y`, map[string]bool{"x-y": true, "x5y": true, "x\x1fy": true, "xay": true, "x y": true}},
		{`[\c0]`, map[string]bool{"\x10": true, "0": false, "\\": false, "c": false}},
		{`x[\0-\12-\d]y`, map[string]bool{"x\ny": true, "x-y": true, "x5y": true, "x\x05y": true, "xay": false}},
		{`x[\0-\47-\d]y`, map[string]bool{"x'y": true, "x-y": true, "x5y": true, "x\x00y": true, "x(y": false}},
		{`x[\477]y`, map[string]bool{"x7y": true, "x'y": true, "x\u013fy": false}},
		{`\400`, map[string]bool{" 0": true, "\u0100": false}},
		{`[\7]`, map[string]bool{"\x07": true, "7": false}}, // camada-all-fugt
		{`[\c]`, map[string]bool{"\\": true, "c": true, "\x03": false}},
		{`x\c_y`, map[string]bool{`x\c_y`: true, "x\x1fy": false}},
		{`x\c`, map[string]bool{`x\c`: true, "x": false}},
	}
	for _, tc := range cases {
		rx := CompileRegex(tc.pat)
		if rx == nil {
			t.Fatalf("%q: did not compile", tc.pat)
		}
		for s, want := range tc.in {
			if got := rx.MatchString(s); got != want {
				t.Errorf("%q on %q: got %v, want %v", tc.pat, s, got, want)
			}
		}
	}
}

// camada-all-fugt: outside a class \1 may be a real backreference; Go refuses it, so the rule fails open as before.
func TestJsToRE2BackreferenceOutsideClass(t *testing.T) {
	if CompileRegex(`(a)\1`) != nil {
		t.Error(`(a)\1: compiled, want nil`)
	}
}
