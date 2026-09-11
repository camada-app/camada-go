package snapshot

// Container handling the golden cases do not reach: malformed input, the advisory version byte,
// and the rule-compilation rules (drop, never guess).

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/camada/camada-go/internal/testutil"
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

func TestJSRegexSpellingsAreTranslated(t *testing.T) {
	m := rulesSnapshot(t, []Rule{{ID: "ver", Action: "block", Conds: []Cond{{F: "path", Op: "matches", V: `^/api/(?<ver>v\d+)/`}}}}, nil)
	if m.Match(MatchInput{Path: "/api/v2/dump"}).Rule != "ver" {
		t.Fatal("named group")
	}
	if m.Match(MatchInput{Path: "/api/v٣/dump"}).Rule != "" { // \d is ASCII, as JS reads it
		t.Fatal("\\d matched a non-ASCII digit")
	}
	m2 := rulesSnapshot(t, []Rule{{ID: "any", Action: "block", Conds: []Cond{{F: "ua", Op: "matches", V: `^a[^]b\cJ$`}}}}, nil)
	if m2.Match(MatchInput{UA: "a\nb\n"}).Rule != "any" {
		t.Fatal("[^] and \\cJ")
	}
	if m2.Match(MatchInput{UA: "ab"}).Rule != "" {
		t.Fatal("matched without the any-char")
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
