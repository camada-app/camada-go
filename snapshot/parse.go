// Package snapshot is the BLK snapshot parser (v3, v4, v5) and matcher, ported from @camada/core
// src/snapshot/parse.ts and match.ts, themselves ports of edge-analyst src/blocklist.js (the
// reference implementation).
//
// Container: sectioned little-endian uint32 —
//
//	[0] magic 0x424c4b3<version>   [1] section count K
//	K x [type, offset(words), length(words)]   then the sections.
//
// Types: 1 V4_STARTS  2 V4_ENDS  3 V4_IDX16  4 V4_BM24  5 V6_STARTS  6 V6_ENDS  7 V6_BM24
// 8 ASN_BM  9 ASN_EXTRA.
// v4 (contracts §A3) adds two side lists as INTERLEAVED range pairs:
// 10 ALLOW_V4  11 ALLOW_V6  12 CHALLENGE_V4  13 CHALLENGE_V6 —
// *_V4: [start, end, …] (2 words per range, sorted by start);
// *_V6: [s0,s1,s2,s3, e0,e1,e2,e3, …] (8 words per range, big-endian word order, sorted by start).
// v5 (contracts §D3) adds the tenant's ordered custom rules, which run BEFORE the three sides:
// 14 RULE_V4  15 RULE_V6 — repeated, word 0 = the rule's index into meta.rules, then range pairs
// exactly as 10/11. One 14 + one 15 per `ip` condition, in condition order (an empty half still
// ships its index word), so a rule with two ip conditions reads two pairs.
// Meta travels separately: { version, country[], tls[], pathsExact[], pathsPrefix[], pathsRegex[],
// allow?: side, challenge?: side, rules?: [] } with side = { asn[], country[], pathsExact[], pathsPrefix[] }.
// The version byte is advisory: sections 10-15 are read whenever they are present.
//
// The body is copied into a []uint32 once per poll with encoding/binary's little-endian reader,
// so the parsed snapshot never aliases a transport buffer and a big-endian host reads it right.
package snapshot

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/camada-app/camada-go/internal/ipparse"
)

// Bits is a uint32 word view of one container section.
type Bits []uint32

// Words is an IPv6 address as four big-endian uint32 words.
type Words = ipparse.Words

var formats = map[uint32]int{0x424C4B33: 3, 0x424C4B34: 4, 0x424C4B35: 5}

var actions = map[string]bool{"skip": true, "block": true, "challenge": true, "warn": true}

// Meta is the JSON the snapshot frame carries beside the container.
type Meta struct {
	Version     string   `json:"version"`
	Country     []string `json:"country"`
	TLS         []string `json:"tls"`
	PathsExact  []string `json:"pathsExact"`
	PathsPrefix []string `json:"pathsPrefix"`
	PathsRegex  []string `json:"pathsRegex"`
	Allow       *Side    `json:"allow"`
	Challenge   *Side    `json:"challenge"`
	Rules       []Rule   `json:"rules"`
}

// Side is a v4 side list's meta half (§A3: no tls key).
type Side struct {
	ASN         []any    `json:"asn"`
	Country     []string `json:"country"`
	PathsExact  []string `json:"pathsExact"`
	PathsPrefix []string `json:"pathsPrefix"`
}

// Rule is one ordered custom rule (§D3): enabled and request-enforceable only.
type Rule struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Conds  []Cond `json:"conds"`
}

// Cond is one condition: { f, op, v } | { f: "header", op, name, v } | { f: "ip", op, set: true }.
// V is a string, a number, or a list of either.
type Cond struct {
	F    string `json:"f"`
	Op   string `json:"op"`
	Name string `json:"name"`
	V    any    `json:"v"`
	Set  bool   `json:"set"`
}

// DecodeMeta reads the meta JSON; numbers stay exact (json.Number) so an ASN never reads as a float.
func DecodeMeta(b []byte) (*Meta, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	var m Meta
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// RangeSet is a v4 side list. Empty short-circuits the matcher on the (common) v3 snapshot.
type RangeSet struct {
	R4          Bits // interleaved [start, end]
	R6          Bits // interleaved [4-word start, 4-word end]
	N6          int  // range count in R6
	ASN         map[int64]struct{}
	Country     map[string]struct{}
	PathsExact  map[string]struct{}
	PathsPrefix map[string]struct{}
	Empty       bool
}

// RuleRequest is the request a compiled condition reads. HasIP4/HasIP6 say which address parsed.
type RuleRequest struct {
	N4      uint32
	HasIP4  bool
	IP6     Words
	HasIP6  bool
	ASN     int
	Country string
	TLSX    string
	Path    string // already query-stripped
	UA      string
	Header  func(name string) (string, bool) // called with an already lower-cased name; nil where the tap cannot read headers
}

// RuleCond is one compiled condition.
type RuleCond func(r *RuleRequest) bool

// CompiledRule is one rule ready to run: every condition must hold.
type CompiledRule struct {
	ID     string
	Action string
	Conds  []RuleCond
}

// Snapshot is a parsed container plus its meta.
type Snapshot struct {
	Version     string
	Format      int // what the container's version byte claimed
	S4, E4      Bits
	Idx4, Bm4   Bits
	S6, E6      Bits
	N6          int
	Bm6         Bits
	ASNBm       Bits
	ASNExtra    Bits
	Country     map[string]struct{}
	TLS         map[string]struct{}
	PathsExact  map[string]struct{}
	PathsPrefix map[string]struct{}
	PathsRegex  []*regexp.Regexp
	Allow       RangeSet
	Challenge   RangeSet
	Rules       []CompiledRule // v5 only; empty on v3/v4, and the matcher then skips them
}

func set(xs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		out[x] = struct{}{}
	}
	return out
}

func asInt(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case float64:
		return int64(x), true
	case int:
		return int64(x), true
	case int64:
		return x, true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		return n, err == nil
	}
	return 0, false
}

func rangeSet(r4, r6 Bits, m *Side) RangeSet {
	if m == nil {
		m = &Side{}
	}
	asn := make(map[int64]struct{}, len(m.ASN))
	for _, a := range m.ASN {
		if n, ok := asInt(a); ok {
			asn[n] = struct{}{}
		}
	}
	exact, prefix, country := set(m.PathsExact), set(m.PathsPrefix), set(m.Country)
	empty := len(r4) == 0 && len(r6) == 0 && len(asn) == 0 && len(country) == 0 && len(exact) == 0 && len(prefix) == 0
	return RangeSet{R4: r4, R6: r6, N6: len(r6) >> 3, ASN: asn, Country: country, PathsExact: exact, PathsPrefix: prefix, Empty: empty}
}

// InRange4 is a binary search over interleaved [start, end] uint32 pairs sorted by start.
func InRange4(r Bits, n uint32) bool {
	lo, hi := 0, (len(r)>>1)-1
	if hi < 0 {
		return false
	}
	for lo < hi {
		m := (lo + hi + 1) >> 1
		if r[m*2] <= n {
			lo = m
		} else {
			hi = m - 1
		}
	}
	return r[lo*2] <= n && n <= r[lo*2+1]
}

// cmpWords compares the 4 words at a[o..o+3] against the address words.
func cmpWords(a Bits, o int, w Words) int {
	for k := 0; k < 4; k++ {
		x, y := a[o+k], w[k]
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// InRange6 is a binary search over an interleaved [4-word start, 4-word end] side section of n ranges.
func InRange6(r Bits, n int, w Words) bool {
	if n < 1 {
		return false
	}
	lo, hi := 0, n-1
	for lo < hi {
		m := (lo + hi + 1) >> 1
		if cmpWords(r, m*8, w) <= 0 {
			lo = m
		} else {
			hi = m - 1
		}
	}
	o := lo * 8
	return cmpWords(r, o, w) <= 0 && cmpWords(r, o+4, w) >= 0
}

// CompileRegex compiles a JS-authored pattern under RE2; a pattern RE2 rejects (lookaround,
// backreferences) is nil and never matches — fail open, never throw. The JS spellings RE2 refuses
// are translated first (jsToRE2); \d \w \b are ASCII in RE2 as JS reads them, and (?<name> is native.
func CompileRegex(pattern string) *regexp.Regexp {
	rx, err := regexp.Compile(jsToRE2(pattern))
	if err != nil {
		return nil
	}
	return rx
}

// jsToRE2 translates the JS-only spellings a tenant is likely to author: `[^]` (any char) ->
// `[\s\S]`, `\cX` -> the control character, `\uXXXX` -> `\x{XXXX}` (RE2's code-point escape;
// Python's re reads `\uXXXX` natively, so the family agrees). Anything else RE2 rejects still fails open.
func jsToRE2(pattern string) string {
	var out strings.Builder
	n, inClass := len(pattern), false
	for i := 0; i < n; {
		ch := pattern[i]
		if ch == '\\' && i+1 < n {
			nxt := pattern[i+1]
			if nxt == 'c' && i+2 < n && isASCIILetter(pattern[i+2]) {
				out.WriteString(regexp.QuoteMeta(string(rune(pattern[i+2]&^0x20) - 64)))
				i += 3
				continue
			}
			if nxt == 'u' && i+5 < n && isHex4(pattern[i+2:i+6]) {
				out.WriteString(`\x{` + pattern[i+2:i+6] + `}`)
				i += 6
				continue
			}
			out.WriteString(pattern[i : i+2])
			i += 2
			continue
		}
		if inClass {
			inClass = ch != ']'
		} else if ch == '[' {
			if strings.HasPrefix(pattern[i:], "[^]") {
				out.WriteString(`[\s\S]`)
				i += 3
				continue
			}
			inClass = true
		}
		out.WriteByte(ch)
		i++
	}
	return out.String()
}

func isASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isHex4(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// ---------- custom rules (v5) ----------

// fieldValue is the string one condition reads, or absent when this request cannot answer the
// field. `header` is not here: it needs the condition's own name, so compileCond builds its reader.
func fieldValue(f string, r *RuleRequest) (string, bool) {
	switch f {
	case "asn":
		if r.ASN == 0 {
			return "", false
		}
		return strconv.Itoa(r.ASN), true
	case "country":
		return r.Country, r.Country != ""
	case "tlsx":
		return r.TLSX, r.TLSX != ""
	case "path":
		return r.Path, true
	case "ua":
		return r.UA, r.UA != ""
	}
	return "", false // an entity-plane field (bot.verified, rule): never true here
}

func stringValues(raw any) []string {
	one := func(x any) string {
		switch v := x.(type) {
		case string:
			return v
		case json.Number:
			return v.String()
		case nil:
			return ""
		default:
			return fmt.Sprint(v)
		}
	}
	if list, ok := raw.([]any); ok {
		out := make([]string, len(list))
		for i, x := range list {
			out[i] = one(x)
		}
		return out
	}
	return []string{one(raw)}
}

// safeHeader reads the request through the caller's getter. A tap that cannot read headers (no
// getter) and a header the request does not carry are both absent, and absent is false for every
// op — the rule simply does not fire (fail open, §A4). The getter is app code: one that panics is
// read as "no header" rather than allowed to take the whole match() down.
func safeHeader(r *RuleRequest, name string) (v string, ok bool) {
	if name == "" || r.Header == nil {
		return "", false
	}
	defer func() {
		if recover() != nil {
			v, ok = "", false
		}
	}()
	return r.Header(name)
}

// compileCond turns one condition into a predicate. `sets` yields this rule's (v4, v6) section
// pair per ip condition, in condition order, so an ip condition consumes the next one.
func compileCond(c Cond, sets *[][2]Bits) RuleCond {
	f, op := c.F, c.Op
	negate := op == "is_not" || op == "not_in"
	var read func(r *RuleRequest) (string, bool)
	if f == "header" {
		hname := strings.ToLower(c.Name)
		read = func(r *RuleRequest) (string, bool) { return safeHeader(r, hname) }
	} else {
		read = func(r *RuleRequest) (string, bool) { return fieldValue(f, r) }
	}
	if f == "ip" {
		var p4, p6 Bits
		if len(*sets) > 0 {
			p4, p6 = (*sets)[0][0], (*sets)[0][1]
			*sets = (*sets)[1:]
		}
		n6 := len(p6) >> 3
		return func(r *RuleRequest) bool {
			if !r.HasIP4 && !r.HasIP6 {
				return false // no address: false for every op, negatives included
			}
			hit := (r.HasIP4 && InRange4(p4, r.N4)) || (r.HasIP6 && InRange6(p6, n6, r.IP6))
			return hit != negate
		}
	}
	values := stringValues(c.V)
	switch op {
	case "matches":
		rx := CompileRegex(values[0])
		return func(r *RuleRequest) bool {
			v, ok := read(r)
			return ok && rx != nil && rx.MatchString(v)
		}
	case "contains":
		needle := values[0]
		return func(r *RuleRequest) bool {
			v, ok := read(r)
			return ok && strings.Contains(v, needle)
		}
	case "starts_with":
		prefix := values[0]
		return func(r *RuleRequest) bool {
			v, ok := read(r)
			return ok && strings.HasPrefix(v, prefix)
		}
	}
	members := set(values) // is | is_not | is_in | not_in
	return func(r *RuleRequest) bool {
		v, ok := read(r)
		if !ok {
			return false
		}
		_, in := members[v]
		return in != negate
	}
}

// compileRules turns meta.rules + the repeated 14/15 sections into predicates, in evaluation
// order. A rule this SDK cannot compile (unknown action, no conditions) is dropped rather than guessed at.
func compileRules(meta *Meta, v4s, v6s []Bits) []CompiledRule {
	var out []CompiledRule
	for i, r := range meta.Rules {
		if !actions[r.Action] {
			continue // an action this SDK does not know: ignore the rule rather than guess
		}
		if len(r.Conds) == 0 {
			continue // a rule with no conditions would match everything
		}
		var v4, v6 []Bits
		for _, s := range v4s {
			if int(s[0]) == i {
				v4 = append(v4, s[1:])
			}
		}
		for _, s := range v6s {
			if int(s[0]) == i {
				v6 = append(v6, s[1:])
			}
		}
		sets := make([][2]Bits, max(len(v4), len(v6)))
		for k := range sets {
			if k < len(v4) {
				sets[k][0] = v4[k]
			}
			if k < len(v6) {
				sets[k][1] = v6[k]
			}
		}
		conds := make([]RuleCond, 0, len(r.Conds))
		for _, c := range r.Conds {
			conds = append(conds, compileCond(c, &sets))
		}
		out = append(out, CompiledRule{ID: r.ID, Action: r.Action, Conds: conds})
	}
	return out
}

func words(raw []byte) Bits {
	usable := len(raw) - len(raw)%4 // a trailing partial word is dropped, as the Uint32Array view does
	u := make(Bits, usable/4)
	for i := range u {
		u[i] = binary.LittleEndian.Uint32(raw[i*4:])
	}
	return u
}

// fixed is a section whose size the format fixes (idx4 65537, bm4/bm6 524288, asn_bm 131072
// words): zero-filled when absent, refused when shorter — the matcher indexes it blindly.
func fixed(s Bits, n int) (Bits, error) {
	if len(s) == 0 {
		return make(Bits, n), nil
	}
	if len(s) < n {
		return nil, errors.New("camada: short BLK3 section")
	}
	return s, nil
}

// ParseSnapshot parses a BLK container + meta into a Snapshot. It errors on a malformed
// container — callers keep the previous snapshot, exactly like the edge collector does.
func ParseSnapshot(raw []byte, meta *Meta) (*Snapshot, error) {
	if meta == nil {
		meta = &Meta{}
	}
	u := words(raw)
	if len(u) < 2 {
		return nil, errors.New("camada: not a BLK3 snapshot")
	}
	format, ok := formats[u[0]]
	if !ok {
		return nil, errors.New("camada: not a BLK3 snapshot")
	}
	count := int(u[1])
	if count < 0 || len(u) < 2+count*3 {
		return nil, errors.New("camada: truncated BLK3 header")
	}
	sec := map[uint32]Bits{}
	var rule4, rule6 []Bits
	for i := 0; i < count; i++ {
		t, off, ln := u[2+i*3], int(u[3+i*3]), int(u[4+i*3])
		if off < 0 || ln < 0 || off+ln > len(u) {
			return nil, errors.New("camada: truncated BLK3 section")
		}
		s := u[off : off+ln]
		switch t {
		case 14:
			if ln > 0 {
				rule4 = append(rule4, s) // repeated, one per ip condition: kept in container order
			}
		case 15:
			if ln > 0 {
				rule6 = append(rule6, s)
			}
		default:
			sec[t] = s
		}
	}
	var regexes []*regexp.Regexp
	for _, p := range meta.PathsRegex {
		if rx := CompileRegex(p); rx != nil {
			regexes = append(regexes, rx)
		}
	}
	idx4, err := fixed(sec[3], 65537)
	if err != nil {
		return nil, err
	}
	bm4, err := fixed(sec[4], 524288)
	if err != nil {
		return nil, err
	}
	bm6, err := fixed(sec[7], 524288)
	if err != nil {
		return nil, err
	}
	asnBm, err := fixed(sec[8], 131072)
	if err != nil {
		return nil, err
	}
	s6 := sec[5]
	return &Snapshot{
		Version: meta.Version,
		Format:  format,
		S4:      sec[1], E4: sec[2], Idx4: idx4, Bm4: bm4,
		S6: s6, E6: sec[6], N6: len(s6) / 4, Bm6: bm6,
		ASNBm: asnBm, ASNExtra: sec[9],
		Country:     set(meta.Country),
		TLS:         set(meta.TLS),
		PathsExact:  set(meta.PathsExact),
		PathsPrefix: set(meta.PathsPrefix),
		PathsRegex:  regexes,
		Allow:       rangeSet(sec[10], sec[11], meta.Allow),
		Challenge:   rangeSet(sec[12], sec[13], meta.Challenge),
		Rules:       compileRules(meta, rule4, rule6),
	}, nil
}
