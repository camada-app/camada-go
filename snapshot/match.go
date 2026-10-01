package snapshot

// Matcher: sub-millisecond checks over a parsed Snapshot, ported from @camada/core
// src/snapshot/match.ts (itself from edge-analyst src/blocklist.js). Matching is fully
// synchronous and allocation-light. The original's per-instance scratch request is not ported:
// a JS isolate runs one match() at a time, but here one Matcher serves every request goroutine,
// so the rule loop reads a RuleRequest built per call.
//
// Outcome order is contract (contracts §D3, fixtures pin it): the tenant's ordered custom rules
// first (first match wins, the order IS the precedence), then allow -> block -> challenge.
// Within each side the axis order is ip4 -> ip6 -> asn -> country -> tls -> path.
// At the SDK position only ip, path, ua and the request headers are usually known;
// asn/country/tlsx entries and conditions then simply never match — that is the documented,
// honest enforcement scope (fail open, never guess).

import (
	"strings"

	"github.com/camada-app/camada-go/internal/ipparse"
)

// MatchInput is one request as the tap sees it. ASN 0 means unknown (AS0 is reserved).
type MatchInput struct {
	IP      string
	ASN     int
	Country string
	TLSX    string
	Path    string
	UA      string                           // v5 rules read it; the three sides never do
	Header  func(name string) (string, bool) // v5 header conditions read it, always with a lower-cased name
}

// MatchResult is the verdict. At most one of Allowed/Block/Challenge/Warn is true.
type MatchResult struct {
	Block     bool
	Challenge bool
	Allowed   bool // true for skip (which absorbed the old allow) and for the allow side
	Warn      bool
	Action    string // the action of the rule that decided, "" when a side did
	Rule      string // the rule id, present only when reason is "rule"
	Reason    string // ip4 | ip6 | asn | country | tls | path | rule | cold | ""
	Version   string
}

// CleanPath strips the query (and any fragment) from a path.
func CleanPath(raw string) string { return stripQuery(raw) }

// ruleResult: a rule decided this request (§D3): at most one of allowed / block / challenge /
// warn is true, Reason is "rule", and Rule names the id the adapters stamp on the event.
func ruleResult(rule *CompiledRule, version string) MatchResult {
	a := rule.Action
	return MatchResult{
		Block: a == "block", Challenge: a == "challenge", Allowed: a == "skip", Warn: a == "warn",
		Action: a, Rule: rule.ID, Reason: "rule", Version: version,
	}
}

// Matcher answers Match over one parsed Snapshot; safe for concurrent use.
type Matcher struct {
	Snap *Snapshot
}

// NewMatcher wraps a parsed snapshot.
func NewMatcher(snap *Snapshot) *Matcher { return &Matcher{Snap: snap} }

func (m *Matcher) blocked4(n uint32) bool {
	s := m.Snap
	b := n >> 8
	if (s.Bm4[b>>5]>>(b&31))&1 == 0 {
		return false
	}
	hi := n >> 16
	left, right := int(s.Idx4[hi]), int(s.Idx4[hi+1])-1
	if left > 0 {
		left--
	}
	if right < left {
		return false
	}
	s4 := s.S4
	for left < right {
		mid := (left + right + 1) >> 1
		if s4[mid] <= n {
			left = mid
		} else {
			right = mid - 1
		}
	}
	return s4[left] <= n && n <= s.E4[left]
}

func (m *Matcher) blocked6(w Words) bool {
	s := m.Snap
	b := w[0] >> 8
	if (s.Bm6[b>>5]>>(b&31))&1 == 0 {
		return false
	}
	left, right := 0, s.N6-1
	if right < 0 {
		return false
	}
	for left < right {
		mid := (left + right + 1) >> 1
		if cmpWords(s.S6, mid*4, w) <= 0 {
			left = mid
		} else {
			right = mid - 1
		}
	}
	o := left * 4
	return cmpWords(s.S6, o, w) <= 0 && cmpWords(s.E6, o, w) >= 0
}

func (m *Matcher) blockedASN(asn int) bool {
	s := m.Snap
	if asn < 4194304 {
		return (s.ASNBm[asn>>5]>>(uint(asn)&31))&1 != 0
	}
	extra := s.ASNExtra
	left, right := 0, len(extra)-1
	for left <= right {
		mid := (left + right) >> 1
		v := int(extra[mid])
		if v == asn {
			return true
		}
		if v < asn {
			left = mid + 1
		} else {
			right = mid - 1
		}
	}
	return false
}

func (m *Matcher) blockedPath(forms *[3]string) bool {
	s := m.Snap
	return pathHit(func(p string) bool { return pathIn(s.PathsExact, s.PathsPrefix, s.PathsRegex, p) }, forms, true)
}

// blockSide is the block side: v3 sections plus the top-level meta.
func (m *Matcher) blockSide(i *MatchInput, forms *[3]string, n4 uint32, has4 bool, w Words, has6 bool) string {
	s := m.Snap
	if has4 && m.blocked4(n4) {
		return "ip4"
	}
	if has6 && m.blocked6(w) {
		return "ip6"
	}
	if i.ASN > 0 && m.blockedASN(i.ASN) {
		return "asn"
	}
	if _, ok := s.Country[i.Country]; ok && i.Country != "" {
		return "country"
	}
	if _, ok := s.TLS[i.TLSX]; ok && i.TLSX != "" {
		return "tls"
	}
	if (len(s.PathsExact) > 0 || len(s.PathsPrefix) > 0 || len(s.PathsRegex) > 0) && m.blockedPath(forms) {
		return "path"
	}
	return ""
}

// side is a v4 side list (allow or challenge). No tls axis: §A3's side meta has no tls key.
// deny is false for the allow side: an exemption needs every canonical spelling of the path.
func side(st *RangeSet, i *MatchInput, forms *[3]string, deny bool, n4 uint32, has4 bool, w Words, has6 bool) string {
	if st.Empty {
		return "" // the common v3 snapshot
	}
	if has4 && InRange4(st.R4, n4) {
		return "ip4"
	}
	if has6 && InRange6(st.R6, st.N6, w) {
		return "ip6"
	}
	if _, ok := st.ASN[int64(i.ASN)]; ok && i.ASN > 0 {
		return "asn"
	}
	if _, ok := st.Country[i.Country]; ok && i.Country != "" {
		return "country"
	}
	if (len(st.PathsExact) > 0 || len(st.PathsPrefix) > 0) &&
		pathHit(func(p string) bool { return pathIn(st.PathsExact, st.PathsPrefix, nil, p) }, forms, deny) {
		return "path"
	}
	return ""
}

// Match decides one request: rules first, then allow -> block -> challenge.
func (m *Matcher) Match(i MatchInput) MatchResult {
	s := m.Snap
	var n4 uint32
	var w Words
	var has4, has6 bool
	if i.IP != "" {
		if !strings.Contains(i.IP, ":") {
			n4, has4 = ParseIP4(i.IP)
		} else {
			w, has6 = ParseIP6(i.IP)
		}
	}
	forms := PathForms(i.Path) // [raw, lit, full]: see path.go
	if len(s.Rules) > 0 {
		r := RuleRequest{N4: n4, HasIP4: has4, IP6: w, HasIP6: has6, ASN: i.ASN, Country: i.Country, TLSX: i.TLSX, Path: forms[0], Paths: forms, UA: i.UA, Header: i.Header}
	rules:
		for k := range s.Rules { // the order IS the precedence (§A4): first match wins
			rule := &s.Rules[k]
			for _, cond := range rule.Conds {
				if !cond(&r) {
					continue rules
				}
			}
			return ruleResult(rule, s.Version)
		}
	}
	if reason := side(&s.Allow, &i, &forms, false, n4, has4, w, has6); reason != "" {
		return MatchResult{Allowed: true, Reason: reason, Version: s.Version}
	}
	if reason := m.blockSide(&i, &forms, n4, has4, w, has6); reason != "" {
		return MatchResult{Block: true, Reason: reason, Version: s.Version}
	}
	if reason := side(&s.Challenge, &i, &forms, true, n4, has4, w, has6); reason != "" {
		return MatchResult{Challenge: true, Reason: reason, Version: s.Version}
	}
	return MatchResult{Version: s.Version}
}

// ParseIP4 and ParseIP6 are the container's own parsers, re-exported for callers that build a RuleRequest.
var (
	ParseIP4 = ipparse.ParseIP4
	ParseIP6 = ipparse.ParseIP6
)
