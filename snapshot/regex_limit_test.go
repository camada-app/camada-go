package snapshot

// Contract regex-limit v1 (camada-all-2pap): the shared vectors in camada-core. Go's regexp is
// linear, so every over-limit row answers hit[linear] and no source change is needed here. A
// failure means the port drifted from the contract — fix the port, never the vectors.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/camada-app/camada-go/internal/testutil"
)

const regexLimitVectorsSHA256 = "26a8c7bdac744186870cc41ed37f2a9c1673320d84bad403c2b1ee95fba92619"

const regexLimitVectors = "regex-limit/regex-limit-vectors.json"

// rlValue is an input value: a string, or {prefix?, repeat, times, suffix?}.
type rlValue struct {
	s string
}

func (v *rlValue) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		return json.Unmarshal(b, &v.s)
	}
	var o struct {
		Prefix string `json:"prefix"`
		Repeat string `json:"repeat"`
		Times  int    `json:"times"`
		Suffix string `json:"suffix"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	v.s = o.Prefix + strings.Repeat(o.Repeat, o.Times) + o.Suffix
	return nil
}

type rlInput struct {
	IP   string  `json:"ip"`
	UA   rlValue `json:"ua"`
	Path rlValue `json:"path"`
}

type rlRow struct {
	ID      string  `json:"id"`
	Rule    Rule    `json:"rule"`
	Input   rlInput `json:"input"`
	MaxMS   int     `json:"max_ms"`
	Pattern string  `json:"pattern"`
	Cases   []struct {
		UA  rlValue         `json:"ua"`
		Hit map[string]bool `json:"hit"`
	} `json:"cases"`
}

type rlVectors struct {
	Constants struct {
		MaxMatchInput int `json:"MAX_MATCH_INPUT"`
	} `json:"constants"`
	OverLimit []struct {
		rlRow
		Hit map[string]bool `json:"hit"`
	} `json:"over_limit"`
	LinearTime []struct {
		rlRow
		Hit bool `json:"hit"`
	} `json:"linear_time"`
	Refused     []rlRow `json:"refused"`
	RefusedRule struct {
		ID     string `json:"id"`
		Action string `json:"action"`
		Field  string `json:"field"`
	} `json:"refused_rule"`
}

func loadRegexLimit(t *testing.T) rlVectors {
	t.Helper()
	raw := testutil.ReadBin(t, regexLimitVectors)
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != regexLimitVectorsSHA256 {
		t.Fatalf("regex-limit vectors drifted: sha256 %x want %s", sum, regexLimitVectorsSHA256)
	}
	var v rlVectors
	testutil.ReadJSON(t, regexLimitVectors, &v)
	return v
}

// ruleMatcher builds the rule into a v5 snapshot (blk5/v5-empty) and returns the public matcher.
func ruleMatcher(t *testing.T, rule Rule) *Matcher {
	t.Helper()
	meta, err := DecodeMeta(testutil.ReadBin(t, "blk5/v5-empty.meta.json"))
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	meta.Rules = []Rule{rule}
	snap, err := ParseSnapshot(testutil.ReadBin(t, "blk5/v5-empty.bin"), meta)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return NewMatcher(snap)
}

func (i rlInput) match(m *Matcher) MatchResult {
	return m.Match(MatchInput{IP: i.IP, Path: i.Path.s, UA: i.UA.s})
}

func TestRegexLimitVectors(t *testing.T) {
	v := loadRegexLimit(t)

	t.Run("constants", func(t *testing.T) {
		if v.Constants.MaxMatchInput != MaxMatchInput {
			t.Fatalf("MAX_MATCH_INPUT %d want %d", v.Constants.MaxMatchInput, MaxMatchInput)
		}
	})

	t.Run("over_limit", func(t *testing.T) {
		for _, r := range v.OverLimit {
			if got := r.Input.match(ruleMatcher(t, r.Rule)).Rule == r.Rule.ID; got != r.Hit["linear"] {
				t.Errorf("%s: hit %v want %v", r.ID, got, r.Hit["linear"])
			}
		}
	})

	t.Run("linear_time", func(t *testing.T) {
		for _, r := range v.LinearTime {
			best := time.Duration(1<<63 - 1)
			var got bool
			for n := 0; n < 3; n++ {
				start := time.Now()
				m := ruleMatcher(t, r.Rule)
				got = r.Input.match(m).Rule == r.Rule.ID
				if d := time.Since(start); d < best {
					best = d
				}
			}
			if got != r.Hit {
				t.Errorf("%s: hit %v want %v", r.ID, got, r.Hit)
			}
			if limit := time.Duration(r.MaxMS) * time.Millisecond; best >= limit {
				t.Errorf("%s: compile+match %v, want under %v", r.ID, best, limit)
			}
		}
	})

	t.Run("refused", func(t *testing.T) {
		for _, r := range v.Refused {
			rule := Rule{ID: v.RefusedRule.ID, Action: v.RefusedRule.Action,
				Conds: []Cond{{F: v.RefusedRule.Field, Op: "matches", V: r.Pattern}}}
			m := ruleMatcher(t, rule) // an uncompilable pattern must not fail the parse
			for _, c := range r.Cases {
				in := rlInput{IP: "8.8.8.8", UA: c.UA}
				if got := in.match(m).Rule == rule.ID; got != c.Hit["go"] {
					t.Errorf("%s %.40q: hit %v want %v", r.ID, c.UA.s, got, c.Hit["go"])
				}
			}
		}
	})
}
