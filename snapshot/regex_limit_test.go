package snapshot

// Contract regex-limit v1 (camada-all-2pap): the shared vectors in camada-core. Go's regexp is
// linear, so every over-limit row answers hit[linear] and no source change is needed here; the
// translate_refused rows (camada-all-pcht) are the one place jsToRE2 must refuse. A
// failure means the port drifted from the contract — fix the port, never the vectors.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/camada-app/camada-go/internal/testutil"
)

const regexLimitVectorsSHA256 = "95a4a0ceda235f59f7a6224c2b9bb2f6f16445068f07cf7c45a111c6334cd144"

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
	Refused          []rlRow  `json:"refused"`
	AstralSplit      []rlRow  `json:"astral_split"`
	TranslateRefused []string `json:"translate_refused"`
	Accepted         []string `json:"accepted"`
	AcceptedMatch    []rlRow  `json:"accepted_match"`
	RefusedRule      struct {
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
			if got := r.Input.match(rulesSnapshot(t, []Rule{r.Rule}, nil)).Rule == r.Rule.ID; got != r.Hit["linear"] {
				t.Errorf("%s: hit %v want %v", r.ID, got, r.Hit["linear"])
			}
		}
	})

	t.Run("linear_time", func(t *testing.T) {
		for _, r := range v.LinearTime {
			best := time.Duration(1<<63 - 1)
			var got bool
			for n := 0; n < 5; n++ { // best of 5: a gate run on a loaded machine can stall a few tries
				start := time.Now()
				m := rulesSnapshot(t, []Rule{r.Rule}, nil)
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

	for _, s := range []struct {
		name string
		rows []rlRow
	}{{"refused", v.Refused}, {"astral_split", v.AstralSplit}, {"accepted_match", v.AcceptedMatch}} {
		t.Run(s.name, func(t *testing.T) {
			if len(s.rows) == 0 {
				t.Fatalf("%s is empty", s.name)
			}
			for _, r := range s.rows {
				rule := Rule{ID: v.RefusedRule.ID, Action: v.RefusedRule.Action,
					Conds: []Cond{{F: v.RefusedRule.Field, Op: "matches", V: r.Pattern}}}
				m := rulesSnapshot(t, []Rule{rule}, nil) // an uncompilable pattern must not fail the parse
				for _, c := range r.Cases {
					in := rlInput{IP: "8.8.8.8", UA: c.UA}
					want, ok := c.Hit["go"]
					if !ok {
						t.Fatalf("%s %.40q: no hit[go]", r.ID, c.UA.s)
					}
					if got := in.match(m).Rule == rule.ID; got != want {
						t.Errorf("%s %.40q: hit %v want %v", r.ID, c.UA.s, got, want)
					}
				}
			}
		})
	}

	// camada-all-pcht: a - next to \s \d \w in a class is a SyntaxError in the JS copies; here ok=false, so a stored rule never matches.
	t.Run("translate_refused", func(t *testing.T) {
		if len(v.TranslateRefused) == 0 {
			t.Fatal("no translate_refused rows")
		}
		for _, p := range v.TranslateRefused {
			if _, ok := jsToRE2(p); ok {
				t.Errorf("%q: jsToRE2 ok, want refused", p)
			}
			rule := Rule{ID: v.RefusedRule.ID, Action: v.RefusedRule.Action,
				Conds: []Cond{{F: v.RefusedRule.Field, Op: "matches", V: p}}}
			m := rulesSnapshot(t, []Rule{rule}, nil)
			for _, ua := range []string{"z-", "az", "x[-5y", "-", " z", "xay", "xAy", "x5y", "a-b"} {
				if (rlInput{IP: "8.8.8.8", UA: rlValue{ua}}).match(m).Rule == rule.ID {
					t.Errorf("%q matched ua %q", p, ua)
				}
			}
		}
	})

	t.Run("accepted_translate", func(t *testing.T) {
		if len(v.Accepted) == 0 {
			t.Fatal("no accepted rows")
		}
		for _, p := range v.Accepted {
			if _, ok := jsToRE2(p); !ok {
				t.Errorf("%q: jsToRE2 refused an accepted row", p)
			}
		}
	})
}

// camada-all-zpbv: a stored `matches` value that is empty or not a string never matches (no String()
// coercion, no empty regex that matches everything), over or under the input cap.
func TestEmptyOrNonStringMatchesNeverMatches(t *testing.T) {
	vals := []any{json.Number("123"), json.Number("0"), true, nil, map[string]any{"x": 1}, []any{"^/a"}, []any{json.Number("123")}, ""}
	str := "123 null 0 true None True [object Object] map[x:1] {'x': 1} [^/a] [123]" // every coerced form of vals
	over := strings.Repeat("a", MaxMatchInput+1)
	blk := Rule{ID: "cr_blk", Action: "block", Conds: []Cond{{F: "ip", Op: "is_not", V: "1.1.1.1"}}}
	for _, v := range vals {
		for _, f := range []string{"ua", "path", "header"} {
			for _, cap := range []string{"", f} {
				cond := Cond{F: f, Op: "matches", V: v}
				if f == "header" {
					cond.Name = "x-h"
				}
				in := MatchInput{IP: "8.8.8.8", Path: "/a/123/null/0/true", UA: str,
					Header: func(string) (string, bool) { return str, true }}
				switch cap {
				case "ua":
					in.UA = str + " " + over
				case "path":
					in.Path = "/a/123/null/0/true/" + over
				case "header":
					in.Header = func(string) (string, bool) { return str + " " + over, true }
				}
				t.Run(fmt.Sprintf("%v on %s cap=%s", v, f, cap), func(t *testing.T) {
					if rulesSnapshot(t, []Rule{{ID: "cr_b", Action: "block", Conds: []Cond{cond}}}, nil).Match(in).Block {
						t.Error("block rule blocked")
					}
					r := rulesSnapshot(t, []Rule{{ID: "cr_s", Action: "skip", Conds: []Cond{cond}}, blk}, nil).Match(in)
					if r.Allowed || r.Rule != "cr_blk" {
						t.Errorf("skip exempted (allowed=%v rule=%q)", r.Allowed, r.Rule)
					}
				})
			}
		}
	}
}
