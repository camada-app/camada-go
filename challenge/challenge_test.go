package challenge_test

// The SDK-served challenge (contracts §D2): a stateless per-(ip, UTC day) HMAC nonce, a 16-bit
// SHA-256 proof of work, and an HMAC cookie bound to the ip for one hour. Ported case for case
// from camada-core/test/challenge.test.ts via camada-python/tests/test_challenge.py.

import (
	"encoding/hex"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/camada/camada-go/challenge"
	"github.com/camada/camada-go/internal/testutil"
)

const (
	day = int64(86_400_000)
	now = int64(1_800_000_000_000)
	ip  = "203.0.113.9"
)

func TestNonceDeterministicPerIPAndUTCDay(t *testing.T) {
	kit := challenge.New("secret")
	a, b := kit.Nonce(ip, now), kit.Nonce(ip, now+1000)
	if a != b || len(a) != challenge.NonceHex {
		t.Fatalf("nonce %q vs %q", a, b)
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Fatalf("not hex: %q", a)
	}
	if kit.Nonce("203.0.113.10", now) == a || kit.Nonce(ip, now+day) == a || challenge.New("other").Nonce(ip, now) == a {
		t.Fatal("nonce not bound to ip, day and secret")
	}
}

func TestNonceAcceptsTodayAndYesterdayRejectsOlderAndForgeries(t *testing.T) {
	kit := challenge.New("secret")
	yesterday := kit.Nonce(ip, now-day)
	if !kit.NonceValid(ip, now, kit.Nonce(ip, now)) || !kit.NonceValid(ip, now, yesterday) {
		t.Fatal("today/yesterday refused")
	}
	for name, bad := range map[string]struct {
		ip, nonce string
	}{
		"two days old": {ip, kit.Nonce(ip, now-2*day)},
		"zeros":        {ip, strings.Repeat("0", 32)},
		"truncated":    {ip, kit.Nonce(ip, now)[:31]},
		"no ip":        {"", kit.Nonce(ip, now)},
		"no nonce":     {ip, ""},
	} {
		if kit.NonceValid(bad.ip, now, bad.nonce) {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestTokenRoundTripsWithinTheHourAndExpiresAfter(t *testing.T) {
	kit := challenge.New("secret")
	tok := kit.Issue(ip, now)
	if !kit.TokenValid(ip, now+3_599_000, tok) || kit.TokenValid(ip, now+3_600_000, tok) {
		t.Fatal("ttl")
	}
}

func TestTokenBoundToTheIPAndUnforgeable(t *testing.T) {
	kit := challenge.New("secret")
	tok := kit.Issue(ip, now)
	if kit.TokenValid("203.0.113.10", now, tok) {
		t.Fatal("another ip")
	}
	exp, mac, _ := strings.Cut(tok, ".")
	if kit.TokenValid(ip, now, exp+"."+strings.Repeat("0", len(mac))) {
		t.Fatal("forged mac")
	}
	e, _ := strconv.ParseInt(exp, 10, 64)
	if kit.TokenValid(ip, now, strconv.FormatInt(e+1, 10)+"."+mac) {
		t.Fatal("tampered exp")
	}
	if kit.TokenValid("", now, tok) { // no ip: never
		t.Fatal("no ip")
	}
	for _, junk := range []string{"", "x", ".mac", "notanumber.mac"} {
		if kit.TokenValid(ip, now, junk) {
			t.Errorf("junk %q accepted", junk)
		}
	}
}

func TestTokenRefusesAnExpiryFurtherOutThanTheTTL(t *testing.T) {
	kit := challenge.New("secret")
	far := kit.Issue(ip, now+10_000_000) // minted "in the future": exp > now + TTL
	if kit.TokenValid(ip, now, far) {
		t.Fatal("accepted")
	}
}

func TestProofOfWorkAcceptsA16BitSolutionAndRejectsAnythingElse(t *testing.T) {
	kit := challenge.New("secret")
	nonce := kit.Nonce(ip, now)
	sol := testutil.Solve(nonce)
	if !kit.SolutionOK(nonce, sol) || !kit.Verify(ip, now, nonce, sol) {
		t.Fatal("real work refused")
	}
	if kit.SolutionOK(nonce, sol+"1") || kit.SolutionOK(nonce, strings.Repeat("x", 33)) || kit.SolutionOK(nonce, "") {
		t.Fatal("bad solution accepted")
	}
	forged := strings.Repeat("f", 32)
	if kit.Verify(ip, now, forged, testutil.Solve(forged)) { // a forged nonce, even with real work
		t.Fatal("forged nonce accepted")
	}
}

func TestPowOKCountsLeadingZeroBits(t *testing.T) {
	for _, c := range []struct {
		hex  string
		bits int
		ok   bool
	}{
		{"0000ffff", 16, true}, {"0001ffff", 16, false},
		{"00007fff", 17, true}, {"0000ffff", 17, false},
		{"0", 4, true}, {"", 4, false},
	} {
		if challenge.PowOK(c.hex, c.bits) != c.ok {
			t.Errorf("PowOK(%q, %d) != %v", c.hex, c.bits, c.ok)
		}
	}
}

func TestCookieString(t *testing.T) {
	if got := challenge.Cookie("1.abc", false); got != "_cch=1.abc; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax" {
		t.Fatalf("got %q", got)
	}
	if !strings.HasSuffix(challenge.Cookie("1.abc", true), "; Secure") {
		t.Fatal("secure flag missing")
	}
}

func TestSafeReturnToKeepsOnlyASameSitePath(t *testing.T) {
	if challenge.SafeReturnTo("/a/b?c=1") != "/a/b?c=1" {
		t.Fatal("a plain path was rewritten")
	}
	for _, bad := range []string{"", "https://evil", "//evil", `/\evil`, "/a b", "/é", "/" + strings.Repeat("a", 2048), "relative"} {
		if got := challenge.SafeReturnTo(bad); got != "/" {
			t.Errorf("SafeReturnTo(%q) = %q", bad, got)
		}
	}
}

func TestWantsHTML(t *testing.T) {
	if !challenge.WantsHTML("text/html,*/*", "") || !challenge.WantsHTML("text/html", "document") {
		t.Fatal("html navigation refused")
	}
	if challenge.WantsHTML("application/json", "") || challenge.WantsHTML("text/html", "empty") || challenge.WantsHTML("", "") {
		t.Fatal("non-navigation accepted")
	}
}

func TestFormBodyLastValueWinsAndNeverPanics(t *testing.T) {
	got := challenge.ParseFormBody("a=1&b=x+y&a=2&c&%zz=%zz")
	if want := map[string]string{"a": "2", "b": "x y", "c": "", "%zz": "%zz"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	f := challenge.ParseFormBody("nonce=abc&solution=7&to=%2Fx%3Fy%3D1")
	if want := map[string]string{"nonce": "abc", "solution": "7", "to": "/x?y=1"}; !reflect.DeepEqual(f, want) {
		t.Fatalf("got %v", f)
	}
	if len(challenge.ParseFormBody("")) != 0 {
		t.Fatal("empty body")
	}
}

func TestEscaping(t *testing.T) {
	if got := challenge.EscapeAttr(`a<b>&"c'`); got != "a&lt;b&gt;&amp;&quot;c&#39;" {
		t.Fatalf("attr %q", got)
	}
	if got := challenge.EscapeScript("</script>"); got != `"\u003c/script>"` {
		t.Fatalf("script %q", got)
	}
}

func TestPageSelfContainedAndEscaped(t *testing.T) {
	html := challenge.Page(strings.Repeat("ab", 16), "/__camada/challenge", `/x"><script>`, challenge.PowBits)
	if !strings.HasPrefix(html, "<!doctype html>") {
		t.Fatal("doctype")
	}
	head := strings.SplitN(html, "<script>", 2)[0]
	if strings.Contains(strings.ReplaceAll(head, "http-equiv", ""), "http") { // no external assets before the solver
		t.Fatal("external asset")
	}
	for _, want := range []string{`action="/__camada/challenge"`, `value="/x&quot;&gt;&lt;script&gt;"`, "__camadaSha256Words", "shift=16"} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(html, "crypto.subtle") {
		t.Fatal("subtle")
	}
}

func TestDifficultyIsClamped(t *testing.T) {
	if !strings.Contains(challenge.Page(strings.Repeat("a", 32), "/v", "/", 99), "shift=0") {
		t.Fatal("bits above 32")
	}
	if !strings.Contains(challenge.Page(strings.Repeat("a", 32), "/v", "/", 0), "shift=31") {
		t.Fatal("bits below 1")
	}
}
