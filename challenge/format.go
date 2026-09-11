// Package challenge is the SDK-served proof-of-work challenge (contracts §D2), ported from
// @camada/core src/challenge/{format,verify,page}.ts: wire constants and pure helpers here, the
// HMAC/SHA-256 kit in verify.go, the self-contained page in page.go. The format has exactly one
// definition across the family.
package challenge

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"strconv"
	"strings"
)

const (
	CookieName  = "_cch"
	TTLMS       = 3_600_000 // 1 h (contract)
	PowBits     = 16        // leading zero bits of SHA-256("<nonce>.<solution>")
	NonceHex    = 32        // the nonce is the first 32 hex chars of the HMAC
	dayMS       = 86_400_000
	maxReturnTo = 2048
	maxSolution = 32
)

// UTCDay is the UTC day number the nonce is bound to.
func UTCDay(nowMS int64) int64 { return nowMS / dayMS }

// Domain-separated messages: a nonce HMAC can never be replayed as a cookie HMAC.
func nonceMessage(ip string, day int64) string {
	return "camada-challenge-nonce|" + ip + "|" + strconv.FormatInt(day, 10)
}

func tokenMessage(ip string, exp int64) string {
	return "camada-challenge-token|" + ip + "|" + strconv.FormatInt(exp, 10)
}

func splitToken(value string) (exp int64, mac string, ok bool) {
	dot := strings.IndexByte(value, '.')
	if dot <= 0 {
		return 0, "", false
	}
	exp, err := strconv.ParseInt(value[:dot], 10, 64)
	if err != nil {
		return 0, "", false
	}
	mac = value[dot+1:]
	return exp, mac, mac != ""
}

// safeEqual is constant-time for equal-length strings; length itself is not a secret here.
func safeEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// PowOK is true when the hex digest starts with `bits` zero bits.
func PowOK(hexDigest string, bits int) bool {
	nibbles, rest := bits>>2, bits&3
	need := nibbles
	if rest != 0 {
		need++
	}
	if len(hexDigest) < need {
		return false
	}
	for i := 0; i < nibbles; i++ {
		if hexDigest[i] != '0' {
			return false
		}
	}
	if rest == 0 {
		return true
	}
	v, err := strconv.ParseUint(hexDigest[nibbles:nibbles+1], 16, 8)
	return err == nil && v>>(4-uint(rest)) == 0
}

func solutionShapeOK(solution string) bool {
	return solution != "" && len(solution) <= maxSolution
}

// Cookie is the Set-Cookie value carrying a passed challenge.
func Cookie(value string, secure bool) string {
	s := CookieName + "=" + value + "; Path=/; Max-Age=" + strconv.Itoa(TTLMS/1000) + "; HttpOnly; SameSite=Lax"
	if secure {
		s += "; Secure"
	}
	return s
}

// SafeReturnTo keeps only a printable-ASCII same-site absolute path: never an absolute URL, a
// protocol-relative '//host' redirect, a control character, or something absurdly long.
func SafeReturnTo(raw string) string {
	if raw == "" || len(raw) > maxReturnTo {
		return "/"
	}
	if raw[0] != '/' || (len(raw) > 1 && (raw[1] == '/' || raw[1] == '\\')) {
		return "/"
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x21 || raw[i] > 0x7E {
			return "/"
		}
	}
	return raw
}

// WantsHTML: a challenge page is only worth serving to a top-level HTML navigation (contract §D2).
func WantsHTML(accept, secFetchDest string) bool {
	if !strings.Contains(accept, "text/html") {
		return false
	}
	return secFetchDest == "" || secFetchDest == "document"
}

var attrEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")

// EscapeAttr makes a string safe inside a double-quoted HTML attribute.
func EscapeAttr(s string) string { return attrEscaper.Replace(s) }

// EscapeScript is a JSON string literal safe to drop inside an inline <script>: `<` is escaped
// so no value can close the element early.
func EscapeScript(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.ReplaceAll(strings.TrimRight(buf.String(), "\n"), "<", `\u003c`)
}

// ParseFormBody reads application/x-www-form-urlencoded, last value wins. Never fails on junk.
func ParseFormBody(body string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(body, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		out[unquote(k)] = unquote(v)
	}
	return out
}

// unquote decodes + and %XX the way urllib.parse.unquote does: an invalid escape stays as it
// is, and bytes that are not UTF-8 become U+FFFD.
func unquote(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	if !strings.Contains(s, "%") {
		return s
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s)+0 && isHex(s[i+1]) && isHex(s[i+2]) {
			b, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			out = append(out, byte(b))
			i += 2
			continue
		}
		out = append(out, s[i])
	}
	return strings.ToValidUTF8(string(out), "\uFFFD")
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
