package snapshot

// Path matching (contracts §D3 "Path matching"), ported byte for byte from edge-analyst
// src/blocklist.js canonPath / pathForms / pathHit. A path rule must catch every spelling a
// framework routes to the same handler, so both sides of a comparison are canonicalised: query cut
// at ? or #; %XX decoded when it is printable ASCII other than / and % (so %2F never becomes a
// separator, and decoding stays one pass); every other byte, raw non-ASCII included, written as
// lower-case %xx; ASCII lower-cased; each segment cut at its first ;; empty segments dropped; and
// . / .. resolved — the `full` form. The `lit` form skips that last step, for a router that sends
// /locked/../x to the /locked handler unresolved. A deny (block, challenge, warn) fires when the
// raw path, lit or full matches; an exemption (allow side, skip) needs lit AND full. Path regexes
// are case-insensitive. A rule value goes through the same function once, at load.

import (
	"regexp"
	"strings"
)

const hexDigits = "0123456789abcdef"

// canonFast: already canonical, so the common case skips the byte walk.
var canonFast = regexp.MustCompile(`^(?:/[a-z0-9\-._~!$&'()*+,=:@]+)+$`)

func hexv(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func stripQuery(raw string) string {
	if raw == "" {
		return "/"
	}
	if q := strings.IndexAny(raw, "?#"); q != -1 {
		return raw[:q]
	}
	return raw
}

// isCanonical: the fast-path regex plus the dot-segment check RE2 cannot express as a lookahead.
func isCanonical(p string) bool {
	if p == "/" {
		return true
	}
	if !canonFast.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// CanonPath is the canonical form of a path; dots=false leaves . and .. segments in place (lit).
func CanonPath(raw string, dots bool) string {
	p := stripQuery(raw)
	if isCanonical(p) {
		return p
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '%' && i+2 < len(p) && hexv(p[i+1]) >= 0 && hexv(p[i+2]) >= 0 {
			c = byte(hexv(p[i+1])*16 + hexv(p[i+2]))
			i += 2
			if c == '/' {
				b.WriteString("%2f")
				continue
			}
		}
		if c < 0x21 || c > 0x7e || c == '%' {
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b.WriteByte(c)
	}
	var out []string
	for _, seg := range strings.Split(b.String(), "/") {
		if k := strings.IndexByte(seg, ';'); k != -1 {
			seg = seg[:k]
		}
		if seg == "" || (dots && seg == ".") {
			continue
		}
		if dots && seg == ".." {
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			continue
		}
		out = append(out, seg)
	}
	return "/" + strings.Join(out, "/")
}

// PathForms is [raw (query cut), lit, full] for one request path.
func PathForms(raw string) [3]string {
	p := stripQuery(raw)
	if isCanonical(p) {
		return [3]string{p, p, p}
	}
	return [3]string{p, CanonPath(p, false), CanonPath(p, true)}
}

func dir(p string) string {
	if strings.HasSuffix(p, "/") {
		return p
	}
	return p + "/"
}

// dirKey: a prefix entry or a starts_with value ending in / -> its canonical directory key ('/' stays '/').
func dirKey(v string) string { return dir(CanonPath(v, true)) }

// prefixHit walks '/' boundaries of dir(path): /a/b tries /, /a/, /a/b/.
func prefixHit(prefixes map[string]struct{}, path string) bool {
	d := dir(path)
	for i := 0; i != -1; i = indexFrom(d, '/', i+1) {
		if _, ok := prefixes[d[:i+1]]; ok {
			return true
		}
	}
	return false
}

func indexFrom(s string, c byte, from int) int {
	if from >= len(s) {
		return -1
	}
	if j := strings.IndexByte(s[from:], c); j != -1 {
		return from + j
	}
	return -1
}

// pathHit: deny (block/challenge/warn) = any spelling; exemption (allow/skip) = both canonical forms.
func pathHit(pred func(string) bool, forms *[3]string, deny bool) bool {
	if deny {
		return pred(forms[0]) || pred(forms[1]) || pred(forms[2])
	}
	return pred(forms[1]) && pred(forms[2])
}

// compilePathRegex: a path regex runs case-insensitively.
func compilePathRegex(pattern string) *regexp.Regexp { return CompileRegex("(?i)" + pattern) }

// pathPred turns one path condition into a predicate over a single path form.
func pathPred(op string, values []string) func(string) bool {
	switch op {
	case "matches":
		rx := compilePathRegex(values[0])
		return func(p string) bool { return rx != nil && rx.MatchString(p) }
	case "starts_with":
		v, key := values[0], ""
		if strings.HasSuffix(v, "/") {
			key = dirKey(v)
		} else {
			key = CanonPath(v, true)
		}
		return func(p string) bool { return strings.HasPrefix(dir(p), key) }
	}
	members := make(map[string]struct{}, len(values))
	for _, v := range values {
		members[CanonPath(v, true)] = struct{}{}
	}
	return func(p string) bool { _, ok := members[p]; return ok }
}

func canonSet(xs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		out[CanonPath(x, true)] = struct{}{}
	}
	return out
}

func dirSet(xs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		out[dirKey(x)] = struct{}{}
	}
	return out
}

func pathIn(exact, prefix map[string]struct{}, regexes []*regexp.Regexp, p string) bool {
	if _, ok := exact[p]; ok {
		return true
	}
	if len(prefix) > 0 && prefixHit(prefix, p) {
		return true
	}
	for _, rx := range regexes {
		if rx.MatchString(p) {
			return true
		}
	}
	return false
}
