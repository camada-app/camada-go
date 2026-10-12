package camada

// Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer:
// raw X-Forwarded-For is attacker-writable and is NEVER trusted without explicit configuration;
// a spoofed XFF must not reach the analysis or the blocklist. Ported from @camada/core src/ip.ts.

import (
	"strconv"
	"strings"
)

type cidr struct {
	base4 uint32
	base6 Words
	v6    bool
	bits  int
}

// validIP is a plain IPv4 or IPv6 address (C6 v3), by our own grammar, never net/netip (which accept zone ids and
// embedded dotted quads). Stricter than ParseIP6, which mirrors edge-analyst and must not drift: a single leading or
// trailing `:` (`:8:8:8`, `2001:db8::1:`) is rejected here only. Dotted quads and zone ids already fail ParseIP6.
func validIP(s string) bool {
	if !strings.Contains(s, ":") {
		_, ok := ParseIP4(s)
		return ok
	}
	n := len(s)
	if n < 2 || (s[0] == ':' && s[1] != ':') || (s[n-1] == ':' && s[n-2] != ':') {
		return false
	}
	_, ok := ParseIP6(s)
	return ok
}

// unmap is `::ffff:a.b.c.d` (any case) -> `a.b.c.d`, only when a valid dotted quad follows; anything else comes back
// unchanged (`::ffff:7f00:1` stays an ordinary IPv6 address). C6 v2.
func unmap(s string) string {
	if len(s) < 14 || !strings.EqualFold(s[:7], "::ffff:") {
		return s
	}
	if _, ok := ParseIP4(s[7:]); ok {
		return s[7:]
	}
	return s
}

// trimOWS removes HTTP optional whitespace only (SP, HTAB), never strings.TrimSpace's Unicode whitespace (C6 v3).
func trimOWS(s string) string { return strings.Trim(s, " \t") }

// xffEntries is the X-Forwarded-For list: split on `,`, each entry OWS-trimmed, port-stripped and unmapped, empty
// entries dropped (before `hops` counts).
func xffEntries(xff string) []string {
	var entries []string
	for _, e := range strings.Split(xff, ",") {
		if e = unmap(stripPort(trimOWS(e))); e != "" {
			entries = append(entries, e)
		}
	}
	return entries
}

// stripPort is one X-Forwarded-For entry without its port (camada-all-0vho): `[v6]:port` and `[v6]` -> `v6`,
// `a.b.c.d:port` -> `a.b.c.d`. A bare IPv6 literal comes back whole (its last group is never a port); anything else
// malformed comes back unchanged, so validation still rejects it and the peer wins.
func stripPort(e string) string {
	if strings.HasPrefix(e, "[") {
		end := strings.IndexByte(e, ']')
		if end == -1 {
			return e
		}
		inner, rest := e[1:end], e[end+1:]
		if strings.Contains(inner, ":") && (rest == "" || isPort(rest)) {
			return inner
		}
		return e
	}
	colon := strings.IndexByte(e, ':')
	if colon == -1 || strings.IndexByte(e[colon+1:], ':') != -1 {
		return e // no colon, or a bare IPv6 literal
	}
	if _, ok := ParseIP4(e[:colon]); ok && isPort(e[colon:]) {
		return e[:colon]
	}
	return e
}

// isPort is `:` followed by 1-5 ASCII digits.
func isPort(s string) bool {
	if len(s) < 2 || len(s) > 6 || s[0] != ':' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isLoopback is 127.0.0.0/8 or ::1 (camada-all-yfc6, decision D1), compared by value, never netip's IsLoopback.
// The peer's `::ffff:127.x.x.x` form is already reduced to the dotted quad by unmap; `::ffff:7f00:1` is not loopback.
func isLoopback(ip string) bool {
	if !strings.Contains(ip, ":") {
		n, ok := ParseIP4(ip)
		return ok && n>>24 == 127
	}
	w, ok := ParseIP6(ip)
	return ok && w == Words{0, 0, 0, 1}
}

func parseCIDR(c string) (cidr, bool) {
	slash := strings.IndexByte(c, '/')
	if slash == -1 {
		return cidr{}, false
	}
	addr := c[:slash]
	bits, err := strconv.Atoi(c[slash+1:])
	if err != nil {
		return cidr{}, false
	}
	if !strings.Contains(addr, ":") {
		base, ok := ParseIP4(addr)
		if !ok || bits < 0 || bits > 32 {
			return cidr{}, false
		}
		return cidr{base4: base, bits: bits}, true
	}
	words, ok := ParseIP6(addr)
	if !ok || bits < 0 || bits > 128 {
		return cidr{}, false
	}
	return cidr{base6: words, v6: true, bits: bits}, true
}

func inCIDR(ip string, c cidr) bool {
	if !c.v6 {
		n, ok := ParseIP4(ip)
		if !ok {
			return false
		}
		var mask uint32
		if c.bits > 0 {
			mask = 0xFFFFFFFF << uint(32-c.bits)
		}
		return n&mask == c.base4&mask
	}
	words, ok := ParseIP6(ip)
	if !ok {
		return false
	}
	remaining := c.bits
	for k := 0; k < 4 && remaining > 0; k++ {
		take := min(32, remaining)
		mask := uint32(0xFFFFFFFF)
		if take < 32 {
			mask = 0xFFFFFFFF << uint(32-take)
		}
		if words[k]&mask != c.base6[k]&mask {
			return false
		}
		remaining -= take
	}
	return true
}

// ResolveClientIP is the client IP from the socket peer and X-Forwarded-For per the trusted-proxy config. The result
// is always a valid ip or "" (no address), in every mode (C6 v3). Anything unresolvable falls back to the peer.
//
// XFF entries are trimmed of SP/HTAB only, read without a port (`ip:port`, `[v6]:port`, as Azure writes them) and
// with `::ffff:a.b.c.d` reduced to `a.b.c.d`, in every mode. The peer is unmap(peer) when that is a valid ip, else
// "": a non-empty peer that is not an ip (a socket path, `@`, `ip:port`, a zone id) could not be read, and the
// result falls back to "", never to the XFF walk. The peer is never trimmed or port-stripped.
//
// `cidrs` (also what the dashboard's Cloudflare option stores) walks the chain `[...xff, peer]` from the right: if
// the peer is not a trusted proxy, the request did not come through one and the peer IS the client; XFF is ignored,
// since anyone hitting the origin directly can write it. A loopback peer (127.0.0.0/8, ::1, ::ffff:127.x.x.x) counts
// as a trusted hop: it is a local front end or sidecar (App Engine's is always 127.0.0.1), and no remote client can be
// one. Loopback is trusted only as the peer, never as an XFF entry; an XFF entry that is not an ip is never a trusted
// hop. With no peer at all (peer "": a unix-socket listener, see Handler) the walk runs over XFF alone: such a host
// trusts its network edge to have written XFF, and the app must not be reachable around that edge. `hops` and
// `vercel` trust XFF by definition and ignore the peer.
func ResolveClientIP(peer, xff string, cfg *TrustedProxy) string {
	mapped := unmap(peer) // dual-stack v4-mapped form; "" is no peer
	sock := ""
	if mapped != "" && validIP(mapped) {
		sock = mapped
	}
	if cfg == nil || cfg.Mode == "none" || xff == "" {
		return sock
	}
	entries := xffEntries(xff)
	if len(entries) == 0 {
		return sock
	}
	candidate := ""
	switch cfg.Mode {
	case "hops":
		if cfg.Hops >= 1 && cfg.Hops <= len(entries) {
			candidate = entries[len(entries)-cfg.Hops]
		}
	case "vercel":
		candidate = entries[len(entries)-1] // Vercel overwrites XFF, so its rightmost entry is trustworthy
	case "cidrs":
		var trusted []cidr
		for _, x := range cfg.CIDRs {
			if c, ok := parseCIDR(x); ok {
				trusted = append(trusted, c)
			}
		}
		// the peer is the first hop: if it is not a trusted proxy, it is the client. An unreadable (non-ip) peer gives
		// "", never the walk; only no peer at all walks.
		if mapped != "" && (sock == "" || (!isLoopback(sock) && !isTrusted(sock, trusted))) {
			return sock
		}
		for i := len(entries) - 1; i >= 0; i-- {
			if !isTrusted(entries[i], trusted) {
				candidate = entries[i]
				break
			}
		}
	}
	if candidate != "" && validIP(candidate) {
		return candidate
	}
	return sock
}

// isTrusted is a trusted hop: a valid ip inside a configured range. An entry that is not an ip never is (C6 v3).
func isTrusted(ip string, cidrs []cidr) bool {
	return validIP(ip) && anyCIDR(ip, cidrs)
}

func anyCIDR(ip string, cidrs []cidr) bool {
	for _, c := range cidrs {
		if inCIDR(ip, c) {
			return true
		}
	}
	return false
}
