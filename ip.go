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

func validIP(s string) bool {
	if !strings.Contains(s, ":") {
		_, ok := ParseIP4(s)
		return ok
	}
	_, ok := ParseIP6(s)
	return ok
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

// isLoopback is 127.0.0.0/8 or ::1 (camada-all-yfc6, decision D1). The peer's `::ffff:127.x.x.x` form is already
// reduced to the dotted quad by ResolveClientIP.
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

// ResolveClientIP is the client IP from the socket peer and X-Forwarded-For per the
// trusted-proxy config. Anything unresolvable falls back to the peer (fail safe); "" is no address.
//
// XFF entries are read without a port (`ip:port`, `[v6]:port`, as Azure writes them) in every mode.
//
// `cidrs` (also what the dashboard's Cloudflare option stores) walks the chain `[...xff, peer]` from the right: if
// the peer is not a trusted proxy, the request did not come through one and the peer IS the client; XFF is ignored,
// since anyone hitting the origin directly can write it. A loopback peer (127.0.0.0/8, ::1, ::ffff:127.x.x.x) counts
// as a trusted hop: it is a local front end or sidecar (App Engine's is always 127.0.0.1), and no remote client can be
// one. Loopback is trusted only as the peer, never as an XFF entry. With no peer at all (peer "", or not an ip, as
// on a unix socket) the walk runs over XFF alone: such a host trusts its network edge to have written XFF, and the
// app must not be reachable around that edge. `hops` and `vercel` trust XFF by definition and ignore the peer.
func ResolveClientIP(peer, xff string, cfg *TrustedProxy) string {
	sock := peer
	if len(sock) >= 7 && strings.EqualFold(sock[:7], "::ffff:") {
		sock = sock[7:] // dual-stack v4-mapped form
	}
	if cfg == nil || cfg.Mode == "none" || xff == "" {
		return sock
	}
	var entries []string
	for _, e := range strings.Split(xff, ",") {
		if e = stripPort(strings.TrimSpace(e)); e != "" {
			entries = append(entries, e)
		}
	}
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
		// the peer is the first hop: if it is not a trusted proxy, it is the client. A peer that is not an ip (a unix
		// socket: a local proxy) is no network peer at all, as core sees it, and keeps the walk.
		if validIP(sock) && !isLoopback(sock) && !anyCIDR(sock, trusted) {
			return sock
		}
		for i := len(entries) - 1; i >= 0; i-- {
			if !anyCIDR(entries[i], trusted) {
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

func anyCIDR(ip string, cidrs []cidr) bool {
	for _, c := range cidrs {
		if inCIDR(ip, c) {
			return true
		}
	}
	return false
}
