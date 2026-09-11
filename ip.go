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
func ResolveClientIP(peer, xff string, cfg *TrustedProxy) string {
	sock := strings.TrimPrefix(peer, "::ffff:") // dual-stack v4-mapped form
	if cfg == nil || cfg.Mode == "none" || xff == "" {
		return sock
	}
	var entries []string
	for _, e := range strings.Split(xff, ",") {
		if e = strings.TrimSpace(e); e != "" {
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
