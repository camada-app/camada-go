// Package ipparse holds the allocation-free IP parsers, ported 1:1 from edge-analyst
// src/blocklist.js through @camada/core src/snapshot/ipparse.ts (the reference the conformance
// fixtures are generated from). Behaviour must not drift: ip4 is not-ok on anything unusual;
// ip6 rejects zone ids and v4-mapped forms.
package ipparse

// Words is an IPv6 address as four big-endian uint32 words.
type Words [4]uint32

// ParseIP4 reads a dotted quad into a uint32; ok is false when the string is not a plain IPv4 address.
func ParseIP4(s string) (uint32, bool) {
	var n, part, digits, dots uint32
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '.':
			if digits == 0 || part > 255 {
				return 0, false
			}
			dots++
			if dots > 3 {
				return 0, false
			}
			n = n*256 + part
			part, digits = 0, 0
		case ch >= '0' && ch <= '9':
			part = part*10 + uint32(ch-'0')
			digits++
			if digits > 3 {
				return 0, false
			}
		default:
			return 0, false
		}
	}
	if dots != 3 || digits == 0 || part > 255 {
		return 0, false
	}
	return n*256 + part, true
}

// ParseIP6 reads IPv6 text into four big-endian uint32 words; ok is false when it is not a plain IPv6 address.
func ParseIP6(s string) (Words, bool) {
	length := len(s)
	var groups [8]uint32
	n, val, digits := 0, uint32(0), 0
	dbl := -1
	i := 0
	if length > 1 && s[0] == ':' && s[1] == ':' {
		dbl = 0
		i = 2
	}
	for ; i <= length; i++ {
		c := byte(':') // a sentinel colon closes the last group
		if i < length {
			c = s[i]
		}
		if c == ':' {
			if digits > 0 {
				if n >= 8 {
					return Words{}, false
				}
				groups[n] = val
				n++
				val, digits = 0, 0
			} else if i < length {
				if dbl != -1 {
					return Words{}, false
				}
				dbl = n
			}
			continue
		}
		var d uint32
		switch {
		case c >= '0' && c <= '9':
			d = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint32(c-'A') + 10
		default:
			return Words{}, false
		}
		val = val<<4 | d
		digits++
		if digits > 4 {
			return Words{}, false
		}
	}
	if dbl == -1 {
		if n != 8 {
			return Words{}, false
		}
	} else {
		if n >= 8 {
			return Words{}, false
		}
		shift := 8 - n
		for k := 7; k >= dbl+shift; k-- {
			groups[k] = groups[k-shift]
		}
		for k := dbl; k < dbl+shift; k++ {
			groups[k] = 0
		}
	}
	return Words{
		groups[0]<<16 | groups[1],
		groups[2]<<16 | groups[3],
		groups[4]<<16 | groups[5],
		groups[6]<<16 | groups[7],
	}, true
}
