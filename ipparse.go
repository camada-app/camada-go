package camada

import "github.com/camada-app/camada-go/internal/ipparse"

// Words is an IPv6 address as four big-endian uint32 words, the form the BLK container stores.
type Words = ipparse.Words

// ParseIP4 reads a dotted quad into a uint32; ok is false when the string is not a plain IPv4 address.
func ParseIP4(s string) (uint32, bool) { return ipparse.ParseIP4(s) }

// ParseIP6 reads IPv6 text into four big-endian words; ok is false for zone ids, v4-mapped and malformed forms.
func ParseIP6(s string) (Words, bool) { return ipparse.ParseIP6(s) }
