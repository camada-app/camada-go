package testutil

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/camada-app/camada-go/challenge"
)

// Solve hunts the counter whose SHA-256("<nonce>.<counter>") starts with challenge.PowBits zero
// bits — what the challenge page's inline solver does, for tests that pass the challenge.
func Solve(nonce string) string {
	for n := 0; ; n++ {
		sum := sha256.Sum256([]byte(nonce + "." + strconv.Itoa(n)))
		if challenge.PowOK(hex.EncodeToString(sum[:]), challenge.PowBits) {
			return strconv.Itoa(n)
		}
	}
}
