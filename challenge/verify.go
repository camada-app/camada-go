package challenge

// The challenge kit over crypto/hmac and crypto/sha256, ported from @camada/core
// src/challenge/verify.ts. Synchronous, so the engine's Handle stays a plain function.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// Kit mints and checks nonces, proofs of work and cookies under one secret.
type Kit struct {
	secret []byte
}

// New builds a kit; the secret is the tenant key and never leaves the process.
func New(secret string) *Kit { return &Kit{secret: []byte(secret)} }

func (k *Kit) hmac(msg string) string {
	m := hmac.New(sha256.New, k.secret)
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

func (k *Kit) at(ip string, day int64) string {
	return k.hmac(nonceMessage(ip, day))[:NonceHex]
}

// Nonce is the stateless per-(ip, UTC day) nonce; the verify endpoint recomputes it, nothing is stored.
func (k *Kit) Nonce(ip string, nowMS int64) string {
	return k.at(ip, UTCDay(nowMS))
}

// NonceValid accepts today's and yesterday's nonce: a solve started before midnight UTC must
// not be thrown away. So one solved (nonce, solution) pair is replayable from its own IP for up
// to ~48 h, minting a fresh 1 h cookie each time. That is the price of a stateless nonce (§D2)
// and it is deliberate — do not "fix" it into something that needs shared server state.
func (k *Kit) NonceValid(ip string, nowMS int64, nonce string) bool {
	if ip == "" || len(nonce) != NonceHex {
		return false
	}
	day := UTCDay(nowMS)
	return safeEqual(nonce, k.at(ip, day)) || safeEqual(nonce, k.at(ip, day-1))
}

// Issue mints the _cch value: "<exp>.<HMAC-SHA256(secret, token message)>".
func (k *Kit) Issue(ip string, nowMS int64) string {
	exp := nowMS + TTLMS
	return strconv.FormatInt(exp, 10) + "." + k.hmac(tokenMessage(ip, exp))
}

// TokenValid checks a _cch value. An empty ip is refused outright: without one the token is
// bound to nothing, so a single solve would mint a cookie every other unidentified client could
// present. Adapters must fail open (serve no challenge) rather than challenge a client they
// cannot identify.
func (k *Kit) TokenValid(ip string, nowMS int64, cookieValue string) bool {
	if ip == "" {
		return false
	}
	exp, mac, ok := splitToken(cookieValue)
	if !ok || exp <= nowMS || exp > nowMS+TTLMS {
		return false
	}
	return safeEqual(mac, k.hmac(tokenMessage(ip, exp)))
}

// SolutionOK is the proof of work ONLY. Never call it without a passing NonceValid for the same nonce.
func (k *Kit) SolutionOK(nonce, solution string) bool {
	if !solutionShapeOK(solution) {
		return false
	}
	sum := sha256.Sum256([]byte(nonce + "." + solution))
	return PowOK(hex.EncodeToString(sum[:]), PowBits)
}

// Verify checks the whole submission: the nonce is ours and unexpired, and the work is done.
func (k *Kit) Verify(ip string, nowMS int64, nonce, solution string) bool {
	return k.NonceValid(ip, nowMS, nonce) && k.SolutionOK(nonce, solution)
}
