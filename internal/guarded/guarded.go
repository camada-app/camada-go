// Package guarded is the fail-open envelope: a camada bug must never 5xx the customer. Every
// public entry point of the SDK recovers, falls back, and reports through LogRateLimited: at
// most one line a minute.
package guarded

import (
	"log"
	"sync"
	"time"
)

var (
	mu     sync.Mutex
	last   time.Time
	logger = log.Default()
)

// SetLogger routes the rate-limited line somewhere other than the standard logger.
func SetLogger(l *log.Logger) {
	mu.Lock()
	defer mu.Unlock()
	logger = l
}

// LogRateLimited reports a suppressed error, at most once a minute. Even logging must not panic.
func LogRateLimited(err any) {
	defer func() { _ = recover() }()
	mu.Lock()
	now := time.Now()
	if now.Sub(last) < time.Minute {
		mu.Unlock()
		return
	}
	last = now
	l := logger
	mu.Unlock()
	l.Printf("[camada] suppressed error (SDK fails open): %v", err)
}

// Reset forgets the last report so the next one is written (tests).
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	last = time.Time{}
}
