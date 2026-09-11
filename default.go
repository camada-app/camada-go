package camada

import (
	"context"
	"sync"
)

var (
	defaultMu     sync.Mutex
	defaultEngine *Camada
)

// Default is the lazy singleton wired from the process environment on first use: what
// Handler(next) and the app helpers share when no engine was handed in.
func Default() *Camada {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultEngine == nil {
		defaultEngine = New(Options{})
	}
	return defaultEngine
}

// Configure replaces the default engine (stopping the old one) — for tests and explicit wiring.
func Configure(o Options) *Camada {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultEngine != nil {
		defaultEngine.Stop(context.Background())
	}
	defaultEngine = New(o)
	return defaultEngine
}

// resetDefault forgets the default engine without stopping it (tests).
func resetDefault() {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	defaultEngine = nil
}

// engineFor is the engine that produced a request context, else the default: what the app
// helpers resolve through.
func engineFor(ctx *Ctx) *Camada {
	if ctx != nil && ctx.engine != nil {
		return ctx.engine
	}
	return Default()
}
