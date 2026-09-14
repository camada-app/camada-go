package events

// Queue: fire-and-forget batched shipping to POST /e (ported from @camada/core
// src/events/queue.ts). The collector ships one event per request; an in-process SDK batches,
// flushes on size or interval, and drains at exit — but the same law holds: NOTHING here may
// ever panic into the customer's request path, and a dead ingest must cost nothing but dropped
// telemetry. Defaults (15 s / 500): every flush is one request and one R2 put at the analyst,
// so the bill scales with instance count x flush cadence — not with traffic.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/camada-app/camada-go/internal/guarded"
	"github.com/camada-app/camada-go/internal/transport"
)

const (
	DefaultMaxBatch      = 500 // flush when the queue reaches this many (server caps at 1000)
	DefaultMaxQueue      = 2000
	DefaultFlushInterval = 15 * time.Second
	DefaultTimeout       = 2 * time.Second
	DrainBudget          = 500 * time.Millisecond // the most an exit drain may hold the process
	postCap              = 1000                   // the server slices there
)

// QueueOptions tune a Queue; the zero value is the production default.
type QueueOptions struct {
	MaxBatch      int
	MaxQueue      int // drop-oldest beyond this
	FlushInterval time.Duration
	Timeout       time.Duration
	Transport     transport.Transport
	SDK           string // "<package>/<version>": sent as x-camada-sdk on every batch (SDK-03)
}

// Queue batches events and ships them off the request path.
type Queue struct {
	URL, Token    string
	MaxBatch      int
	MaxQueue      int
	FlushInterval time.Duration
	Timeout       time.Duration
	Transport     transport.Transport
	SDK           string

	dropped  atomic.Int64 // debug counter, not an API promise
	mu       sync.Mutex
	q        []any
	started  bool
	stopped  bool
	inflight sync.Mutex // one POST loop at a time
	busy     atomic.Bool
	wake     chan struct{}
	stop     chan struct{}
}

// NewQueue builds a queue; the flush goroutine starts lazily on the first Push.
func NewQueue(url, token string, o QueueOptions) *Queue {
	q := &Queue{
		URL: strings.TrimRight(url, "/"), Token: token,
		MaxBatch: o.MaxBatch, MaxQueue: o.MaxQueue, FlushInterval: o.FlushInterval, Timeout: o.Timeout,
		Transport: o.Transport, SDK: o.SDK,
		wake: make(chan struct{}, 1), stop: make(chan struct{}),
	}
	if q.MaxBatch <= 0 {
		q.MaxBatch = DefaultMaxBatch
	}
	if q.MaxQueue <= 0 {
		q.MaxQueue = DefaultMaxQueue
	}
	if q.FlushInterval <= 0 {
		q.FlushInterval = DefaultFlushInterval
	}
	if q.Timeout <= 0 {
		q.Timeout = DefaultTimeout
	}
	if q.Transport == nil {
		q.Transport = transport.HTTP
	}
	return q
}

// Size is the number of events waiting.
func (q *Queue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.q)
}

// Dropped counts events lost to the queue cap or a dead ingest.
func (q *Queue) Dropped() int64 { return q.dropped.Load() }

// InFlight reports whether a POST loop is running.
func (q *Queue) InFlight() bool { return q.busy.Load() }

// Push enqueues one event; synchronous, never panics. Starts the flush goroutine lazily on
// first push; a stopped queue stays stopped (Configure replaces the engine rather than reviving one).
func (q *Queue) Push(event any) {
	defer func() {
		if r := recover(); r != nil { // never into the request path
			guarded.LogRateLimited(r)
		}
	}()
	q.mu.Lock()
	if len(q.q) >= q.MaxQueue {
		q.q = q.q[1:]
		q.dropped.Add(1)
	}
	q.q = append(q.q, event)
	n := len(q.q)
	if !q.started && !q.stopped {
		q.started = true
		go q.run()
	}
	q.mu.Unlock()
	if n >= q.MaxBatch {
		select {
		case q.wake <- struct{}{}:
		default:
		}
	}
}

func (q *Queue) run() {
	for {
		timer := time.NewTimer(q.FlushInterval)
		select {
		case <-q.wake:
		case <-timer.C:
		case <-q.stop:
			timer.Stop()
			return
		}
		timer.Stop()
		q.flush(false)
	}
}

// Flush drains the queue now, <=1000 events per POST; yields when a flush is already in
// flight; never panics.
func (q *Queue) Flush() { q.flush(false) }

// flush: `wait` queues behind a flush already in flight instead of yielding to it — the exit
// drain needs the full queue gone, not just the batch someone else is posting.
func (q *Queue) flush(wait bool) {
	if wait {
		q.inflight.Lock()
	} else if !q.inflight.TryLock() {
		return
	}
	q.busy.Store(true)
	defer func() {
		q.busy.Store(false)
		q.inflight.Unlock()
	}()
	headers := map[string]string{"x-tenant": q.Token, "content-type": "application/json"}
	if q.SDK != "" {
		headers["x-camada-sdk"] = q.SDK
	}
	for {
		q.mu.Lock()
		if len(q.q) == 0 {
			q.mu.Unlock()
			return
		}
		n := min(postCap, len(q.q))
		batch := append([]any{}, q.q[:n]...)
		q.q = q.q[n:]
		q.mu.Unlock()
		if err := q.post(headers, batch); err != nil {
			q.dropped.Add(int64(len(batch)))
			// Dropping telemetry is by design, doing it silently is not: a mount that can never
			// reach ingest looks identical to a healthy one otherwise.
			guarded.LogRateLimited(err)
		}
	}
}

func (q *Queue) post(headers map[string]string, batch []any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("camada: transport panic")
		}
	}()
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	res := q.Transport(transport.Request{Method: "POST", URL: q.URL + "/e", Headers: headers, Body: body, Timeout: q.Timeout})
	if res.Status == 0 {
		return errors.New("camada: ingest unreachable")
	}
	return nil
}

// Stop ends the flush goroutine; what is queued stays until Drain. Idempotent.
func (q *Queue) Stop() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.stopped {
		q.stopped = true
		close(q.stop)
	}
}

// Drain ships everything queued, behind any flush in flight, until the queue is empty or ctx
// is done — the process is never held longer than the caller allows. No signal handlers are
// installed: an app owns its own shutdown.
func (q *Queue) Drain(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		q.flush(true)
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
