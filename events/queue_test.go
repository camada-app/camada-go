package events

// Queue: fire-and-forget batched shipping to POST /e. Nothing here may ever panic into the
// customer's request path, and a dead ingest must cost nothing but dropped telemetry.

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/camada/camada-go/internal/testutil"
	"github.com/camada/camada-go/internal/transport"
)

func queue(a *testutil.FakeAnalyst, o QueueOptions) *Queue {
	o.Transport, o.SDK = a.Transport, "@camada/go/0.0.0"
	return NewQueue("https://analyst.test", "tok-test", o)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition never held")
}

func rows(is ...int) []map[string]any {
	var out []map[string]any
	for _, i := range is {
		out = append(out, map[string]any{"i": float64(i)})
	}
	return out
}

func TestFlushPostsAJSONArrayWithTheTenantAndSDKHeaders(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	q := queue(a, QueueOptions{})
	q.Push(map[string]any{"p": "/"})
	q.Flush()
	if got := a.Batches(); !reflect.DeepEqual(got, [][]map[string]any{{{"p": "/"}}}) {
		t.Fatalf("%v", got)
	}
	if got := a.SDKHeaderList(); !reflect.DeepEqual(got, []string{"@camada/go/0.0.0"}) {
		t.Fatalf("%v", got)
	}
	q.Stop()
}

func TestFlushesWhenTheBatchSizeIsReached(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	q := queue(a, QueueOptions{MaxBatch: 3, FlushInterval: time.Minute})
	for i := 0; i < 3; i++ {
		q.Push(map[string]any{"i": i})
	}
	waitFor(t, func() bool { return len(a.Batches()) > 0 })
	if got := a.Batches(); !reflect.DeepEqual(got, [][]map[string]any{rows(0, 1, 2)}) {
		t.Fatalf("%v", got)
	}
	q.Stop()
}

func TestFlushesOnTheInterval(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	q := queue(a, QueueOptions{FlushInterval: 20 * time.Millisecond})
	q.Push(map[string]any{"i": 1})
	waitFor(t, func() bool { return len(a.Batches()) > 0 })
	if got := a.Batches(); !reflect.DeepEqual(got, [][]map[string]any{rows(1)}) {
		t.Fatalf("%v", got)
	}
	q.Stop()
}

func TestDrainsInSlicesOf1000(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	q := queue(a, QueueOptions{MaxBatch: 5000, MaxQueue: 5000, FlushInterval: time.Minute})
	for i := 0; i < 1500; i++ {
		q.Push(map[string]any{"i": i})
	}
	q.Flush()
	var sizes []int
	for _, b := range a.Batches() {
		sizes = append(sizes, len(b))
	}
	if !reflect.DeepEqual(sizes, []int{1000, 500}) {
		t.Fatalf("%v", sizes)
	}
	q.Stop()
}

func TestDropsOldestBeyondTheQueueCap(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	q := queue(a, QueueOptions{MaxQueue: 3, MaxBatch: 100, FlushInterval: time.Minute})
	for i := 0; i < 5; i++ {
		q.Push(map[string]any{"i": i})
	}
	if q.Size() != 3 || q.Dropped() != 2 {
		t.Fatalf("size %d dropped %d", q.Size(), q.Dropped())
	}
	q.Flush()
	if got := a.Batches(); !reflect.DeepEqual(got, [][]map[string]any{rows(2, 3, 4)}) {
		t.Fatalf("%v", got)
	}
	q.Stop()
}

func TestDeadIngestDropsSilentlyAndRecovers(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	a.IngestDown = true
	q := queue(a, QueueOptions{FlushInterval: time.Minute})
	q.Push(map[string]any{"i": 1})
	q.Flush()
	if q.Dropped() != 1 || q.Size() != 0 {
		t.Fatalf("dropped %d size %d", q.Dropped(), q.Size())
	}
	a.Update(func(a *testutil.FakeAnalyst) { a.IngestDown = false })
	q.Push(map[string]any{"i": 2})
	q.Flush()
	if got := a.Batches(); !reflect.DeepEqual(got, [][]map[string]any{rows(2)}) {
		t.Fatalf("%v", got)
	}
	q.Stop()
}

func TestPushAndFlushNeverPanic(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	q := queue(a, QueueOptions{FlushInterval: time.Minute})
	q.Transport = nil // a broken transport is swallowed and logged, never raised
	q.Push(map[string]any{"i": 1})
	q.Push(make(chan int)) // unmarshalable: dropped, never a panic
	q.Flush()
	if q.Size() != 0 || q.Dropped() != 2 {
		t.Fatalf("size %d dropped %d", q.Size(), q.Dropped())
	}
	q.Stop()
}

func TestStopEndsTheFlushGoroutine(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	q := queue(a, QueueOptions{FlushInterval: 10 * time.Millisecond})
	q.Push(map[string]any{"i": 1})
	q.Stop()
	time.Sleep(30 * time.Millisecond)
	n := len(a.Batches())
	q.Push(map[string]any{"i": 2})
	time.Sleep(30 * time.Millisecond)
	if len(a.Batches()) != n { // nothing flushes on its own after Stop
		t.Fatal("flushed after stop")
	}
}

func TestAWaitingDrainRunsBehindTheFlushInFlight(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	gate := make(chan struct{})
	inner := a.Transport
	q := queue(a, QueueOptions{MaxBatch: 1, FlushInterval: time.Minute})
	q.Transport = func(req transport.Request) transport.Response {
		<-gate // the periodic flush is mid-POST when the exit drain starts
		return inner(req)
	}
	q.Push(map[string]any{"i": 1})
	waitFor(t, func() bool { return q.InFlight() })
	q.Push(map[string]any{"i": 2})
	q.Flush() // the request-path flush yields to the one in flight
	if len(a.Batches()) != 0 {
		t.Fatal("flushed past the gate")
	}
	done := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		q.Drain(ctx)
		close(done)
	}()
	close(gate)
	<-done
	if got := a.Batches(); !reflect.DeepEqual(got, [][]map[string]any{rows(1), rows(2)}) {
		t.Fatalf("%v", got)
	}
	q.Stop()
}

func TestDrainGivesUpWhenTheBudgetIsSpent(t *testing.T) {
	a := testutil.NewFakeAnalyst(t)
	q := queue(a, QueueOptions{FlushInterval: time.Minute})
	q.Transport = func(req transport.Request) transport.Response {
		time.Sleep(300 * time.Millisecond)
		return a.Transport(req)
	}
	q.Push(map[string]any{"i": 1})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	q.Drain(ctx)
	if time.Since(t0) > 200*time.Millisecond {
		t.Fatal("drain outlived its budget")
	}
	q.Stop()
}
