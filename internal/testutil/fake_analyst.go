package testutil

// An in-process transport standing in for the analyst Worker (GET /snapshot, POST /e): the Go
// twin of camada-python/tests/fake_analyst.py. Every field is read under the mutex because the
// snapshot client polls from its own goroutine; tests change fields through Update.

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/camada-app/camada-go/internal/transport"
)

const (
	BlockedIP    = "203.0.113.66" // an ip4 entry in v3-basic and v4-basic
	ChallengedIP = "192.0.2.20"   // a challenge-only ip4 entry in v4-basic
	AllowedIP    = "10.0.0.7"     // allow-listed inside the blocked 10.0.0.0/8
	// v5-rules only (§D3): the ordered custom rules the golden container carries.
	RuleBlockedIP      = "198.51.100.7"                      // builtin:block, a manual-block entry
	SkipPath           = "/healthz"                          // cr_00000000000a, skip — beats every side
	RuleBlockedPath    = "/api/v2/dump"                      // cr_00000000000c, block by path regex
	WarnUA             = "Scrapy/2.11 (+https://scrapy.org)" // cr_00000000000e, warn
	BlockedUA          = "curl/8.4.0"                        // cr_00000000000f, block
	BlockedHeader      = "x-api-key"                         // cr_000000000019, `header is` -> block
	BlockedHeaderValue = "leaked-key-1"
)

var metaFiles = map[string]string{"v3": "blk3/v3-basic.meta.json", "v4": "blk3/v4-basic.meta.json", "v5": "blk5/v5-rules.meta.json"}
var binFiles = map[string]string{"v3": "blk3/v3-basic.bin", "v4": "blk3/v4-basic.bin", "v5": "blk5/v5-rules.bin"}

// Frame is the GET /snapshot 200 body: [u32 LE meta length][meta JSON][BLK container].
func Frame(meta []byte, body []byte) []byte {
	out := binary.LittleEndian.AppendUint32(nil, uint32(len(meta)))
	return append(append(out, meta...), body...)
}

// FakeAnalyst records what the SDK sent and answers from the golden containers.
type FakeAnalyst struct {
	t  testing.TB
	mu sync.Mutex

	Events           [][]map[string]any // batches POSTed to /e
	SDKHeaders       []string           // x-camada-sdk seen on /snapshot and /e
	SnapshotVersions []string           // x-camada-snapshot seen on /snapshot
	SnapshotRequests []transport.Request

	Config         map[string]any
	SnapshotDown   bool
	IngestDown     bool
	SnapshotStatus int    // force a status (204, 304, 401, 500); 0 = answer normally
	Container      string // v3 | v4 | v5
	Gzip           bool   // gzip the frame when the client asks for it
	IngestStatus   int
}

// NewFakeAnalyst is a healthy analyst serving the v3 container with the seed's tenant config.
func NewFakeAnalyst(t testing.TB) *FakeAnalyst {
	return &FakeAnalyst{
		t: t,
		Config: map[string]any{
			"tenant": "acme", "beacon": true, "sample": 1, "exclude": []string{}, "trusted_proxy": map[string]any{"mode": "none"}, "poll_seconds": 30,
		},
		Container:    "v3",
		IngestStatus: 202,
	}
}

// Update changes the analyst's state under its lock.
func (a *FakeAnalyst) Update(fn func(a *FakeAnalyst)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn(a)
}

// SetConfig changes one tenant-config key.
func (a *FakeAnalyst) SetConfig(key string, value any) {
	a.Update(func(a *FakeAnalyst) { a.Config[key] = value })
}

// Meta is the current container's meta JSON.
func (a *FakeAnalyst) Meta() []byte { return ReadBin(a.t, metaFiles[a.Container]) }

// Version is the current container's meta.version.
func (a *FakeAnalyst) Version() string {
	var m struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(a.Meta(), &m)
	return m.Version
}

// Binary is the current container.
func (a *FakeAnalyst) Binary() []byte { return ReadBin(a.t, binFiles[a.Container]) }

// Etag is what the analyst stamps on the current container.
func (a *FakeAnalyst) Etag() string {
	suffix := map[string]string{"v3": "", "v4": "-v4", "v5": "-v5"}[a.Container]
	return `"` + a.Version() + suffix + `"`
}

// Transport is the seam the SDK is handed.
func (a *FakeAnalyst) Transport(req transport.Request) transport.Response {
	a.mu.Lock()
	defer a.mu.Unlock()
	if strings.HasSuffix(req.URL, "/snapshot") || strings.HasSuffix(req.URL, "/e") {
		a.SDKHeaders = append(a.SDKHeaders, req.Headers["x-camada-sdk"])
	}
	if strings.HasSuffix(req.URL, "/snapshot") {
		a.SnapshotRequests = append(a.SnapshotRequests, req)
		a.SnapshotVersions = append(a.SnapshotVersions, req.Headers["x-camada-snapshot"])
		if a.SnapshotDown {
			return transport.Response{Headers: map[string]string{}}
		}
		cfg, _ := json.Marshal(a.Config)
		headers := map[string]string{"x-camada-config": string(cfg), "cache-control": "private, no-store"}
		if a.SnapshotStatus != 0 {
			return transport.Response{Status: a.SnapshotStatus, Headers: headers, Body: []byte{}}
		}
		if req.Headers["if-none-match"] == a.Etag() {
			return transport.Response{Status: 304, Headers: headers, Body: []byte{}}
		}
		body := Frame(a.Meta(), a.Binary())
		headers["etag"] = a.Etag()
		if a.Gzip && strings.Contains(req.Headers["accept-encoding"], "gzip") {
			var buf bytes.Buffer
			w := gzip.NewWriter(&buf)
			_, _ = w.Write(body)
			_ = w.Close()
			headers["content-encoding"] = "gzip"
			body = buf.Bytes()
		}
		return transport.Response{Status: 200, Headers: headers, Body: body}
	}
	if a.IngestDown {
		return transport.Response{Headers: map[string]string{}}
	}
	if strings.HasSuffix(req.URL, "/e") {
		var batch []map[string]any
		if err := json.Unmarshal(req.Body, &batch); err != nil {
			a.t.Errorf("fake analyst: bad batch: %v", err)
		}
		a.Events = append(a.Events, batch)
		return transport.Response{Status: a.IngestStatus, Headers: map[string]string{}, Body: []byte{}}
	}
	a.t.Errorf("unmocked request: %s", req.URL)
	return transport.Response{Headers: map[string]string{}}
}

// AllEvents flattens every batch.
func (a *FakeAnalyst) AllEvents() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []map[string]any
	for _, b := range a.Events {
		out = append(out, b...)
	}
	return out
}

// Batches is a copy of the batches POSTed so far.
func (a *FakeAnalyst) Batches() [][]map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([][]map[string]any{}, a.Events...)
}

// Snapshots is a copy of the snapshot requests seen so far.
func (a *FakeAnalyst) Snapshots() []transport.Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]transport.Request{}, a.SnapshotRequests...)
}

// SDKHeaderList is a copy of the x-camada-sdk values seen so far.
func (a *FakeAnalyst) SDKHeaderList() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string{}, a.SDKHeaders...)
}

// SnapshotVersionList is a copy of the x-camada-snapshot values seen so far.
func (a *FakeAnalyst) SnapshotVersionList() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string{}, a.SnapshotVersions...)
}
