package camada

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/camada/camada-go/internal/guarded"
)

func TestLogRateLimitedWritesOneLineAMinute(t *testing.T) {
	var buf bytes.Buffer
	SetLogger(log.New(&buf, "", 0))
	t.Cleanup(func() { SetLogger(log.Default()) })
	guarded.Reset()
	LogRateLimited("first")
	LogRateLimited("second")
	out := buf.String()
	if strings.Count(out, "\n") > 1 || !strings.Contains(out, "[camada] suppressed error (SDK fails open)") {
		t.Fatalf("%q", out)
	}
}
