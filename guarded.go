package camada

import (
	"log"

	"github.com/camada/camada-go/internal/guarded"
)

// SetLogger routes the SDK's one-line-a-minute error report somewhere other than log.Default().
func SetLogger(l *log.Logger) { guarded.SetLogger(l) }

// LogRateLimited reports a suppressed error the way the SDK does: at most one line a minute.
func LogRateLimited(err any) { guarded.LogRateLimited(err) }
