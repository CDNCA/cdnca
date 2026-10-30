package approvalcenter

import (
	"context"
	"log/slog"
	"time"
)

// RecoveryInterval: the recovery pass runs at control plane start and then every minute.
const RecoveryInterval = time.Minute

// StaleMarker is Store.MarkStaleExecuting.
type StaleMarker interface {
	MarkStaleExecuting(context.Context) (int, error)
}

// RunRecovery marks requests left executing by an interrupted process as
// unknown (approval-center 遗留 5). It never replays them: a replay could run
// the operation twice. Errors are logged and retried on the next tick.
func RunRecovery(ctx context.Context, marker StaleMarker, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		marked, err := marker.MarkStaleExecuting(ctx)
		if err != nil && ctx.Err() == nil {
			logger.Warn("approval center recovery failed", "error", err)
		} else if marked > 0 {
			logger.Info("approval center recovery marked requests outcome unknown", "requests", marked)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
