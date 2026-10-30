package dynroute

import (
	"context"
	"log/slog"
	"time"
)

// Intervals of the background maintenance (Run).
type Intervals struct {
	OCSP     time.Duration // dyntls.RefreshOCSP (it replaces a response past half its validity)
	Quota    time.Duration // soft cache quota cleaning
	ErrorLog time.Duration // error.log reading (the heartbeat reports the summary)
}

// DefaultIntervals: OCSP hourly (RefreshMaximum is 12 h), quota every 5
// minutes, error.log every 10 seconds.
var DefaultIntervals = Intervals{OCSP: time.Hour, Quota: 5 * time.Minute, ErrorLog: 10 * time.Second}

// Run is the runtime's background maintenance until ctx ends: OCSP refresh,
// soft quota cleaning and error.log reading on their intervals. Failures are
// logged and retried on the next tick; nothing here changes the index.
func (runtime *Runtime) Run(ctx context.Context, intervals Intervals) error {
	if intervals.OCSP <= 0 {
		intervals.OCSP = DefaultIntervals.OCSP
	}
	if intervals.Quota <= 0 {
		intervals.Quota = DefaultIntervals.Quota
	}
	if intervals.ErrorLog <= 0 {
		intervals.ErrorLog = DefaultIntervals.ErrorLog
	}
	ocsp, quota, errorLog := time.NewTicker(intervals.OCSP), time.NewTicker(intervals.Quota), time.NewTicker(intervals.ErrorLog)
	defer ocsp.Stop()
	defer quota.Stop()
	defer errorLog.Stop()
	runtime.refreshOCSP(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ocsp.C:
			runtime.refreshOCSP(ctx)
		case <-quota.C:
			if result, err := runtime.CleanQuota(ctx); err != nil {
				slog.Warn("dynamic routing cache quota cleaning failed", "error", err)
			} else if result.Removed > 0 {
				slog.Info("dynamic routing cache quota cleaned", "sites", result.Sites, "removed", result.Removed, "bytes", result.Bytes)
			}
		case <-errorLog.C:
			before := runtime.ErrorLogSnapshot().SevereTotal
			stats, err := runtime.ReadErrorLog()
			if err != nil {
				slog.Warn("dynamic routing error.log read failed", "error", err)
			} else if stats.SevereTotal > before && len(stats.Recent) > 0 {
				slog.Warn("dynamic routing OpenResty error", "new", stats.SevereTotal-before, "last", stats.Recent[len(stats.Recent)-1])
			}
		}
	}
}

func (runtime *Runtime) refreshOCSP(ctx context.Context) {
	for _, status := range runtime.RefreshOCSP(ctx) {
		if status.Err != nil {
			slog.Warn("dynamic routing OCSP refresh failed", "certificate_version_id", status.VersionID, "stapled", status.Stapled, "error", status.Err)
		}
	}
}
