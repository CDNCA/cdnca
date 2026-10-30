package site

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// AutoDNSPointer writes one domain's CNAME through the task's account and
// reads it back (dnsproviderremotesource.SiteAutoDNSWriter). before is the
// previous target; code a stable failure code; temporary whether a retry
// later may succeed.
type AutoDNSPointer func(ctx context.Context, scopeID, siteID, providerID uuid.UUID, domain, target string) (before, code string, temporary bool)

// AutoDNSWorker runs the due site_auto_dns_tasks.
type AutoDNSWorker struct {
	store    *Store
	point    AutoDNSPointer
	interval time.Duration
	logger   *slog.Logger
}

func NewAutoDNSWorker(store *Store, point AutoDNSPointer, logger *slog.Logger) *AutoDNSWorker {
	if logger == nil {
		logger = slog.Default()
	}
	return &AutoDNSWorker{store: store, point: point, interval: 10 * time.Second, logger: logger}
}

func (w *AutoDNSWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		if _, err := w.RunOnce(ctx); err != nil && ctx.Err() == nil {
			w.logger.Warn("site auto DNS round failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// RunOnce handles one batch of due tasks and returns how many it handled.
func (w *AutoDNSWorker) RunOnce(ctx context.Context) (int, error) {
	claims, err := w.store.ClaimAutoDNS(ctx, 20, 5*time.Minute)
	if err != nil {
		return 0, err
	}
	for _, claim := range claims {
		err := w.store.CompleteAutoDNS(ctx, claim, w.apply(ctx, claim))
		if errors.Is(err, ErrAutoDNSClaimLost) {
			// Another claim owns the task now; this result is stale.
			w.logger.Warn("site auto DNS claim lost before completion", "site_id", claim.SiteID,
				"generation", claim.Generation, "attempt", claim.Attempts)
			continue
		}
		if err != nil {
			return 0, err
		}
	}
	return len(claims), nil
}

// apply points every domain; the task is done only when all of them point
// at the CNAME. A site still waiting for its CNAME retries later.
func (w *AutoDNSWorker) apply(ctx context.Context, claim AutoDNSClaim) AutoDNSOutcome {
	if claim.CNAME == "" {
		return AutoDNSOutcome{Code: AutoDNSWaitingCNAME, Temporary: true}
	}
	outcome := AutoDNSOutcome{Results: make([]AutoDNSRecordRow, 0, len(claim.Domains))}
	allTemporary := true
	for _, domain := range claim.Domains {
		before, code, temporary := w.point(ctx, claim.ScopeID, claim.SiteID, claim.ProviderID, domain, claim.CNAME)
		outcome.Results = append(outcome.Results, AutoDNSRecordRow{Domain: domain, Before: before, Code: code})
		if code != "" {
			if outcome.Code == "" {
				outcome.Code = code
			}
			allTemporary = allTemporary && temporary
		}
	}
	outcome.Temporary = outcome.Code != "" && allTemporary
	return outcome
}
