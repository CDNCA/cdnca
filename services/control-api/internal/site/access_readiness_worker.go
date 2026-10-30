package site

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
)

// DNSCheckWorker runs the due site_dns_resolution_checks through the
// control plane host's resolver (access_readiness dns_resolved).
type DNSCheckWorker struct {
	store    *Store
	resolver DNSResolver
	interval time.Duration
	logger   *slog.Logger
}

func NewDNSCheckWorker(store *Store, resolver DNSResolver, logger *slog.Logger) *DNSCheckWorker {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DNSCheckWorker{store: store, resolver: resolver, interval: 15 * time.Second, logger: logger}
}

func (w *DNSCheckWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		if _, err := w.RunOnce(ctx); err != nil && ctx.Err() == nil {
			w.logger.Warn("site DNS resolution check round failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// RunOnce checks one batch of due sites and returns how many it checked.
func (w *DNSCheckWorker) RunOnce(ctx context.Context) (int, error) {
	claims, err := w.store.ClaimDNSChecks(ctx, 50, 5*time.Minute)
	if err != nil {
		return 0, err
	}
	for _, claim := range claims {
		if err := w.store.CompleteDNSCheck(ctx, claim, resolveSiteDNS(ctx, w.resolver, claim.Target)); err != nil {
			return 0, err
		}
	}
	return len(claims), nil
}

// CheckAccessNow is 详情 > 接入状态 > 立即检查 (once a minute per site).
func (s *Service) CheckAccessNow(ctx context.Context, actor Actor, siteID uuid.UUID) (AccessReadiness, error) {
	if !validActor(actor) || siteID == uuid.Nil {
		return AccessReadiness{}, ErrInvalidInput
	}
	return s.store.CheckAccessNow(ctx, actor, siteID, net.DefaultResolver)
}
