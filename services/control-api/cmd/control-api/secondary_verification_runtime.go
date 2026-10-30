package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

const (
	secondaryVerificationPollInterval = time.Minute
	secondaryVerificationBatch        = 100
)

// runSecondaryVerificationEnforcement stops the sites of overdue FX57 requests
// and restores them once the reverification is approved, every minute; each
// change is republished at once (edgeautopublish.RequestRepublicationTx).
// Errors are logged and retried on the next tick.
func runSecondaryVerificationEnforcement(ctx context.Context, store *identity.Store, logger *slog.Logger) {
	ticker := time.NewTicker(secondaryVerificationPollInterval)
	defer ticker.Stop()
	for {
		pass, err := store.EnforceSecondaryVerificationDeadlines(ctx, edgeautopublish.SecondaryVerificationRepublisher{}, secondaryVerificationBatch)
		if err != nil && ctx.Err() == nil {
			logger.Warn("secondary verification enforcement failed", "error", err)
		} else if pass.Held+pass.Released > 0 {
			logger.Info("secondary verification enforcement", "stopped_requests", pass.Held, "restored_requests", pass.Released)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

const accountSuspensionPollInterval = 15 * time.Second

// runAccountSuspensionEnforcement takes the sites of disabled users, suspended
// memberships and suspended/closed tenants off the nodes, and restores them
// once the owner is active again; each change is
// republished at once. Errors are logged and retried on the next tick.
func runAccountSuspensionEnforcement(ctx context.Context, store *identity.Store, logger *slog.Logger) {
	ticker := time.NewTicker(accountSuspensionPollInterval)
	defer ticker.Stop()
	for {
		pass, err := store.EnforceAccountSuspensions(ctx, edgeautopublish.AccountSuspensionRepublisher{}, secondaryVerificationBatch)
		if err != nil && ctx.Err() == nil {
			logger.Warn("account suspension enforcement failed", "error", err)
		} else if pass.Held+pass.Released > 0 {
			logger.Info("account suspension enforcement", "stopped_owners", pass.Held, "restored_owners", pass.Released)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
