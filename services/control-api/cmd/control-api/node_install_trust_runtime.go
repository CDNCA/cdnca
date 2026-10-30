package main

import (
	"context"
	"log/slog"

	"github.com/cdnca/cdnca/services/control-api/internal/nativebackup"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/jackc/pgx/v5/pgxpool"
)

// openNodeInstallTrustWatcher keeps the node install trust (upgrade-trust.json
// and the digests in node-install-defaults / runtime-config.js) in step with
// the control-plane domain's current resolution and control.env (fix-btenv5):
// checked at start and every 10 minutes, republished on a difference (audited),
// failure streaks notified to nodes.manage platform members.
func openNodeInstallTrustWatcher(pool *pgxpool.Pool) (*nativebackup.NodeInstallTrustWatcher, error) {
	alerts, err := notification.NewStore(pool)
	if err != nil {
		return nil, err
	}
	logger := slog.Default().With("component", "node_install_trust")
	return &nativebackup.NodeInstallTrustWatcher{Layout: nativebackup.Layout{Root: "/"}, Logger: logger,
		OnPublished: func(ctx context.Context, change nativebackup.NodeInstallTrustChange) {
			if err := nativebackup.AuditNodeInstallTrustRepublish(context.WithoutCancel(ctx), pool, change); err != nil {
				logger.Error("cannot audit the node install trust republication", "error", err)
			}
		},
		OnAlert: func(ctx context.Context, alert nativebackup.NodeInstallTrustAlert) error {
			return nativebackup.AlertNodeInstallTrustFailed(ctx, pool, alerts, alert)
		}}, nil
}
