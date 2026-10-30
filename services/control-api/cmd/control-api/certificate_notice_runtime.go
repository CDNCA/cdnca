package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/certnotify"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemothersettings"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Certificate expiry reminders (certnotify): every installation
// runs them, uploaded certificates included, independent of the ACME runtime.
const (
	certificateNoticeInterval = time.Hour
	certificateNoticeBatch    = 500
)

type certificateNoticeWorker struct {
	notifier *certnotify.Notifier
	interval time.Duration
}

func buildCertificateNoticeWorker(pool *pgxpool.Pool) (*certificateNoticeWorker, error) {
	if pool == nil {
		return nil, nil
	}
	notifications, err := notification.NewStore(pool)
	if err != nil {
		return nil, err
	}
	notifier, err := certnotify.New(pool, notifications, time.Now, func(ctx context.Context, tx pgx.Tx) ([]int, error) {
		return systemothersettings.CertificateExpiryNoticeDays(ctx, tx)
	})
	if err != nil {
		return nil, err
	}
	return &certificateNoticeWorker{notifier: notifier, interval: certificateNoticeInterval}, nil
}

// Run checks once at start and then every interval; a failed pass is logged
// and retried on the next tick.
func (worker *certificateNoticeWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(worker.interval)
	defer ticker.Stop()
	for {
		sent, err := worker.notifier.NotifyExpiring(ctx, certificateNoticeBatch)
		if err != nil && ctx.Err() == nil {
			slog.Default().Warn("certificate expiry notices failed", "error", err)
		} else if sent > 0 {
			slog.Default().Info("certificate expiry notices enqueued", "count", sent)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
