package securityrulereport

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

type Reporter struct {
	collector      *Collector
	store          *Store
	client         *Client
	installationID uuid.UUID
	privateKey     ed25519.PrivateKey
	interval       time.Duration
	logger         *slog.Logger
}

type Config struct {
	Collector      *Collector
	Store          *Store
	Client         *Client
	InstallationID uuid.UUID
	PrivateKey     ed25519.PrivateKey
	Interval       time.Duration
	Logger         *slog.Logger
}

func NewReporter(config Config) (*Reporter, error) {
	if config.Collector == nil || config.Store == nil || config.Client == nil || config.InstallationID == uuid.Nil ||
		len(config.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid security custom rule report runtime configuration")
	}
	if config.Interval <= 0 {
		config.Interval = 5 * time.Minute
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Reporter{collector: config.Collector, store: config.Store, client: config.Client, installationID: config.InstallationID,
		privateKey: append(ed25519.PrivateKey(nil), config.PrivateKey...), interval: config.Interval, logger: config.Logger}, nil
}

func (reporter *Reporter) Run(ctx context.Context) error {
	backoff := time.Duration(0)
	for {
		if err := reporter.ReportOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			reporter.logger.Warn("security custom rule report deferred", "error", err)
			_ = reporter.store.MarkFailed(ctx, reporter.installationID, err)
			backoff = min(max(backoff*2, 15*time.Second), 30*time.Minute)
		} else {
			backoff = 0
		}
		timer := time.NewTimer(max(reporter.interval, backoff))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// ReportOnce collects, records and (when changed or unsent) uploads one snapshot.
func (reporter *Reporter) ReportOnce(ctx context.Context) error {
	report, digest, err := reporter.collector.Collect(ctx, reporter.installationID)
	if err != nil {
		return err
	}
	snapshot, send, err := reporter.store.Prepare(ctx, reporter.installationID, report, digest)
	if err != nil || !send {
		return err
	}
	if err := reporter.client.Report(ctx, snapshot, reporter.privateKey); err != nil {
		return err
	}
	return reporter.store.MarkSent(ctx, snapshot)
}
