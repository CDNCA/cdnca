package wafreport

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"time"

	"github.com/google/uuid"
)

type Reporter struct {
	source interface {
		ListCustomWAFForReport(context.Context) ([]json.RawMessage, error)
	}
	store          *Store
	client         *Client
	installationID uuid.UUID
	privateKey     ed25519.PrivateKey
	interval       time.Duration
	now            func() time.Time
	logger         *slog.Logger
}

type Config struct {
	Source interface {
		ListCustomWAFForReport(context.Context) ([]json.RawMessage, error)
	}
	Store          *Store
	Client         *Client
	InstallationID uuid.UUID
	PrivateKey     ed25519.PrivateKey
	Interval       time.Duration
	Now            func() time.Time
	Logger         *slog.Logger
}

func NewReporter(config Config) (*Reporter, error) {
	if config.Source == nil || config.Store == nil || config.Client == nil || config.InstallationID == uuid.Nil || len(config.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid WAF report runtime configuration")
	}
	if config.Interval <= 0 {
		config.Interval = 5 * time.Minute
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Reporter{source: config.Source, store: config.Store, client: config.Client,
		installationID: config.InstallationID, privateKey: append(ed25519.PrivateKey(nil), config.PrivateKey...),
		interval: config.Interval, now: config.Now, logger: config.Logger}, nil
}

func (reporter *Reporter) Run(ctx context.Context) error {
	if reporter == nil {
		return errors.New("WAF report runtime is not configured")
	}
	backoff := time.Duration(0)
	for {
		if err := reporter.reportOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			reporter.logger.Warn("custom WAF rule report deferred", "error", err)
			backoff = nextBackoff(backoff, err)
		} else {
			backoff = 0
		}
		wait := reporter.interval
		if backoff > wait {
			wait = backoff
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (reporter *Reporter) reportOnce(ctx context.Context) error {
	policies, err := reporter.source.ListCustomWAFForReport(ctx)
	if err != nil {
		return err
	}
	canonical, digest, err := CanonicalPolicies(policies)
	if err != nil {
		return err
	}
	snapshot, send, err := reporter.store.Prepare(ctx, reporter.installationID, canonical, digest)
	if err != nil || !send {
		return err
	}
	if err := reporter.client.Report(ctx, snapshot, reporter.privateKey); err != nil {
		return err
	}
	return reporter.store.MarkSent(ctx, snapshot)
}

func nextBackoff(previous time.Duration, err error) time.Duration {
	if httpErr := new(HTTPError); errors.As(err, &httpErr) && httpErr.RetryAfter > 0 {
		if httpErr.RetryAfter > 30*time.Minute {
			return 30 * time.Minute
		}
		return httpErr.RetryAfter
	}
	if previous <= 0 {
		return 15 * time.Second
	}
	next := time.Duration(float64(previous) * 2)
	if next > 30*time.Minute || next < previous || math.IsNaN(float64(next)) {
		return 30 * time.Minute
	}
	return next
}
