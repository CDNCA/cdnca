package certificatepublish

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type redeliveryTestSigner struct{ private ed25519.PrivateKey }

func (redeliveryTestSigner) ArtifactSigningKeyID() string { return "redelivery-unit" }
func (signer redeliveryTestSigner) ArtifactSigningPublicKey() ed25519.PublicKey {
	return signer.private.Public().(ed25519.PublicKey)
}
func (signer redeliveryTestSigner) SignArtifact(_ context.Context, value []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, value), nil
}

type redeliveryUnitAssets struct{}

func (redeliveryUnitAssets) UseRedeliveryMaterialsInTx(context.Context, pgx.Tx, uuid.UUID,
	[]certificateasset.RedeliverySite, certificateasset.OpaquePublicationResolver,
	certificateasset.PublicationConsumer) ([]uuid.UUID, error) {
	return nil, nil
}

type redeliveryUnitRollouts struct{}

func (redeliveryUnitRollouts) CreateSystemSecretRolloutTx(context.Context, pgx.Tx, edgedeployment.SystemSecretRolloutRequest,
	edgedeployment.SecretArtifactBuilder) (edgedeployment.CreateRolloutResult, error) {
	return edgedeployment.CreateRolloutResult{}, nil
}

func newUnitRedeliverer(t *testing.T, config RedelivererConfig, now func() time.Time) (*Redeliverer, error) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://unused@127.0.0.1:1/unused")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	producer, err := NewProducer(redeliveryTestSigner{private: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))})
	if err != nil {
		t.Fatal(err)
	}
	return NewRedeliverer(pool, redeliveryUnitAssets{}, redeliveryUnitRollouts{}, producer,
		func(context.Context, pgx.Tx, uuid.UUID, []uuid.UUID) (map[uuid.UUID][]uuid.UUID, error) {
			return nil, nil
		},
		func(context.Context, pgx.Tx, uuid.UUID, time.Time) (bool, error) { return false, nil },
		func(context.Context, uuid.UUID, uuid.UUID, time.Time) (bool, error) { return false, nil },
		nil, config, now)
}

func TestRedelivererRejectsInvalidConfiguration(t *testing.T) {
	for name, mutate := range map[string]func(*RedelivererConfig){
		"no sweep interval":        func(config *RedelivererConfig) { config.SweepInterval = 0 },
		"sweep beyond an hour":     func(config *RedelivererConfig) { config.SweepInterval = 2 * time.Hour },
		"round under a minute":     func(config *RedelivererConfig) { config.RoundTimeout = time.Second },
		"no retry base":            func(config *RedelivererConfig) { config.RetryBase = 0 },
		"maximum below the base":   func(config *RedelivererConfig) { config.RetryMaximum = config.RetryBase / 2 },
		"no activation timeout":    func(config *RedelivererConfig) { config.HealthCheck.ActivationTimeout = 0 },
		"no consecutive successes": func(config *RedelivererConfig) { config.HealthCheck.RequiredConsecutiveSuccesses = 0 },
	} {
		config := DefaultRedelivererConfig()
		mutate(&config)
		if _, err := newUnitRedeliverer(t, config, time.Now); err != ErrInvalidInput {
			t.Errorf("%s: err = %v, want ErrInvalidInput", name, err)
		}
	}
	if _, err := newUnitRedeliverer(t, DefaultRedelivererConfig(), time.Now); err != nil {
		t.Fatalf("default configuration: %v", err)
	}
}

// A failed round of a node waits 1, 2, 4 ... minutes, at most an hour.
func TestRedeliveryRetryDelayDoublesUpToTheMaximum(t *testing.T) {
	redeliverer, err := newUnitRedeliverer(t, DefaultRedelivererConfig(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for attempt, want := range map[int]time.Duration{1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute,
		6: 32 * time.Minute, 7: time.Hour, 30: time.Hour} {
		if got := redeliverer.retryDelay(attempt); got != want {
			t.Errorf("attempt %d: delay %s, want %s", attempt, got, want)
		}
	}
}

// RunOnce sweeps at most once per interval: within it, it touches nothing
// (the unreachable pool would fail a sweep).
func TestRedeliveryRunOnceSweepsOncePerInterval(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	redeliverer, err := newUnitRedeliverer(t, DefaultRedelivererConfig(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := redeliverer.RunOnce(ctx); err == nil {
		t.Fatal("first RunOnce did not sweep (no error from the unreachable pool)")
	}
	now = now.Add(59 * time.Second)
	if worked, err := redeliverer.RunOnce(ctx); worked || err != nil {
		t.Fatalf("RunOnce within the interval = %t, %v; want no sweep", worked, err)
	}
	now = now.Add(time.Second)
	if _, err := redeliverer.RunOnce(ctx); err == nil {
		t.Fatal("RunOnce after the interval did not sweep")
	}
}

// The audit action is in the catalog (audit.TestEventCatalogCoversProductionActions
// also checks it is written).
func TestRedeliveryAuditActionIsCatalogued(t *testing.T) {
	if _, ok := audit.Lookup(auditRedeliveryDeliver); !ok {
		t.Fatalf("%s is not in the audit catalog", auditRedeliveryDeliver)
	}
}
