package edgepublish

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type originAuthDeliveryStoreStub struct{}

func (originAuthDeliveryStoreStub) CreateSystemSecretRolloutTx(context.Context, pgx.Tx,
	edgedeployment.SystemSecretRolloutRequest, edgedeployment.SecretArtifactBuilder) (edgedeployment.CreateRolloutResult, error) {
	return edgedeployment.CreateRolloutResult{}, nil
}

type originAuthDeliveryAuditStub struct{}

func (originAuthDeliveryAuditStub) Append(context.Context, pgx.Tx, audit.Event) error { return nil }

func originAuthDeliveryHealth() edgedeployment.HealthCheckPolicy {
	return edgedeployment.HealthCheckPolicy{ActivationTimeout: 30 * time.Second, ObservationWindow: 15 * time.Second,
		RequiredConsecutiveSuccesses: 3}
}

func newTestOriginAuthDeliverer(t *testing.T, retry time.Duration) *OriginAuthDeliverer {
	t.Helper()
	producer, err := NewOriginAuthArtifactProducer(site09ArtifactSigner{private: ed25519.NewKeyFromSeed(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	deliverer, err := NewOriginAuthDeliverer(&pgxpool.Pool{}, originAuthDeliveryStoreStub{}, site09ProductionSource{},
		producer, originAuthDeliveryAuditStub{}, OriginAuthDelivererConfig{RetryDelay: retry, HealthCheck: originAuthDeliveryHealth()})
	if err != nil {
		t.Fatal(err)
	}
	return deliverer
}

func TestOriginAuthDelivererRejectsIncompleteDependencies(t *testing.T) {
	producer, err := NewOriginAuthArtifactProducer(site09ArtifactSigner{private: ed25519.NewKeyFromSeed(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	for name, build := range map[string]func() (*OriginAuthDeliverer, error){
		"pool": func() (*OriginAuthDeliverer, error) {
			return NewOriginAuthDeliverer(nil, originAuthDeliveryStoreStub{}, site09ProductionSource{}, producer,
				originAuthDeliveryAuditStub{}, OriginAuthDelivererConfig{HealthCheck: originAuthDeliveryHealth()})
		},
		"producer": func() (*OriginAuthDeliverer, error) {
			return NewOriginAuthDeliverer(&pgxpool.Pool{}, originAuthDeliveryStoreStub{}, site09ProductionSource{}, nil,
				originAuthDeliveryAuditStub{}, OriginAuthDelivererConfig{HealthCheck: originAuthDeliveryHealth()})
		},
		"auditor": func() (*OriginAuthDeliverer, error) {
			return NewOriginAuthDeliverer(&pgxpool.Pool{}, originAuthDeliveryStoreStub{}, site09ProductionSource{}, producer,
				nil, OriginAuthDelivererConfig{HealthCheck: originAuthDeliveryHealth()})
		},
		"health": func() (*OriginAuthDeliverer, error) {
			return NewOriginAuthDeliverer(&pgxpool.Pool{}, originAuthDeliveryStoreStub{}, site09ProductionSource{}, producer,
				originAuthDeliveryAuditStub{}, OriginAuthDelivererConfig{})
		},
		"retry": func() (*OriginAuthDeliverer, error) {
			return NewOriginAuthDeliverer(&pgxpool.Pool{}, originAuthDeliveryStoreStub{}, site09ProductionSource{}, producer,
				originAuthDeliveryAuditStub{}, OriginAuthDelivererConfig{RetryDelay: 2 * time.Hour, HealthCheck: originAuthDeliveryHealth()})
		},
	} {
		if _, err := build(); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	deliverer := newTestOriginAuthDeliverer(t, 0)
	if deliverer.config.RetryDelay != time.Minute {
		t.Fatalf("default retry delay = %v", deliverer.config.RetryDelay)
	}
	if _, err := deliverer.Deliver(t.Context(), uuid.New(), uuid.Nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Deliver without an accountable owner: %v", err)
	}
}

// The subscriber sees a stable reason, never an error text (which may name
// internals).
func TestOriginAuthDeliveryFailureReason(t *testing.T) {
	for err, want := range map[error]string{
		originauthcontrol.ErrEncryptionUnavailable:                        OriginAuthDeliveryCredential,
		fmt.Errorf("x: %w", originauthcontrol.ErrValidation):              OriginAuthDeliveryPublicationInvalid,
		originauthcontrol.ErrNotFound:                                     OriginAuthDeliveryPublicationInvalid,
		ErrOriginAuthArtifact:                                             OriginAuthDeliveryPublicationInvalid,
		edgedeployment.ErrNodeRecipientKeyUnavailable:                     OriginAuthDeliveryNodeRejected,
		fmt.Errorf("y: %w", edgedeployment.ErrConfigurationScopeConflict): OriginAuthDeliveryNodeRejected,
		errors.New("connection reset"):                                    OriginAuthDeliveryUnavailable,
	} {
		if got := OriginAuthDeliveryFailureReason(err); got != want {
			t.Errorf("%v: reason = %q, want %q", err, got, want)
		}
	}
}

func TestOriginAuthDeliveryBackoffDoublesToTheSystemMaximum(t *testing.T) {
	deliverer := newTestOriginAuthDeliverer(t, 30*time.Second)
	for failures, want := range map[int]time.Duration{1: 30 * time.Second, 2: time.Minute, 3: 2 * time.Minute,
		6: systemRepublicationMaxBackoff, 60: systemRepublicationMaxBackoff} {
		if got := deliverer.backoff(failures); got != want {
			t.Errorf("backoff(%d) = %v, want %v", failures, got, want)
		}
	}
}

// Build failures count per scope and revision (stored, fix-mktsiteconf7 §2):
// a stored count of an older revision does not apply, the next failure of
// the same revision adds one, of a newer revision starts at one.
func TestOriginAuthDeliveryBuildFailuresRestartOnANewRevision(t *testing.T) {
	at := time.Unix(1_800_000_000, 0).UTC()
	stored := &originAuthBuildFailure{revision: 3, attempts: 2, at: at, reason: OriginAuthDeliveryCredential}
	if got, found := currentBuildFailure(stored, 3); !found || got.attempts != 2 {
		t.Fatalf("currentBuildFailure(3) = %+v, %v", got, found)
	}
	if _, found := currentBuildFailure(stored, 4); found {
		t.Fatal("revision 4 inherited revision 3's failures")
	}
	if _, found := currentBuildFailure(nil, 3); found {
		t.Fatal("no stored row reported a failure")
	}
	next := nextBuildFailure(stored, 3, OriginAuthDeliveryPublicationInvalid, at.Add(time.Second))
	if next.attempts != 3 || next.reason != OriginAuthDeliveryPublicationInvalid || !next.at.Equal(at.Add(time.Second)) {
		t.Fatalf("next of the same revision = %+v", next)
	}
	if next := nextBuildFailure(stored, 4, OriginAuthDeliveryCredential, at); next.attempts != 1 || next.revision != 4 {
		t.Fatalf("next of a newer revision = %+v", next)
	}
	if next := nextBuildFailure(nil, 5, OriginAuthDeliveryCredential, at); next.attempts != 1 || next.revision != 5 {
		t.Fatalf("first failure = %+v", next)
	}
	// The count is bounded by the column check (1..100).
	capped := nextBuildFailure(&originAuthBuildFailure{revision: 3, attempts: 100}, 3, OriginAuthDeliveryCredential, at)
	if capped.attempts != 100 {
		t.Fatalf("capped attempts = %d", capped.attempts)
	}
}
