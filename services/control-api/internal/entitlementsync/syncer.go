package entitlementsync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

const (
	defaultBackoffMin = time.Second
	defaultBackoffMax = 5 * time.Minute
)

type CredentialSource func(context.Context) (string, error)

type KeysetRefresher interface {
	Refresh(context.Context) error
}

type Config struct {
	Client           *Client
	Store            LocalStore
	Trust            *entitlementguard.TrustStore
	Keysets          KeysetRefresher
	InstallationID   uuid.UUID
	InstallationName string
	PrivateKey       ed25519.PrivateKey
	// EncryptionPublicKey: the X25519 installation encryption key sent with
	// the activation (PA-14; nil = none, registered later by artifact sync).
	EncryptionPublicKey []byte
	Activation          CredentialSource
	Now                 func() time.Time
	Wait                func(context.Context, time.Duration) error
	Jitter              func(time.Duration) time.Duration
	Logger              *slog.Logger
	BackoffMin          time.Duration
	BackoffMax          time.Duration
}

type Syncer struct {
	mu               sync.Mutex
	client           *Client
	store            LocalStore
	trust            *entitlementguard.TrustStore
	keysets          KeysetRefresher
	installationID   uuid.UUID
	installationName string
	privateKey       ed25519.PrivateKey
	encryptionKey    []byte
	activation       CredentialSource
	now              func() time.Time
	wait             func(context.Context, time.Duration) error
	jitter           func(time.Duration) time.Duration
	logger           *slog.Logger
	backoffMin       time.Duration
	backoffMax       time.Duration
}

func New(config Config) (*Syncer, error) {
	if config.Client == nil || config.Store == nil || config.Trust == nil || config.InstallationID == uuid.Nil ||
		len(config.PrivateKey) != ed25519.PrivateKeySize || config.InstallationName == "" {
		return nil, ErrInvalidConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Wait == nil {
		config.Wait = waitContext
	}
	if config.Jitter == nil {
		config.Jitter = boundedJitter
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.BackoffMin == 0 {
		config.BackoffMin = defaultBackoffMin
	}
	if config.BackoffMax == 0 {
		config.BackoffMax = defaultBackoffMax
	}
	if config.BackoffMin <= 0 || config.BackoffMax < config.BackoffMin {
		return nil, ErrInvalidConfiguration
	}
	return &Syncer{
		client: config.Client, store: config.Store, trust: config.Trust, keysets: config.Keysets,
		installationID: config.InstallationID, installationName: config.InstallationName,
		privateKey: append(ed25519.PrivateKey(nil), config.PrivateKey...), activation: config.Activation,
		encryptionKey: append([]byte(nil), config.EncryptionPublicKey...),
		now:           config.Now, wait: config.Wait, jitter: config.Jitter, logger: config.Logger,
		backoffMin: config.BackoffMin, backoffMax: config.BackoffMax,
	}, nil
}

// Run keeps the lease renewed until ctx ends. A failed round (a definitive
// license service answer, an unverifiable lease, a store error) is logged and
// retried after the maximum back-off: returning would stop renewal for the
// life of the process and lock the installation once the grace period passes.
func (syncer *Syncer) Run(ctx context.Context) error {
	for {
		if err := syncer.runOnce(ctx); err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return err
			}
			syncer.logger.Error("entitlement lease renewal failed; retrying", "error", err, "retry_in", syncer.backoffMax)
			if err := syncer.wait(ctx, syncer.backoffMax); err != nil {
				return err
			}
		}
	}
}

func (syncer *Syncer) runOnce(ctx context.Context) error {
	current, err := syncer.store.Current(ctx)
	if err == nil {
		verified, verifyErr := syncer.verify(current, false)
		if verifyErr != nil {
			return fmt.Errorf("verify restored entitlement lease: %w", verifyErr)
		}
		if delay := renewalDelay(syncer.now(), verified.Lease); delay > 0 {
			if err := syncer.wait(ctx, delay); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, ErrNoLocalLease) {
		return err
	}
	_, err = syncer.SyncOnce(ctx)
	return err
}

func (syncer *Syncer) SyncOnce(ctx context.Context) (entitlementguard.Snapshot, error) {
	if syncer == nil {
		return entitlementguard.Snapshot{}, ErrInvalidConfiguration
	}
	syncer.mu.Lock()
	defer syncer.mu.Unlock()
	signed, err := syncer.FetchOnce(ctx)
	if err != nil {
		return entitlementguard.Snapshot{}, err
	}
	return syncer.Install(ctx, signed)
}

func (syncer *Syncer) FetchOnce(ctx context.Context) (entitlement.SignedLease, error) {
	if syncer.keysets != nil {
		if err := syncer.keysets.Refresh(ctx); err != nil {
			syncer.logger.Warn("signing keyset refresh deferred; retaining last-known-good trust", "error", err)
		}
	}
	current, err := syncer.store.Current(ctx)
	var op operation
	if errors.Is(err, ErrNoLocalLease) {
		if syncer.activation == nil {
			return entitlement.SignedLease{}, errors.New("activation credential is required before the first lease")
		}
		credential, sourceErr := syncer.activation(ctx)
		if sourceErr != nil {
			return entitlement.SignedLease{}, sourceErr
		}
		op, err = prepareActivation(syncer.installationID, syncer.installationName, credential, syncer.privateKey,
			syncer.encryptionKey)
		credential = ""
	} else if err == nil {
		if _, err = syncer.verify(current, false); err == nil {
			op, err = prepareRenewal(syncer.installationID, current.Lease.Serial, syncer.privateKey)
		}
	}
	if err != nil {
		return entitlement.SignedLease{}, err
	}

	signed, err := syncer.exchangeWithRetry(ctx, op)
	for index := range op.body {
		op.body[index] = 0
	}
	if err != nil {
		return entitlement.SignedLease{}, err
	}
	if _, err := syncer.verify(signed, true); err != nil {
		if syncer.keysets != nil {
			if refreshErr := syncer.keysets.Refresh(ctx); refreshErr == nil {
				_, err = syncer.verify(signed, true)
			}
		}
		if err != nil {
			return entitlement.SignedLease{}, fmt.Errorf("verify synchronized entitlement lease: %w", err)
		}
	}
	return signed, nil
}

func (syncer *Syncer) Install(ctx context.Context, signed entitlement.SignedLease) (entitlementguard.Snapshot, error) {
	if syncer == nil || syncer.store == nil {
		return entitlementguard.Snapshot{}, ErrInvalidConfiguration
	}
	return syncer.store.Install(ctx, entitlementguard.InstallBundle{
		InstallationID: syncer.installationID.String(),
		SignedLease:    signed,
	}, syncer.now())
}

func (syncer *Syncer) verify(signed entitlement.SignedLease, requireValid bool) (entitlement.Result, error) {
	result, err := syncer.trust.Verify(signed, entitlement.VerifyOptions{
		Now:                    syncer.now(),
		ExpectedAudience:       entitlement.ControlAudience,
		ExpectedInstallationID: syncer.installationID.String(),
	})
	if err != nil {
		return entitlement.Result{}, err
	}
	if requireValid && result.Status != entitlement.StatusValid {
		return entitlement.Result{}, fmt.Errorf("synchronized lease status is %s", result.Status)
	}
	return result, nil
}

func (syncer *Syncer) exchangeWithRetry(ctx context.Context, op operation) (entitlement.SignedLease, error) {
	delay := syncer.backoffMin
	for {
		signed, err := syncer.client.exchange(ctx, op)
		if err == nil {
			return signed, nil
		}
		retryAfter, canRetry := retryable(err)
		if !canRetry {
			return entitlement.SignedLease{}, err
		}
		wait := syncer.jitter(delay)
		if retryAfter > wait {
			wait = retryAfter
		}
		if wait > syncer.backoffMax {
			wait = syncer.backoffMax
		}
		syncer.logger.Warn("entitlement synchronization deferred", "error", err, "retry_in", wait)
		if err := syncer.wait(ctx, wait); err != nil {
			return entitlement.SignedLease{}, err
		}
		if delay < syncer.backoffMax/2 {
			delay *= 2
		} else {
			delay = syncer.backoffMax
		}
	}
}

func renewalDelay(now time.Time, lease entitlement.Lease) time.Duration {
	remaining := time.Unix(lease.ExpiresAt, 0).Sub(now)
	if remaining <= 0 {
		return 0
	}
	lifetime := time.Duration(lease.ExpiresAt-lease.NotBefore) * time.Second
	lead := lifetime / 3
	if lead < time.Minute {
		lead = time.Minute
	}
	if remaining <= lead {
		return 0
	}
	return remaining - lead
}

func boundedJitter(value time.Duration) time.Duration {
	floor := value - value/4
	width := value - floor
	if width <= 0 {
		return value
	}
	var encoded [8]byte
	if _, err := rand.Read(encoded[:]); err != nil {
		return floor
	}
	return floor + time.Duration(binary.BigEndian.Uint64(encoded[:])%uint64(width+1))
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
