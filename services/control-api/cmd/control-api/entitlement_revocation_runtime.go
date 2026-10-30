package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/cdnca/cdnca/services/control-api/internal/installationban"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const (
	entitlementRevocationPollInterval     = time.Minute
	entitlementRevocationStartupTimeout   = 35 * time.Second
	entitlementRevocationReadinessTimeout = 2 * time.Second

	// installationLeaseRenewTimeout bounds the lease renewal an expired or
	// lifted-revoked lock triggers (installationban.Runtime.RenewLease).
	installationLeaseRenewTimeout = 20 * time.Second
)

type entitlementRevocationKeysetRefresher interface {
	Refresh(context.Context) error
}

type entitlementRevocationSyncer interface {
	SyncOnce(context.Context) (entitlementguard.RevocationSnapshot, error)
}

// LastKnownGood accepts a list past its 15-minute window: a license service
// outage must not stop startup or readiness.
type entitlementRevocationCurrentStore interface {
	LastKnownGood(context.Context, time.Time) (entitlementguard.RevocationSnapshot, error)
}

type entitlementLeaseInitializer interface {
	FetchOnce(context.Context) (entitlement.SignedLease, error)
	Install(context.Context, entitlement.SignedLease) (entitlementguard.Snapshot, error)
}

type preparedEntitlementLease struct {
	signed entitlement.SignedLease
}

type entitlementRevocationRuntime struct {
	keysets      entitlementRevocationKeysetRefresher
	syncer       entitlementRevocationSyncer
	store        entitlementRevocationCurrentStore
	now          func() time.Time
	wait         func(context.Context, time.Duration) error
	logger       *slog.Logger
	readyTimeout time.Duration
	// leaseRefresh renews the lease when the lease refresh generation changed (nil = off).
	leaseRefresh func(context.Context) error
	// installationState polls the installation ban state in the same loop
	// (ADR 0014 §5.1; nil = off): it sets the process-wide installation lock.
	installationState *installationban.Runtime
	installationStore *installationban.Store
	terminalMu        sync.RWMutex
	terminalError     error
}

func fetchEntitlementLeaseBeforeRevocations(
	ctx context.Context,
	activationCredentialFile string,
	initializer entitlementLeaseInitializer,
) (*preparedEntitlementLease, error) {
	if activationCredentialFile == "" {
		return nil, nil
	}
	if initializer == nil {
		return nil, errors.New("entitlement lease initializer is required")
	}
	signed, err := initializer.FetchOnce(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch initial entitlement lease: %w", err)
	}
	return &preparedEntitlementLease{signed: signed}, nil
}

func installEntitlementLeaseAfterRevocations(
	ctx context.Context,
	prepared *preparedEntitlementLease,
	initializer entitlementLeaseInitializer,
) error {
	if prepared == nil {
		return nil
	}
	if initializer == nil {
		return errors.New("entitlement lease initializer is required")
	}
	if _, err := initializer.Install(ctx, prepared.signed); err != nil {
		return fmt.Errorf("install initial entitlement lease: %w", err)
	}
	return nil
}

func openEntitlementRevocationRuntime(
	ctx context.Context,
	cfg config.Config,
	pool *pgxpool.Pool,
	trust *entitlementguard.TrustStore,
	keysets *entitlementsync.KeysetManager,
	lease entitlementsync.LeaseRefresher,
) (*entitlementRevocationRuntime, error) {
	if cfg.LicenseServiceURL == "" {
		return nil, nil
	}
	if pool == nil || trust == nil || keysets == nil {
		return nil, errors.New("entitlement revocation runtime requires database, trust, and keyset manager")
	}
	installationID, err := uuid.Parse(cfg.ControlInstallationID)
	if err != nil || installationID == uuid.Nil || installationID.String() != cfg.ControlInstallationID {
		return nil, errors.New("CONTROL_INSTALLATION_ID must be a canonical UUID")
	}
	privateKey, err := entitlementsync.LoadPrivateKey(cfg.ControlInstallationKeyFile)
	if err != nil {
		return nil, err
	}
	client, err := entitlementsync.NewClient(cfg.LicenseServiceURL, nil)
	if err != nil {
		return nil, err
	}
	revocationClient, err := entitlementsync.NewRevocationClient(client)
	if err != nil {
		return nil, err
	}
	store := entitlementsync.NewPostgresRevocationStore(pool, trust)
	syncer, err := entitlementsync.NewRevocationSyncer(entitlementsync.RevocationSyncConfig{
		Client: revocationClient, Store: store, InstallationID: installationID,
		PrivateKey: privateKey, Logger: slog.Default(), Lease: lease,
	})
	if err != nil {
		return nil, err
	}
	stateClient, err := installationban.NewClient(cfg.LicenseServiceURL, installationID, privateKey, nil)
	if err != nil {
		return nil, err
	}
	stateStore, err := installationban.NewStore(pool, installationID, trust.PublicKey)
	if err != nil {
		return nil, err
	}
	installationState := &installationban.Runtime{Fetcher: stateClient, Store: stateStore, Now: time.Now,
		Logger: slog.Default()}
	if lease != nil {
		installationState.RenewLease = func(ctx context.Context) error {
			// Bounded: SyncOnce retries a remote outage indefinitely, which
			// would stall this minute loop and the "check again" request.
			ctx, cancel := context.WithTimeout(ctx, installationLeaseRenewTimeout)
			defer cancel()
			_, err := lease.SyncOnce(ctx)
			return err
		}
	}
	// a restart while banned is locked before the HTTP server starts
	if err := installationState.Restore(ctx); err != nil {
		return nil, fmt.Errorf("restore installation ban state: %w", err)
	}
	runtime := &entitlementRevocationRuntime{
		keysets: keysets, syncer: syncer, store: store, now: time.Now,
		wait: waitEntitlementRevocationContext, logger: slog.Default(),
		readyTimeout: entitlementRevocationReadinessTimeout, leaseRefresh: syncer.RefreshLease,
		installationState: installationState, installationStore: stateStore,
	}
	startupCtx, cancel := context.WithTimeout(ctx, entitlementRevocationStartupTimeout)
	defer cancel()
	if err := initializeEntitlementRevocationRuntime(startupCtx, runtime); err != nil {
		return nil, err
	}
	return runtime, nil
}

func initializeEntitlementRevocationRuntime(ctx context.Context, runtime *entitlementRevocationRuntime) error {
	if runtime == nil || runtime.keysets == nil || runtime.syncer == nil || runtime.store == nil || runtime.now == nil {
		return errors.New("entitlement revocation runtime is incomplete")
	}
	if err := runtime.keysets.Refresh(ctx); err != nil {
		if !isEntitlementRevocationRemoteError(err) {
			return fmt.Errorf("refresh entitlement verification keyset: %w", err)
		}
		runtime.logger.Warn("entitlement keyset refresh unavailable during startup", "error", err)
	}
	_, err := runtime.syncer.SyncOnce(ctx)
	runtime.syncInstallationState(ctx)
	if err == nil {
		return nil
	}
	remote := isEntitlementRevocationRemoteError(err)
	if !remote && !isEntitlementRevocationDeferredError(err) {
		return fmt.Errorf("synchronize entitlement revocation state: %w", err)
	}
	// Match Run: a remote outage or a rejected artifact keeps the current LKG
	// instead of stopping the control API; without a current LKG, fail closed.
	current, currentErr := runtime.store.LastKnownGood(ctx, runtime.now().UTC())
	if currentErr != nil || current.Revision == 0 {
		return fmt.Errorf("synchronize entitlement revocation state without current LKG: %w", errors.Join(err, currentErr))
	}
	if remote {
		runtime.logger.Warn("entitlement revocation remote unavailable; using current LKG",
			"revision", current.Revision, "expires_at", current.ExpiresAt)
	} else {
		runtime.logger.Error("entitlement revocation state rejected during startup; retaining current LKG",
			"error", err, "revision", current.Revision, "expires_at", current.ExpiresAt)
	}
	return nil
}

func (runtime *entitlementRevocationRuntime) Run(ctx context.Context) (runErr error) {
	if runtime == nil || runtime.keysets == nil || runtime.syncer == nil || runtime.wait == nil || runtime.logger == nil {
		return errors.New("entitlement revocation runtime is incomplete")
	}
	// runWithDBBackoff calls Run again after a transient PostgreSQL failure; the
	// retry must not keep reporting the previous attempt's terminal error.
	runtime.setTerminalError(nil)
	defer func() {
		if ctx.Err() == nil {
			if runErr == nil || errors.Is(runErr, context.Canceled) {
				runErr = errors.New("entitlement revocation runtime stopped unexpectedly")
			}
			runtime.setTerminalError(runErr)
		}
	}()
	for {
		if err := runtime.wait(ctx, entitlementRevocationPollInterval); err != nil {
			return err
		}
		if err := runtime.keysets.Refresh(ctx); err != nil {
			if !isEntitlementRevocationRemoteError(err) {
				return fmt.Errorf("refresh entitlement verification keyset: %w", err)
			}
			runtime.logger.Warn("entitlement keyset refresh deferred", "error", err)
		}
		if _, err := runtime.syncer.SyncOnce(ctx); err != nil {
			switch {
			case isEntitlementRevocationRemoteError(err):
				runtime.logger.Warn("entitlement revocation synchronization deferred", "error", err)
			case isEntitlementRevocationDeferredError(err):
				runtime.logger.Error("entitlement revocation state rejected; retaining current LKG", "error", err)
			default:
				return fmt.Errorf("synchronize entitlement revocation state: %w", err)
			}
		}
		runtime.syncInstallationState(ctx)
		if runtime.leaseRefresh != nil {
			// A failed renewal keeps the current lease; the generation stays pending for the next poll.
			if err := runtime.leaseRefresh(ctx); err != nil && ctx.Err() == nil {
				runtime.logger.Warn("entitlement lease refresh deferred", "error", err)
			}
		}
	}
}

// syncInstallationState runs one installation state round; failures keep the
// stored state (installationban.Runtime) and never stop the loop.
func (runtime *entitlementRevocationRuntime) syncInstallationState(ctx context.Context) {
	if runtime.installationState == nil {
		return
	}
	if err := runtime.installationState.SyncOnce(ctx); err != nil && ctx.Err() == nil {
		level := slog.LevelError
		if installationban.IsRemoteError(err) {
			level = slog.LevelWarn
		}
		runtime.logger.Log(ctx, level, "installation ban state synchronization deferred", "error", err)
	}
}

// installationBanDistributor forwards the installation state to every node
// over the gateway (ADR 0014 §5.3); nil without the runtime or NATS.
func (runtime *entitlementRevocationRuntime) installationBanDistributor(pool *pgxpool.Pool,
	connection natsRuntimeConnection,
) (*installationban.Distributor, error) {
	edgeNATS, _ := connection.(*nats.Conn)
	if runtime == nil || runtime.installationStore == nil || edgeNATS == nil {
		return nil, nil
	}
	commands, err := installationban.NewNATSCommands(edgeNATS, 5*time.Second)
	if err != nil {
		return nil, err
	}
	// Permanent refusals go to the notification center even when the
	// notification runtime is off (like the node security alerts).
	alerts, err := notification.NewStore(pool)
	if err != nil {
		return nil, err
	}
	distributor := &installationban.Distributor{Store: runtime.installationStore,
		Nodes: installationban.ActiveNodes(pool), Commands: commands, Interval: time.Minute, Logger: slog.Default(),
		Alerts: alerts, AlertPool: pool}
	runtime.installationState.Changed = distributor.Wake
	return distributor, nil
}

// CheckInstallationState is the license page's "check again".
func (runtime *entitlementRevocationRuntime) CheckInstallationState(ctx context.Context) error {
	if runtime == nil || runtime.installationState == nil {
		return nil
	}
	return runtime.installationState.SyncOnce(ctx)
}

func (runtime *entitlementRevocationRuntime) Ready() error {
	if runtime == nil || runtime.store == nil || runtime.now == nil || runtime.readyTimeout <= 0 {
		return errors.New("entitlement revocation runtime is not configured")
	}
	runtime.terminalMu.RLock()
	terminalErr := runtime.terminalError
	runtime.terminalMu.RUnlock()
	if terminalErr != nil {
		return terminalErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), runtime.readyTimeout)
	defer cancel()
	snapshot, err := runtime.store.LastKnownGood(ctx, runtime.now().UTC())
	if err != nil {
		return fmt.Errorf("entitlement revocation state is unavailable: %w", err)
	}
	if snapshot.Revision == 0 {
		return errors.New("entitlement revocation state has no current revision")
	}
	return nil
}

func (runtime *entitlementRevocationRuntime) setTerminalError(err error) {
	runtime.terminalMu.Lock()
	runtime.terminalError = err
	runtime.terminalMu.Unlock()
}

func waitEntitlementRevocationContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isEntitlementRevocationRemoteError(err error) bool {
	if err == nil {
		return false
	}
	var httpErr *entitlementsync.HTTPError
	if errors.As(err, &httpErr) {
		// The license service returns a 409 while its append-only revocation
		// snapshot is being advanced by a concurrent lease/revocation writer.
		// Keep the current LKG and retry that short coordination window instead
		// of terminating the control API process.
		if httpErr.StatusCode == http.StatusConflict && httpErr.Code == "revocation_state_conflict" {
			return true
		}
		return httpErr.Retryable()
	}
	var networkErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkErr)
}

func isEntitlementRevocationDeferredError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, entitlementguard.ErrRevocationInvalid) ||
		errors.Is(err, entitlementguard.ErrRevocationExpired) ||
		errors.Is(err, entitlementguard.ErrRevocationConflict) ||
		errors.Is(err, entitlementguard.ErrRevocationRollback) ||
		errors.Is(err, entitlementguard.ErrRevocationShrink) {
		return true
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "P8408"
}
