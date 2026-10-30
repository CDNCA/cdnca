package signerrevocationconsumer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/cdnca/cdnca/services/control-api/internal/signerrevocation"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrProductionNotReady      = errors.New("signer revocation consumer is not ready")
	ErrProductionAlreadyRun    = errors.New("signer revocation consumer already ran")
	ErrProductionClosed        = errors.New("signer revocation consumer is closed")
	ErrProductionShutdownTimed = errors.New("signer revocation consumer shutdown timed out")
)

type ProductionDependencies struct {
	Pool             *pgxpool.Pool
	EntitlementTrust *entitlementguard.TrustStore
	Now              func() time.Time
}

type ProductionRuntime struct {
	config      Config
	coordinator *Coordinator
	client      *Client
	runtime     *signerrevocation.Runtime
	now         func() time.Time

	mu          sync.Mutex
	runStarted  bool
	runActive   bool
	closing     bool
	closed      bool
	terminalErr error
	runCancel   context.CancelFunc
	runDone     chan struct{}

	closeMu  sync.Mutex
	closeErr error
	secret   sync.Once
}

func OpenProductionRuntime(ctx context.Context, config Config, dependencies ProductionDependencies) (*ProductionRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	if ctx == nil || dependencies.Pool == nil || dependencies.EntitlementTrust == nil || !validProductionConfig(config) {
		return nil, ErrInvalidConfiguration
	}
	now := dependencies.Now
	if now == nil {
		now = time.Now
	}
	trust, err := NewDeploymentTrust(dependencies.EntitlementTrust, config)
	if err != nil {
		return nil, err
	}
	privateKey, err := entitlementsync.LoadPrivateKey(config.InstallationPrivateKeyFile)
	if err != nil {
		return nil, err
	}
	defer clearPrivateKey(privateKey)
	client, err := NewClient(ClientConfig{
		BaseURL: config.BaseURL, TLSConfig: config.TLSConfig, InstallationID: config.InstallationID,
		PrivateKey: privateKey, Timeout: config.RequestTimeout, Now: now,
	})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*ProductionRuntime, error) {
		client.http.CloseIdleConnections()
		clearPrivateKey(client.privateKey)
		return nil, err
	}
	checkpointRuntime := &signerrevocation.Runtime{}
	store := signerrevocation.NewCheckpointStore(dependencies.Pool, trust, now)
	coordinator, err := NewCoordinator(store, client, checkpointRuntime)
	if err != nil {
		return fail(err)
	}
	startupCtx, cancel := context.WithTimeout(ctx, config.StartupTimeout)
	err = coordinator.Startup(startupCtx)
	cancel()
	if err != nil {
		return fail(err)
	}
	return &ProductionRuntime{
		config: config, coordinator: coordinator, client: client, runtime: checkpointRuntime,
		now: now, runDone: make(chan struct{}),
	}, nil
}

func validProductionConfig(config Config) bool {
	return config.RefreshInterval >= time.Minute && config.RefreshInterval <= 24*time.Hour &&
		validProductionTimeout(config.RequestTimeout) && validProductionTimeout(config.StartupTimeout) &&
		validProductionTimeout(config.ShutdownTimeout)
}

func validProductionTimeout(timeout time.Duration) bool {
	return timeout >= time.Second && timeout <= 30*time.Second
}

func (runtime *ProductionRuntime) Run(ctx context.Context) (runErr error) {
	if runtime == nil || ctx == nil || runtime.coordinator == nil || runtime.config.RefreshInterval <= 0 {
		return ErrInvalidConfiguration
	}
	runtime.mu.Lock()
	if runtime.closing || runtime.closed {
		runtime.mu.Unlock()
		return ErrProductionClosed
	}
	// Only one Run at a time. After a failed Run returns, control-api's
	// runWithDBBackoff may call Run again (PostgreSQL restart): the retry
	// starts from a clean terminal state and a fresh done channel.
	if runtime.runActive {
		runtime.mu.Unlock()
		return ErrProductionAlreadyRun
	}
	if runtime.runStarted {
		runtime.runDone = make(chan struct{})
		runtime.terminalErr = nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.runStarted = true
	runtime.runActive = true
	runtime.runCancel = cancel
	runDone := runtime.runDone
	runtime.mu.Unlock()

	defer func() {
		cancel()
		runtime.mu.Lock()
		runtime.runActive = false
		runtime.runCancel = nil
		if runErr != nil && !(runtime.closing && errors.Is(runErr, context.Canceled)) {
			runtime.terminalErr = runErr
		}
		close(runDone)
		closing := runtime.closing
		runtime.mu.Unlock()
		if closing {
			runtime.clearPrivateKey()
		}
	}()

	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-runCtx.Done():
			runtime.mu.Lock()
			closing := runtime.closing
			runtime.mu.Unlock()
			if closing {
				return nil
			}
			return runCtx.Err()
		case <-timer.C:
			err := runtime.coordinator.Refresh(runCtx)
			if err != nil {
				if runCtx.Err() != nil {
					continue
				}
				var retryable *retryableRefreshError
				if !errors.As(err, &retryable) {
					return err
				}
			}
			timer.Reset(runtime.config.RefreshInterval)
		}
	}
}

// RevocationGate exposes the in-memory LKG to signature verification paths.
// It allows while no checkpoint has been accepted and denies only signers the
// verified checkpoint revokes.
func (runtime *ProductionRuntime) RevocationGate(logger *slog.Logger) *signerrevocation.Gate {
	if runtime == nil {
		return nil
	}
	return signerrevocation.NewGate(runtime.runtime, runtime.now, logger)
}

func (runtime *ProductionRuntime) Ready() error {
	if runtime == nil {
		return ErrProductionNotReady
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closing || runtime.closed {
		return ErrProductionClosed
	}
	if runtime.terminalErr != nil {
		return errors.Join(ErrProductionNotReady, runtime.terminalErr)
	}
	if !runtime.runActive {
		return ErrProductionNotReady
	}
	return nil
}

func (runtime *ProductionRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.closeMu.Lock()
	defer runtime.closeMu.Unlock()

	runtime.mu.Lock()
	if runtime.closed {
		err := runtime.closeErr
		runtime.mu.Unlock()
		return err
	}
	runtime.closing = true
	cancel := runtime.runCancel
	runActive := runtime.runActive
	runDone := runtime.runDone
	runtime.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	runtime.client.http.CloseIdleConnections()
	var closeErr error
	if runActive {
		timer := time.NewTimer(runtime.config.ShutdownTimeout)
		select {
		case <-runDone:
			timer.Stop()
		case <-timer.C:
			closeErr = ErrProductionShutdownTimed
		}
	}
	runtime.clearPrivateKey()

	runtime.mu.Lock()
	runtime.closed = true
	runtime.closeErr = closeErr
	runtime.mu.Unlock()
	return closeErr
}

func (runtime *ProductionRuntime) clearPrivateKey() {
	if runtime == nil || runtime.client == nil {
		return
	}
	runtime.secret.Do(func() {
		clearPrivateKey(runtime.client.privateKey)
	})
}

func clearPrivateKey(privateKey ed25519.PrivateKey) {
	for index := range privateKey {
		privateKey[index] = 0
	}
}
