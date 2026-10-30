package pluginwebhookruntime

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhook"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

var (
	ErrInvalidConfig       = errors.New("invalid plugin webhook runtime configuration")
	ErrRuntimeClosed       = errors.New("plugin webhook runtime closed")
	ErrRuntimeRunning      = errors.New("plugin webhook runtime already running")
	ErrRuntimeNotReady     = errors.New("plugin webhook runtime not ready")
	ErrNATSUnavailable     = errors.New("plugin webhook runtime NATS unavailable")
	ErrDatabaseUnavailable = errors.New("plugin webhook runtime database unavailable")
)

type Config struct {
	Pool             *pgxpool.Pool
	NATS             *nats.Conn
	NATSURL          string
	NATSName         string
	NATSCredsFile    string
	NATSCAFile       string
	NATSReconnectMin time.Duration
	NATSReconnectMax time.Duration
	JetStream        JetStreamConfig
	WorkerID         string
	PollInterval     time.Duration
	OperationTimeout time.Duration
	LeaseDuration    time.Duration
	ClaimTimeout     time.Duration
	ShutdownTimeout  time.Duration
	Logger           *slog.Logger
	// AttestationKeyID/AttestationKey sign every broker publication the
	// database records (migration 084 publication attestation).
	AttestationKeyID string
	AttestationKey   ed25519.PrivateKey
	// NextAttestationKeyID/NextAttestationKey (optional) are staged for a
	// rotation: the runtime signs with whichever of the two keys the database
	// head names, so advancing the head needs no restart.
	NextAttestationKeyID string
	NextAttestationKey   ed25519.PrivateKey
}

type Dependencies struct {
	Deliverer pluginwebhook.Deliverer
	Secrets   TransactionalSecretProvider
	Fanout    FanoutWorker
}

// FanoutWorker is optional. Keeping it as a local interface preserves the
// existing runtime constructor and tests when deployment source fanout is not
// mounted.
type FanoutWorker interface {
	RunOnce(context.Context) error
}

type TransactionalSecretProvider interface {
	pluginwebhook.V2SecretProvider
	SecretTx(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, uuid.UUID) ([]byte, error)
}

type preparedV2Deliverer interface {
	DeliverV2(context.Context, pluginwebhook.QueueItem, uint64, []byte) pluginwebhook.SendResult
}

type Runtime struct {
	config     Config
	pool       *pgxpool.Pool
	connection *nats.Conn
	jetstream  nats.JetStreamContext
	deliverer  pluginwebhook.Deliverer
	secrets    TransactionalSecretProvider
	fanout     FanoutWorker
	consumer   *runtimeConsumer

	mu      sync.Mutex
	running bool
	ready   bool
	closed  bool
	cancel  context.CancelFunc
	done    chan struct{}
	closeMu sync.Mutex

	attestationMu    sync.Mutex
	attestationReady bool
}

// Open constructs the runtime without mounting it into control-api main. A
// caller may provide an existing NATS connection or a URL; this function owns
// only a connection it creates itself.
func Open(ctx context.Context, config Config, dependencies Dependencies) (*Runtime, error) {
	if config.JetStream.DeliveryStream == "" {
		config.JetStream = DefaultJetStreamConfig()
	}
	if config.PollInterval == 0 {
		config.PollInterval = 100 * time.Millisecond
	}
	if config.OperationTimeout == 0 {
		config.OperationTimeout = config.JetStream.OperationTimeout
	}
	if config.LeaseDuration == 0 {
		config.LeaseDuration = time.Minute
	}
	if config.ClaimTimeout == 0 {
		config.ClaimTimeout = 5 * time.Minute
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = 10 * time.Second
	}
	if config.NATSReconnectMin == 0 {
		config.NATSReconnectMin = 250 * time.Millisecond
	}
	if config.NATSReconnectMax == 0 {
		config.NATSReconnectMax = 5 * time.Second
	}
	if ctx == nil || !validConfig(config) || !validJetStreamConfig(config.JetStream) || !configuredPool(config.Pool) {
		return nil, ErrInvalidConfig
	}
	if config.LeaseDuration > config.JetStream.DuplicateWindow {
		return nil, ErrInvalidConfig
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	connection := config.NATS
	owned := false
	if connection == nil {
		if config.NATSURL == "" {
			return nil, ErrInvalidConfig
		}
		name := config.NATSName
		if name == "" {
			name = "cdnca-plugin-webhook-runtime"
		}
		var err error
		connection, err = nats.Connect(config.NATSURL, runtimeNATSOptions(config, name)...)
		if err != nil {
			return nil, fmt.Errorf("connect plugin webhook runtime NATS: %w", err)
		}
		owned = true
	}
	if connection.IsClosed() {
		if owned {
			connection.Close()
		}
		return nil, ErrNATSUnavailable
	}
	if err := EnsureJetStream(ctx, connection, config.JetStream); err != nil {
		if owned {
			connection.Close()
		}
		return nil, err
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		if owned {
			connection.Close()
		}
		return nil, fmt.Errorf("create plugin webhook runtime JetStream: %w", err)
	}
	if dependencies.Secrets == nil {
		if owned {
			connection.Close()
		}
		return nil, ErrInvalidConfig
	}
	if dependencies.Deliverer == nil {
		senderConfig := pluginwebhook.DefaultHTTPSenderConfig()
		sender, senderErr := pluginwebhook.NewV2HTTPSender(senderConfig, dependencies.Secrets)
		if senderErr != nil {
			if owned {
				connection.Close()
			}
			return nil, senderErr
		}
		dependencies.Deliverer = sender
	}
	if _, ok := dependencies.Deliverer.(preparedV2Deliverer); !ok {
		if owned {
			connection.Close()
		}
		return nil, ErrInvalidConfig
	}
	consumer, err := newRuntimeConsumer(connection, config.JetStream)
	if err != nil {
		if owned {
			connection.Close()
		}
		return nil, err
	}
	return &Runtime{
		config: config, pool: config.Pool, connection: connection, jetstream: jetstream,
		deliverer: dependencies.Deliverer, secrets: dependencies.Secrets, fanout: dependencies.Fanout,
		consumer: consumer,
	}, nil
}

func runtimeNATSOptions(config Config, name string) []nats.Option {
	options := []nats.Option{
		nats.Name(name),
		nats.Timeout(config.OperationTimeout),
		nats.ReconnectWait(config.NATSReconnectMin),
		nats.CustomReconnectDelay(reconnectDelay(config.NATSReconnectMin, config.NATSReconnectMax)),
		nats.MaxReconnects(-1),
	}
	if config.NATSCredsFile != "" {
		options = append(options, nats.UserCredentials(config.NATSCredsFile))
	}
	if config.NATSCAFile != "" {
		options = append(options, nats.RootCAs(config.NATSCAFile))
	}
	return options
}

// NewRuntime is an explicit constructor alias for callers that prefer the
// repository's NewRuntime naming convention.
func NewRuntime(ctx context.Context, config Config, dependencies Dependencies) (*Runtime, error) {
	return Open(ctx, config, dependencies)
}

func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return ErrInvalidConfig
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	runtime.mu.Lock()
	if runtime.closed {
		runtime.mu.Unlock()
		cancel()
		return ErrRuntimeClosed
	}
	if runtime.running {
		runtime.mu.Unlock()
		cancel()
		return ErrRuntimeRunning
	}
	runtime.running, runtime.ready, runtime.cancel, runtime.done = true, false, cancel, done
	runtime.mu.Unlock()
	defer func() {
		cancel()
		runtime.mu.Lock()
		runtime.running, runtime.ready, runtime.cancel = false, false, nil
		close(done)
		runtime.mu.Unlock()
	}()
	first := true
	for {
		if runCtx.Err() != nil {
			return nil
		}
		cycleErr := runtime.runCycle(runCtx)
		runtime.setReady(cycleErr == nil && runCtx.Err() == nil)
		if cycleErr != nil && runCtx.Err() == nil {
			if first {
				runtime.config.Logger.Error("plugin webhook runtime startup reconciliation failed", "error", cycleErr)
			} else {
				runtime.config.Logger.Warn("plugin webhook runtime cycle failed", "error", cycleErr)
			}
		}
		first = false
		select {
		case <-runCtx.Done():
			return nil
		case <-time.After(runtime.config.PollInterval):
		}
	}
}

func (runtime *Runtime) runCycle(ctx context.Context) error {
	if runtime.fanout != nil {
		if err := runtime.fanout.RunOnce(ctx); err != nil {
			return err
		}
	}
	if err := runtime.reconcile(ctx); err != nil {
		return err
	}
	if err := runtime.publishOutbox(ctx); err != nil {
		return err
	}
	if err := runtime.processOne(ctx); err != nil && !errors.Is(err, errNoMessage) {
		return err
	}
	return runtime.probeReadiness(ctx)
}

func (runtime *Runtime) setReady(value bool) {
	runtime.mu.Lock()
	if runtime.closed || !runtime.running {
		value = false
	}
	runtime.ready = value
	runtime.mu.Unlock()
}

func (runtime *Runtime) Ready() error {
	if runtime == nil {
		return ErrInvalidConfig
	}
	runtime.mu.Lock()
	if runtime.closed {
		runtime.mu.Unlock()
		return ErrRuntimeClosed
	}
	if !runtime.running || !runtime.ready {
		runtime.mu.Unlock()
		return ErrRuntimeNotReady
	}
	runtime.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), runtime.config.OperationTimeout)
	defer cancel()
	if err := runtime.probeReadiness(ctx); err != nil {
		runtime.setReady(false)
		return err
	}
	return nil
}

func (runtime *Runtime) probeReadiness(ctx context.Context) error {
	if err := runtime.pool.Ping(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}
	if runtime.connection == nil || runtime.connection.IsClosed() || !runtime.connection.IsConnected() {
		return ErrNATSUnavailable
	}
	if err := checkJetStreamReady(ctx, runtime.jetstream, runtime.config.JetStream); err != nil {
		return fmt.Errorf("%w: %v", ErrNATSUnavailable, err)
	}
	return nil
}

func (runtime *Runtime) Close(ctx context.Context) error {
	if runtime == nil {
		return ErrInvalidConfig
	}
	invalidContext := ctx == nil
	if invalidContext {
		ctx = context.Background()
	}
	runtime.closeMu.Lock()
	defer runtime.closeMu.Unlock()
	runtime.mu.Lock()
	if runtime.closed {
		runtime.mu.Unlock()
		if invalidContext {
			return ErrInvalidConfig
		}
		return nil
	}
	runtime.closed, runtime.ready = true, false
	cancel, done, running := runtime.cancel, runtime.done, runtime.running
	runtime.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	var waitErr error
	if running && done != nil {
		waitCtx, waitCancel := context.WithTimeout(ctx, runtime.config.ShutdownTimeout)
		select {
		case <-done:
		case <-waitCtx.Done():
			waitErr = waitCtx.Err()
		}
		waitCancel()
	}
	if runtime.consumer != nil {
		_ = runtime.consumer.Close()
	}
	if runtime.config.NATS == nil && runtime.connection != nil {
		runtime.connection.Close()
	}
	if invalidContext {
		return errors.Join(ErrInvalidConfig, waitErr)
	}
	return waitErr
}

func validConfig(config Config) bool {
	credentialsComplete := (config.NATSCredsFile == "") == (config.NATSCAFile == "")
	reconnectValid := config.NATSReconnectMin > 0 && config.NATSReconnectMin <= config.NATSReconnectMax &&
		config.NATSReconnectMax <= 5*time.Minute
	return (config.NATS != nil || config.NATSURL != "") &&
		credentialsComplete && reconnectValid &&
		config.PollInterval > 0 && config.PollInterval <= time.Minute &&
		config.OperationTimeout > 0 && config.OperationTimeout <= time.Minute &&
		config.LeaseDuration > 0 && config.LeaseDuration <= 5*time.Minute &&
		config.ClaimTimeout >= config.OperationTimeout && config.ClaimTimeout <= 24*time.Hour &&
		config.ShutdownTimeout > 0 && config.ShutdownTimeout <= time.Minute &&
		validAttestationKey(config.AttestationKeyID, config.AttestationKey) &&
		validNextAttestationKey(config)
}

func reconnectDelay(minimum, maximum time.Duration) nats.ReconnectDelayHandler {
	return func(attempts int) time.Duration {
		delay := minimum
		for attempts > 1 && delay < maximum {
			if delay > maximum/2 {
				return maximum
			}
			delay *= 2
			attempts--
		}
		return min(delay, maximum)
	}
}

func configuredPool(pool interface{ Config() *pgxpool.Config }) bool {
	if pool == nil {
		return false
	}
	defer func() { _ = recover() }()
	return pool.Config() != nil
}

var errNoMessage = errors.New("no plugin webhook runtime message")
