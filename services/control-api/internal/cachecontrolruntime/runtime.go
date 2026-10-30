package cachecontrolruntime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

type Dependencies struct {
	Pool       *pgxpool.Pool
	NATS       *nats.Conn
	NodeLeases nodepresence.LeaseReader
}

type BatchResult struct {
	Recovered  int
	Claimed    int
	Published  int
	Duplicates int
	Offline    int
}

type controlStore interface {
	OpenClaims(context.Context, cachecontrol.OpenClaimsRequest) ([]cachecontrol.Claim, error)
	ResolveClaim(context.Context, cachecontrol.ClaimIdentity) (cachecontrol.Claim, error)
	ReconcileExpired(context.Context, uuid.UUID, string) error
	Claim(context.Context, cachecontrol.ClaimRequest) ([]cachecontrol.Claim, error)
	Report(context.Context, cachecontrol.ReportRequest) (cachecontrol.ReportResult, error)
	SyncCarryingNodes(context.Context, uuid.UUID, string) (int, error)
}

type queueRepository interface {
	activeScopes(context.Context) ([]uuid.UUID, error)
	automaticScopes(context.Context, time.Time) ([]uuid.UUID, error)
	readyNodes(context.Context, time.Time, *queuedNode, int) ([]queuedNode, error)
}

type Runtime struct {
	config      Config
	pool        *pgxpool.Pool
	control     controlStore
	repository  queueRepository
	leases      nodepresence.LeaseReader
	bus         messageBus
	cancels     cancelStore
	consumer    statusConsumer
	limiter     *dispatchLimiter
	status      statusCounters
	closeOnce   sync.Once
	schedulerMu sync.Mutex
	lastScope   uuid.UUID
}

func NewRuntime(config Config, dependencies Dependencies) (*Runtime, error) {
	if err := config.validate(); err != nil || !configuredPool(dependencies.Pool) ||
		dependencies.NodeLeases == nil {
		return nil, ErrInvalidConfig
	}
	control, err := cachecontrol.NewStore(dependencies.Pool, config.Clock)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	bus, consumer, err := newNATS(dependencies.NATS, config)
	if err != nil {
		return nil, err
	}
	limiter, err := newDispatchLimiter(config)
	if err != nil {
		_ = consumer.Close()
		return nil, err
	}
	return &Runtime{
		config: config, pool: dependencies.Pool, control: control, cancels: control,
		repository: &postgresRepository{pool: dependencies.Pool}, leases: dependencies.NodeLeases,
		bus: bus, consumer: consumer, limiter: limiter,
	}, nil
}

func (runtime *Runtime) ConfiguredFor(pool *pgxpool.Pool, connection *nats.Conn) bool {
	return runtime != nil && runtime.pool == pool && runtime.bus != nil && runtime.consumer != nil &&
		configuredPool(pool) && connection != nil && !connection.IsClosed()
}

func (runtime *Runtime) Run(ctx context.Context, onError func(error)) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	errOut := make(chan error, 2)
	go func() { errOut <- runtime.runScheduler(runContext, onError) }()
	go func() { errOut <- runtime.runConsumer(runContext, onError) }()
	first := <-errOut
	cancel()
	second := <-errOut
	if first != nil && !errors.Is(first, context.Canceled) {
		return first
	}
	if second != nil && !errors.Is(second, context.Canceled) {
		return second
	}
	return ctx.Err()
}

func (runtime *Runtime) Close() error {
	var err error
	runtime.closeOnce.Do(func() {
		if runtime.consumer != nil {
			err = runtime.consumer.Close()
		}
	})
	return err
}

func (runtime *Runtime) RunSchedulerOnce(ctx context.Context) (BatchResult, error) {
	if ctx == nil {
		return BatchResult{}, ErrInvalidConfig
	}
	runtime.schedulerMu.Lock()
	defer runtime.schedulerMu.Unlock()
	open, err := runtime.control.OpenClaims(ctx, cachecontrol.OpenClaimsRequest{
		WorkerID: runtime.config.WorkerID, Limit: runtime.config.ClaimBatch,
	})
	if err != nil {
		return BatchResult{}, err
	}
	result := BatchResult{Recovered: len(open)}
	if err := runtime.publishCancels(ctx); err != nil {
		return result, err
	}
	if len(open) > 0 {
		runtime.publishClaims(ctx, open, &result)
		if result.Published != len(open) {
			return result, fmt.Errorf("republish open cache claims: %d of %d published", result.Published, len(open))
		}
	}
	// A node that started carrying a site gets the site's open automatic
	// operations (created without node IDs) as follow-ups (ge-cache I).
	automatic, err := runtime.repository.automaticScopes(ctx, runtime.config.Clock().UTC())
	if err != nil {
		return result, err
	}
	for _, scopeID := range automatic {
		requestID := stableUUID("carrying:" + runtime.config.WorkerID + ":" +
			runtime.config.Clock().UTC().Format(time.RFC3339Nano) + ":" + scopeID.String()).String()
		if _, err := runtime.control.SyncCarryingNodes(ctx, scopeID, requestID); err != nil {
			return result, err
		}
	}
	remaining := runtime.config.ClaimBatch - len(open)
	if remaining == 0 {
		return result, nil
	}

	scopes, err := runtime.repository.activeScopes(ctx)
	if err != nil {
		return result, err
	}
	if runtime.lastScope != uuid.Nil {
		for index, scopeID := range scopes {
			if scopeID == runtime.lastScope {
				next := (index + 1) % len(scopes)
				scopes = append(append([]uuid.UUID(nil), scopes[next:]...), scopes[:next]...)
				break
			}
		}
	}
	now := runtime.config.Clock().UTC().Truncate(time.Microsecond)
	onlineByScope := make(map[uuid.UUID][]uuid.UUID)
	onlineCount := 0
	var after *queuedNode
	for len(scopes) > 0 {
		ready, err := runtime.repository.readyNodes(ctx, now, after, 1000)
		if err != nil {
			return result, err
		}
		if len(ready) == 0 {
			break
		}
		batchReady := false
		for _, node := range ready {
			online, err := runtime.leases.Exists(ctx, node.NodeID)
			if err != nil {
				return result, fmt.Errorf("read cache node presence %s: %w", node.NodeID, err)
			}
			if !online {
				result.Offline++
				continue
			}
			if len(onlineByScope[node.ScopeID]) < remaining {
				onlineByScope[node.ScopeID] = append(onlineByScope[node.ScopeID], node.NodeID)
				onlineCount++
			}
			if len(onlineByScope) == len(scopes) && onlineCount >= remaining {
				batchReady = true
				break
			}
		}
		last := ready[len(ready)-1]
		after = &last
		if batchReady || len(ready) < 1000 {
			break
		}
	}
	for _, scopeID := range scopes {
		requestID := stableUUID("reconcile:" + runtime.config.WorkerID + ":" +
			runtime.config.Clock().UTC().Format(time.RFC3339Nano) + ":" + scopeID.String()).String()
		if err := runtime.control.ReconcileExpired(ctx, scopeID, requestID); err != nil {
			return result, err
		}
	}
	claims := make([]cachecontrol.Claim, 0, remaining)
	for round := 0; len(claims) < remaining; round++ {
		advanced := false
		for _, scopeID := range scopes {
			nodeIDs := onlineByScope[scopeID]
			if len(nodeIDs) == 0 || len(claims) >= remaining {
				continue
			}
			requestID := stableUUID(fmt.Sprintf("claim:%s:%s:%s:%d", runtime.config.WorkerID,
				now.Format(time.RFC3339Nano), scopeID, round)).String()
			claimed, err := runtime.control.Claim(ctx, cachecontrol.ClaimRequest{
				ScopeID: scopeID, WorkerID: runtime.config.WorkerID, OnlineNodeIDs: nodeIDs,
				Limit: 1, LeaseDuration: runtime.config.LeaseDuration,
				RequestID: requestID, RequireActiveConfig: true,
			})
			if err != nil {
				return result, err
			}
			if len(claimed) == 1 {
				claims = append(claims, claimed[0])
				runtime.lastScope = scopeID
				advanced = true
			}
		}
		if !advanced {
			break
		}
	}
	result.Claimed = len(claims)
	expectedPublished := result.Published + len(claims)
	runtime.publishClaims(ctx, claims, &result)
	if result.Published != expectedPublished {
		return result, fmt.Errorf("publish new cache claims: %d of %d published",
			result.Published-len(open), len(claims))
	}
	return result, nil
}

func (runtime *Runtime) publishClaims(ctx context.Context, claims []cachecontrol.Claim, result *BatchResult) {
	for _, claim := range claims {
		if runtime.limiter != nil {
			if err := runtime.limiter.Wait(ctx, claim); err != nil {
				continue
			}
		}
		command, err := buildCommand(claim)
		if err != nil {
			continue
		}
		duplicate, err := runtime.bus.PublishCommand(ctx, claim.NodeID.String(), command)
		if err != nil {
			continue
		}
		result.Published++
		if duplicate {
			result.Duplicates++
		}
	}
}

func (runtime *Runtime) runScheduler(ctx context.Context, onError func(error)) error {
	ticker := time.NewTicker(runtime.config.PollInterval)
	defer ticker.Stop()
	for {
		if _, err := runtime.RunSchedulerOnce(ctx); err != nil && ctx.Err() == nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (runtime *Runtime) runConsumer(ctx context.Context, onError func(error)) error {
	for {
		_, err := runtime.ProcessStatusOnce(ctx)
		if err != nil && !errors.Is(err, ErrNoMessage) && ctx.Err() == nil && onError != nil {
			onError(err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func configuredPool(pool *pgxpool.Pool) (configured bool) {
	if pool == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return pool.Config() != nil && pool.Config().MaxConns > 0
}
