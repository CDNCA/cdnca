package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var ErrSessionOwned = errors.New("session is owned by another gateway")

type SessionCoordinatorMode string

const (
	SessionCoordinatorModeStandalone  SessionCoordinatorMode = "standalone"
	SessionCoordinatorModeDistributed SessionCoordinatorMode = "distributed"
)

type SessionCoordinatorConfig struct {
	Mode        SessionCoordinatorMode
	RedisClient redis.UniversalClient
	Redis       RedisSessionCoordinatorConfig
}

func NewSessionCoordinator(ctx context.Context, config SessionCoordinatorConfig) (SessionCoordinator, error) {
	switch config.Mode {
	case SessionCoordinatorModeStandalone:
		if config.RedisClient != nil {
			return nil, fmt.Errorf("standalone session coordination cannot use Redis")
		}
		return NewMemorySessionCoordinator(), nil
	case SessionCoordinatorModeDistributed:
		if config.RedisClient == nil {
			return nil, fmt.Errorf("distributed session coordination requires Redis")
		}
		return NewRedisSessionCoordinator(ctx, config.RedisClient, config.Redis)
	default:
		return nil, fmt.Errorf("session coordinator mode must be explicitly set to standalone or distributed")
	}
}

type RedisSessionCoordinatorConfig struct {
	GatewayInstanceID    string
	KeyPrefix            string
	LeaseTTL             time.Duration
	RenewInterval        time.Duration
	OperationTimeout     time.Duration
	AcquireTimeout       time.Duration
	AcquireRetryInterval time.Duration
}

func (c RedisSessionCoordinatorConfig) validate() error {
	if c.GatewayInstanceID == "" {
		return fmt.Errorf("gateway instance ID is required")
	}
	if c.KeyPrefix == "" || strings.ContainsAny(c.KeyPrefix, "{}\r\n") {
		return fmt.Errorf("Redis key prefix is required and cannot contain braces or newlines")
	}
	if c.LeaseTTL < time.Millisecond || c.RenewInterval < time.Millisecond || c.OperationTimeout < time.Millisecond {
		return fmt.Errorf("Redis lease, renew, and operation durations must be at least one millisecond")
	}
	if c.RenewInterval > c.LeaseTTL/3 {
		return fmt.Errorf("Redis lease TTL must be at least three renew intervals")
	}
	if c.OperationTimeout > c.RenewInterval {
		return fmt.Errorf("Redis operation timeout cannot exceed the renew interval")
	}
	if c.AcquireTimeout < time.Millisecond || c.AcquireRetryInterval < time.Millisecond || c.AcquireRetryInterval >= c.AcquireTimeout {
		return fmt.Errorf("Redis acquire timeout and retry interval are invalid")
	}
	return nil
}

type RedisSessionCoordinator struct {
	ctx    context.Context
	client redis.UniversalClient
	config RedisSessionCoordinatorConfig
}

func NewRedisSessionCoordinator(ctx context.Context, client redis.UniversalClient, config RedisSessionCoordinatorConfig) (*RedisSessionCoordinator, error) {
	if ctx == nil || client == nil {
		return nil, fmt.Errorf("Redis session coordinator context and client are required")
	}
	config.KeyPrefix = strings.TrimSuffix(config.KeyPrefix, ":")
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &RedisSessionCoordinator{ctx: ctx, client: client, config: config}, nil
}

var redisAcquireSession = redis.NewScript(`
local inflight = tonumber(redis.call('HGET', KEYS[1], 'inflight') or '0')
if inflight > 0 then
  return 0
end
local epoch = redis.call('INCR', KEYS[2])
redis.call('HSET', KEYS[1], 'token', ARGV[1], 'epoch', epoch, 'owner', ARGV[2], 'inflight', 0)
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return epoch
`)

var redisRenewSession = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then
  return 0
end
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return 1
`)

var redisBeginSessionSend = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then
  return 0
end
redis.call('HINCRBY', KEYS[1], 'inflight', 1)
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return 1
`)

var redisEndSessionSend = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then
  return -1
end
local inflight = tonumber(redis.call('HGET', KEYS[1], 'inflight') or '0')
if inflight <= 0 then
  return -2
end
inflight = redis.call('HINCRBY', KEYS[1], 'inflight', -1)
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return inflight
`)

var redisReleaseSession = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then
  return 0
end
if tonumber(redis.call('HGET', KEYS[1], 'inflight') or '0') ~= 0 then
  return 0
end
redis.call('DEL', KEYS[1])
return 1
`)

func (c *RedisSessionCoordinator) Acquire(ctx context.Context, nodeID string) (SessionLease, error) {
	if ctx == nil {
		return nil, fmt.Errorf("acquire context is required")
	}
	parsedNodeID, err := uuid.Parse(nodeID)
	if err != nil || parsedNodeID.String() != nodeID {
		return nil, fmt.Errorf("node ID must be a canonical UUID")
	}
	select {
	case <-c.ctx.Done():
		return nil, fmt.Errorf("session coordinator is closed: %w", c.ctx.Err())
	default:
	}

	acquireCtx, cancel := context.WithTimeout(ctx, c.config.AcquireTimeout)
	defer cancel()
	stateKey, epochKey := c.keys(nodeID)
	sessionID := uuid.NewString()
	token, err := newSessionToken()
	if err != nil {
		return nil, err
	}
	for {
		epoch, err := c.acquire(acquireCtx, stateKey, epochKey, token, sessionID)
		if err != nil {
			return nil, err
		}
		if epoch > 0 {
			lease := &redisSessionLease{
				coordinator: c,
				stateKey:    stateKey,
				id:          sessionID,
				token:       token,
				epoch:       uint64(epoch),
				done:        make(chan struct{}),
				stopRenew:   make(chan struct{}),
				active:      true,
			}
			lease.cond = sync.NewCond(&lease.mu)
			go lease.renewLoop()
			return lease, nil
		}

		timer := time.NewTimer(c.config.AcquireRetryInterval)
		select {
		case <-acquireCtx.Done():
			timer.Stop()
			return nil, fmt.Errorf("%w: %w", ErrSessionOwned, acquireCtx.Err())
		case <-c.ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("session coordinator is closed: %w", c.ctx.Err())
		case <-timer.C:
		}
	}
}

func (c *RedisSessionCoordinator) acquire(ctx context.Context, stateKey, epochKey, token, sessionID string) (int64, error) {
	operationCtx, cancel := context.WithTimeout(ctx, c.config.OperationTimeout)
	defer cancel()
	epoch, err := redisAcquireSession.Run(operationCtx, c.client, []string{stateKey, epochKey}, token, c.config.GatewayInstanceID+"/"+sessionID, c.config.LeaseTTL.Milliseconds()).Int64()
	if err != nil {
		return 0, fmt.Errorf("acquire Redis session: %w", err)
	}
	if epoch < 0 {
		return 0, fmt.Errorf("Redis returned an invalid session epoch")
	}
	return epoch, nil
}

func (c *RedisSessionCoordinator) keys(nodeID string) (string, string) {
	base := c.config.KeyPrefix + ":session:{" + nodeID + "}"
	return base + ":state", base + ":epoch"
}

func newSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

type redisSessionLease struct {
	coordinator *RedisSessionCoordinator
	stateKey    string
	id          string
	token       string
	epoch       uint64
	done        chan struct{}
	stopRenew   chan struct{}

	mu           sync.Mutex
	cond         *sync.Cond
	active       bool
	pendingBegin int
	inFlight     int
	lostOnce     sync.Once
	stopOnce     sync.Once
	releaseOnce  sync.Once
}

func (l *redisSessionLease) ID() string                  { return l.id }
func (l *redisSessionLease) Epoch() uint64               { return l.epoch }
func (l *redisSessionLease) Superseded() <-chan struct{} { return l.done }

func (l *redisSessionLease) FencedSend(send func() error) error {
	l.mu.Lock()
	if !l.active {
		l.mu.Unlock()
		return ErrSessionSuperseded
	}
	l.pendingBegin++
	l.mu.Unlock()

	begun, beginErr := l.beginSend()
	l.mu.Lock()
	l.pendingBegin--
	if begun {
		l.inFlight++
	}
	active := l.active
	l.cond.Broadcast()
	l.mu.Unlock()

	if beginErr != nil || !begun {
		l.markLost()
		if beginErr != nil {
			return fmt.Errorf("%w: begin fenced send: %v", ErrSessionSuperseded, beginErr)
		}
		return ErrSessionSuperseded
	}
	if !active {
		endErr := l.endSend()
		l.finishLocalSend()
		if endErr != nil {
			l.markLost()
		}
		return ErrSessionSuperseded
	}

	sendErr := send()
	endErr := l.endSend()
	l.finishLocalSend()
	if endErr != nil {
		l.markLost()
		return fmt.Errorf("%w: end fenced send: %v", ErrSessionSuperseded, endErr)
	}
	return sendErr
}

func (l *redisSessionLease) Release() {
	l.releaseOnce.Do(func() {
		l.mu.Lock()
		l.deactivateLocked()
		for l.pendingBegin != 0 || l.inFlight != 0 {
			l.cond.Wait()
		}
		l.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), l.coordinator.config.OperationTimeout)
		defer cancel()
		_, _ = redisReleaseSession.Run(ctx, l.coordinator.client, []string{l.stateKey}, l.token).Int64()
	})
}

func (l *redisSessionLease) renewLoop() {
	ticker := time.NewTicker(l.coordinator.config.RenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-l.coordinator.ctx.Done():
			l.markLost()
			return
		case <-l.stopRenew:
			return
		case <-ticker.C:
			owned, err := l.renew()
			if err != nil || !owned {
				l.markLost()
				return
			}
		}
	}
}

func (l *redisSessionLease) renew() (bool, error) {
	ctx, cancel := context.WithTimeout(l.coordinator.ctx, l.coordinator.config.OperationTimeout)
	defer cancel()
	result, err := redisRenewSession.Run(ctx, l.coordinator.client, []string{l.stateKey}, l.token, l.coordinator.config.LeaseTTL.Milliseconds()).Int64()
	return result == 1, err
}

func (l *redisSessionLease) beginSend() (bool, error) {
	ctx, cancel := context.WithTimeout(l.coordinator.ctx, l.coordinator.config.OperationTimeout)
	defer cancel()
	result, err := redisBeginSessionSend.Run(ctx, l.coordinator.client, []string{l.stateKey}, l.token, l.coordinator.config.LeaseTTL.Milliseconds()).Int64()
	return result == 1, err
}

func (l *redisSessionLease) endSend() error {
	ctx, cancel := context.WithTimeout(context.Background(), l.coordinator.config.OperationTimeout)
	defer cancel()
	result, err := redisEndSessionSend.Run(ctx, l.coordinator.client, []string{l.stateKey}, l.token, l.coordinator.config.LeaseTTL.Milliseconds()).Int64()
	if err != nil {
		return err
	}
	if result < 0 {
		return ErrSessionSuperseded
	}
	return nil
}

func (l *redisSessionLease) finishLocalSend() {
	l.mu.Lock()
	l.inFlight--
	l.cond.Broadcast()
	l.mu.Unlock()
}

func (l *redisSessionLease) markLost() {
	l.lostOnce.Do(func() {
		l.mu.Lock()
		l.deactivateLocked()
		l.mu.Unlock()
	})
}

func (l *redisSessionLease) deactivateLocked() {
	l.active = false
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	l.stopOnce.Do(func() { close(l.stopRenew) })
	l.cond.Broadcast()
}
