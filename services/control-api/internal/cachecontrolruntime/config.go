package cachecontrolruntime

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"
)

const (
	DefaultCommandSubjectPrefix = "cdnca.agent.commands.cache"
	DefaultStatusSubjectPrefix  = "cdnca.agent.deployment-status.cache"
	DefaultDLQSubjectPrefix     = "cdnca.agent.deployment-status.cache-dlq"
	maxStreamReplicas           = 5
)

var (
	ErrInvalidConfig = errors.New("invalid cache control runtime configuration")
	ErrNoMessage     = errors.New("no cache control status message")
)

type Config struct {
	CommandStream        string
	StatusStream         string
	CommandSubjectPrefix string
	StatusSubjectPrefix  string
	DLQSubjectPrefix     string
	// Replicas is the minimum replica count the shared Agent streams must
	// carry: 1 on the single-host native NATS, 3 on clustered deployments.
	Replicas            int
	Durable             string
	WorkerID            string
	PollInterval        time.Duration
	FetchTimeout        time.Duration
	OperationTimeout    time.Duration
	LeaseDuration       time.Duration
	AckWait             time.Duration
	NakBaseDelay        time.Duration
	NakMaximumDelay     time.Duration
	ClaimBatch          int
	MaxDeliver          int
	MaxAckPending       int
	MaxWaiting          int
	MaxPayloadBytes     int
	TenantDispatchRate  float64
	TenantDispatchBurst int
	SiteDispatchRate    float64
	SiteDispatchBurst   int
	NodeDispatchRate    float64
	NodeDispatchBurst   int
	MaxDispatchLimiters int
	Clock               func() time.Time
	DispatchSleep       func(context.Context, time.Duration) error
}

func DefaultConfig() Config {
	return Config{
		CommandStream: "AGENT_COMMANDS", StatusStream: "AGENT_DEPLOYMENT_STATUS",
		CommandSubjectPrefix: DefaultCommandSubjectPrefix,
		StatusSubjectPrefix:  DefaultStatusSubjectPrefix,
		DLQSubjectPrefix:     DefaultDLQSubjectPrefix,
		Replicas:             1,
		Durable:              "control_api_cache_status", WorkerID: "control-api-cache-runtime",
		PollInterval: 500 * time.Millisecond, FetchTimeout: 2 * time.Second,
		OperationTimeout: 5 * time.Second, LeaseDuration: time.Hour,
		AckWait: 2 * time.Minute, NakBaseDelay: time.Second, NakMaximumDelay: 30 * time.Second,
		ClaimBatch: 16, MaxDeliver: 5, MaxAckPending: 64, MaxWaiting: 16,
		MaxPayloadBytes:    1 << 20,
		TenantDispatchRate: 64, TenantDispatchBurst: 16,
		SiteDispatchRate: 32, SiteDispatchBurst: 8,
		NodeDispatchRate: 16, NodeDispatchBurst: 4,
		MaxDispatchLimiters: 32_768,
		Clock:               time.Now, DispatchSleep: sleepContext,
	}
}

func (config Config) validate() error {
	if !validNATSName(config.CommandStream) || !validNATSName(config.StatusStream) ||
		!validNATSName(config.Durable) || !validIdentifier(config.WorkerID) ||
		!validSubjectPrefix(config.CommandSubjectPrefix) ||
		!validSubjectPrefix(config.StatusSubjectPrefix) ||
		!validSubjectPrefix(config.DLQSubjectPrefix) ||
		config.CommandStream == config.StatusStream ||
		config.CommandSubjectPrefix == config.StatusSubjectPrefix ||
		config.CommandSubjectPrefix == config.DLQSubjectPrefix ||
		config.StatusSubjectPrefix == config.DLQSubjectPrefix ||
		config.Replicas < 1 || config.Replicas > maxStreamReplicas ||
		config.Clock == nil ||
		config.PollInterval <= 0 || config.FetchTimeout <= 0 || config.OperationTimeout <= 0 ||
		config.LeaseDuration < time.Second || config.LeaseDuration > time.Hour ||
		config.AckWait <= 0 || config.NakBaseDelay <= 0 ||
		config.NakMaximumDelay < config.NakBaseDelay || config.ClaimBatch < 1 ||
		config.ClaimBatch > 16 || config.MaxDeliver < 2 || config.MaxDeliver > 100 ||
		config.MaxAckPending < config.ClaimBatch || config.MaxWaiting < 1 ||
		config.MaxPayloadBytes < 1 || config.MaxPayloadBytes > 1<<20 ||
		!validDispatchLimit(config.TenantDispatchRate, config.TenantDispatchBurst) ||
		!validDispatchLimit(config.SiteDispatchRate, config.SiteDispatchBurst) ||
		!validDispatchLimit(config.NodeDispatchRate, config.NodeDispatchBurst) ||
		config.MaxDispatchLimiters < 3 || config.MaxDispatchLimiters > 1_000_000 ||
		config.DispatchSleep == nil {
		return ErrInvalidConfig
	}
	return nil
}

func validDispatchLimit(rate float64, burst int) bool {
	return rate > 0 && rate <= 100_000 && !math.IsNaN(rate) && !math.IsInf(rate, 0) &&
		burst > 0 && burst <= 100_000
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func validNATSName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validIdentifier(value string) bool {
	return len(value) <= 128 && validNATSName(value)
}

func validSubjectPrefix(value string) bool {
	if value == "" || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, token := range strings.Split(value, ".") {
		if !validNATSName(token) {
			return false
		}
	}
	return true
}

func retryDelay(base, maximum time.Duration, delivery uint64) time.Duration {
	delay := base
	for current := uint64(1); current < delivery && delay < maximum; current++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}
