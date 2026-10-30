package acmehttp01

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeartifact"
)

const (
	ArtifactMediaType     = "application/vnd.cdnca.acme-http01-overlay.v1+json"
	ArtifactSchemaVersion = "cdnca.edge.acme-http01-overlay/v1"
	commandSubjectPrefix  = "cdnca.agent.commands.acme-http01"
	statusSubjectPrefix   = "cdnca.agent.deployment-status.acme-http01"
)

var (
	ErrInvalidConfig     = errors.New("invalid ACME HTTP-01 runtime configuration")
	ErrInvalidChallenge  = errors.New("invalid ACME HTTP-01 challenge")
	ErrNoTarget          = errors.New("no eligible ACME HTTP-01 overlay target")
	ErrArtifactBinding   = errors.New("ACME HTTP-01 artifact binding conflict")
	ErrArtifactIntegrity = errors.New("ACME HTTP-01 artifact integrity failure")
)

type ProviderConfig struct {
	Clock             func() time.Time
	ChallengeLifetime time.Duration
	HealthPoll        time.Duration
	MaxAttempts       int
	MaxTargets        int
}

func DefaultProviderConfig() ProviderConfig {
	return ProviderConfig{
		Clock: time.Now, ChallengeLifetime: 15 * time.Minute,
		HealthPoll: 100 * time.Millisecond, MaxAttempts: 3, MaxTargets: 1000,
	}
}

type ArtifactConfig struct {
	Clock                        func() time.Time
	SigningKeyID                 string
	SigningKey                   ed25519.PrivateKey
	MaxArtifactBytes             int
	MaxChunkBytes                int
	ActivationTimeout            time.Duration
	ObservationWindow            time.Duration
	RequiredConsecutiveSuccesses uint32
}

func DefaultArtifactConfig() ArtifactConfig {
	return ArtifactConfig{
		Clock: time.Now, MaxArtifactBytes: 8 << 20, MaxChunkBytes: 256 << 10,
		ActivationTimeout: 30 * time.Second, ObservationWindow: 2 * time.Second,
		RequiredConsecutiveSuccesses: 2,
	}
}

type DispatcherConfig struct {
	Clock            func() time.Time
	Stream           string
	BatchSize        int
	LeaseDuration    time.Duration
	PollInterval     time.Duration
	OperationTimeout time.Duration
	RetryDelay       time.Duration
	AttemptTimeout   time.Duration
}

func DefaultDispatcherConfig() DispatcherConfig {
	return DispatcherConfig{
		Clock: time.Now, Stream: "AGENT_COMMANDS", BatchSize: 4, LeaseDuration: 30 * time.Second,
		PollInterval: 500 * time.Millisecond, OperationTimeout: 3 * time.Second,
		RetryDelay: time.Second, AttemptTimeout: 2 * time.Minute,
	}
}

type StatusConfig struct {
	Stream           string
	Durable          string
	SubjectPrefix    string
	AckWait          time.Duration
	FetchTimeout     time.Duration
	OperationTimeout time.Duration
	NakDelay         time.Duration
	MaxAckPending    int
	MaxWaiting       int
	MaxBytes         int
}

func DefaultStatusConfig() StatusConfig {
	return StatusConfig{
		Stream: "AGENT_DEPLOYMENT_STATUS", Durable: "control_api_acme_http01_status",
		SubjectPrefix: statusSubjectPrefix, AckWait: 2 * time.Minute, FetchTimeout: 5 * time.Second,
		OperationTimeout: 5 * time.Second, NakDelay: time.Second, MaxAckPending: 256,
		MaxWaiting: 32, MaxBytes: 1 << 20,
	}
}

type FetchStore interface {
	FetchChunk(context.Context, *controlv1.FetchArtifactRequest) (edgeartifact.FetchResult, error)
}
