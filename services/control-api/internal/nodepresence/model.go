package nodepresence

import (
	"errors"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

const (
	StatusOnline  = "online"
	StatusOffline = "offline"

	OutcomeAdvanced  = "advanced"
	OutcomeDuplicate = "duplicate"
	OutcomeStale     = "stale"
)

var (
	ErrInvalidHeartbeat   = errors.New("invalid heartbeat")
	ErrNodeNotFound       = errors.New("heartbeat node not found")
	ErrProjectionConflict = errors.New("heartbeat projection conflict")
	ErrLeaseExpired       = errors.New("heartbeat lease expired")
	ErrNoMessage          = errors.New("no heartbeat message available")
)

type Envelope struct {
	NodeID    uuid.UUID
	Heartbeat *agentv1.Heartbeat
	Digest    [32]byte
}

type ProjectionResult struct {
	NodeID            uuid.UUID
	SessionEpoch      int64
	HeartbeatSequence int64
	EventID           uuid.UUID
	RequestID         uuid.UUID
	Digest            [32]byte
	ProjectedAt       time.Time
	LeaseExpiresAt    time.Time
	Status            string
	Outcome           string
	RefreshLease      bool
	AgentVersion      *string
}

type LeaseRecord struct {
	NodeID            uuid.UUID
	SessionEpoch      int64
	HeartbeatSequence int64
	EventID           uuid.UUID
	LastSeenAt        time.Time
	ExpiresAt         time.Time
}

type OfflineCandidate struct {
	NodeID            uuid.UUID
	SessionEpoch      int64
	HeartbeatSequence int64
	EventID           uuid.UUID
	RequestID         uuid.UUID
	Digest            [32]byte
	LastSeenAt        time.Time
	LeaseExpiresAt    time.Time
}
