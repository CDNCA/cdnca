package edgestatus

import (
	"context"
	"errors"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

var (
	ErrNoMessage          = errors.New("no deployment status message available")
	ErrInvalidStatus      = errors.New("invalid deployment status")
	ErrDeploymentMissing  = errors.New("deployment status target does not exist")
	ErrBindingConflict    = errors.New("deployment status binding conflict")
	ErrPayloadConflict    = errors.New("deployment status payload conflict")
	ErrInvalidTransition  = errors.New("invalid deployment status transition")
	ErrProjectionConflict = errors.New("deployment status projection conflict")
)

const (
	DispositionAck  = "ack"
	DispositionNak  = "nak"
	DispositionTerm = "term"

	OutcomeAdvanced  = "advanced"
	OutcomeStale     = "stale"
	OutcomeDuplicate = "duplicate"
)

type Envelope struct {
	NodeID       uuid.UUID
	DeploymentID uuid.UUID
	ConfigID     uuid.UUID
	EventID      uuid.UUID
	RequestID    uuid.UUID
	Status       *agentv1.DeploymentStatus
	Payload      []byte
	Digest       [32]byte
}

type ProjectionResult struct {
	Outcome            string
	DeploymentID       uuid.UUID
	Attempt            uint32
	TransitionSequence uint64
	State              string
	ReceivedAt         time.Time
}

type Projector interface {
	Project(context.Context, Envelope) (ProjectionResult, error)
}
