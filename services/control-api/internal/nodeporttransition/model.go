package nodeporttransition

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidInput    = errors.New("invalid node gateway port transition input")
	ErrConflict        = errors.New("node gateway port transition conflict")
	ErrUnauthenticated = errors.New("node gateway port transition identity is not authenticated")
	ErrNotFound        = errors.New("node gateway port transition not found")
)

type State string

type CommandAction string

const (
	StatePreparing  State = "preparing"
	StateSwitching  State = "switching"
	StateSwitched   State = "switched"
	StateFailed     State = "failed"
	StateRolledBack State = "rolled_back"
	StateFinalized  State = "finalized"
)

const (
	ActionSwitch   CommandAction = "switch"
	ActionFinalize CommandAction = "finalize"
	ActionRollback CommandAction = "rollback"
)

type Actor struct {
	ScopeID uuid.UUID
	UserID  uuid.UUID
}

type Endpoint struct {
	Address       string `json:"address"`
	ServerName    string `json:"server_name"`
	ListenAddress string `json:"listen_address"`
}

type ActionRequest struct {
	TransitionID   uuid.UUID
	NodeID         uuid.UUID
	RequestID      string
	IdempotencyKey string
}

type CommandOutbox struct {
	ID           uuid.UUID
	TransitionID uuid.UUID
	NodeID       uuid.UUID
	Action       CommandAction
	Subject      string
	MessageID    string
	Payload      []byte
	ClaimToken   uuid.UUID
}

type Transition struct {
	ID                    uuid.UUID
	ScopeID               uuid.UUID
	NodeID                uuid.UUID
	Revision              uint64
	ExpectedNodeRevision  int64
	OldEndpoint           Endpoint
	NewEndpoint           Endpoint
	CompatibilityDeadline time.Time
	RollbackDeadline      time.Time
	CertificateSHA256     string
	State                 State
	StatusRevision        uint64
	ActiveEndpoint        Endpoint
	ErrorCode             string
	RequestID             string
	IdempotencyKey        string
	CreatedByUserID       uuid.UUID
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

type CreateRequest struct {
	NodeID                uuid.UUID
	ExpectedNodeRevision  int64
	OldEndpoint           Endpoint
	NewEndpoint           Endpoint
	CompatibilityDeadline time.Time
	RollbackDeadline      time.Time
	CertificateSHA256     string
	RequestID             string
	IdempotencyKey        string
}

type StatusReport struct {
	PayloadSHA256     []byte
	TransitionID      uuid.UUID
	NodeID            uuid.UUID
	Revision          uint64
	StatusRevision    uint64
	State             State
	ActiveEndpoint    Endpoint
	CertificateSHA256 string
	ErrorCode         string
	EventID           uuid.UUID
	PubAckStream      string
	PubAckSequence    uint64
	ObservedAt        time.Time
}
