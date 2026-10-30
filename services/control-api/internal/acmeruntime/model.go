package acmeruntime

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput           = errors.New("acme_runtime_invalid_input")
	ErrConflict               = errors.New("acme_runtime_conflict")
	ErrLeaseLost              = errors.New("acme_runtime_lease_lost")
	ErrUnsupportedKeyMaterial = errors.New("acme_runtime_unsupported_key_material")
)

type Issuer interface {
	Issue(context.Context, acmeworker.IssueRequest) (acmeworker.IssueResult, error)
}

type Config struct {
	DirectoryURL  string
	Contacts      []string
	AcceptTerms   bool
	LeaseDuration time.Duration
	SettleTimeout time.Duration
	RetryBase     time.Duration
	RetryMaximum  time.Duration
	MaxAttempts   int
}

func DefaultConfig(directoryURL string, contacts []string) Config {
	return Config{
		DirectoryURL: directoryURL, Contacts: append([]string(nil), contacts...), AcceptTerms: true,
		LeaseDuration: 10 * time.Minute, SettleTimeout: 30 * time.Second,
		RetryBase: time.Minute, RetryMaximum: time.Hour, MaxAttempts: 10,
	}
}

type Lease struct {
	OutboxID  uuid.UUID
	ScopeID   uuid.UUID
	OrderID   uuid.UUID
	Token     uuid.UUID
	Attempt   int
	ExpiresAt time.Time
	Payload   json.RawMessage
}

type DispatchOutcome string

const (
	OutcomeIdle      DispatchOutcome = "idle"
	OutcomeCompleted DispatchOutcome = "completed"
	OutcomeRetry     DispatchOutcome = "retry_scheduled"
	OutcomeExhausted DispatchOutcome = "exhausted"
)

type DispatchResult struct {
	Outcome   DispatchOutcome
	OutboxID  uuid.UUID
	OrderID   uuid.UUID
	Attempt   int
	ErrorCode string
}

type runtimeError struct {
	code string
	err  error
}

func (e *runtimeError) Error() string { return e.code }
func (e *runtimeError) Unwrap() error { return e.err }

func codedError(code string, err error) error {
	return &runtimeError{code: code, err: err}
}
