package identity

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	MembershipStatusActive    = "active"
	MembershipStatusSuspended = "suspended"
)

var (
	ErrInvalidMembershipInput   = errors.New("invalid membership mutation input")
	ErrMembershipNotFound       = errors.New("membership not found")
	ErrMembershipStatusConflict = errors.New("membership status conflict")
	ErrMembershipUnavailable    = errors.New("membership mutation unavailable")
	membershipReasonPattern     = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
)

type SuspendMembershipInput struct {
	ScopeID        uuid.UUID
	UserID         uuid.UUID
	ExpectedStatus string
	ReasonCode     string
	IdempotencyKey string
	RequestID      string
	TraceID        string
}

type MembershipMutationResult struct {
	ScopeID         uuid.UUID `json:"scope_id"`
	UserID          uuid.UUID `json:"user_id"`
	PreviousStatus  string    `json:"previous_status"`
	Status          string    `json:"status"`
	ReasonCode      string    `json:"reason_code"`
	SessionsRevoked int64     `json:"sessions_revoked"`
	SuspendedAt     time.Time `json:"suspended_at"`
	Replayed        bool      `json:"replayed"`
}

func (s *Service) SuspendMembership(
	ctx context.Context,
	actor Actor,
	input SuspendMembershipInput,
) (MembershipMutationResult, error) {
	if err := normalizeSuspendMembershipInput(actor, &input); err != nil {
		return MembershipMutationResult{}, err
	}
	if s == nil || s.store == nil || !s.store.configured() {
		return MembershipMutationResult{}, ErrMembershipUnavailable
	}
	digest, err := digestMembershipMutation(input)
	if err != nil {
		return MembershipMutationResult{}, ErrMembershipUnavailable
	}
	return s.store.suspendMembership(ctx, actor, input, digest)
}

func normalizeSuspendMembershipInput(actor Actor, input *SuspendMembershipInput) error {
	if input == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil ||
		(actor.ScopeKind != "platform" && actor.ScopeKind != "tenant") ||
		input.ScopeID == uuid.Nil || input.UserID == uuid.Nil {
		return ErrInvalidMembershipInput
	}
	input.ExpectedStatus = strings.TrimSpace(input.ExpectedStatus)
	input.ReasonCode = strings.TrimSpace(input.ReasonCode)
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.TraceID = strings.TrimSpace(input.TraceID)
	if input.ExpectedStatus != MembershipStatusActive ||
		!membershipReasonPattern.MatchString(input.ReasonCode) ||
		!idempotencyPattern.MatchString(input.IdempotencyKey) ||
		!validMembershipMetadata(input.RequestID) || !validMembershipMetadata(input.TraceID) {
		return ErrInvalidMembershipInput
	}
	return nil
}

func validMembershipMetadata(value string) bool {
	return value != "" && utf8.ValidString(value) && utf8.RuneCountInString(value) <= 128
}

func digestMembershipMutation(input SuspendMembershipInput) ([32]byte, error) {
	return digestIdentityRequest(struct {
		ScopeID        uuid.UUID `json:"scope_id"`
		UserID         uuid.UUID `json:"user_id"`
		ExpectedStatus string    `json:"expected_status"`
		ReasonCode     string    `json:"reason_code"`
	}{
		ScopeID: input.ScopeID, UserID: input.UserID,
		ExpectedStatus: input.ExpectedStatus, ReasonCode: input.ReasonCode,
	})
}
