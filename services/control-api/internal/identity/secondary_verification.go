package identity

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Secondary identity verification (FX57): an administrator requires a tenant
// user to repeat personal verification with the first approved identity
// document (identityverification personal_reverification, which already
// enforces the fingerprint match). A request is complete once an approved and
// settled reverification case exists after requested_at. When the deadline
// passes with expiry_action=lock_sites, the enforcement worker locks the user's
// sites once.

const (
	secondaryVerificationOperation = "identity.user.secondary_verification.update"
	SecondaryVerificationEventType = "identity.secondary_verification"
	secondaryVerificationTemplate  = "identity_secondary_verification"

	SecondaryExpiryNone      = "none"
	SecondaryExpiryLockSites = "lock_sites"

	// SecondaryVerificationLockReason is stored on sites locked at the deadline.
	SecondaryVerificationLockReason = "二次实名认证逾期未完成"
)

var ErrSecondaryVerificationUnavailable = errors.New("secondary verification unavailable")

type ManagedUserSecondaryVerification struct {
	UserID        uuid.UUID  `json:"user_id"`
	TenantScopeID uuid.UUID  `json:"tenant_scope_id"`
	Revision      int64      `json:"revision"`
	Enabled       bool       `json:"enabled"`
	Deadline      *time.Time `json:"deadline"`
	ExpiryAction  string     `json:"expiry_action"`
	RequestedAt   *time.Time `json:"requested_at"`
	Completed     bool       `json:"completed"`
	EnforcedAt    *time.Time `json:"enforced_at"`
}

type UpdateManagedUserSecondaryVerificationInput struct {
	UserID           uuid.UUID
	TenantScopeID    uuid.UUID
	ExpectedRevision int64
	Enabled          bool
	Deadline         *time.Time
	ExpiryAction     string
	IdempotencyKey   string
	RequestID        string
}

// SecondaryVerificationNotifier enqueues the user notification in the caller's transaction.
type SecondaryVerificationNotifier interface {
	NotifySecondaryVerificationTx(ctx context.Context, tx pgx.Tx, request SecondaryVerificationNotice) error
}

type SecondaryVerificationNotice struct {
	ScopeID     uuid.UUID
	UserID      uuid.UUID
	Username    string
	Deadline    *time.Time
	RequestedAt time.Time
	RequestID   string
}

func (s *Service) SetSecondaryVerificationNotifier(notifier SecondaryVerificationNotifier) {
	if s != nil {
		s.secondaryVerificationNotifier = notifier
	}
}

func (s *Service) GetManagedUserSecondaryVerification(ctx context.Context, actor Actor, userID, tenantScopeID uuid.UUID) (ManagedUserSecondaryVerification, error) {
	if !validAdminActor(actor) || actor.SessionID == uuid.Nil || userID == uuid.Nil || tenantScopeID == uuid.Nil {
		return ManagedUserSecondaryVerification{}, ErrInvalidUserInput
	}
	return s.store.getManagedUserSecondaryVerification(ctx, actor, userID, tenantScopeID)
}

func (s *Service) UpdateManagedUserSecondaryVerification(ctx context.Context, actor Actor, input UpdateManagedUserSecondaryVerificationInput) (ManagedUserSecondaryVerification, error) {
	if !validAdminActor(actor) || actor.SessionID == uuid.Nil || input.UserID == uuid.Nil || input.TenantScopeID == uuid.Nil ||
		input.ExpectedRevision < 0 || input.ExpectedRevision == 1<<63-1 || !validWriteMetadata(input.IdempotencyKey, input.RequestID) ||
		(input.ExpiryAction != SecondaryExpiryNone && input.ExpiryAction != SecondaryExpiryLockSites) ||
		input.ExpiryAction == SecondaryExpiryLockSites && input.Deadline == nil ||
		!input.Enabled && (input.Deadline != nil || input.ExpiryAction != SecondaryExpiryNone) {
		return ManagedUserSecondaryVerification{}, ErrInvalidUserInput
	}
	if input.Deadline != nil {
		deadline := input.Deadline.UTC().Truncate(time.Second)
		if deadline.Year() < 2000 || deadline.Year() > 9999 {
			return ManagedUserSecondaryVerification{}, ErrInvalidUserInput
		}
		input.Deadline = &deadline
	}
	var deadline string
	if input.Deadline != nil {
		deadline = input.Deadline.Format(time.RFC3339)
	}
	digest, err := digestIdentityRequest(struct {
		ActorScopeID     uuid.UUID `json:"actor_scope_id"`
		UserID           uuid.UUID `json:"user_id"`
		TenantScopeID    uuid.UUID `json:"tenant_scope_id"`
		ExpectedRevision int64     `json:"expected_revision"`
		Enabled          bool      `json:"enabled"`
		Deadline         string    `json:"deadline"`
		ExpiryAction     string    `json:"expiry_action"`
	}{actor.ScopeID, input.UserID, input.TenantScopeID, input.ExpectedRevision, input.Enabled, deadline, input.ExpiryAction})
	if err != nil {
		return ManagedUserSecondaryVerification{}, ErrSecondaryVerificationUnavailable
	}
	return s.store.updateManagedUserSecondaryVerification(ctx, actor, input, digest, s.secondaryVerificationNotifier)
}
