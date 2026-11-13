package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Tenant member email invitations (migration 398). The
// tenant administrator invites an email; the anonymous notification outbox
// mails a one-time link that expires after TenantMemberInvitationTTL; the
// invitee picks a username and password and becomes a tenant_viewer
// sub-account with the invited email. The link token is
// HMAC(invitation key, invitation id) so the dispatcher can rebuild it; only
// SHA-256(token) is stored. A new invitation to the same email revokes the
// pending one.

const (
	TenantMemberInvitationEventType = "identity.tenant_member_invitation"
	TenantMemberInvitationTTL       = 72 * time.Hour
	tenantMemberInvitationTemplate  = "tenant_member_invitation"
	tenantMemberInvitationDomain    = "cdnca/identity/tenant-member-invitation/v1\x00"
)

var (
	ErrTenantMemberInvitationUnavailable = errors.New("tenant member invitation is unavailable")
	ErrTenantMemberInvitationInvalid     = errors.New("tenant member invitation is invalid or expired")
	ErrTenantMemberEmailTaken            = errors.New("tenant member email is already used")
)

type TenantMemberInvitation struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AcceptTenantMemberInvitationInput struct {
	Token       string
	Username    string
	DisplayName string
	Password    string
	RequestID   string
}

// SetTenantMemberInvitationKey enables invitations. key (32+ bytes) derives
// the link tokens; the outbox enqueues the invitation mail.
func (s *Service) SetTenantMemberInvitationKey(key []byte, outbox *notification.Store) error {
	if s == nil || len(key) < 32 || outbox == nil {
		return errors.New("tenant member invitation key and outbox are required")
	}
	s.invitationKey = append([]byte(nil), key...)
	s.invitationOutbox = outbox
	return nil
}

func invitationToken(key []byte, id uuid.UUID) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(tenantMemberInvitationDomain))
	_, _ = mac.Write(id[:])
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func invitationTokenDigest(token string) []byte {
	digest := sha256.Sum256([]byte(token))
	return digest[:]
}

func normalizeInvitationEmail(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	address, err := mail.ParseAddress(value)
	return value, err == nil && address.Address == value && len(value) <= 254
}

// InviteTenantMember records an invitation and enqueues its mail in one
// transaction.
func (s *Service) InviteTenantMember(ctx context.Context, actor Principal, email, requestID string) (TenantMemberInvitation, error) {
	if s.invitationOutbox == nil || len(s.invitationKey) == 0 {
		return TenantMemberInvitation{}, ErrTenantMemberInvitationUnavailable
	}
	email, valid := normalizeInvitationEmail(email)
	if !valid || requestID == "" || len(requestID) > 128 {
		return TenantMemberInvitation{}, ErrInvalidUserInput
	}
	id, err := uuid.NewV7()
	if err != nil {
		return TenantMemberInvitation{}, err
	}
	reference, err := uuid.NewV7()
	if err != nil {
		return TenantMemberInvitation{}, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	invitation := TenantMemberInvitation{ID: id, Email: email, Status: "pending", CreatedAt: now, ExpiresAt: now.Add(TenantMemberInvitationTTL)}
	err = pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		if err := s.store.authorizeTenantMemberAdminTx(ctx, tx, actor); err != nil {
			return err
		}
		var taken bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`, email).Scan(&taken); err != nil {
			return err
		}
		if taken {
			return ErrTenantMemberEmailTaken
		}
		if _, err := tx.Exec(ctx, `UPDATE tenant_member_invitations_398 SET status='revoked',finished_at=$3
			WHERE scope_id=$1 AND email=$2 AND status='pending'`, actor.ScopeID, email, now); err != nil {
			return err
		}
		enqueued, err := s.invitationOutbox.EnqueueDispatchTx(ctx, tx, notification.DispatchEnqueueRequest{
			ScopeID: actor.ScopeID, SourceEventID: id.String(), AnonymousDispatchReference: reference,
			EventType: TenantMemberInvitationEventType, SelectedChannel: notification.ChannelEmail,
			Templates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: {
				ID: tenantMemberInvitationTemplate, Version: 1, Channel: notification.ChannelEmail}},
			AuditRequestID: requestID,
		})
		if errors.Is(err, notification.ErrInvalidPolicy) {
			return ErrTenantMemberInvitationUnavailable
		}
		if err != nil {
			return err
		}
		if len(enqueued.Deliveries) != 1 {
			return ErrTenantMemberInvitationUnavailable
		}
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_member_invitations_398(id,scope_id,email,token_digest,
			anonymous_dispatch_reference,outbox_id,invited_by_user_id,status,created_at,expires_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9)`, id, actor.ScopeID, email,
			invitationTokenDigest(invitationToken(s.invitationKey, id)), reference, enqueued.Deliveries[0].OutboxID,
			actor.UserID, now, invitation.ExpiresAt); err != nil {
			return err
		}
		return s.store.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: "identity.tenant_member.invite", ResourceType: "tenant_member_invitation", ResourceID: id.String(),
			RequestID: requestID, Result: "success", Changes: []audit.Change{{Field: "email", Before: nil, After: email}},
			Payload: map[string]any{"expires_at": invitation.ExpiresAt, "role": UserRoleViewer}})
	})
	if err != nil {
		return TenantMemberInvitation{}, err
	}
	return invitation, nil
}

// ListTenantMemberInvitations lists the scope's recent invitations; pending
// ones past their expiry read as expired.
func (s *Service) ListTenantMemberInvitations(ctx context.Context, actor Principal) ([]TenantMemberInvitation, error) {
	var items []TenantMemberInvitation
	err := pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		if err := s.store.authorizeTenantMemberAdminTx(ctx, tx, actor); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id,email,
			CASE WHEN status='pending' AND expires_at<=$2 THEN 'expired' ELSE status END,created_at,expires_at
			FROM tenant_member_invitations_398 WHERE scope_id=$1 ORDER BY created_at DESC,id LIMIT 200`, actor.ScopeID, s.now().UTC())
		if err != nil {
			return err
		}
		items, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (TenantMemberInvitation, error) {
			var item TenantMemberInvitation
			return item, row.Scan(&item.ID, &item.Email, &item.Status, &item.CreatedAt, &item.ExpiresAt)
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list tenant member invitations: %w", err)
	}
	return items, nil
}

// RevokeTenantMemberInvitation withdraws a pending invitation.
func (s *Service) RevokeTenantMemberInvitation(ctx context.Context, actor Principal, id uuid.UUID, requestID string) error {
	if id == uuid.Nil || requestID == "" {
		return ErrInvalidUserInput
	}
	return pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		if err := s.store.authorizeTenantMemberAdminTx(ctx, tx, actor); err != nil {
			return err
		}
		var email string
		err := tx.QueryRow(ctx, `UPDATE tenant_member_invitations_398 SET status='revoked',finished_at=$3
			WHERE scope_id=$1 AND id=$2 AND status='pending' RETURNING email`, actor.ScopeID, id, s.now().UTC()).Scan(&email)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMembershipNotFound
		}
		if err != nil {
			return err
		}
		return s.store.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: "identity.tenant_member.invitation.revoke", ResourceType: "tenant_member_invitation", ResourceID: id.String(),
			RequestID: requestID, Result: "success", Changes: []audit.Change{{Field: "status", Before: "pending", After: "revoked"}}})
	})
}

// AcceptTenantMemberInvitation turns a valid pending invitation into a
// tenant_viewer sub-account. Anonymous: the token is the only credential.
func (s *Service) AcceptTenantMemberInvitation(ctx context.Context, input AcceptTenantMemberInvitationInput) (TenantMember, error) {
	if len(s.invitationKey) == 0 {
		return TenantMember{}, ErrTenantMemberInvitationUnavailable
	}
	input.Username = strings.ToLower(strings.TrimSpace(input.Username))
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if len(input.Token) != 43 || !validUsername(input.Username) || input.DisplayName == "" || len(input.DisplayName) > 128 ||
		len(input.Password) < 12 || len(input.Password) > 1024 || input.RequestID == "" {
		return TenantMember{}, ErrInvalidUserInput
	}
	hash, err := HashPassword(input.Password)
	if err != nil {
		return TenantMember{}, ErrInvalidUserInput
	}
	userID, err := newUUID()
	if err != nil {
		return TenantMember{}, err
	}
	var member TenantMember
	err = pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		var id, scopeID, invitedBy uuid.UUID
		var email string
		var expiresAt time.Time
		err := tx.QueryRow(ctx, `SELECT invitation.id,invitation.scope_id,invitation.email,invitation.invited_by_user_id,invitation.expires_at
			FROM tenant_member_invitations_398 invitation
			JOIN access_scopes scope ON scope.id=invitation.scope_id AND scope.kind='tenant'
			JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
			WHERE invitation.token_digest=$1 AND invitation.status='pending' FOR UPDATE OF invitation`,
			invitationTokenDigest(input.Token)).Scan(&id, &scopeID, &email, &invitedBy, &expiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTenantMemberInvitationInvalid
		}
		if err != nil {
			return err
		}
		now := s.now().UTC()
		if !hmac.Equal([]byte(invitationToken(s.invitationKey, id)), []byte(input.Token)) || !now.Before(expiresAt) {
			return ErrTenantMemberInvitationInvalid
		}
		if _, err := tx.Exec(ctx, `INSERT INTO users(id,username,display_name,email,password_hash,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$6)`, userID, input.Username, input.DisplayName, email, hash, now); err != nil {
			if isUniqueViolation(err) {
				if strings.Contains(err.Error(), "users_email_registration_unique_159") {
					return ErrTenantMemberEmailTaken
				}
				return ErrConflict
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,$3)`, scopeID, userID, now); err != nil {
			return err
		}
		roleID, err := tenantRoleID(ctx, tx, scopeID, UserRoleViewer)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$3,$4)`,
			scopeID, userID, roleID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE tenant_member_invitations_398 SET status='accepted',accepted_user_id=$2,finished_at=$3
			WHERE id=$1`, id, userID, now); err != nil {
			return err
		}
		member = TenantMember{UserID: userID, Username: input.Username, DisplayName: input.DisplayName, Email: &email,
			Status: UserStatusActive, Role: UserRoleViewer, CreatedAt: now}
		return s.store.auditor.Append(ctx, tx, audit.Event{ScopeID: scopeID, ActorUserID: &userID,
			Action: "identity.tenant_member.invitation.accept", ResourceType: "user", ResourceID: userID.String(),
			RequestID: input.RequestID, Result: "success",
			Changes: []audit.Change{{Field: "username", Before: nil, After: input.Username}, {Field: "role", Before: nil, After: UserRoleViewer}},
			Payload: map[string]any{"invitation_id": id.String(), "invited_by_user_id": invitedBy.String()}})
	})
	if err != nil {
		return TenantMember{}, err
	}
	return member, nil
}

// TenantMemberInvitationMail is what the provider sends.
type TenantMemberInvitationMail struct {
	OutboxID       uuid.UUID
	Contact        string
	Subject        string
	Body           string
	ActionURL      string
	IdempotencyKey string
	AttemptNumber  int
	TemplateID     string
}

type TenantMemberInvitationSender interface {
	SendTenantMemberInvitation(context.Context, TenantMemberInvitationMail) notification.SendResult
}

// TenantMemberInvitationDispatcher delivers identity.tenant_member_invitation
// outbox rows: it rebuilds the link of a still pending, unexpired invitation
// and hands the mail to the sender; a finished or expired one is acknowledged
// without sending.
type TenantMemberInvitationDispatcher struct {
	pool      *pgxpool.Pool
	key       []byte
	acceptURL url.URL
	sender    TenantMemberInvitationSender
	now       func() time.Time
}

func NewTenantMemberInvitationDispatcher(pool *pgxpool.Pool, key []byte, acceptURL string, sender TenantMemberInvitationSender) (*TenantMemberInvitationDispatcher, error) {
	parsed, err := url.Parse(acceptURL)
	if pool == nil || len(key) < 32 || sender == nil || err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("tenant member invitation dispatcher configuration is invalid")
	}
	return &TenantMemberInvitationDispatcher{pool: pool, key: append([]byte(nil), key...), acceptURL: *parsed, sender: sender, now: time.Now}, nil
}

func (d *TenantMemberInvitationDispatcher) Dispatch(ctx context.Context, attempt notification.AnonymousDeliveryAttempt) notification.AnonymousDispatchResult {
	if d == nil || attempt.EventType != TenantMemberInvitationEventType || attempt.Channel != notification.ChannelEmail ||
		attempt.OutboxID == uuid.Nil || attempt.AnonymousDispatchReference == uuid.Nil || attempt.DedupKey == "" || attempt.AttemptNumber < 1 {
		return invitationDispatchFailure(notification.FailurePermanent, "tenant_member_invitation_dispatch_invalid")
	}
	var id uuid.UUID
	var email, tenantName, status string
	var expiresAt time.Time
	err := d.pool.QueryRow(ctx, `SELECT invitation.id,invitation.email,invitation.status,invitation.expires_at,tenant.display_name
		FROM tenant_member_invitations_398 invitation
		JOIN access_scopes scope ON scope.id=invitation.scope_id
		JOIN tenants tenant ON tenant.id=scope.tenant_id
		WHERE invitation.anonymous_dispatch_reference=$1 AND invitation.outbox_id=$2 AND invitation.scope_id=$3`,
		attempt.AnonymousDispatchReference, attempt.OutboxID, attempt.ScopeID).Scan(&id, &email, &status, &expiresAt, &tenantName)
	if errors.Is(err, pgx.ErrNoRows) {
		return notification.AnonymousDispatchResult{Disposition: notification.AnonymousDispatchNoopACK}
	}
	if err != nil {
		return invitationDispatchFailure(notification.FailureTemporary, "tenant_member_invitation_dispatch_unavailable")
	}
	if status != "pending" || !d.now().Before(expiresAt) {
		return notification.AnonymousDispatchResult{Disposition: notification.AnonymousDispatchNoopACK}
	}
	link := d.acceptURL
	link.Fragment = url.Values{"token": {invitationToken(d.key, id)}}.Encode()
	render := func(text string) string { return strings.ReplaceAll(text, "{{.tenant}}", tenantName) }
	sent := d.sender.SendTenantMemberInvitation(ctx, TenantMemberInvitationMail{
		OutboxID: attempt.OutboxID, Contact: email, Subject: render(attempt.Subject), Body: render(attempt.Body),
		ActionURL: link.String(), IdempotencyKey: attempt.DedupKey, AttemptNumber: attempt.AttemptNumber, TemplateID: attempt.Template.ID,
	})
	if sent.Failure != nil {
		return notification.AnonymousDispatchResult{Failure: sent.Failure, Observation: sent.Observation}
	}
	result := notification.AnonymousDispatchResult{Provider: sent.Provider, ProviderDeliveryID: sent.ProviderDeliveryID, Observation: sent.Observation}
	switch sent.Disposition {
	case "", notification.SendDelivered:
		result.Disposition = notification.AnonymousDispatchDelivered
	case notification.SendAccepted:
		result.Disposition = notification.AnonymousDispatchAccepted
	case notification.SendUnknown:
		result.Disposition = notification.AnonymousDispatchUnknown
	default:
		return invitationDispatchFailure(notification.FailurePermanent, "tenant_member_invitation_sender_contract_invalid")
	}
	return result
}

func invitationDispatchFailure(class notification.FailureClass, code string) notification.AnonymousDispatchResult {
	return notification.AnonymousDispatchResult{Failure: &notification.Failure{Class: class, Code: code}}
}
