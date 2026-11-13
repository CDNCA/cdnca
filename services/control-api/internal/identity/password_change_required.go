package identity

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Change the password at the next sign-in (migration
// 404). A tenant administrator sets users.password_change_required on a
// sub-account. Sign-in itself is unchanged (password, sign-in code, MFA and
// step-up run as before and a session is issued), but every session request
// is refused with ErrPasswordChangeRequired (403 password_change_required)
// except the requests a client needs to finish the change: reading the
// session (GET /v1/auth/me) and changing the password (POST
// /v1/account/password, which still requires the current password). The
// password change clears the flag and, as before, signs the user out
// everywhere, so the next sign-in is a normal one. Refresh and sign-out are
// not session requests and keep working.

var ErrPasswordChangeRequired = errors.New("password change required")

type passwordChangeExemptKey struct{}

// WithPasswordChangeExempt marks a request that may run while the session's
// user still has to change the password.
func WithPasswordChangeExempt(ctx context.Context) context.Context {
	return context.WithValue(ctx, passwordChangeExemptKey{}, true)
}

func checkPasswordChangeRequired(ctx context.Context, principal Principal) error {
	if !principal.PasswordChangeRequired {
		return nil
	}
	if exempt, _ := ctx.Value(passwordChangeExemptKey{}).(bool); exempt {
		return nil
	}
	return ErrPasswordChangeRequired
}

// SetTenantMemberPasswordChangeRequired sets or clears "change the password
// at the next sign-in" for a sub-account of the actor's tenant scope (not the
// owner, not yourself, not a user shared with another scope). Setting it
// does not sign the member out: its open sessions are limited to the password
// change from the next request on.
func (s *Service) SetTenantMemberPasswordChangeRequired(ctx context.Context, actor Principal, userID uuid.UUID, required bool, requestID string) (TenantMember, error) {
	if userID == uuid.Nil || requestID == "" {
		return TenantMember{}, ErrInvalidUserInput
	}
	err := pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		if err := s.store.authorizeTenantMemberAdminTx(ctx, tx, actor); err != nil {
			return err
		}
		if err := lockTenantMemberTargetTx(ctx, tx, actor, userID); err != nil {
			return err
		}
		var before bool
		if err := tx.QueryRow(ctx, `SELECT password_change_required FROM users WHERE id=$1`, userID).Scan(&before); err != nil {
			return err
		}
		if before == required {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET password_change_required=$2,revision=revision+1,updated_at=$3 WHERE id=$1`,
			userID, required, s.now().UTC()); err != nil {
			return err
		}
		action := "identity.tenant_member.password_change.require"
		if !required {
			action = "identity.tenant_member.password_change.release"
		}
		return s.store.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: action, ResourceType: "user", ResourceID: userID.String(), RequestID: requestID, Result: "success",
			Changes: []audit.Change{{Field: "password_change_required", Before: before, After: required}}})
	})
	if err != nil {
		return TenantMember{}, err
	}
	return s.tenantMember(ctx, actor, userID)
}
