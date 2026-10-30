package identity

import (
	"context"
	"errors"
)

// Change the password at the next sign-in (migration
// 404). users.password_change_required is set by the migration import
// (migrateimport) for imported accounts; the tenant administrator's member
// endpoints that also set it were removed in 1.0.35. Sign-in itself is unchanged (password, sign-in code, MFA and
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
