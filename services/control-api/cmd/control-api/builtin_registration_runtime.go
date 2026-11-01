package main

import (
	"crypto/sha256"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/jackc/pgx/v5/pgxpool"
)

// openBuiltInRegistration builds the built-in CAPTCHA registration used when
// ACCOUNT_REGISTRATION_ENABLED is off. Its digest key is
// derived from the access secret like the sign-in throttle key, so a fresh
// installation needs no extra secret.
func openBuiltInRegistration(
	pool *pgxpool.Pool,
	settings *systemusersettings.Service,
	identityService *identity.Service,
	accessSecret string,
) (*accountregistration.BuiltInService, error) {
	store, err := accountregistration.NewPostgresStore(pool)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(append([]byte("cdnca.account-registration.builtin.v1\x00"), accessSecret...))
	return accountregistration.NewBuiltInService(store, settings, identityService, key[:])
}
