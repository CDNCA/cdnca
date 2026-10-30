package identity

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// LegacyPasswordVerifier checks the source-system password hash an imported
// user keeps until the first sign-in (ADR 0016 §6.1, plan B). The hashes
// live sealed in migrate_import_legacy_passwords; only migrateimport reads
// them. A nil verifier keeps legacy users on forced reset.
type LegacyPasswordVerifier interface {
	// VerifyLegacyPassword reports whether userID has an unexpired source
	// hash that accepts password.
	VerifyLegacyPassword(ctx context.Context, userID uuid.UUID, password string) (bool, error)
	// ConsumeLegacyPasswordTx deletes the user's source hash in tx; false
	// when it is gone (expired, cleared or used by a concurrent sign-in).
	ConsumeLegacyPasswordTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (bool, error)
}

// SetLegacyPasswordVerifier attaches the plan B verifier.
func (s *Service) SetLegacyPasswordVerifier(verifier LegacyPasswordVerifier) {
	if s != nil {
		s.legacyPasswords = verifier
	}
}

// hashLegacyUpgrade hashes a password accepted by a source hash. Source
// systems allowed passwords that break cdnca's policy, so the policy is not
// applied here; such users are asked for a new password at once.
func hashLegacyUpgrade(password string) (string, error) {
	return hashPasswordUnchecked(password)
}
