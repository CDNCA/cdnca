package systemusersettings

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// the Cloudflare Turnstile secret typed on the settings
// page is one of the page secrets (SecretCaptchaTurnstileSecret) in the same
// envelope as the CAPTCHA and KYC secrets; the site key is a public settings
// field.

// turnstileSiteKeyPattern: Cloudflare site keys are short ASCII tokens.
var turnstileSiteKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

// ErrTurnstileSecretUnset: no secret is saved on the page.
var ErrTurnstileSecretUnset = errors.New("platform Turnstile secret is not configured")

func turnstileSiteKeyFieldError(value string) error {
	if value == "" || turnstileSiteKeyPattern.MatchString(value) {
		return nil
	}
	return fielderr.New(ErrInvalidInput, "value.captcha_turnstile_site_key", fielderr.InvalidFormat)
}

// TurnstileSecretConfigured reports whether the page holds a Turnstile
// secret (no decryption; the anonymous registration config reads it).
func TurnstileSecretConfigured(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	if pool == nil {
		return false, ErrInvalidStore
	}
	var configured bool
	err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform_system_user_settings settings
		JOIN access_scopes scope ON scope.id=settings.platform_scope_id AND scope.kind='platform' AND scope.tenant_id IS NULL
		WHERE settings.secrets_fingerprints ? $1)`, SecretCaptchaTurnstileSecret).Scan(&configured)
	if err != nil {
		return false, fmt.Errorf("read platform Turnstile secret state: %w", err)
	}
	return configured, nil
}

// OpenTurnstileSecret decrypts the page-saved Turnstile secret
// (ErrTurnstileSecretUnset: none saved). The caller clears the result.
func OpenTurnstileSecret(ctx context.Context, pool *pgxpool.Pool, cipher SecretCipher) ([]byte, error) {
	if pool == nil {
		return nil, ErrInvalidStore
	}
	var row secretsRow
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var err error
		_, row, err = platformSettingsRowTx(ctx, tx, uuid.Nil)
		return err
	})
	if errors.Is(err, ErrPermissionDenied) || err == nil && row.keyID == nil {
		return nil, ErrTurnstileSecretUnset
	}
	if err != nil {
		return nil, fmt.Errorf("read platform Turnstile secret: %w", err)
	}
	secrets, err := openSecrets(cipher, row.scopeID.String(), *row.keyID, row.ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(secrets)
	secret, ok := secrets[SecretCaptchaTurnstileSecret]
	if !ok {
		return nil, ErrTurnstileSecretUnset
	}
	return []byte(secret), nil
}
