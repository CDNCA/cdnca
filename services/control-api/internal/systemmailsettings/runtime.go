package systemmailsettings

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RuntimeSettings is the read-only projection consumed by a process runtime.
// It intentionally contains provider metadata and references only; secret
// material is resolved by the process environment/secret manager.
type RuntimeSettings struct {
	Configured bool
	Revision   int64
	Value      Settings

	scopeID          uuid.UUID
	secretKeyID      *string
	secretCiphertext []byte

	mailKeyID      *string
	mailCiphertext []byte
	mailProvider   *string

	smtpKeyID      *string
	smtpCiphertext []byte

	smsTokenKeyID      *string
	smsTokenCiphertext []byte
}

// HasSMTPPassword reports whether the settings page stored an SMTP password.
func (settings RuntimeSettings) HasSMTPPassword() bool { return settings.smtpKeyID != nil }

// OpenSMTPPassword decrypts the stored SMTP password. The caller must clear
// the returned bytes.
func (settings RuntimeSettings) OpenSMTPPassword(cipher SecretCipher) ([]byte, error) {
	if settings.smtpKeyID == nil {
		return nil, ErrUnavailable
	}
	return openSMTPPassword(cipher, settings.scopeID.String(), *settings.smtpKeyID, settings.smtpCiphertext)
}

// OpenMailSecret decrypts the official mail service credential of the
// chosen provider (ErrUnavailable when it belongs to another provider). The
// caller must clear the returned bytes.
func (settings RuntimeSettings) OpenMailSecret(cipher SecretCipher) ([]byte, error) {
	if settings.mailKeyID == nil || settings.mailProvider == nil || *settings.mailProvider != settings.Value.MailProvider {
		return nil, ErrUnavailable
	}
	return openMailSecret(cipher, settings.scopeID.String(), *settings.mailProvider, *settings.mailKeyID, settings.mailCiphertext)
}

// OpenSMSSecret decrypts the native SMS provider credential. The caller must
// clear the returned bytes.
func (settings RuntimeSettings) OpenSMSSecret(cipher SecretCipher) ([]byte, error) {
	if settings.secretKeyID == nil {
		return nil, ErrUnavailable
	}
	return openSMSSecret(cipher, settings.scopeID, *settings.secretKeyID, settings.secretCiphertext)
}

// ReadRuntime reads the single platform-scope mail settings row without
// requiring an HTTP actor. The runtime must fail closed when more than one
// platform row exists or when the persisted JSON is invalid.
func ReadRuntime(ctx context.Context, pool *pgxpool.Pool) (RuntimeSettings, error) {
	if pool == nil {
		return RuntimeSettings{}, ErrUnavailable
	}
	return readRuntime(ctx, pool)
}

// ReadRuntimeTx is ReadRuntime inside tx (sees a save not yet committed).
func ReadRuntimeTx(ctx context.Context, tx pgx.Tx) (RuntimeSettings, error) {
	if tx == nil {
		return RuntimeSettings{}, ErrUnavailable
	}
	return readRuntime(ctx, tx)
}

func readRuntime(ctx context.Context, db interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) (RuntimeSettings, error) {
	if ctx == nil {
		return RuntimeSettings{}, ErrUnavailable
	}
	rows, err := db.Query(ctx, `SELECT settings.revision,settings.settings,settings.platform_scope_id,
		       settings.sms_secret_key_id,settings.sms_secret_ciphertext,
		       settings.mail_secret_key_id,settings.mail_secret_ciphertext,settings.mail_secret_provider,
		       settings.smtp_password_key_id,settings.smtp_password_ciphertext,
		       settings.sms_auth_token_key_id,settings.sms_auth_token_ciphertext
		FROM platform_system_mail_settings settings
		JOIN access_scopes scope ON scope.id=settings.platform_scope_id
		WHERE scope.kind='platform' AND scope.tenant_id IS NULL
		ORDER BY settings.platform_scope_id
		LIMIT 2`)
	if err != nil {
		return RuntimeSettings{}, ErrUnavailable
	}
	defer rows.Close()

	result := RuntimeSettings{Value: DefaultSettings()}
	for rows.Next() {
		if result.Configured {
			return RuntimeSettings{}, errors.New("platform system mail settings has multiple runtime rows")
		}
		var raw []byte
		if err := rows.Scan(&result.Revision, &raw, &result.scopeID, &result.secretKeyID, &result.secretCiphertext,
			&result.mailKeyID, &result.mailCiphertext, &result.mailProvider, &result.smtpKeyID, &result.smtpCiphertext,
			&result.smsTokenKeyID, &result.smsTokenCiphertext); err != nil {
			return RuntimeSettings{}, ErrUnavailable
		}
		if json.Unmarshal(raw, &result.Value) != nil || !validSettings(result.Value) {
			return RuntimeSettings{}, ErrUnavailable
		}
		result.Configured = true
	}
	if err := rows.Err(); err != nil {
		return RuntimeSettings{}, ErrUnavailable
	}
	return result, nil
}
