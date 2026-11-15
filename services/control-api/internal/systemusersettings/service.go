package systemusersettings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/phonenumber"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const operationUpdate = "system_user_settings.update"

var (
	metadataPattern              = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	sensitiveTemplatePlaceholder = regexp.MustCompile(`(?i)\{\{\s*\.?password\s*\}\}|\$\{\s*password\s*\}`)
)

type Service struct {
	pool    *pgxpool.Pool
	auditor AuditAppender
	now     Clock
	cipher  SecretCipher
	// senders reports the configured email / SMS senders of sign-up codes
	// (nil: not checked)
	senders func(context.Context) (email, sms bool)
}

func NewService(pool *pgxpool.Pool, auditor AuditAppender, now Clock) (*Service, error) {
	if pool == nil || auditor == nil || now == nil {
		return nil, ErrInvalidStore
	}
	return &Service{pool: pool, auditor: auditor, now: now}, nil
}

// WithSecretCipher enables saving the page secrets (CAPTCHA and enterprise
// verification keys) and opening them for CaptchaRuntime.
func (s *Service) WithSecretCipher(cipher SecretCipher) *Service {
	s.cipher = cipher
	return s
}

// WithVerificationSenders refuses turning on email / phone verification
// while senders reports no sender of that channel. A setting already on is
// kept (the registration readiness reasons tell the administrator).
func (s *Service) WithVerificationSenders(senders func(context.Context) (email, sms bool)) *Service {
	s.senders = senders
	return s
}

func (s *Service) Get(ctx context.Context, actor Actor) (Document, error) {
	if err := validActor(actor); err != nil {
		return Document{}, err
	}
	var result Document
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, "system_configuration.read"); err != nil {
			return err
		}
		var revision int64
		var raw, rawFingerprints []byte
		var updatedAt time.Time
		err := tx.QueryRow(ctx, `SELECT revision,settings,updated_at,secrets_fingerprints FROM platform_system_user_settings WHERE platform_scope_id=$1`, actor.ScopeID).Scan(&revision, &raw, &updatedAt, &rawFingerprints)
		if err == pgx.ErrNoRows {
			result = Document{Schema: schema, Value: DefaultSettings()}
			return nil
		}
		if err != nil {
			return err
		}
		fingerprints, stored, err := decodeFingerprints(rawFingerprints)
		if err != nil {
			return err
		}
		value, err := decodeSettings(raw, stored...)
		if err != nil {
			return err
		}
		result = Document{Schema: schema, Revision: revision, UpdatedAt: updatedAt.UTC(), Value: value}
		result.setSecrets(fingerprints)
		return nil
	})
	if err != nil {
		return Document{}, fmt.Errorf("get platform system user settings: %w", err)
	}
	return result, nil
}

// GetPublic reads the small, non-sensitive policy projection used by anonymous
// account flows. Tenant and nil scopes resolve to the single platform scope;
// no actor permission is required because these values only describe whether a
// public flow exists.
func (s *Service) GetPublic(ctx context.Context, scopeID uuid.UUID) (PublicSettings, error) {
	if s == nil || s.pool == nil {
		return PublicSettings{}, ErrInvalidStore
	}
	var result PublicSettings
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		result, err = GetPublicTx(ctx, tx, scopeID)
		return err
	})
	return result, err
}

// GetPublicTx shares the existing settings writer lock, including an absent row.
// The email / phone verification and code login it reports are in effect
// only while the matching notification channel switch is on (the switch is
// the feature switch; off, sign-up and sign-in go on without codes).
func GetPublicTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (PublicSettings, error) {
	value, err := platformSettingsTx(ctx, tx, scopeID)
	if err != nil {
		return PublicSettings{}, fmt.Errorf("get public platform system user settings: %w", err)
	}
	email, sms, err := channelSwitchesTx(ctx, tx)
	if err != nil {
		return PublicSettings{}, fmt.Errorf("get public platform system user settings: %w", err)
	}
	value.EmailVerificationRequired = value.EmailVerificationRequired && email
	value.PhoneVerificationRequired = value.PhoneVerificationRequired && sms
	value.EmailCodeLoginEnabled = value.EmailCodeLoginEnabled && email
	value.SMSCodeLoginEnabled = value.SMSCodeLoginEnabled && sms
	return PublicSettings{
		SessionTTLSeconds:     value.SessionTTLSeconds,
		RegistrationEnabled:   value.RegistrationEnabled,
		EmailCodeLoginEnabled: value.EmailCodeLoginEnabled,
		SMSCodeLoginEnabled:   value.SMSCodeLoginEnabled,
		EmailAntiAbuseMode:    value.EmailAntiAbuseMode,
		SMSAntiAbuseMode:      value.SMSAntiAbuseMode,
		EmailRequired:         value.EmailRequired, EmailVerificationRequired: value.EmailVerificationRequired,
		PhoneRequired: value.PhoneRequired, PhoneVerificationRequired: value.PhoneVerificationRequired,
		CaptchaProvider: value.CaptchaProvider, CaptchaAppID: value.CaptchaAppID,
		CaptchaTurnstileSiteKey:  value.CaptchaTurnstileSiteKey,
		DefaultPhoneCountryCode:  value.DefaultPhoneCountryCode,
		LoginFailureLimitPerHour: value.LoginFailureLimitPerHour, LoginCaptchaThresholdPerHour: value.LoginCaptchaThresholdPerHour,
		SessionRegionCheck: value.SessionRegionCheck,
	}, nil
}

// ChannelSwitchesTx reads the notification channel switches (no row: off).
func ChannelSwitchesTx(ctx context.Context, tx pgx.Tx) (email, sms bool, err error) {
	return channelSwitchesTx(ctx, tx)
}

// channelSwitchesTx reads the notification channel switches (no row: off).
func channelSwitchesTx(ctx context.Context, tx pgx.Tx) (email, sms bool, err error) {
	err = tx.QueryRow(ctx, `SELECT email_enabled,sms_enabled FROM notification_channel_settings WHERE singleton`).Scan(&email, &sms)
	if err == pgx.ErrNoRows {
		return false, false, nil
	}
	return email, sms, err
}

// CaptchaRuntime reads the platform CAPTCHA provider, app ID and secret
// references for server-side ticket verification. It needs no actor because it
// is only reachable from the control-plane runtime, never from an HTTP payload.
func (s *Service) CaptchaRuntime(ctx context.Context) (CaptchaRuntime, error) {
	if s == nil || s.pool == nil {
		return CaptchaRuntime{}, ErrInvalidStore
	}
	var value Settings
	var row secretsRow
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		value, row, err = platformSettingsRowTx(ctx, tx, uuid.Nil)
		return err
	})
	if err != nil {
		return CaptchaRuntime{}, fmt.Errorf("get platform captcha runtime settings: %w", err)
	}
	runtime := CaptchaRuntime{
		Provider: value.CaptchaProvider, SecretIDReference: value.CaptchaSecretIDReference,
		SecretKeyReference: value.CaptchaSecretKeyReference, AppID: value.CaptchaAppID,
		AppSecretReference: value.CaptchaAppSecretReference,
	}
	if row.keyID != nil {
		// the page-saved secrets take precedence over the references
		secrets, err := openSecrets(s.cipher, row.scopeID.String(), *row.keyID, row.ciphertext)
		if err != nil {
			return CaptchaRuntime{}, fmt.Errorf("open platform captcha secrets: %w", err)
		}
		runtime.SecretID, runtime.SecretKey = secrets[SecretCaptchaSecretID], secrets[SecretCaptchaSecretKey]
		runtime.AppSecret = secrets[SecretCaptchaAppSecret]
	}
	return runtime, nil
}

// IdentityVerificationRuntime reads the identity policy and the KYC provider
// configuration (fields and secrets) saved on the page for the identity verification runtime. Like
// CaptchaRuntime it needs no actor and is only reachable from the runtime.
func (s *Service) IdentityVerificationRuntime(ctx context.Context) (IdentityVerificationRuntime, error) {
	return s.identityVerificationRuntime(ctx, true)
}

// IdentityPolicy is IdentityVerificationRuntime without the provider
// configuration (no decryption), for the per-request kind gate.
func (s *Service) IdentityPolicy(ctx context.Context) (IdentityVerificationRuntime, error) {
	return s.identityVerificationRuntime(ctx, false)
}

func (s *Service) identityVerificationRuntime(ctx context.Context, credentials bool) (IdentityVerificationRuntime, error) {
	if s == nil || s.pool == nil {
		return IdentityVerificationRuntime{}, ErrInvalidStore
	}
	var value Settings
	var row secretsRow
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		value, row, err = platformSettingsRowTx(ctx, tx, uuid.Nil)
		return err
	})
	if err != nil {
		return IdentityVerificationRuntime{}, fmt.Errorf("get platform identity verification runtime settings: %w", err)
	}
	runtime := IdentityVerificationRuntime{PolicySaved: value.IdentityPolicySaved,
		PersonalEnabled: value.IdentityVerificationMethod != "none", EnterpriseEnabled: value.EnterpriseVerificationEnabled}
	if !credentials {
		return runtime, nil
	}
	var secrets map[string]string
	if row.keyID != nil {
		if secrets, err = openSecrets(s.cipher, row.scopeID.String(), *row.keyID, row.ciphertext); err != nil {
			return IdentityVerificationRuntime{}, fmt.Errorf("open platform KYC credentials: %w", err)
		}
	}
	setKYCProviderRuntime(&runtime, value, secrets)
	clear(secrets)
	return runtime, nil
}

// secretsRow is the stored envelope of the page secrets (keyID nil: none).
type secretsRow struct {
	scopeID    uuid.UUID
	keyID      *string
	ciphertext []byte
}

// platformSettingsTx resolves tenant and nil scopes to the single platform
// scope and returns its settings, or the defaults when no row exists.
func platformSettingsTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (Settings, error) {
	value, _, err := platformSettingsRowTx(ctx, tx, scopeID)
	return value, err
}

// platformSettingsRowTx is platformSettingsTx that also returns the stored
// page secrets envelope.
func platformSettingsRowTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (Settings, secretsRow, error) {
	if tx == nil {
		return Settings{}, secretsRow{}, ErrInvalidStore
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, "platform-system-user-settings:v1"); err != nil {
		return Settings{}, secretsRow{}, err
	}
	platformScopeID := scopeID
	if platformScopeID == uuid.Nil {
		if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&platformScopeID); err != nil {
			if err == pgx.ErrNoRows {
				return Settings{}, secretsRow{}, ErrPermissionDenied
			}
			return Settings{}, secretsRow{}, err
		}
	} else {
		var kind string
		var tenantID *uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1`, platformScopeID).Scan(&kind, &tenantID); err != nil {
			return Settings{}, secretsRow{}, err
		}
		if kind != "platform" || tenantID != nil {
			// Tenant logins still use the single platform-wide policy.
			if kind != "tenant" || tenantID == nil {
				return Settings{}, secretsRow{}, ErrPermissionDenied
			}
			if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&platformScopeID); err != nil {
				if err == pgx.ErrNoRows {
					return Settings{}, secretsRow{}, ErrPermissionDenied
				}
				return Settings{}, secretsRow{}, err
			}
		}
	}
	var raw, rawFingerprints []byte
	row := secretsRow{scopeID: platformScopeID}
	if err := tx.QueryRow(ctx, `SELECT settings,secrets_key_id,secrets_ciphertext,secrets_fingerprints FROM platform_system_user_settings WHERE platform_scope_id=$1`,
		platformScopeID).Scan(&raw, &row.keyID, &row.ciphertext, &rawFingerprints); err == pgx.ErrNoRows {
		return DefaultSettings(), secretsRow{scopeID: platformScopeID}, nil
	} else if err != nil {
		return Settings{}, secretsRow{}, err
	}
	_, stored, err := decodeFingerprints(rawFingerprints)
	if err != nil {
		return Settings{}, secretsRow{}, err
	}
	value, err := decodeSettings(raw, stored...)
	return value, row, err
}

// decodeSettings reads a stored document; documents saved before a field
// existed get that field's default (FX38 default_phone_country_code).
// secrets lists the page secrets stored next to it.
func decodeSettings(raw []byte, secrets ...string) (Settings, error) {
	var value Settings
	if json.Unmarshal(raw, &value) != nil {
		return Settings{}, ErrUnavailable
	}
	if value.DefaultPhoneCountryCode == "" {
		value.DefaultPhoneCountryCode = phonenumber.DefaultCountryCode
	}
	if !validSettings(value, secrets...) {
		return Settings{}, ErrUnavailable
	}
	return value, nil
}

func (s *Service) Save(ctx context.Context, actor Actor, request SaveRequest) (Document, error) {
	if err := validActor(actor); err != nil {
		return Document{}, err
	}
	if request.ExpectedRevision < 0 || request.ExpectedRevision >= 1<<63-1 || !validMetadata(request.IdempotencyKey) || !validMetadata(request.RequestID) {
		return Document{}, ErrInvalidInput
	}
	if err := secretsFieldError(request.Value, request.Secrets, nil); err != nil {
		return Document{}, err
	}
	// a secret omitted here may be stored; the exact check runs in the transaction
	if err := settingsFieldError(request.Value, keptSecrets(request.Secrets, secretNames)...); err != nil {
		return Document{}, err
	}
	for _, secret := range request.Secrets {
		if secret != nil && *secret != "" && s.cipher == nil {
			return Document{}, ErrInvalidInput
		}
	}
	templateDefinitions, err := settingsNotificationDefinitions(request.Value, uint64(request.ExpectedRevision)+1)
	if err != nil {
		return Document{}, err
	}
	digest := requestDigest(request)
	var result Document
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, "system_configuration.manage"); err != nil {
			return err
		}
		// Recharge order and checkout transactions take the same lock before
		// reading this policy, including while the first settings row is absent.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
			"platform-system-user-settings:v1"); err != nil {
			return err
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		var existingDigest, existingResponse []byte
		err := tx.QueryRow(ctx, `SELECT request_digest,response_body FROM platform_system_user_settings_write_requests WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`, actor.UserID, operationUpdate, request.IdempotencyKey).Scan(&existingDigest, &existingResponse)
		if err == nil {
			if !bytesEqual(existingDigest, digest[:]) || len(existingResponse) == 0 {
				return ErrIdempotencyConflict
			}
			if json.Unmarshal(existingResponse, &result) != nil {
				return ErrUnavailable
			}
			result.Replayed = true
			return nil
		}
		if err != pgx.ErrNoRows {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO platform_system_user_settings_write_requests(id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,request_digest,created_at) VALUES($1,$2,$3,$3,$4,$5,$6,$7)`, uuid.New(), actor.UserID, actor.ScopeID, operationUpdate, request.IdempotencyKey, digest[:], now); err != nil {
			return err
		}
		var currentRevision int64
		var currentRaw, rawFingerprints []byte
		var secretsKeyID *string
		var secretsCiphertext []byte
		err = tx.QueryRow(ctx, `SELECT revision,settings,secrets_key_id,secrets_ciphertext,secrets_fingerprints FROM platform_system_user_settings WHERE platform_scope_id=$1 FOR UPDATE`, actor.ScopeID).Scan(&currentRevision, &currentRaw, &secretsKeyID, &secretsCiphertext, &rawFingerprints)
		exists := err == nil
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if currentRevision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		fingerprints, stored, err := decodeFingerprints(rawFingerprints)
		if err != nil {
			return err
		}
		if err := s.verificationSenderError(ctx, tx, exists, currentRaw, request.Value); err != nil {
			return err
		}
		if err := secretsFieldError(request.Value, request.Secrets, stored); err != nil {
			return err
		}
		changes := map[string]string{}
		if secretsChange(request.Secrets, stored) {
			current := map[string]string{}
			if secretsKeyID != nil {
				if current, err = openSecrets(s.cipher, actor.ScopeID.String(), *secretsKeyID, secretsCiphertext); err != nil {
					return err
				}
			}
			var next map[string]string
			next, changes = nextSecrets(current, request.Secrets)
			secretsKeyID, secretsCiphertext, fingerprints = nil, nil, nil
			if len(next) > 0 {
				keyID, sealed, sealErr := sealSecrets(s.cipher, actor.ScopeID.String(), next)
				if sealErr != nil {
					return sealErr
				}
				secretsKeyID, secretsCiphertext, fingerprints = &keyID, sealed, secretFingerprints(next)
			}
			stored = stored[:0]
			for name := range next {
				stored = append(stored, name)
			}
			clear(next)
			clear(current)
		}
		if err := settingsFieldError(request.Value, stored...); err != nil {
			return err
		}
		var encodedFingerprints []byte
		if fingerprints != nil {
			if encodedFingerprints, err = json.Marshal(fingerprints); err != nil {
				return ErrInvalidInput
			}
		}
		encoded, err := json.Marshal(request.Value)
		if err != nil {
			return ErrInvalidInput
		}
		nextRevision := currentRevision + 1
		if exists {
			_, err = tx.Exec(ctx, `UPDATE platform_system_user_settings SET revision=$2,settings=$3,updated_by_user_id=$4,updated_at=$5,
				secrets_key_id=$6,secrets_ciphertext=$7,secrets_fingerprints=$8 WHERE platform_scope_id=$1`, actor.ScopeID, nextRevision, string(encoded), actor.UserID, now,
				secretsKeyID, secretsCiphertext, nullableJSON(encodedFingerprints))
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO platform_system_user_settings(platform_scope_id,revision,settings,updated_by_user_id,updated_at,
				secrets_key_id,secrets_ciphertext,secrets_fingerprints) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, actor.ScopeID, nextRevision, string(encoded), actor.UserID, now,
				secretsKeyID, secretsCiphertext, nullableJSON(encodedFingerprints))
		}
		if err != nil {
			return err
		}
		if err := insertSettingsNotificationTemplates(ctx, tx, templateDefinitions, now); err != nil {
			return err
		}
		result = Document{Schema: schema, Revision: nextRevision, UpdatedAt: now, Value: request.Value}
		result.setSecrets(fingerprints)
		payload := map[string]any{"revision": nextRevision}
		for name, change := range changes {
			if change != "unchanged" {
				payload[name] = change
			}
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: operationUpdate, ResourceType: "platform_system_user_settings", ResourceID: actor.ScopeID.String(), RequestID: request.RequestID, Result: "success", Payload: payload}); err != nil {
			return err
		}
		response, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE platform_system_user_settings_write_requests SET response_body=$4,completed_at=$5 WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`, actor.UserID, operationUpdate, request.IdempotencyKey, string(response), now)
		return err
	})
	if err != nil {
		return Document{}, fmt.Errorf("save platform system user settings: %w", err)
	}
	return result, nil
}

// verificationSenderError refuses a save that turns on email / phone
// verification while its notification channel switch is on (the
// verification would be in effect) and no sender of that channel is
// configured. With the switch off the verification is not in effect.
func (s *Service) verificationSenderError(ctx context.Context, tx pgx.Tx, exists bool, currentRaw []byte, value Settings) error {
	if s.senders == nil || !value.EmailVerificationRequired && !value.PhoneVerificationRequired {
		return nil
	}
	var current Settings
	if exists && json.Unmarshal(currentRaw, &current) != nil {
		return ErrUnavailable
	}
	emailOn, smsOn, err := channelSwitchesTx(ctx, tx)
	if err != nil {
		return err
	}
	email, sms := s.senders(ctx)
	switch {
	case value.EmailVerificationRequired && !current.EmailVerificationRequired && emailOn && !email:
		return fielderr.New(ErrVerificationSenderUnavailable, "value.email_verification_required", fielderr.Invalid)
	case value.PhoneVerificationRequired && !current.PhoneVerificationRequired && smsOn && !sms:
		return fielderr.New(ErrVerificationSenderUnavailable, "value.phone_verification_required", fielderr.Invalid)
	}
	return nil
}

func validSettings(value Settings, secrets ...string) bool {
	return settingsFieldError(value, secrets...) == nil
}

// settingsFieldError is ErrInvalidInput naming the first refused field of the
// save body (value.<field>, fix-fielderr-be2); nil when the settings are valid.
// secrets lists the page secrets that are set: a set secret stands in for its
// empty *_reference field.
func settingsFieldError(value Settings, secrets ...string) error {
	configured := func(name string) bool {
		return secretReference(value, name) != "" || slices.Contains(secrets, name)
	}
	field := func(name, reason string) error { return fielderr.New(ErrInvalidInput, "value."+name, reason) }
	if value.SessionTTLSeconds < 300 || value.SessionTTLSeconds > 31536000 {
		return field("session_ttl_seconds", fielderr.OutOfRange)
	}
	for _, item := range []struct {
		name     string
		value    string
		min, max int
		template bool
	}{
		{"user_login_domains", value.UserLoginDomains, 0, 4096, false}, {"admin_login_domains", value.AdminLoginDomains, 0, 4096, false},
		{"registration_success_subject", value.RegistrationSuccessSubject, 1, 256, false}, {"registration_success_body", value.RegistrationSuccessBody, 1, 65536, true},
		{"password_reset_subject", value.PasswordResetSubject, 1, 256, false}, {"password_reset_body", value.PasswordResetBody, 1, 65536, true},
	} {
		if err := textFieldError(field, item.name, item.value, item.min, item.max, item.template); err != nil {
			return err
		}
	}
	if !member(value.VerificationTemplateChannel, "email", "sms") {
		return field("verification_template_channel", fielderr.Invalid)
	}
	for _, item := range []struct {
		name     string
		value    string
		min, max int
		template bool
	}{
		{"verification_subject", value.VerificationSubject, 1, 256, false}, {"verification_body", value.VerificationBody, 1, 65536, true},
		{"verification_sms_body", value.VerificationSMSBody, 1, 1024, false}, {"verification_sms_template_id", value.VerificationSMSTemplateID, 0, 256, false},
		{"terms_title", value.TermsTitle, 1, 256, false}, {"terms_body", value.TermsBody, 1, 65536, false},
	} {
		if err := textFieldError(field, item.name, item.value, item.min, item.max, item.template); err != nil {
			return err
		}
	}
	switch {
	case value.EmailVerificationRequired && !value.EmailRequired:
		return field("email_verification_required", fielderr.Invalid)
	case value.PhoneVerificationRequired && !value.PhoneRequired:
		return field("phone_verification_required", fielderr.Invalid)
	case value.LoginFailureLimitPerHour < 1 || value.LoginFailureLimitPerHour > 1000:
		return field("login_failure_limit_per_hour", fielderr.OutOfRange)
	case value.LoginCaptchaThresholdPerHour < 1 || value.LoginCaptchaThresholdPerHour > value.LoginFailureLimitPerHour:
		return field("login_captcha_threshold_per_hour", fielderr.OutOfRange)
	}
	for _, item := range []struct {
		name, value string
		allowed     []string
	}{
		{"email_anti_abuse_mode", value.EmailAntiAbuseMode, []string{"none", "native", "tencent", "geetest_v4"}},
		{"sms_anti_abuse_mode", value.SMSAntiAbuseMode, []string{"none", "native", "tencent", "geetest_v4"}},
		{"captcha_provider", value.CaptchaProvider, []string{"tencent", "geetest_v4"}},
		{"identity_verification_method", value.IdentityVerificationMethod, []string{"none", "alipay", "wechat_face", "phone_three_factor"}},
		{"default_recharge_method", value.DefaultRechargeMethod, []string{"none", "wechat", "alipay", "bank_transfer"}},
		{"recharge_restriction", value.RechargeRestriction, []string{"none", "individual_verified", "enterprise_verified"}},
	} {
		if !member(item.value, item.allowed...) {
			return field(item.name, fielderr.Invalid)
		}
	}
	for _, item := range []struct{ name, value string }{
		{"captcha_secret_id_reference", value.CaptchaSecretIDReference}, {"captcha_secret_key_reference", value.CaptchaSecretKeyReference},
		{"captcha_app_secret_reference", value.CaptchaAppSecretReference},
	} {
		if !validReference(item.value) {
			return field(item.name, fielderr.InvalidFormat)
		}
	}
	if err := textFieldError(field, "captcha_app_id", value.CaptchaAppID, 0, 256, false); err != nil {
		return err
	}
	if err := turnstileSiteKeyFieldError(value.CaptchaTurnstileSiteKey); err != nil {
		return err
	}
	if value.DefaultPhoneCountryCode == "" {
		return field("default_phone_country_code", fielderr.Required)
	}
	if !phonenumber.ValidCountryCode(value.DefaultPhoneCountryCode) {
		return field("default_phone_country_code", fielderr.Invalid)
	}
	if err := kycProviderFieldError(value); err != nil {
		return err
	}
	externalCaptchaConfigured := configured(SecretCaptchaSecretID) && configured(SecretCaptchaSecretKey) && value.CaptchaAppID != "" && configured(SecretCaptchaAppSecret)
	switch {
	case externalAntiAbuse(value.EmailAntiAbuseMode) && !(value.EmailAntiAbuseMode == value.CaptchaProvider && externalCaptchaConfigured):
		return field("email_anti_abuse_mode", fielderr.Invalid)
	case externalAntiAbuse(value.SMSAntiAbuseMode) && !(value.SMSAntiAbuseMode == value.CaptchaProvider && externalCaptchaConfigured):
		return field("sms_anti_abuse_mode", fielderr.Invalid)
	case value.DefaultRechargeMethod == "wechat" && !value.WeChatPaymentEnabled,
		value.DefaultRechargeMethod == "alipay" && !value.AlipayPaymentEnabled,
		value.DefaultRechargeMethod == "bank_transfer" && !value.BankTransferEnabled:
		return field("default_recharge_method", fielderr.Invalid)
	}
	return nil
}

// textFieldError names a text field outside validText (and, for templates, one
// carrying a password placeholder).
func textFieldError(field func(string, string) error, name, value string, min, max int, template bool) error {
	if validText(value, min, max) {
		if template && sensitiveTemplatePlaceholder.MatchString(value) {
			return field(name, fielderr.Invalid)
		}
		return nil
	}
	count := utf8.RuneCountInString(value)
	switch {
	case !utf8.ValidString(value) || strings.IndexFunc(value, func(r rune) bool { return r == 0 || r == '\r' || unicode.Is(unicode.Cf, r) }) >= 0:
		return field(name, fielderr.InvalidFormat)
	case count == 0 && min > 0:
		return field(name, fielderr.Required)
	case count < min:
		return field(name, fielderr.TooShort)
	}
	return field(name, fielderr.TooLong)
}

func externalAntiAbuse(value string) bool {
	return value == "tencent" || value == "geetest_v4"
}

func validReference(value string) bool {
	return validText(value, 0, 1024) && (value == "" || len(value) > len("vault://") && strings.HasPrefix(value, "vault://") || len(value) > len("kms-envelope://") && strings.HasPrefix(value, "kms-envelope://"))
}
func validText(value string, min, max int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= min && utf8.RuneCountInString(value) <= max && strings.IndexFunc(value, func(r rune) bool { return r == 0 || r == '\r' || unicode.Is(unicode.Cf, r) }) < 0
}
func member(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
func validActor(actor Actor) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != "platform" {
		return ErrPermissionDenied
	}
	return nil
}
func validMetadata(value string) bool { return metadataPattern.MatchString(value) }
func requestDigest(request SaveRequest) [32]byte {
	// the secrets enter the digest only as hashes, never in plaintext
	var secrets map[string]string
	for name, secret := range request.Secrets {
		if secret == nil {
			continue
		}
		if secrets == nil {
			secrets = map[string]string{}
		}
		secrets[name] = "clear"
		if *secret != "" {
			sum := sha256.Sum256([]byte(secretsDomain + name + "\x00" + *secret))
			secrets[name] = hex.EncodeToString(sum[:])
		}
	}
	encoded, _ := json.Marshal(struct {
		ExpectedRevision int64             `json:"expected_revision"`
		Value            Settings          `json:"value"`
		Secrets          map[string]string `json:"secret_digests,omitempty"`
	}{request.ExpectedRevision, request.Value, secrets})
	return sha256.Sum256(encoded)
}

// keptSecrets lists the names a save does not clear (sent or omitted).
func keptSecrets(request map[string]*string, names []string) []string {
	result := make([]string, 0, len(names))
	for _, name := range names {
		if secret, sent := request[name]; !sent || secret == nil || *secret != "" {
			result = append(result, name)
		}
	}
	return result
}

func nullableJSON(raw []byte) any {
	if raw == nil {
		return nil
	}
	return string(raw)
}
func bytesEqual(left, right []byte) bool {
	return len(left) == len(right) && string(left) == string(right)
}

func authorize(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('platform-system-user-settings-authorization:' || $1::text || ':' || $2::text,0))`, actor.ScopeID, actor.UserID); err != nil {
		return err
	}
	var kind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1 FOR SHARE`, actor.ScopeID).Scan(&kind, &tenantID); err != nil || kind != "platform" || tenantID != nil {
		return ErrPermissionDenied
	}
	var accountStatus, membershipStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR SHARE`, actor.UserID).Scan(&accountStatus); err != nil || accountStatus != "active" {
		return ErrPermissionDenied
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships WHERE scope_id=$1 AND user_id=$2 FOR SHARE`, actor.ScopeID, actor.UserID).Scan(&membershipStatus); err != nil || membershipStatus != "active" {
		return ErrPermissionDenied
	}
	var roleID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT assignment.role_id FROM role_assignments assignment JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id JOIN role_permissions grant_row ON grant_row.role_id=role.id WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND grant_row.permission_name=$3 ORDER BY assignment.role_id LIMIT 1 FOR UPDATE OF assignment,role,grant_row`, actor.ScopeID, actor.UserID, permission).Scan(&roleID); err != nil {
		return ErrPermissionDenied
	}
	return nil
}
