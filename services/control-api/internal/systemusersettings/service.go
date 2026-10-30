package systemusersettings

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
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
}

func NewService(pool *pgxpool.Pool, auditor AuditAppender, now Clock) (*Service, error) {
	if pool == nil || auditor == nil || now == nil {
		return nil, ErrInvalidStore
	}
	return &Service{pool: pool, auditor: auditor, now: now}, nil
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
		var raw []byte
		var updatedAt time.Time
		err := tx.QueryRow(ctx, `SELECT revision,settings,updated_at FROM platform_system_user_settings WHERE platform_scope_id=$1`, actor.ScopeID).Scan(&revision, &raw, &updatedAt)
		if err == pgx.ErrNoRows {
			result = Document{Schema: schema, Value: DefaultSettings()}
			return nil
		}
		if err != nil {
			return err
		}
		value, err := decodeSettings(raw)
		if err != nil {
			return err
		}
		result = Document{Schema: schema, Revision: revision, UpdatedAt: updatedAt.UTC(), Value: value}
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
func GetPublicTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (PublicSettings, error) {
	value, err := platformSettingsTx(ctx, tx, scopeID)
	if err != nil {
		return PublicSettings{}, fmt.Errorf("get public platform system user settings: %w", err)
	}
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
		DefaultPhoneCountryCode:  value.DefaultPhoneCountryCode,
		LoginFailureLimitPerHour: value.LoginFailureLimitPerHour, LoginCaptchaThresholdPerHour: value.LoginCaptchaThresholdPerHour,
		SessionRegionCheck: value.SessionRegionCheck,
	}, nil
}

// CaptchaRuntime reads the platform CAPTCHA provider, app ID and secret
// references for server-side ticket verification. It needs no actor because it
// is only reachable from the control-plane runtime, never from an HTTP payload.
func (s *Service) CaptchaRuntime(ctx context.Context) (CaptchaRuntime, error) {
	if s == nil || s.pool == nil {
		return CaptchaRuntime{}, ErrInvalidStore
	}
	var value Settings
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		value, err = platformSettingsTx(ctx, tx, uuid.Nil)
		return err
	})
	if err != nil {
		return CaptchaRuntime{}, fmt.Errorf("get platform captcha runtime settings: %w", err)
	}
	return CaptchaRuntime{
		Provider: value.CaptchaProvider, SecretIDReference: value.CaptchaSecretIDReference,
		SecretKeyReference: value.CaptchaSecretKeyReference, AppID: value.CaptchaAppID,
		AppSecretReference: value.CaptchaAppSecretReference,
	}, nil
}

// platformSettingsTx resolves tenant and nil scopes to the single platform
// scope and returns its settings, or the defaults when no row exists.
func platformSettingsTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (Settings, error) {
	if tx == nil {
		return Settings{}, ErrInvalidStore
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, "platform-system-user-settings:v1"); err != nil {
		return Settings{}, err
	}
	platformScopeID := scopeID
	if platformScopeID == uuid.Nil {
		if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&platformScopeID); err != nil {
			if err == pgx.ErrNoRows {
				return Settings{}, ErrPermissionDenied
			}
			return Settings{}, err
		}
	} else {
		var kind string
		var tenantID *uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1`, platformScopeID).Scan(&kind, &tenantID); err != nil {
			return Settings{}, err
		}
		if kind != "platform" || tenantID != nil {
			// Tenant logins still use the single platform-wide policy.
			if kind != "tenant" || tenantID == nil {
				return Settings{}, ErrPermissionDenied
			}
			if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&platformScopeID); err != nil {
				if err == pgx.ErrNoRows {
					return Settings{}, ErrPermissionDenied
				}
				return Settings{}, err
			}
		}
	}
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT settings FROM platform_system_user_settings WHERE platform_scope_id=$1`, platformScopeID).Scan(&raw); err == pgx.ErrNoRows {
		return DefaultSettings(), nil
	} else if err != nil {
		return Settings{}, err
	}
	return decodeSettings(raw)
}

// decodeSettings reads a stored document; documents saved before a field
// existed get that field's default (FX38 default_phone_country_code).
func decodeSettings(raw []byte) (Settings, error) {
	var value Settings
	if json.Unmarshal(raw, &value) != nil {
		return Settings{}, ErrUnavailable
	}
	if value.DefaultPhoneCountryCode == "" {
		value.DefaultPhoneCountryCode = phonenumber.DefaultCountryCode
	}
	if !validSettings(value) {
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
	if err := settingsFieldError(request.Value); err != nil {
		return Document{}, err
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
		var currentRaw []byte
		err = tx.QueryRow(ctx, `SELECT revision,settings FROM platform_system_user_settings WHERE platform_scope_id=$1 FOR UPDATE`, actor.ScopeID).Scan(&currentRevision, &currentRaw)
		exists := err == nil
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if currentRevision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		encoded, err := json.Marshal(request.Value)
		if err != nil {
			return ErrInvalidInput
		}
		nextRevision := currentRevision + 1
		if exists {
			_, err = tx.Exec(ctx, `UPDATE platform_system_user_settings SET revision=$2,settings=$3,updated_by_user_id=$4,updated_at=$5 WHERE platform_scope_id=$1`, actor.ScopeID, nextRevision, string(encoded), actor.UserID, now)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO platform_system_user_settings(platform_scope_id,revision,settings,updated_by_user_id,updated_at) VALUES($1,$2,$3,$4,$5)`, actor.ScopeID, nextRevision, string(encoded), actor.UserID, now)
		}
		if err != nil {
			return err
		}
		if err := insertSettingsNotificationTemplates(ctx, tx, templateDefinitions, now); err != nil {
			return err
		}
		result = Document{Schema: schema, Revision: nextRevision, UpdatedAt: now, Value: request.Value}
		if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: operationUpdate, ResourceType: "platform_system_user_settings", ResourceID: actor.ScopeID.String(), RequestID: request.RequestID, Result: "success", Payload: map[string]any{"revision": nextRevision}}); err != nil {
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

func validSettings(value Settings) bool { return settingsFieldError(value) == nil }

// settingsFieldError is ErrInvalidInput naming the first refused field of the
// save body (value.<field>, fix-fielderr-be2); nil when the settings are valid.
func settingsFieldError(value Settings) error {
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
		{"enterprise_secret_id_reference", value.EnterpriseSecretIDReference}, {"enterprise_secret_key_reference", value.EnterpriseSecretKeyReference},
	} {
		if !validReference(item.value) {
			return field(item.name, fielderr.InvalidFormat)
		}
	}
	if err := textFieldError(field, "captcha_app_id", value.CaptchaAppID, 0, 256, false); err != nil {
		return err
	}
	if value.DefaultPhoneCountryCode == "" {
		return field("default_phone_country_code", fielderr.Required)
	}
	if !phonenumber.ValidCountryCode(value.DefaultPhoneCountryCode) {
		return field("default_phone_country_code", fielderr.Invalid)
	}
	externalCaptchaConfigured := value.CaptchaSecretIDReference != "" && value.CaptchaSecretKeyReference != "" && value.CaptchaAppID != "" && value.CaptchaAppSecretReference != ""
	switch {
	case externalAntiAbuse(value.EmailAntiAbuseMode) && !(value.EmailAntiAbuseMode == value.CaptchaProvider && externalCaptchaConfigured):
		return field("email_anti_abuse_mode", fielderr.Invalid)
	case externalAntiAbuse(value.SMSAntiAbuseMode) && !(value.SMSAntiAbuseMode == value.CaptchaProvider && externalCaptchaConfigured):
		return field("sms_anti_abuse_mode", fielderr.Invalid)
	case value.EnterpriseVerificationEnabled && value.EnterpriseSecretIDReference == "":
		return field("enterprise_secret_id_reference", fielderr.Required)
	case value.EnterpriseVerificationEnabled && value.EnterpriseSecretKeyReference == "":
		return field("enterprise_secret_key_reference", fielderr.Required)
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
	encoded, _ := json.Marshal(struct {
		ExpectedRevision int64    `json:"expected_revision"`
		Value            Settings `json:"value"`
	}{request.ExpectedRevision, request.Value})
	return sha256.Sum256(encoded)
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
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1 FOR UPDATE`, actor.ScopeID).Scan(&kind, &tenantID); err != nil || kind != "platform" || tenantID != nil {
		return ErrPermissionDenied
	}
	var accountStatus, membershipStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR UPDATE`, actor.UserID).Scan(&accountStatus); err != nil || accountStatus != "active" {
		return ErrPermissionDenied
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships WHERE scope_id=$1 AND user_id=$2 FOR UPDATE`, actor.ScopeID, actor.UserID).Scan(&membershipStatus); err != nil || membershipStatus != "active" {
		return ErrPermissionDenied
	}
	var roleID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT assignment.role_id FROM role_assignments assignment JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id JOIN role_permissions grant_row ON grant_row.role_id=role.id WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND grant_row.permission_name=$3 ORDER BY assignment.role_id LIMIT 1 FOR UPDATE OF assignment,role,grant_row`, actor.ScopeID, actor.UserID, permission).Scan(&roleID); err != nil {
		return ErrPermissionDenied
	}
	return nil
}
