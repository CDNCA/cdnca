package systemusersettings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/phonenumber"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidInput        = errors.New("invalid platform system user settings input")
	ErrInvalidStore        = errors.New("invalid platform system user settings store")
	ErrPermissionDenied    = errors.New("platform system user settings permission denied")
	ErrRevisionConflict    = errors.New("platform system user settings revision conflict")
	ErrIdempotencyConflict = errors.New("platform system user settings idempotency conflict")
	ErrUnavailable         = errors.New("platform system user settings unavailable")
	// ErrVerificationSenderUnavailable: a save turns on email / phone
	// verification while no sender of that channel is configured (sign-up
	// would then refuse everyone). Located at value.<field>_verification_required.
	ErrVerificationSenderUnavailable = errors.New("platform system user settings verification sender unavailable")
)

const schema = "cdnca.platform-system-user-settings/v1"

type Clock func() time.Time

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

type Settings struct {
	SessionTTLSeconds            int    `json:"session_ttl_seconds"`
	UserLoginDomains             string `json:"user_login_domains"`
	AdminLoginDomains            string `json:"admin_login_domains"`
	EmailCodeLoginEnabled        bool   `json:"email_code_login_enabled"`
	SMSCodeLoginEnabled          bool   `json:"sms_code_login_enabled"`
	RegistrationEnabled          bool   `json:"registration_enabled"`
	RegistrationSuccessSubject   string `json:"registration_success_subject"`
	RegistrationSuccessBody      string `json:"registration_success_body"`
	PasswordResetSubject         string `json:"password_reset_subject"`
	PasswordResetBody            string `json:"password_reset_body"`
	VerificationTemplateChannel  string `json:"verification_template_channel"`
	VerificationSubject          string `json:"verification_subject"`
	VerificationBody             string `json:"verification_body"`
	VerificationSMSBody          string `json:"verification_sms_body"`
	VerificationSMSTemplateID    string `json:"verification_sms_template_id"`
	TermsTitle                   string `json:"terms_title"`
	TermsBody                    string `json:"terms_body"`
	UsernameRequired             bool   `json:"username_required"`
	EmailRequired                bool   `json:"email_required"`
	EmailVerificationRequired    bool   `json:"email_verification_required"`
	PhoneRequired                bool   `json:"phone_required"`
	PhoneVerificationRequired    bool   `json:"phone_verification_required"`
	QQRequired                   bool   `json:"qq_required"`
	LoginFailureLimitPerHour     int    `json:"login_failure_limit_per_hour"`
	LoginCaptchaThresholdPerHour int    `json:"login_captcha_threshold_per_hour"`
	// SessionRegionCheck requires re-entering the password when a session's
	// requests move to another country/province (IP intelligence library).
	SessionRegionCheck        bool   `json:"session_region_check"`
	EmailAntiAbuseMode        string `json:"email_anti_abuse_mode"`
	SMSAntiAbuseMode          string `json:"sms_anti_abuse_mode"`
	CaptchaProvider           string `json:"captcha_provider"`
	CaptchaSecretIDReference  string `json:"captcha_secret_id_reference"`
	CaptchaSecretKeyReference string `json:"captcha_secret_key_reference"`
	CaptchaAppID              string `json:"captcha_app_id"`
	CaptchaAppSecretReference string `json:"captcha_app_secret_reference"`
	// CaptchaTurnstileSiteKey is the Cloudflare Turnstile site key of the
	// registration flow (public: it is embedded in the browser widget).
	// ACCOUNT_REGISTRATION_TURNSTILE_SITE_KEY, when set, wins over it.
	CaptchaTurnstileSiteKey       string `json:"captcha_turnstile_site_key"`
	IdentityVerificationMethod    string `json:"identity_verification_method"`
	EnterpriseVerificationEnabled bool   `json:"enterprise_verification_enabled"`
	// IdentityPolicySaved marks identity_verification_method and
	// enterprise_verification_enabled as chosen on the page. Until then the
	// runtime keeps the earlier behaviour: personal and enterprise
	// verification are on whenever the KYC provider is configured.
	IdentityPolicySaved bool `json:"identity_policy_saved"`
	// The KYC provider and its private object store (identity documents and
	// liveness material). Empty: not set on the page, the runtime uses the
	// matching IDENTITY_VERIFICATION_* environment value. The provider keys
	// and object store keys are page secrets (SecretKYC*).
	KYCProviderName   string `json:"kyc_provider_name"`
	KYCEndpoint       string `json:"kyc_endpoint"`
	KYCCallbackKeyID  string `json:"kyc_callback_key_id"`
	KYCObjectEndpoint string `json:"kyc_object_endpoint"`
	KYCObjectRegion   string `json:"kyc_object_region"`
	KYCObjectBucket   string `json:"kyc_object_bucket"`
	KYCObjectPrefix   string `json:"kyc_object_prefix"`
	KYCObjectKMSKeyID string `json:"kyc_object_kms_key_id"`
	// The evidence issuer (mTLS listener the trusted workloads pull sealed
	// evidence from). Empty / false: not set on the page, the
	// runtime uses IDENTITY_VERIFICATION_ISSUER_*. The certificates are PEM
	// text (the environment names files); the server private key is the page
	// secret SecretKYCIssuerServerPrivateKey.
	KYCIssuerEnabled            bool   `json:"kyc_issuer_enabled"`
	KYCIssuerListenAddress      string `json:"kyc_issuer_listen_address"`
	KYCIssuerServerCertificate  string `json:"kyc_issuer_server_certificate"`
	KYCIssuerClientCA           string `json:"kyc_issuer_client_ca"`
	KYCIssuerWorkloadIdentities string `json:"kyc_issuer_workload_identities"`
	KYCIssuerKMSEndpoint        string `json:"kyc_issuer_kms_endpoint"`

	WeChatPaymentEnabled  bool   `json:"wechat_payment_enabled"`
	AlipayPaymentEnabled  bool   `json:"alipay_payment_enabled"`
	BankTransferEnabled   bool   `json:"bank_transfer_enabled"`
	DefaultRechargeMethod string `json:"default_recharge_method"`
	RechargeRestriction   string `json:"recharge_restriction"`
	// DefaultPhoneCountryCode completes phone numbers entered without a
	// country/region calling code (FX38); 1-4 digits, default 86.
	DefaultPhoneCountryCode string `json:"default_phone_country_code"`
}

// PublicSettings contains only the settings that anonymous account flows may
// need. It intentionally excludes credentials, templates, and payment details.
type PublicSettings struct {
	SessionTTLSeconds         int
	RegistrationEnabled       bool
	EmailCodeLoginEnabled     bool
	SMSCodeLoginEnabled       bool
	EmailAntiAbuseMode        string
	SMSAntiAbuseMode          string
	EmailRequired             bool
	EmailVerificationRequired bool
	PhoneRequired             bool
	PhoneVerificationRequired bool
	// QQRequired: sign-up must give a QQ number.
	QQRequired bool
	// UsernameRequired: sign-up must give a username; off, an empty one is
	// generated (accountregistration.ResolveUsername).
	UsernameRequired bool
	// The sign-up terms edited on the settings page: the only
	// source of the agreement visitors accept. TermsVersion is derived from
	// them (TermsVersion), so changing either asks for a new acceptance.
	TermsTitle   string
	TermsBody    string
	TermsVersion string
	// TermsPublished: the settings page has terms of its own (
	// TermsPublished); otherwise the sites link their own terms page.
	TermsPublished bool
	// The CAPTCHA provider and app ID are embedded in the browser widget, so they are public.
	CaptchaProvider string
	CaptchaAppID    string
	// CaptchaTurnstileSiteKey is the Turnstile site key saved on the page.
	CaptchaTurnstileSiteKey string
	// DefaultPhoneCountryCode completes bare phone numbers (FX38).
	DefaultPhoneCountryCode string
	// Password sign-in throttle (identity.loginThrottle): failures per hour
	// that lock an account+source pair, and failures per hour after which the
	// built-in sign-in CAPTCHA is required. Never serialized to clients.
	LoginFailureLimitPerHour     int
	LoginCaptchaThresholdPerHour int
	SessionRegionCheck           bool
}

// CaptchaRuntime is the server-side view of the external CAPTCHA settings.
// SecretID/SecretKey/AppSecret are the values saved on the settings page
// (decrypted; empty when not saved); otherwise the runtime resolves the
// matching reference to secret material.
type CaptchaRuntime struct {
	Provider           string
	SecretIDReference  string
	SecretKeyReference string
	AppID              string
	AppSecretReference string
	SecretID           string
	SecretKey          string
	AppSecret          string
}

// SecretCipher is the control-api credential keyring
// (dnsacme.AESGCMCredentialCipher satisfies it).
// IdentityVerificationRuntime is what the KYC runtime reads from the page:
// whether personal / enterprise verification is offered and the KYC provider
// configuration saved there ("" / nil when not saved; the caller clears the
// secrets).
type IdentityVerificationRuntime struct {
	// PolicySaved is false until the page saved the identity policy; the
	// runtime then treats both kinds as on (the earlier behaviour).
	PolicySaved       bool
	PersonalEnabled   bool
	EnterpriseEnabled bool
	KYCAPIKey         []byte
	KYCCallbackHMAC   []byte

	KYCProviderName    string
	KYCEndpoint        string
	KYCCallbackKeyID   string
	ObjectEndpoint     string
	ObjectRegion       string
	ObjectBucket       string
	ObjectPrefix       string
	ObjectKMSKeyID     string
	ObjectAccessKey    []byte
	ObjectSecretKey    []byte
	ObjectSessionToken []byte

	IssuerEnabled            bool
	IssuerListenAddress      string
	IssuerServerCertificate  string
	IssuerClientCA           string
	IssuerWorkloadIdentities string
	IssuerKMSEndpoint        string
	IssuerServerPrivateKey   []byte
}

// Clear wipes the secrets of the runtime view.
func (runtime *IdentityVerificationRuntime) Clear() {
	clear(runtime.KYCAPIKey)
	clear(runtime.KYCCallbackHMAC)
	clear(runtime.ObjectAccessKey)
	clear(runtime.ObjectSecretKey)
	clear(runtime.ObjectSessionToken)
	clear(runtime.IssuerServerPrivateKey)
}

// KindEnabled reports whether a verification kind (personal_initial,
// personal_reverification or enterprise) may start.
func (runtime IdentityVerificationRuntime) KindEnabled(kind string) bool {
	if !runtime.PolicySaved {
		return true
	}
	if kind == "enterprise" {
		return runtime.EnterpriseEnabled
	}
	return runtime.PersonalEnabled
}

type SecretCipher interface {
	Encrypt([]byte) (keyID string, ciphertext []byte, err error)
	Decrypt(keyID string, ciphertext []byte) ([]byte, error)
}

type PublicSettingsReader interface {
	GetPublic(context.Context, uuid.UUID) (PublicSettings, error)
}

// PhoneCountryCode returns the platform default calling code used to complete
// a bare phone number (FX38). It reads the settings only when phone is set;
// a nil reader means the product default ("").
func PhoneCountryCode(ctx context.Context, reader interface {
	GetPublic(context.Context, uuid.UUID) (PublicSettings, error)
}, scopeID uuid.UUID, phone string) (string, error) {
	if reader == nil || strings.TrimSpace(phone) == "" {
		return "", nil
	}
	settings, err := reader.GetPublic(ctx, scopeID)
	if err != nil {
		return "", err
	}
	return settings.DefaultPhoneCountryCode, nil
}

type Document struct {
	Schema    string    `json:"schema"`
	Revision  int64     `json:"revision"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	Value     Settings  `json:"value"`
	// The CAPTCHA, Turnstile and KYC provider secrets entered on the page
	// are write-only: only whether each is set and a fingerprint are returned.
	CaptchaSecretIDConfigured            bool   `json:"captcha_secret_id_configured"`
	CaptchaSecretIDFingerprint           string `json:"captcha_secret_id_fingerprint,omitempty"`
	CaptchaSecretKeyConfigured           bool   `json:"captcha_secret_key_configured"`
	CaptchaSecretKeyFingerprint          string `json:"captcha_secret_key_fingerprint,omitempty"`
	CaptchaAppSecretConfigured           bool   `json:"captcha_app_secret_configured"`
	CaptchaAppSecretFingerprint          string `json:"captcha_app_secret_fingerprint,omitempty"`
	CaptchaTurnstileSecretConfigured     bool   `json:"captcha_turnstile_secret_configured"`
	CaptchaTurnstileSecretFingerprint    string `json:"captcha_turnstile_secret_fingerprint,omitempty"`
	KYCAPIKeyConfigured                  bool   `json:"kyc_api_key_configured"`
	KYCAPIKeyFingerprint                 string `json:"kyc_api_key_fingerprint,omitempty"`
	KYCCallbackHMACKeyConfigured         bool   `json:"kyc_callback_hmac_key_configured"`
	KYCCallbackHMACKeyFingerprint        string `json:"kyc_callback_hmac_key_fingerprint,omitempty"`
	KYCObjectAccessKeyIDConfigured       bool   `json:"kyc_object_access_key_id_configured"`
	KYCObjectAccessKeyIDFingerprint      string `json:"kyc_object_access_key_id_fingerprint,omitempty"`
	KYCObjectSecretAccessKeyConfigured   bool   `json:"kyc_object_secret_access_key_configured"`
	KYCObjectSecretAccessKeyFingerprint  string `json:"kyc_object_secret_access_key_fingerprint,omitempty"`
	KYCObjectSessionTokenConfigured      bool   `json:"kyc_object_session_token_configured"`
	KYCObjectSessionTokenFingerprint     string `json:"kyc_object_session_token_fingerprint,omitempty"`
	KYCIssuerServerPrivateKeyConfigured  bool   `json:"kyc_issuer_server_private_key_configured"`
	KYCIssuerServerPrivateKeyFingerprint string `json:"kyc_issuer_server_private_key_fingerprint,omitempty"`
	Replayed                             bool   `json:"-"`
}

type SaveRequest struct {
	ExpectedRevision int64
	Value            Settings
	// Secrets are the write-only page secrets by name (SecretCaptchaSecretID
	// ...): absent/nil keeps the stored one, "" clears it, anything else
	// replaces it. A secret cannot coexist with its *_reference field.
	Secrets        map[string]*string
	IdempotencyKey string
	RequestID      string
}

func DefaultSettings() Settings {
	return Settings{
		// UsernameRequired: sign-up always asked for a username before
		// so no row and a row without the field keep that.
		SessionTTLSeconds: 2592000, EmailCodeLoginEnabled: true, UsernameRequired: true,
		RegistrationSuccessSubject:  "用户注册成功",
		RegistrationSuccessBody:     "<p>您好，{{username}}。您的账户已创建，请使用注册时设置的密码登录。</p>",
		PasswordResetSubject:        "找回密码",
		PasswordResetBody:           "您好，{{username}}。你正在找回账号密码，请在有效期内打开下面的链接设置新密码；如果不是你本人操作，请忽略本邮件。",
		VerificationTemplateChannel: "email", VerificationSubject: "用户验证码",
		VerificationBody:    "<p>您好，您的验证码为 {{captcha}}。</p>",
		VerificationSMSBody: "您的验证码为${captcha}，在5分钟内有效。",
		// no terms until the administrator writes them
		TermsTitle: legacyDefaultTermsTitle, TermsBody: "",
		LoginFailureLimitPerHour: 30, LoginCaptchaThresholdPerHour: 3, SessionRegionCheck: false,
		EmailAntiAbuseMode: "none", SMSAntiAbuseMode: "native", CaptchaProvider: "tencent",
		IdentityVerificationMethod: "none", DefaultRechargeMethod: "none", RechargeRestriction: "none",
		DefaultPhoneCountryCode: phonenumber.DefaultCountryCode,
	}
}

func Schema() string { return schema }

// The terms every installation was given before a placeholder
// sentence, never real terms. A document still holding exactly this pair has
// no terms of its own.
const (
	legacyDefaultTermsTitle = "用户协议、法律声明和隐私政策"
	legacyDefaultTermsBody  = "这里填写协议内容"
)

// TermsPublished reports whether the settings page holds terms visitors can
// be shown: a body that is not blank and not the old default
// title and body together. Unpublished, GET /v1/auth/registration-terms
// answers 404 and the sites link their own terms page; sign-up stays open.
func TermsPublished(title, body string) bool {
	return strings.TrimSpace(body) != "" && !(title == legacyDefaultTermsTitle && body == legacyDefaultTermsBody)
}

// adminTermsView is how the settings page reads the terms: the old default
// placeholder pair reads as an empty body (the page shows the placeholder as
// a hint). Read only: the stored document and its revision are unchanged.
func adminTermsView(value Settings) Settings {
	if value.TermsTitle == legacyDefaultTermsTitle && value.TermsBody == legacyDefaultTermsBody {
		value.TermsBody = ""
	}
	return value
}

// TermsVersion is the version of the sign-up terms:
// "terms-" and the first 12 hex digits of (title NUL body). The same
// text always has the same version, so stored settings need no migration
// and any edit of the title or body is a new version. it is
// computed the same while the terms are unpublished (an empty body has a
// version too), so a sign-up accepts that version; the site's own terms page
// is not part of it: editing that page keeps the version, only publishing or
// changing the terms on the settings page makes a new one.
//
// An unpublished body (blank, or the old default placeholder) counts as empty,
// so an old installation keeps the same version when the settings page first
// saves the placeholder back as "" with an unrelated change.
func TermsVersion(title, body string) string {
	if !TermsPublished(title, body) {
		body = ""
	}
	sum := sha256.Sum256([]byte(title + "\x00" + body))
	return "terms-" + hex.EncodeToString(sum[:])[:12]
}
