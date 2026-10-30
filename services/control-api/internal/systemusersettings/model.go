package systemusersettings

import (
	"context"
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
	SessionRegionCheck            bool   `json:"session_region_check"`
	EmailAntiAbuseMode            string `json:"email_anti_abuse_mode"`
	SMSAntiAbuseMode              string `json:"sms_anti_abuse_mode"`
	CaptchaProvider               string `json:"captcha_provider"`
	CaptchaSecretIDReference      string `json:"captcha_secret_id_reference"`
	CaptchaSecretKeyReference     string `json:"captcha_secret_key_reference"`
	CaptchaAppID                  string `json:"captcha_app_id"`
	CaptchaAppSecretReference     string `json:"captcha_app_secret_reference"`
	IdentityVerificationMethod    string `json:"identity_verification_method"`
	EnterpriseVerificationEnabled bool   `json:"enterprise_verification_enabled"`
	EnterpriseSecretIDReference   string `json:"enterprise_secret_id_reference"`
	EnterpriseSecretKeyReference  string `json:"enterprise_secret_key_reference"`
	WeChatPaymentEnabled          bool   `json:"wechat_payment_enabled"`
	AlipayPaymentEnabled          bool   `json:"alipay_payment_enabled"`
	BankTransferEnabled           bool   `json:"bank_transfer_enabled"`
	DefaultRechargeMethod         string `json:"default_recharge_method"`
	RechargeRestriction           string `json:"recharge_restriction"`
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
	// The CAPTCHA provider and app ID are embedded in the browser widget, so they are public.
	CaptchaProvider string
	CaptchaAppID    string
	// DefaultPhoneCountryCode completes bare phone numbers (FX38).
	DefaultPhoneCountryCode string
	// Password sign-in throttle (identity.loginThrottle): failures per hour
	// that lock an account+source pair, and failures per hour after which the
	// built-in sign-in CAPTCHA is required. Never serialized to clients.
	LoginFailureLimitPerHour     int
	LoginCaptchaThresholdPerHour int
	SessionRegionCheck           bool
}

// CaptchaRuntime is the server-side view of the external CAPTCHA settings. It
// holds only secret references; the runtime resolves them to secret material.
type CaptchaRuntime struct {
	Provider           string
	SecretIDReference  string
	SecretKeyReference string
	AppID              string
	AppSecretReference string
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
	Replayed  bool      `json:"-"`
}

type SaveRequest struct {
	ExpectedRevision int64
	Value            Settings
	IdempotencyKey   string
	RequestID        string
}

func DefaultSettings() Settings {
	return Settings{
		SessionTTLSeconds: 2592000, EmailCodeLoginEnabled: true,
		RegistrationSuccessSubject:  "用户注册成功",
		RegistrationSuccessBody:     "<p>您好，{{username}}。您的账户已创建，请使用注册时设置的密码登录。</p>",
		PasswordResetSubject:        "用户密码已重置",
		PasswordResetBody:           "<p>您好，{{username}}。您的密码已完成重置。如非本人操作，请立即联系管理员。</p>",
		VerificationTemplateChannel: "email", VerificationSubject: "用户验证码",
		VerificationBody:    "<p>您好，您的验证码为 {{captcha}}。</p>",
		VerificationSMSBody: "您的验证码为${captcha}，在5分钟内有效。",
		TermsTitle:          "用户协议、法律声明和隐私政策", TermsBody: "这里填写协议内容",
		LoginFailureLimitPerHour: 30, LoginCaptchaThresholdPerHour: 3, SessionRegionCheck: true,
		EmailAntiAbuseMode: "none", SMSAntiAbuseMode: "native", CaptchaProvider: "tencent",
		IdentityVerificationMethod: "none", DefaultRechargeMethod: "none", RechargeRestriction: "none",
		DefaultPhoneCountryCode: phonenumber.DefaultCountryCode,
	}
}

func Schema() string { return schema }
