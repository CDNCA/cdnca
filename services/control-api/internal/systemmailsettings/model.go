package systemmailsettings

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidInput        = errors.New("invalid platform system mail settings input")
	ErrInvalidStore        = errors.New("invalid platform system mail settings store")
	ErrPermissionDenied    = errors.New("platform system mail settings permission denied")
	ErrRevisionConflict    = errors.New("platform system mail settings revision conflict")
	ErrIdempotencyConflict = errors.New("platform system mail settings idempotency conflict")
	ErrUnavailable         = errors.New("platform system mail settings unavailable")
	// ErrModuleNotLicensed: the chosen official mail service's module
	// (mail.ModuleCode) is not granted by the installation licence.
	ErrModuleNotLicensed = errors.New("official mail service is not included in the licence")
)

// ModuleGate reports whether the local lease grants a module code
// (entitlementguard.Guard.GrantedModules, read-only). nil: not gated.
type ModuleGate func(ctx context.Context, tx pgx.Tx, module string) (bool, error)

const schema = "cdnca.platform-system-mail-settings/v1"

type Clock func() time.Time

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

// Settings stores provider metadata and references to secrets. Secret values are
// deliberately not accepted by this contract.
type Settings struct {
	SMTPAddress           string `json:"smtp_address"`
	SMTPSSL               bool   `json:"smtp_ssl"`
	SMTPPort              int    `json:"smtp_port"`
	SMTPUser              string `json:"smtp_user"`
	SMTPPasswordReference string `json:"smtp_password_reference"`
	SMSProvider           string `json:"sms_provider"`
	SMSAccessKeyID        string `json:"sms_access_key_id"`
	SMSAccessKeyReference string `json:"sms_access_key_reference"`
	SMSSignatureName      string `json:"sms_signature_name"`
	// SMSTemplateMap (aliyun/submail only) is a JSON object:
	// {"<our template id>":{"code":"<provider template>","variables":{"<ours>":"<theirs>"}}}.
	// Kept as text so Settings stays comparable.
	SMSTemplateMap string `json:"sms_template_map"`
	// MailProvider is the one system mail sender: "" or "smtp" = the
	// built-in SMTP above (unchanged), "aliyun" / "sendgrid" = an official
	// mail service (libs/mail), "plugin:<plugin id>" = a third-party mail
	// plugin. The SMTP fields and the official fields below are kept
	// whatever is chosen, so switching back works without re-entry.
	MailProvider    string `json:"mail_provider"`
	MailRegion      string `json:"mail_region"`
	MailAccessKeyID string `json:"mail_access_key_id"`
	MailFrom        string `json:"mail_from"`
	MailFromName    string `json:"mail_from_name"`
}

const (
	MailProviderSMTP     = "smtp"
	MailProviderAliyun   = "aliyun"
	MailProviderSendGrid = "sendgrid"
	MailPluginPrefix     = "plugin:"

	MailKindSMTP     = "smtp"
	MailKindOfficial = "official"
	MailKindPlugin   = "plugin"
)

const (
	SMSProviderHTTPSJSON = "https_json"
	SMSProviderAliyun    = "aliyun"
	SMSProviderSubmail   = "submail"
)

// NativeSMSProvider reports whether the provider stores its credential here.
func NativeSMSProvider(provider string) bool {
	return provider == SMSProviderAliyun || provider == SMSProviderSubmail
}

// SecretCipher is the control-api credential keyring
// (dnsacme.AESGCMCredentialCipher satisfies it).
type SecretCipher interface {
	Encrypt([]byte) (keyID string, ciphertext []byte, err error)
	Decrypt(keyID string, ciphertext []byte) ([]byte, error)
}

// SMSTemplate maps one of our notification templates to a provider template.
type SMSTemplate struct {
	Code      string            `json:"code"`
	Variables map[string]string `json:"variables"`
}

type Document struct {
	Schema    string    `json:"schema"`
	Revision  int64     `json:"revision"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	Value     Settings  `json:"value"`
	// The native SMS credential is never returned, only whether it is set and
	// a short fingerprint so operators can tell credentials apart.
	SMSSecretConfigured  bool   `json:"sms_secret_configured"`
	SMSSecretFingerprint string `json:"sms_secret_fingerprint,omitempty"`
	// The official mail service credential, likewise write-only; it belongs
	// to MailSecretProvider and is reused only for that provider.
	MailSecretConfigured  bool   `json:"mail_secret_configured"`
	MailSecretProvider    string `json:"mail_secret_provider,omitempty"`
	MailSecretFingerprint string `json:"mail_secret_fingerprint,omitempty"`
	Replayed              bool   `json:"-"`
}

type SaveRequest struct {
	ExpectedRevision int64
	Value            Settings
	// SMSAccessKeySecret is write-only; empty keeps the stored credential.
	SMSAccessKeySecret string
	// MailSecret is the official mail service credential (DirectMail
	// AccessKeySecret / SendGrid API key), write-only; empty keeps it.
	MailSecret     string
	IdempotencyKey string
	RequestID      string
}

func DefaultSettings() Settings {
	return Settings{SMTPSSL: true, SMTPPort: 465}
}

func Schema() string { return schema }
