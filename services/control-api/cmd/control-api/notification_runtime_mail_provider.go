package main

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/cdnca/cdnca/libs/mail"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginproviders"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// System mail sender (mail-plugin). systemmailsettings.mail_provider picks
// exactly one email transport at start:
//
//	"" / smtp          the built-in SMTP transport, unchanged (environment +
//	                   persisted SMTP fields)
//	aliyun / sendgrid  an official mail service (libs/mail); credential from
//	                   the settings row, opened with the credential keyring
//	plugin:<id>        a third-party mail plugin (pluginproviders.MailTransport)
//
// A failing provider is never replaced by another one: its sends fail and
// are recorded on the outbox like any provider failure (the administrator
// sees them in the notification history), so mail never silently leaves from
// a different sender domain.
const (
	// notificationEmailProviderSettings (NOTIFICATION_EMAIL_PROVIDER=settings)
	// needs no SMTP environment: the sender comes from the system settings
	// page, which must then choose an official service or a plugin.
	notificationEmailProviderSettings = "settings"
	notificationEmailProviderService  = "mail_service"
	notificationEmailProviderPlugin   = "mail_plugin"
)

// notificationMailChoice is the non-SMTP sender merged from the settings.
type notificationMailChoice struct {
	Service  mail.ServiceConfig
	PluginID string
	// Granted reports whether the local lease grants a module code; an
	// official service sends only while its module.mail.<provider> is
	// granted (nil: not gated, tests only).
	Granted func(context.Context, string) (bool, error)
}

func (choice *notificationMailChoice) clearSecrets() {
	choice.Service.AccessKeySecret = ""
}

// notificationEmailConfigured reports whether an email transport can be built.
func notificationEmailConfigured(config notificationRuntimeConfig) bool {
	switch config.EmailProvider {
	case notificationEmailProviderSMTPTLS:
		return !config.SMTP.StartTLS
	case notificationEmailProviderSMTPSTARTTLS:
		return config.SMTP.StartTLS
	case notificationEmailProviderService:
		return mail.ValidServiceConfig(config.Mail.Service)
	case notificationEmailProviderPlugin:
		return config.Mail.PluginID != ""
	default:
		return false
	}
}

// notificationChannelTransports is what the notification runtime can send
// with (after mergePersistedNotificationMailSettings); customers are only
// offered these channels.
func notificationChannelTransports(config notificationRuntimeConfig) notificationcontrol.ChannelTransports {
	return notificationcontrol.ChannelTransports{SMS: config.Enabled && notificationSMSConfigured(config),
		Email: config.Enabled && notificationEmailConfigured(config)}
}

// mergePersistedMailProvider applies mail_provider. open returns the stored
// official credential (nil: no keyring). Email that is not enabled for this
// runtime keeps the choice dormant.
func mergePersistedMailProvider(config *notificationRuntimeConfig, value systemmailsettings.Settings, open func() ([]byte, error)) error {
	if config == nil || config.EmailProvider == "" {
		return nil
	}
	switch systemmailsettings.MailProviderKind(value.MailProvider) {
	case systemmailsettings.MailKindSMTP:
		if config.EmailProvider == notificationEmailProviderSettings {
			return errors.New("NOTIFICATION_EMAIL_PROVIDER=settings needs an official mail service or a mail plugin chosen in the system settings")
		}
		return nil
	case systemmailsettings.MailKindOfficial:
		if open == nil {
			return errors.New("official mail service requires the credential keyring")
		}
		secret, err := open()
		if err != nil {
			return errors.New("persisted mail service credential cannot be opened")
		}
		service := mail.ServiceConfig{Provider: value.MailProvider, Region: value.MailRegion, AccessKeyID: value.MailAccessKeyID,
			AccessKeySecret: string(secret), From: value.MailFrom, FromName: value.MailFromName}
		clear(secret)
		if !mail.ValidServiceConfig(service) {
			return errors.New("persisted mail service settings are invalid")
		}
		config.EmailProvider, config.Mail = notificationEmailProviderService, notificationMailChoice{Service: service}
		return nil
	case systemmailsettings.MailKindPlugin:
		pluginID, _ := systemmailsettings.MailPluginID(value.MailProvider)
		config.EmailProvider, config.Mail = notificationEmailProviderPlugin, notificationMailChoice{PluginID: pluginID}
		return nil
	default:
		return errors.New("persisted mail provider is invalid")
	}
}

// newConfiguredEmailTransport builds the chosen email transport. plugins is
// the provider plugin client source (nil: the plugin is never usable); html
// is the theme email layout the SMTP transport also uses (nil: text only).
func newConfiguredEmailTransport(
	config notificationRuntimeConfig,
	newSMTP func(smtpTLSConfig) (notificationruntime.ProviderTransport, error),
	plugins pluginproviders.Clients,
	html smtpHTMLLayout,
) (notificationruntime.ProviderTransport, error) {
	switch config.EmailProvider {
	case notificationEmailProviderService:
		transport, err := newOfficialMailTransport(config.Mail.Service, html)
		if err != nil {
			return nil, err
		}
		transport.module, transport.granted = mail.ModuleCode(config.Mail.Service.Provider), config.Mail.Granted
		return transport, nil
	case notificationEmailProviderPlugin:
		transport := pluginproviders.MailTransport{Clients: plugins, PluginID: config.Mail.PluginID}
		if html != nil {
			transport.HTML = func(ctx context.Context, message notificationruntime.ProviderMessage) string {
				rendered, _ := html.Render(ctx, message.ScopeID, message.Subject, message.Body)
				return string(rendered)
			}
		}
		return transport, nil
	default:
		return newSMTP(config.SMTP)
	}
}

// leaseModuleGate is systemmailsettings.ModuleGate over the verified local
// lease (read-only: no lock, no audit, like GET /v1/modules).
func leaseModuleGate(guard *entitlementguard.Guard) systemmailsettings.ModuleGate {
	return func(ctx context.Context, tx pgx.Tx, module string) (bool, error) {
		grants, err := guard.GrantedModules(ctx, tx)
		return err == nil && grants.Has(module), err
	}
}

// leaseModuleGranted runs leaseModuleGate in its own read-only transaction.
func leaseModuleGranted(pool *pgxpool.Pool, guard *entitlementguard.Guard) func(context.Context, string) (bool, error) {
	gate := leaseModuleGate(guard)
	return func(ctx context.Context, module string) (granted bool, err error) {
		err = pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
			granted, err = gate(ctx, tx, module)
			return err
		})
		return granted, err
	}
}

// officialMailTransport adapts a libs/mail service sender.
type officialMailTransport struct {
	mu     sync.Mutex
	sender mail.Sender
	closed bool
	html   smtpHTMLLayout
	// module is the provider's licence module, asked before every send
	// (like a payment checkout): revoking it stops new mail at once, the
	// failure is recorded on the outbox and never falls back to SMTP.
	module  string
	granted func(context.Context, string) (bool, error)
}

// mailServiceEndpointOverride points official services at a test server.
var mailServiceEndpointOverride func(*mail.ServiceConfig)

func newOfficialMailTransport(config mail.ServiceConfig, html smtpHTMLLayout) (*officialMailTransport, error) {
	if mailServiceEndpointOverride != nil {
		mailServiceEndpointOverride(&config)
	}
	sender, err := mail.NewService(config)
	if err != nil {
		return nil, err
	}
	return &officialMailTransport{sender: sender, html: html}, nil
}

// Ready checks configuration only: neither service offers a side-effect-free
// credential probe that does not count against quota.
func (transport *officialMailTransport) Ready(ctx context.Context) error {
	_, err := transport.current(ctx)
	return err
}

func (transport *officialMailTransport) Send(ctx context.Context, message notificationruntime.ProviderMessage) (
	notificationruntime.ProviderResult, error) {
	if message.OutboxID == uuid.Nil || message.Channel != notification.ChannelEmail || message.AttemptNumber < 1 ||
		message.IdempotencyKey == "" || !mail.ValidAddress(message.Contact) {
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderPermanentFailure, Code: "mail_message_invalid"}, nil
	}
	sender, err := transport.current(ctx)
	if err != nil {
		return notificationruntime.ProviderResult{}, err
	}
	if transport.granted != nil {
		granted, err := transport.granted(ctx, transport.module)
		if err != nil {
			return notificationruntime.ProviderResult{}, err
		}
		if !granted {
			return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderPermanentFailure, Code: "mail_module_not_licensed"}, nil
		}
	}
	text := message.Body
	if message.ActionURL != "" {
		text += "\n\n" + message.ActionURL
	}
	outgoing := mail.Message{To: message.Contact, Subject: message.Subject, Text: text, ID: message.IdempotencyKey}
	if transport.html != nil {
		if rendered, ok := transport.html.Render(ctx, message.ScopeID, message.Subject, message.Body); ok {
			outgoing.HTML = string(rendered)
		}
	}
	result, err := sender.Send(ctx, outgoing)
	if err == nil {
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderAccepted, ProviderDeliveryID: result.MessageID}, nil
	}
	failure := mail.ErrorOf(err)
	if failure == nil {
		return notificationruntime.ProviderResult{}, err
	}
	code := "mail_" + failure.Code
	switch failure.Disposition {
	case mail.RateLimited:
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderRateLimited, Code: code, RetryAfter: failure.RetryAfter}, nil
	case mail.Temporary:
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderTemporaryFailure, Code: code}, nil
	case mail.Unknown:
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderUnknown, Code: code}, nil
	default:
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderPermanentFailure, Code: code}, nil
	}
}

func (transport *officialMailTransport) Close(context.Context) error {
	if transport == nil {
		return nil
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.closed, transport.sender = true, nil
	return nil
}

func (transport *officialMailTransport) current(ctx context.Context) (mail.Sender, error) {
	if transport == nil || ctx == nil {
		return nil, errors.New("notification_mail_service_unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.closed || transport.sender == nil {
		return nil, errors.New("notification_mail_service_closed")
	}
	return transport.sender, nil
}

var _ notificationruntime.ProviderTransport = (*officialMailTransport)(nil)

// newSystemMailTestSender sends the system settings page's test mail with
// the provider on the page: SMTP uses the runtime SMTP configuration (its
// password lives in the environment) with the page's SMTP fields, an
// official service the given credential, a plugin its usable client. nil
// when email is not enabled for this runtime.
func newSystemMailTestSender(base notificationRuntimeConfig, plugins pluginproviders.Clients) systemmailsettings.TestSender {
	if !base.Enabled || base.EmailProvider == "" {
		return nil
	}
	return func(ctx context.Context, target systemmailsettings.TestTarget) (string, error) {
		config := base
		config.Mail = notificationMailChoice{}
		value := target.Value
		var open func() ([]byte, error)
		if target.Secret != nil {
			open = func() ([]byte, error) { return append([]byte(nil), target.Secret...), nil }
		}
		if systemmailsettings.MailProviderKind(value.MailProvider) == systemmailsettings.MailKindSMTP {
			// The SMTP password only exists in the environment
			// (NOTIFICATION_SMTP_PASSWORD): without it there is no SMTP to test.
			if err := mergePersistedNotificationMailSettings(&config, systemmailsettings.RuntimeSettings{Configured: true,
				Value: systemmailsettings.Settings{SMTPAddress: value.SMTPAddress, SMTPSSL: value.SMTPSSL, SMTPPort: value.SMTPPort,
					SMTPUser: value.SMTPUser, SMTPPasswordReference: value.SMTPPasswordReference}}); err != nil ||
				len(config.SMTP.Password) == 0 || config.EmailProvider != notificationEmailProviderSMTPTLS &&
				config.EmailProvider != notificationEmailProviderSMTPSTARTTLS {
				return "", &mail.Error{Disposition: mail.Permanent, Code: mail.CodeInvalidConfig}
			}
		} else if err := mergePersistedMailProvider(&config, value, open); err != nil {
			return "", &mail.Error{Disposition: mail.Permanent, Code: mail.CodeInvalidConfig}
		}
		defer config.Mail.clearSecrets()
		transport, err := newConfiguredEmailTransport(config, func(smtp smtpTLSConfig) (notificationruntime.ProviderTransport, error) {
			return newSMTPTLSTransport(smtp)
		}, plugins, nil)
		if err != nil {
			return "", &mail.Error{Disposition: mail.Permanent, Code: mail.CodeInvalidConfig}
		}
		defer func() { _ = transport.Close(context.WithoutCancel(ctx)) }()
		result, err := transport.Send(ctx, notificationruntime.ProviderMessage{OutboxID: uuid.New(), Channel: notification.ChannelEmail,
			Contact: target.To, Subject: "CDNCA 测试邮件", Body: "这是一封来自 CDNCA 系统设置的测试邮件，收到即表示发信配置可用。",
			IdempotencyKey: "system-mail-test-" + uuid.NewString(), AttemptNumber: 1})
		if err != nil {
			return "", &mail.Error{Disposition: mail.Temporary, Code: mail.CodeUnavailable}
		}
		if result.Disposition != notificationruntime.ProviderAccepted {
			code := strings.TrimPrefix(strings.TrimPrefix(result.Code, "mail_"), "plugin_")
			if code == "" {
				code = mail.CodeRejected
			}
			return "", &mail.Error{Disposition: mail.Permanent, Code: code}
		}
		return result.ProviderDeliveryID, nil
	}
}
