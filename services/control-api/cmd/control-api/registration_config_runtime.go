package main

import (
	"context"
	"os"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Reason codes of GET /v1/auth/registration-config for administrators
// (registration-ready): why sign-up verification is not ready, each one a
// setting the operator can change.
const (
	registrationReasonDisabled             = "registration_disabled"
	registrationReasonNotificationDisabled = "notification_runtime_disabled"
	registrationReasonSenderBuildFailed    = "sender_build_failed"
	// the Turnstile flow lacks its site key or secret: the built-in image
	// CAPTCHA stands in until both are set
	registrationReasonTurnstileNotConfigured = "turnstile_not_configured"
	registrationReasonNoChannel              = "verification_channel_unavailable"
	registrationReasonSMSTemplateUnmapped    = "sms_template_unmapped"
)

// registrationConfigSource is httpapi.RegistrationConfigSource: a
// verification is required while its setting and its notification channel
// switch are both on (systemusersettings.GetPublic); the configured senders
// and templates decide what can be sent. Every value is read per request, so
// a change on the settings pages shows without restarting control-api.
type registrationConfigSource struct {
	pool     *pgxpool.Pool
	settings *systemusersettings.Service
	// verified: the Turnstile registration runtime is mounted (not merely
	// requested by ACCOUNT_REGISTRATION_ENABLED: a runtime that failed to
	// open falls back to the built-in flow).
	verified bool
	builtIn  *accountregistration.BuiltInService
	// termsVersion: ACCOUNT_REGISTRATION_TERMS_VERSION of the Turnstile flow
	// (a deployment that pins the version); empty, the version is derived
	// from the terms on the settings page.
	termsVersion string
	// envSiteKey (ACCOUNT_REGISTRATION_TURNSTILE_SITE_KEY) wins over the page
	// value; envSecret: ACCOUNT_REGISTRATION_TURNSTILE_SECRET supplies the
	// secret, otherwise the page does.
	envSiteKey string
	envSecret  bool
	// sendable: channels a registration code can go out by; channels, when
	// set, answers it live (the auto mode rebuilds the senders).
	sendEmail, sendSMS bool
	channels           registrationCodeChannels
	// templates are the mounted flow's default verification templates (a
	// template published from the settings page replaces them).
	templates     map[notification.Channel]notification.TemplateRef
	notifications registrationNotificationView
	recovery      accountRecoveryRuntimeConfig
	// recoveryReady reports whether the account recovery runtime can take a
	// request now (the page offers the form only then); nil: ready.
	recoveryReady func() bool
	// terms decides terms_required, as both sign-up entries do.
	terms registrationTerms
}

type registrationTermsSite interface {
	RegistrationTermsReadable(context.Context) (bool, error)
}

// registrationTerms decides whether sign-up asks to accept
// terms: only while a visitor has some to read: the terms published on the
// settings page (site: a website's own terms page; nil here, the community
// edition has no themed website). The same answer is
// registration-config terms_required and what both sign-up entries (built-in
// and the Turnstile flow) follow. A deployment pinning
// ACCOUNT_REGISTRATION_TERMS_VERSION still needs such a page for visitors.
type registrationTerms struct {
	settings systemusersettings.PublicSettingsReader
	site     registrationTermsSite
}

func newRegistrationTerms(pool *pgxpool.Pool, settings systemusersettings.PublicSettingsReader) registrationTerms {
	// No themed website in the community edition: only the terms published
	// on the settings page count.
	_ = pool
	return registrationTerms{settings: settings}
}

func (terms registrationTerms) requiredFor(ctx context.Context, policy systemusersettings.PublicSettings) (bool, error) {
	if policy.TermsPublished {
		return true, nil
	}
	if terms.site == nil {
		return false, nil
	}
	return terms.site.RegistrationTermsReadable(ctx)
}

// Required is what the sign-up entries follow (RequireTermsWhen, TermsRequired).
func (terms registrationTerms) Required(ctx context.Context) (bool, error) {
	if terms.settings == nil {
		return true, nil
	}
	policy, err := terms.settings.GetPublic(ctx, uuid.Nil)
	if err != nil {
		return false, err
	}
	return terms.requiredFor(ctx, policy)
}

// registrationCodeChannels reports which channels can carry a code now.
type registrationCodeChannels interface {
	Channels() (email, sms bool)
}

// registrationSenderState is the accountMailSlot build state (degraded: the
// last rebuild failed).
type registrationSenderState interface {
	state() (string, string)
}

// registrationNotificationView is what the notification runtime offers the
// readiness check.
type registrationNotificationView struct {
	// requested: NOTIFICATION_RUNTIME_ENABLED is not off
	requested bool
	// smsTemplateMapped: whether the SMS provider is a native one (Aliyun,
	// SUBMAIL) and maps the template (nil: no native provider)
	smsTemplateMapped func(templateID string) (native, mapped bool)
}

func newRegistrationConfigSource(
	pool *pgxpool.Pool,
	settings *systemusersettings.Service,
	registration accountRegistrationRuntimeConfig,
	verified bool,
	builtIn *accountregistration.BuiltInService,
	channels registrationCodeChannels,
	notifications registrationNotificationView,
	recovery accountRecoveryRuntimeConfig,
) *registrationConfigSource {
	source := &registrationConfigSource{pool: pool, settings: settings, builtIn: builtIn, recovery: recovery,
		channels: channels, templates: builtInRegistrationTemplates,
		notifications: notifications, terms: newRegistrationTerms(pool, settings)}
	if verified && registration.Enabled {
		source.verified = true
		source.termsVersion = registration.TermsVersion
		source.envSiteKey = os.Getenv("ACCOUNT_REGISTRATION_TURNSTILE_SITE_KEY")
		source.envSecret = registration.turnstileSecretFromEnv()
		source.templates = registration.Templates
		_, source.sendEmail = registration.Templates[notification.ChannelEmail]
		_, source.sendSMS = registration.Templates[notification.ChannelSMS]
	}
	return source
}

// registrationChannelState is one channel as the readiness check saw it.
type registrationChannelState struct {
	send, on        bool
	templateMissing bool
	smsUnmapped     bool
}

type registrationState struct {
	config        httpapi.RegistrationConfig
	policyEnabled bool
	email, sms    registrationChannelState
	// turnstile: the Turnstile flow has its site key and secret
	turnstile bool
}

func (source *registrationConfigSource) RegistrationConfig(ctx context.Context) (httpapi.RegistrationConfig, error) {
	state, err := source.state(ctx)
	return state.config, err
}

func (source *registrationConfigSource) state(ctx context.Context) (registrationState, error) {
	policy, err := source.settings.GetPublic(ctx, uuid.Nil)
	if err != nil {
		return registrationState{}, err
	}
	config := httpapi.RegistrationConfig{Mode: "closed", HumanCheck: "builtin_captcha", TermsVersion: source.currentTermsVersion(policy),
		QQRequired: policy.QQRequired, TermsPublished: policy.TermsPublished, UsernameRequired: policy.UsernameRequired, Recovery: httpapi.RecoveryConfig{Channels: []string{}}}
	var switches notification.ChannelSwitches
	if err := source.pool.QueryRow(ctx, `SELECT sms_enabled,email_enabled FROM notification_channel_settings WHERE singleton`).
		Scan(&switches.SMS, &switches.Email); err != nil {
		switches = notification.ChannelSwitches{}
	}
	sendEmail, sendSMS := source.sendEmail, source.sendSMS
	if source.channels != nil {
		sendEmail, sendSMS = source.channels.Channels()
	}
	state := registrationState{policyEnabled: policy.RegistrationEnabled,
		email: registrationChannelState{send: sendEmail, on: switches.Email},
		sms:   registrationChannelState{send: sendSMS, on: switches.SMS}}
	// templates are checked for the channels a sign-up depends on: the
	// required ones, or (Turnstile flow, nothing required) any
	diagnosed := func(required bool) bool {
		return required || source.verified && !policy.EmailVerificationRequired && !policy.PhoneVerificationRequired
	}
	for _, item := range []struct {
		channel  notification.Channel
		state    *registrationChannelState
		required bool
	}{
		{notification.ChannelEmail, &state.email, policy.EmailVerificationRequired},
		{notification.ChannelSMS, &state.sms, policy.PhoneVerificationRequired},
	} {
		if !policy.RegistrationEnabled || !item.state.send || !diagnosed(item.required) {
			continue
		}
		if err := source.checkTemplate(ctx, item.channel, item.state); err != nil {
			return registrationState{}, err
		}
	}
	available := func(channel registrationChannelState) bool {
		return channel.send && channel.on && !channel.templateMissing && !channel.smsUnmapped
	}
	config.Email = httpapi.RegistrationChannel{Required: policy.EmailVerificationRequired, Available: available(state.email)}
	config.SMS = httpapi.RegistrationChannel{Required: policy.PhoneVerificationRequired, Available: available(state.sms)}
	config.EmailRequired, config.PhoneRequired = policy.EmailRequired, policy.PhoneRequired
	if source.verified {
		siteKey, ready, err := source.turnstileReady(ctx, policy)
		if err != nil {
			return registrationState{}, err
		}
		state.turnstile = ready
		if ready {
			config.HumanCheck, config.TurnstileSiteKey = "turnstile", siteKey
		}
	}
	config.RegistrationEnabled = policy.RegistrationEnabled && (source.verified || source.builtIn != nil)
	if config.RegistrationEnabled {
		config.Mode = "builtin"
		if source.verified {
			config.Mode = "verified"
		}
	}
	config.Ready = config.RegistrationEnabled &&
		(!config.Email.Required || config.Email.Available) && (!config.SMS.Required || config.SMS.Available)
	if source.verified {
		// The Turnstile runtime always proves one channel, behind Turnstile
		// or, until it is configured, the built-in image CAPTCHA.
		config.Ready = config.Ready && (config.Email.Available || config.SMS.Available)
	}
	if source.recovery.Enabled {
		for _, candidate := range []struct {
			channel notification.Channel
			on      bool
		}{{notification.ChannelEmail, switches.Email}, {notification.ChannelSMS, switches.SMS}} {
			if _, ok := source.recovery.Templates[candidate.channel]; ok && candidate.on {
				config.Recovery.Channels = append(config.Recovery.Channels, string(candidate.channel))
			}
		}
		config.Recovery.Enabled = len(config.Recovery.Channels) > 0
		if config.Recovery.Enabled && source.recoveryReady != nil && !source.recoveryReady() {
			config.Recovery.Enabled, config.Recovery.Channels = false, []string{}
		}
	}
	if config.TermsRequired, err = source.terms.requiredFor(ctx, policy); err != nil {
		return registrationState{}, err
	}
	state.config = config
	return state, nil
}

// currentTermsVersion is the terms version a sign-up must accept: the
// deployment's pinned one, else the one of the terms on the settings page.
func (source *registrationConfigSource) currentTermsVersion(policy systemusersettings.PublicSettings) string {
	if source.termsVersion != "" {
		return source.termsVersion
	}
	return policy.TermsVersion
}

// RegistrationTerms is httpapi.RegistrationTermsSource.
func (source *registrationConfigSource) RegistrationTerms(ctx context.Context) (httpapi.RegistrationTerms, error) {
	policy, err := source.settings.GetPublic(ctx, uuid.Nil)
	if err != nil {
		return httpapi.RegistrationTerms{}, err
	}
	if !policy.TermsPublished {
		return httpapi.RegistrationTerms{}, httpapi.ErrRegistrationTermsNotConfigured
	}
	return httpapi.RegistrationTerms{Title: policy.TermsTitle, Body: policy.TermsBody, Version: source.currentTermsVersion(policy)}, nil
}

// turnstileReady reports the Turnstile site key in use and whether the flow
// has both it and a secret (environment values win over the page).
func (source *registrationConfigSource) turnstileReady(ctx context.Context, policy systemusersettings.PublicSettings) (string, bool, error) {
	siteKey := source.envSiteKey
	if siteKey == "" {
		siteKey = policy.CaptchaTurnstileSiteKey
	}
	if siteKey == "" {
		return "", false, nil
	}
	if source.envSecret {
		return siteKey, true, nil
	}
	secret, err := systemusersettings.TurnstileSecretConfigured(ctx, source.pool)
	return siteKey, secret, err
}

// TurnstileReady is the per-request choice of the Turnstile flow's human
// check: Turnstile once configured, the built-in image CAPTCHA before.
func (source *registrationConfigSource) TurnstileReady(ctx context.Context) (bool, error) {
	policy, err := source.settings.GetPublic(ctx, uuid.Nil)
	if err != nil {
		return false, err
	}
	_, ready, err := source.turnstileReady(ctx, policy)
	return ready, err
}

// checkTemplate resolves the verification template a code of channel would
// use (published from the settings page, else the flow default) and notes a
// missing template row or, for a native SMS provider, a missing mapping.
func (source *registrationConfigSource) checkTemplate(ctx context.Context, channel notification.Channel,
	state *registrationChannelState) error {
	var scopeID uuid.UUID
	if err := source.pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL
		ORDER BY created_at, id LIMIT 1`).Scan(&scopeID); err != nil {
		return err
	}
	ref, found, err := source.settings.GetRegistrationVerificationTemplate(ctx, scopeID, channel)
	if err != nil {
		return err
	}
	if !found {
		ref = source.templates[channel]
		if ref.ID != "" {
			if err := source.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_templates
				WHERE template_id=$1 AND version=$2 AND channel=$3)`, ref.ID, ref.Version, ref.Channel).Scan(&found); err != nil {
				return err
			}
		}
	}
	state.templateMissing = !found
	if found && channel == notification.ChannelSMS && source.notifications.smsTemplateMapped != nil {
		native, mapped := source.notifications.smsTemplateMapped(ref.ID)
		state.smsUnmapped = native && !mapped
	}
	return nil
}

// RegistrationReasons is httpapi.RegistrationDiagnostics: the reason codes
// shown to administrators only (empty: nothing is missing).
func (source *registrationConfigSource) RegistrationReasons(ctx context.Context) ([]string, error) {
	state, err := source.state(ctx)
	if err != nil {
		return nil, err
	}
	return registrationReasons(state, source.verified, source.notifications.requested, source.senderDegraded()), nil
}

func (source *registrationConfigSource) senderDegraded() bool {
	sender, ok := source.channels.(registrationSenderState)
	if !ok || sender == nil {
		return false
	}
	current, _ := sender.state()
	return current == "degraded"
}

// registrationReasons lists what keeps sign-up verification from being ready.
func registrationReasons(state registrationState, verified, notificationsRequested, senderDegraded bool) []string {
	config := state.config
	if !state.policyEnabled {
		return []string{registrationReasonDisabled}
	}
	reasons := []string{}
	if !notificationsRequested {
		reasons = append(reasons, registrationReasonNotificationDisabled)
	}
	if senderDegraded {
		reasons = append(reasons, registrationReasonSenderBuildFailed)
	}
	noneRequired := !config.Email.Required && !config.SMS.Required
	for _, item := range []struct {
		name     string
		state    registrationChannelState
		required bool
	}{{"email", state.email, config.Email.Required}, {"sms", state.sms, config.SMS.Required}} {
		if !item.required && !(verified && noneRequired && !config.Email.Available && !config.SMS.Available) {
			continue
		}
		switch {
		case !item.state.send:
			reasons = append(reasons, item.name+"_sender_unavailable")
		case item.state.templateMissing:
			reasons = append(reasons, item.name+"_template_missing")
		case item.state.smsUnmapped:
			reasons = append(reasons, registrationReasonSMSTemplateUnmapped)
		}
	}
	if verified {
		if !state.turnstile {
			reasons = append(reasons, registrationReasonTurnstileNotConfigured)
		}
		if !config.Email.Available && !config.SMS.Available {
			reasons = append(reasons, registrationReasonNoChannel)
		}
	}
	return reasons
}

var (
	_ httpapi.RegistrationDiagnostics = (*registrationConfigSource)(nil)
	_ httpapi.RegistrationTermsSource = (*registrationConfigSource)(nil)
)
