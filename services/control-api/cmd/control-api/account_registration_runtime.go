package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/accountloginchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoverycontext"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallengehttp"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationproof"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginproviders"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	accountRegistrationRateWindow   = 15 * time.Minute
	accountRegistrationSourceLimit  = 10
	accountRegistrationSubjectLimit = 5
)

var accountRegistrationProviderCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// accountRegistrationMailPlugins resolves a mail plugin chosen as the
// system mail sender, accountRegistrationMailLayout is the theme email
// layout of a non-SMTP sender (both set by main with the process pool).
var (
	accountRegistrationMailPlugins pluginproviders.Clients
	accountRegistrationMailLayout  smtpHTMLLayout
)

type accountRegistrationRuntimeConfig struct {
	Enabled              bool
	DigestKey            []byte
	DispatchKeys         *accountregistrationchallenge.EnvelopeKeyring
	ProofKeys            *accountregistrationchallenge.EnvelopeKeyring
	TermsVersion         string
	Turnstile            accountregistrationchallenge.TurnstileConfig
	TrustedProxyCIDRs    []string
	PlatformHosts        []string
	AllowPrivateSourceIP bool
	MaxProxyHops         int
	Templates            map[notification.Channel]notification.TemplateRef
}

func loadAccountRegistrationRuntimeConfig(
	trusted accountRecoveryRuntimeConfig,
) (accountRegistrationRuntimeConfig, error) {
	return loadAccountRegistrationRuntimeConfigFromEnv(trusted, os.LookupEnv)
}

func loadAccountRegistrationRuntimeConfigFromEnv(
	trusted accountRecoveryRuntimeConfig,
	lookup accountRecoveryEnvLookup,
) (accountRegistrationRuntimeConfig, error) {
	if lookup == nil {
		return accountRegistrationRuntimeConfig{}, errors.New("account registration environment lookup is required")
	}
	enabled, err := accountRecoveryEnvBool(lookup, "ACCOUNT_REGISTRATION_ENABLED", false)
	if err != nil || !enabled {
		return accountRegistrationRuntimeConfig{}, err
	}
	if !trusted.Enabled || len(trusted.DigestKey) != 32 {
		return accountRegistrationRuntimeConfig{}, errors.New("account registration requires the trusted account recovery runtime")
	}
	config := accountRegistrationRuntimeConfig{
		Enabled: true, TrustedProxyCIDRs: append([]string(nil), trusted.TrustedProxyCIDRs...),
		PlatformHosts:        append([]string(nil), trusted.PlatformHosts...),
		AllowPrivateSourceIP: trusted.AllowPrivateSourceIP, MaxProxyHops: trusted.MaxProxyHops,
	}
	config.DigestKey, err = accountRecoveryEnvKey(lookup, "ACCOUNT_REGISTRATION_HMAC_KEY_BASE64")
	if err != nil {
		return accountRegistrationRuntimeConfig{}, err
	}
	failed := true
	defer func() {
		if failed {
			config.clearSecrets()
		}
	}()
	config.DispatchKeys, err = loadAccountRegistrationEnvelopeKeyring(lookup, "DISPATCH")
	if err != nil {
		return accountRegistrationRuntimeConfig{}, err
	}
	config.ProofKeys, err = loadAccountRegistrationEnvelopeKeyring(lookup, "PROOF")
	if err != nil {
		return accountRegistrationRuntimeConfig{}, err
	}
	config.TermsVersion, err = accountRecoveryRequiredEnv(lookup, "ACCOUNT_REGISTRATION_TERMS_VERSION")
	if err != nil || !accountRecoveryTemplateIDPattern.MatchString(config.TermsVersion) {
		return accountRegistrationRuntimeConfig{}, errors.New("ACCOUNT_REGISTRATION_TERMS_VERSION is invalid")
	}
	config.Templates, err = loadAccountRegistrationTemplates(lookup)
	if err != nil {
		return accountRegistrationRuntimeConfig{}, err
	}
	config.Turnstile.Secret, err = accountRecoveryRequiredEnv(lookup, "ACCOUNT_REGISTRATION_TURNSTILE_SECRET")
	if err != nil {
		return accountRegistrationRuntimeConfig{}, err
	}
	config.Turnstile.ExpectedHostname, err = accountRecoveryRequiredEnv(lookup, "ACCOUNT_REGISTRATION_TURNSTILE_HOSTNAME")
	if err != nil {
		return accountRegistrationRuntimeConfig{}, err
	}
	config.Turnstile.ExpectedAction, err = accountRecoveryRequiredEnv(lookup, "ACCOUNT_REGISTRATION_TURNSTILE_ACTION")
	if err != nil {
		return accountRegistrationRuntimeConfig{}, err
	}
	if endpoint, exists := lookup("ACCOUNT_REGISTRATION_TURNSTILE_ENDPOINT"); exists {
		if strings.TrimSpace(endpoint) != endpoint || endpoint == "" {
			return accountRegistrationRuntimeConfig{}, errors.New("ACCOUNT_REGISTRATION_TURNSTILE_ENDPOINT is invalid")
		}
		config.Turnstile.Endpoint = endpoint
	}
	if caFile, exists := lookup("ACCOUNT_REGISTRATION_TURNSTILE_CA_FILE"); exists {
		if caFile == "" || strings.TrimSpace(caFile) != caFile || strings.ContainsRune(caFile, '\x00') {
			return accountRegistrationRuntimeConfig{}, errors.New("ACCOUNT_REGISTRATION_TURNSTILE_CA_FILE is invalid")
		}
		config.Turnstile.CAFile = caFile
	}
	if _, err := accountregistrationchallenge.NewTurnstileVerifier(config.Turnstile); err != nil {
		return accountRegistrationRuntimeConfig{}, errors.New("account registration Turnstile configuration is invalid")
	}
	failed = false
	return config, nil
}

func (config *accountRegistrationRuntimeConfig) clearSecrets() {
	if config == nil {
		return
	}
	clear(config.DigestKey)
	config.DigestKey = nil
	config.DispatchKeys = nil
	config.ProofKeys = nil
	config.Turnstile.Secret = ""
}

func loadAccountRegistrationEnvelopeKeyring(
	lookup accountRecoveryEnvLookup,
	kind string,
) (*accountregistrationchallenge.EnvelopeKeyring, error) {
	prefix := "ACCOUNT_REGISTRATION_" + kind + "_KEK_"
	activeID, err := accountRecoveryRequiredEnv(lookup, prefix+"ACTIVE_KEY_ID")
	if err != nil {
		return nil, err
	}
	rawKeys, err := accountRecoveryRequiredEnv(lookup, prefix+"KEYS_JSON")
	if err != nil {
		return nil, err
	}
	keys, err := decodeAccountRecoveryKeyring(rawKeys)
	if err != nil {
		return nil, errors.New(prefix + "KEYS_JSON is invalid")
	}
	keyring, keyringErr := accountregistrationchallenge.NewEnvelopeKeyring(activeID, keys)
	for keyID, key := range keys {
		clear(key)
		delete(keys, keyID)
	}
	if keyringErr != nil {
		return nil, errors.New(prefix + "keyring is invalid")
	}
	return keyring, nil
}

func loadAccountRegistrationTemplates(
	lookup accountRecoveryEnvLookup,
) (map[notification.Channel]notification.TemplateRef, error) {
	templates := make(map[notification.Channel]notification.TemplateRef, 2)
	for _, candidate := range []struct {
		channel     notification.Channel
		idName      string
		versionName string
	}{
		{notification.ChannelEmail, "ACCOUNT_REGISTRATION_EMAIL_TEMPLATE_ID", "ACCOUNT_REGISTRATION_EMAIL_TEMPLATE_VERSION"},
		{notification.ChannelSMS, "ACCOUNT_REGISTRATION_SMS_TEMPLATE_ID", "ACCOUNT_REGISTRATION_SMS_TEMPLATE_VERSION"},
	} {
		_, idExists := lookup(candidate.idName)
		_, versionExists := lookup(candidate.versionName)
		if !idExists && !versionExists {
			continue
		}
		id, err := accountRecoveryRequiredEnv(lookup, candidate.idName)
		if err != nil || !accountRecoveryTemplateIDPattern.MatchString(id) {
			return nil, errors.New(candidate.idName + " is invalid")
		}
		version, err := accountRecoveryRequiredEnv(lookup, candidate.versionName)
		if err != nil {
			return nil, err
		}
		parsed, err := strconv.ParseUint(version, 10, 64)
		if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != version {
			return nil, errors.New(candidate.versionName + " must be a positive canonical integer")
		}
		templates[candidate.channel] = notification.TemplateRef{ID: id, Version: parsed, Channel: candidate.channel}
	}
	if len(templates) == 0 {
		return nil, errors.New("at least one account registration notification template is required")
	}
	return templates, nil
}

type accountRegistrationRuntime struct {
	handler        http.Handler
	dispatcher     notification.AnonymousDispatcher
	provider       *accountRegistrationContactProvider
	shutdownPeriod time.Duration
}

func openAccountRegistrationRuntime(
	ctx context.Context,
	config accountRegistrationRuntimeConfig,
	notificationConfig notificationRuntimeConfig,
	pool *pgxpool.Pool,
	logger *slog.Logger,
) (*accountRegistrationRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	if ctx == nil || pool == nil || len(config.DigestKey) != 32 || config.DispatchKeys == nil || config.ProofKeys == nil ||
		!notificationConfig.Enabled || logger == nil {
		return nil, errors.New("account registration production dependencies are incomplete")
	}
	provider, err := newAccountRegistrationContactProvider(ctx, pool, config.Templates, notificationConfig)
	if err != nil {
		return nil, runtimeStageError{stage: "configure account registration notification provider", err: err}
	}
	providerOwned := true
	defer func() {
		if providerOwned {
			closeCtx, cancel := context.WithTimeout(context.Background(), notificationConfig.ShutdownTimeout)
			defer cancel()
			_ = provider.Close(closeCtx)
		}
	}()
	notificationStore, err := notification.NewStore(pool)
	if err != nil {
		return nil, err
	}
	publicSettings, err := systemusersettings.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		return nil, runtimeStageError{stage: "configure public system user settings", err: err}
	}
	store, err := accountregistration.NewPostgresStoreWithNotifications(pool, notificationStore, publicSettings)
	if err != nil {
		return nil, err
	}
	trustedResolver, err := accountrecoverycontext.NewResolver(pool, accountrecoverycontext.Config{
		TrustedProxyCIDRs: config.TrustedProxyCIDRs, PlatformHosts: config.PlatformHosts,
		AllowPrivateSourceIP: config.AllowPrivateSourceIP, MaxProxyHops: config.MaxProxyHops,
	})
	if err != nil {
		return nil, err
	}
	proofAuthority, err := accountregistrationproof.NewAuthority(pool, accountregistrationproof.Config{
		DigestKey: config.DigestKey,
	})
	if err != nil {
		return nil, err
	}
	limiter := &accountRegistrationPostgresLimiter{
		pool: pool, digestKey: append([]byte(nil), config.DigestKey...), window: accountRegistrationRateWindow,
		sourceLimit: accountRegistrationSourceLimit, subjectLimit: accountRegistrationSubjectLimit,
	}
	service, err := accountregistration.NewService(store, limiter, accountregistration.ServiceConfig{
		DigestKey: config.DigestKey, ProofAuthority: proofAuthority, PublicSettings: publicSettings,
	})
	if err != nil {
		return nil, err
	}
	sourceResolver, err := accountrecoverycontext.NewSourceIPResolver(config.TrustedProxyCIDRs, config.MaxProxyHops)
	if err != nil {
		return nil, err
	}
	registrationHandler, err := accountregistrationhttp.NewHandler(
		service, sourceResolver, accountregistrationproof.CookieReferenceResolver{}, accountregistrationhttp.Config{
			TermsVersion: config.TermsVersion, Logger: logger,
			ScopeResolver: accountregistrationhttp.ScopeResolverFunc(func(request *http.Request) (uuid.UUID, error) {
				trusted, err := trustedResolver.Resolve(request)
				if err != nil {
					return uuid.Nil, err
				}
				return trusted.ScopeID, nil
			}),
		},
	)
	if err != nil {
		return nil, err
	}
	contactSender, err := accountregistrationchallenge.NewNotificationContactSender(
		notificationStore, config.DispatchKeys, config.Templates,
	)
	if err != nil {
		return nil, err
	}
	turnstile, err := accountregistrationchallenge.NewTurnstileVerifier(config.Turnstile)
	if err != nil {
		return nil, err
	}
	challengeService, err := accountregistrationchallenge.NewService(
		pool, turnstile, contactSender, proofAuthority, config.ProofKeys,
		accountregistrationchallenge.Config{
			DigestKey: config.DigestKey, PublicSettings: publicSettings, TemplateSettings: publicSettings,
		},
	)
	if err != nil {
		return nil, err
	}
	challengeHandler, err := accountregistrationchallengehttp.NewHandler(
		challengeService,
		accountregistrationchallengehttp.TrustedContextResolverFunc(func(request *http.Request) (
			accountregistrationchallengehttp.TrustedContext, error,
		) {
			trusted, err := trustedResolver.Resolve(request)
			if err != nil {
				return accountregistrationchallengehttp.TrustedContext{}, err
			}
			return accountregistrationchallengehttp.TrustedContext{ScopeID: trusted.ScopeID, SourceIP: trusted.SourceIP}, nil
		}),
		accountregistrationchallengehttp.Config{},
	)
	if err != nil {
		return nil, err
	}
	dispatcher, err := accountregistrationchallenge.NewDispatcher(pool, config.DispatchKeys, provider, config.DigestKey)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("POST /v1/auth/register", registrationHandler)
	mux.Handle("POST /v1/auth/registration-challenges", challengeHandler)
	mux.Handle("POST /v1/auth/registration-challenge-verifications", challengeHandler)
	providerOwned = false
	return &accountRegistrationRuntime{
		handler: mux, dispatcher: dispatcher, provider: provider,
		shutdownPeriod: notificationConfig.ShutdownTimeout,
	}, nil
}

func (runtime *accountRegistrationRuntime) HandlerFactory() httpapi.MountedHandlerFactory {
	if runtime == nil || runtime.handler == nil {
		return nil
	}
	return func() (http.Handler, error) { return runtime.handler, nil }
}

func (runtime *accountRegistrationRuntime) Dispatcher() notification.AnonymousDispatcher {
	if runtime == nil {
		return nil
	}
	return runtime.dispatcher
}

func (runtime *accountRegistrationRuntime) Close() error {
	if runtime == nil || runtime.provider == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), runtime.shutdownPeriod)
	defer cancel()
	return runtime.provider.Close(ctx)
}

type accountRegistrationPostgresLimiter struct {
	pool         *pgxpool.Pool
	digestKey    []byte
	window       time.Duration
	sourceLimit  int
	subjectLimit int
}

func (limiter *accountRegistrationPostgresLimiter) Allow(
	ctx context.Context,
	request accountregistration.RateLimitRequest,
) (bool, error) {
	address, err := netip.ParseAddr(request.Source)
	if limiter == nil || limiter.pool == nil || ctx == nil || err != nil || address.Zone() != "" ||
		address != address.Unmap() || request.SubjectDigest == ([sha256.Size]byte{}) || len(limiter.digestKey) != 32 ||
		limiter.window <= 0 || limiter.sourceLimit < 1 || limiter.subjectLimit < 1 || request.IdempotencyKey == "" {
		return false, errors.New("account registration rate limiter unavailable")
	}
	sourceMAC := hmac.New(sha256.New, limiter.digestKey)
	_, _ = sourceMAC.Write([]byte("account-registration-proof:v1:source\x00"))
	_, _ = sourceMAC.Write([]byte(address.String()))
	sourceDigest := sourceMAC.Sum(nil)
	var sourceCount, subjectCount int
	err = limiter.pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE source_digest=$1),
		count(*) FILTER (WHERE subject_digest=$2)
		FROM account_registration_proofs_162
		WHERE created_at>=clock_timestamp()-($3*interval '1 second')`,
		sourceDigest, request.SubjectDigest[:], int64(limiter.window/time.Second),
	).Scan(&sourceCount, &subjectCount)
	if err != nil || sourceCount < 0 || subjectCount < 0 {
		return false, errors.New("account registration rate limiter unavailable")
	}
	return sourceCount < limiter.sourceLimit && subjectCount < limiter.subjectLimit, nil
}

type accountRegistrationContactProvider struct {
	catalog   *notification.Catalog
	templates map[notification.Channel]notification.TemplateRef
	providers map[notification.Channel]notificationruntime.ProviderTransport
	timeout   time.Duration
	now       func() time.Time
}

func newAccountRegistrationContactProvider(
	ctx context.Context,
	pool *pgxpool.Pool,
	templates map[notification.Channel]notification.TemplateRef,
	config notificationRuntimeConfig,
) (*accountRegistrationContactProvider, error) {
	if ctx == nil || pool == nil || !config.Enabled || config.SendTimeout <= 0 ||
		config.StartupTimeout <= 0 || config.ShutdownTimeout <= 0 {
		return nil, errors.New("account registration contact provider configuration is incomplete")
	}
	channels, err := accountRegistrationProviderChannels(templates, config)
	if err != nil {
		return nil, err
	}
	catalog := notification.NewCatalog()
	for _, channel := range channels {
		ref, exists := templates[channel]
		if !exists || ref.Channel != channel {
			return nil, errors.New("account registration notification template is unavailable")
		}
		definition := notification.TemplateDefinition{Ref: ref}
		if err := pool.QueryRow(ctx, `SELECT subject,body,variables FROM notification_templates
			WHERE template_id=$1 AND version=$2 AND channel=$3`, ref.ID, ref.Version, ref.Channel).Scan(
			&definition.Subject, &definition.Body, &definition.Variables,
		); err != nil || len(definition.Variables) != 0 || catalog.Register(definition) != nil {
			return nil, errors.New("account registration notification template is unavailable")
		}
	}
	providers, err := openAccountRegistrationProviderTransports(
		ctx, templates, config,
		func(config smtpTLSConfig) (notificationruntime.ProviderTransport, error) {
			return newThemedSMTPTLSTransport(config, pool)
		},
		func(config smsHTTPSJSONConfig) (notificationruntime.ProviderTransport, error) {
			return newHTTPSJSONSMSTransport(config)
		},
	)
	if err != nil {
		return nil, err
	}
	return &accountRegistrationContactProvider{
		catalog: catalog, templates: templates, providers: providers, timeout: config.SendTimeout,
	}, nil
}

func accountRegistrationProviderChannels(
	templates map[notification.Channel]notification.TemplateRef,
	config notificationRuntimeConfig,
) ([]notification.Channel, error) {
	emailConfigured := notificationEmailConfigured(config)
	smsConfigured := notificationSMSConfigured(config)
	if !config.Enabled || config.EmailProvider != "" && !emailConfigured || config.SMSProvider != "" && !smsConfigured ||
		!emailConfigured && !smsConfigured {
		return nil, errors.New("account registration notification provider configuration is invalid")
	}
	channels := make([]notification.Channel, 0, 2)
	if emailConfigured {
		channels = append(channels, notification.ChannelEmail)
	}
	if smsConfigured {
		channels = append(channels, notification.ChannelSMS)
	}
	if len(templates) != len(channels) {
		return nil, errors.New("account registration notification template/provider mismatch")
	}
	for _, channel := range channels {
		ref, exists := templates[channel]
		if !exists || ref.Channel != channel || ref.ID == "" || ref.Version == 0 {
			return nil, errors.New("account registration notification template/provider mismatch")
		}
	}
	return channels, nil
}

func openAccountRegistrationProviderTransports(
	ctx context.Context,
	templates map[notification.Channel]notification.TemplateRef,
	config notificationRuntimeConfig,
	newSMTP func(smtpTLSConfig) (notificationruntime.ProviderTransport, error),
	newSMS func(smsHTTPSJSONConfig) (notificationruntime.ProviderTransport, error),
) (map[notification.Channel]notificationruntime.ProviderTransport, error) {
	channels, err := accountRegistrationProviderChannels(templates, config)
	if err != nil || ctx == nil || newSMTP == nil || newSMS == nil || config.StartupTimeout <= 0 || config.ShutdownTimeout <= 0 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("account registration notification provider configuration is invalid")
	}
	providers := make(map[notification.Channel]notificationruntime.ProviderTransport, len(channels))
	for _, channel := range channels {
		var provider notificationruntime.ProviderTransport
		if channel == notification.ChannelEmail {
			provider, err = newConfiguredEmailTransport(config, newSMTP, accountRegistrationMailPlugins, accountRegistrationMailLayout)
		} else {
			provider, err = newConfiguredSMSTransport(config, newSMS)
		}
		if err != nil || provider == nil {
			closeNotificationProviders(providers, config.ShutdownTimeout)
			return nil, errors.New("account registration notification provider is unavailable")
		}
		providers[channel] = provider
	}
	readyCtx, cancel := context.WithTimeout(ctx, config.StartupTimeout)
	defer cancel()
	for _, channel := range channels {
		if err := providers[channel].Ready(readyCtx); err != nil {
			closeNotificationProviders(providers, config.ShutdownTimeout)
			return nil, errors.New("account registration notification provider is not ready")
		}
	}
	return providers, nil
}

func (provider *accountRegistrationContactProvider) SendRegistrationVerification(
	ctx context.Context,
	delivery accountregistrationchallenge.ContactDelivery,
) notification.SendResult {
	return provider.sendVerification(ctx, accountVerificationDelivery{
		OutboxID: delivery.OutboxID, Channel: delivery.Channel, Template: delivery.Template,
		Destination: delivery.Destination, OTP: delivery.OTP, Subject: delivery.Subject, Body: delivery.Body,
		IdempotencyKey: delivery.IdempotencyKey, AttemptNumber: delivery.AttemptNumber,
	})
}

func (provider *accountRegistrationContactProvider) SendLoginVerification(
	ctx context.Context,
	delivery accountloginchallenge.ContactDelivery,
) notification.SendResult {
	return provider.sendVerification(ctx, accountVerificationDelivery{
		OutboxID: delivery.OutboxID, Channel: delivery.Channel, Template: delivery.Template,
		Destination: delivery.Destination, OTP: delivery.OTP, Subject: delivery.Subject, Body: delivery.Body,
		IdempotencyKey: delivery.IdempotencyKey, AttemptNumber: delivery.AttemptNumber,
	})
}

type accountVerificationDelivery struct {
	OutboxID       uuid.UUID
	Channel        notification.Channel
	Template       notification.TemplateRef
	Destination    string
	OTP            string
	Subject        string
	Body           string
	IdempotencyKey string
	AttemptNumber  int
}

func (provider *accountRegistrationContactProvider) sendVerification(
	ctx context.Context,
	delivery accountVerificationDelivery,
) notification.SendResult {
	if provider == nil || provider.catalog == nil || ctx == nil || delivery.OutboxID == uuid.Nil ||
		(delivery.Channel != notification.ChannelEmail && delivery.Channel != notification.ChannelSMS) ||
		delivery.Template.ID == "" || delivery.Template.Version == 0 || delivery.Template.Channel != delivery.Channel ||
		delivery.Destination == "" || len(delivery.OTP) != 6 || strings.IndexFunc(delivery.OTP, func(r rune) bool {
		return !unicode.IsDigit(r) || r > unicode.MaxASCII
	}) >= 0 || delivery.IdempotencyKey == "" || delivery.AttemptNumber < 1 {
		return registrationProviderFailure(notification.FailurePermanent, "provider_contract_invalid", 0)
	}
	transport := provider.providers[delivery.Channel]
	ref, exists := provider.templates[delivery.Channel]
	if transport == nil || !exists {
		return registrationProviderFailure(notification.FailureTemporary, "provider_unavailable", 0)
	}
	var subject, body string
	if strings.Contains(delivery.Subject+delivery.Body, "{{.captcha}}") {
		var ok bool
		subject, body, ok = renderRegistrationVerification(delivery)
		if !ok {
			return registrationProviderFailure(notification.FailurePermanent, "template_unavailable", 0)
		}
	} else if delivery.Template == ref {
		rendered, err := provider.catalog.Render(ref, notification.TemplateContext{})
		if err != nil {
			return registrationProviderFailure(notification.FailurePermanent, "template_unavailable", 0)
		}
		subject, body = rendered.Subject, rendered.Body+"\n"+delivery.OTP
	} else {
		return registrationProviderFailure(notification.FailurePermanent, "template_unavailable", 0)
	}
	message := notificationruntime.ProviderMessage{
		OutboxID: delivery.OutboxID, Channel: delivery.Channel, Contact: delivery.Destination,
		Subject: subject, Body: body,
		IdempotencyKey: delivery.IdempotencyKey, AttemptNumber: delivery.AttemptNumber,
		TemplateID: delivery.Template.ID, Params: map[string]string{"code": delivery.OTP},
	}
	sendCtx, cancel := context.WithTimeout(ctx, provider.timeout)
	defer cancel()
	result, err, panicked, observation := notificationruntime.CallObservedProvider(sendCtx, transport, message, provider.now)
	if err != nil || panicked {
		return notification.SendResult{Disposition: notification.SendUnknown, Provider: "configured_" + string(delivery.Channel), Observation: observation}
	}
	sendResult := mapAccountRegistrationProviderResult(delivery.Channel, result)
	sendResult.Observation = observation
	return sendResult
}

func renderRegistrationVerification(
	delivery accountVerificationDelivery,
) (string, string, bool) {
	const placeholder = "{{.captcha}}"
	if !strings.Contains(delivery.Subject+delivery.Body, placeholder) ||
		(delivery.Channel == notification.ChannelEmail && delivery.Subject == "") ||
		(delivery.Channel == notification.ChannelSMS && delivery.Subject != "") {
		return "", "", false
	}
	subject := strings.ReplaceAll(delivery.Subject, placeholder, delivery.OTP)
	body := strings.ReplaceAll(delivery.Body, placeholder, delivery.OTP)
	if subject == "" && delivery.Channel == notification.ChannelEmail || body == "" ||
		strings.Contains(subject, "{{") || strings.Contains(body, "{{") {
		return "", "", false
	}
	return subject, body, true
}

func mapAccountRegistrationProviderResult(
	channel notification.Channel,
	result notificationruntime.ProviderResult,
) notification.SendResult {
	provider := "configured_" + string(channel)
	switch result.Disposition {
	case notificationruntime.ProviderAccepted:
		if !validAccountRegistrationDeliveryID(result.ProviderDeliveryID) || result.Code != "" || result.RetryAfter != 0 {
			break
		}
		return notification.SendResult{Disposition: notification.SendAccepted, Provider: provider,
			ProviderDeliveryID: result.ProviderDeliveryID}
	case notificationruntime.ProviderUnknown:
		if result.Code == "" && result.RetryAfter == 0 && result.ProviderDeliveryID == "" {
			return notification.SendResult{Disposition: notification.SendUnknown, Provider: provider}
		}
	case notificationruntime.ProviderTemporaryFailure, notificationruntime.ProviderRateLimited:
		if accountRegistrationProviderCode.MatchString(result.Code) && result.ProviderDeliveryID == "" && result.RetryAfter >= 0 &&
			(result.Disposition != notificationruntime.ProviderRateLimited || result.RetryAfter > 0) {
			return registrationProviderFailure(notification.FailureTemporary, result.Code, result.RetryAfter)
		}
	case notificationruntime.ProviderPermanentFailure:
		if accountRegistrationProviderCode.MatchString(result.Code) && result.RetryAfter == 0 && result.ProviderDeliveryID == "" {
			return registrationProviderFailure(notification.FailurePermanent, result.Code, 0)
		}
	}
	return registrationProviderFailure(notification.FailurePermanent, "provider_contract_invalid", 0)
}

func validAccountRegistrationDeliveryID(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	return strings.IndexFunc(value, func(character rune) bool {
		return character < ' ' || character == unicode.MaxASCII
	}) < 0
}

func registrationProviderFailure(
	class notification.FailureClass,
	code string,
	retryAfter time.Duration,
) notification.SendResult {
	return notification.SendResult{Failure: &notification.Failure{Class: class, Code: code, RetryAfter: retryAfter}}
}

func (provider *accountRegistrationContactProvider) Close(ctx context.Context) error {
	if provider == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("account registration provider close context is required")
	}
	var closeErr error
	for channel, transport := range provider.providers {
		if transport != nil {
			closeErr = errors.Join(closeErr, transport.Close(ctx))
		}
		delete(provider.providers, channel)
	}
	return closeErr
}

var _ accountregistration.RateLimiter = (*accountRegistrationPostgresLimiter)(nil)
var _ accountregistrationchallenge.ContactProvider = (*accountRegistrationContactProvider)(nil)
var _ accountloginchallenge.ContactProvider = (*accountRegistrationContactProvider)(nil)
