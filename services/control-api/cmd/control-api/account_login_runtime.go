package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountloginchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/accountloginchallengehttp"
	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoverycontext"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/jackc/pgx/v5/pgxpool"
)

var accountLoginFallbackTemplates = map[notification.Channel]notification.TemplateRef{
	notification.ChannelEmail: {ID: "account_login_verification", Version: 1, Channel: notification.ChannelEmail},
	notification.ChannelSMS:   {ID: "account_login_verification", Version: 1, Channel: notification.ChannelSMS},
}

type accountLoginRuntime struct {
	handler        http.Handler
	dispatcher     notification.AnonymousDispatcher
	provider       *accountRegistrationContactProvider
	shutdownPeriod time.Duration
}

func openAccountLoginRuntime(
	ctx context.Context,
	config accountRecoveryRuntimeConfig,
	notificationConfig notificationRuntimeConfig,
	pool *pgxpool.Pool,
	issuer *identity.Service,
	cookieSecure bool,
	cookieDomain string,
	registrationMounted bool,
) (*accountLoginRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	if ctx == nil || pool == nil || issuer == nil || len(config.DigestKey) != 32 || config.LoginDispatchKeys == nil ||
		!notificationConfig.Enabled {
		return nil, errors.New("account login production dependencies are incomplete")
	}
	templates := accountLoginTemplates(notificationConfig)
	if len(templates) == 0 {
		return nil, errors.New("account login notification provider is unavailable")
	}
	provider, err := newAccountRegistrationContactProvider(ctx, pool, templates, notificationConfig)
	if err != nil {
		return nil, runtimeStageError{stage: "configure account login notification provider", err: err}
	}
	providerOwned := true
	defer func() {
		if providerOwned {
			closeCtx, cancel := context.WithTimeout(context.Background(), notificationConfig.ShutdownTimeout)
			defer cancel()
			_ = provider.Close(closeCtx)
		}
	}()
	trusted, err := accountrecoverycontext.NewResolver(pool, accountrecoverycontext.Config{
		TrustedProxyCIDRs: config.TrustedProxyCIDRs, PlatformHosts: config.PlatformHosts,
		AllowPrivateSourceIP: config.AllowPrivateSourceIP, MaxProxyHops: config.MaxProxyHops,
	})
	if err != nil {
		return nil, err
	}
	notificationStore, err := notification.NewStore(pool)
	if err != nil {
		return nil, err
	}
	settings, err := systemusersettings.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		return nil, err
	}
	contacts, err := accountloginchallenge.NewNotificationContactSender(
		notificationStore, config.LoginDispatchKeys, templates,
	)
	if err != nil {
		return nil, err
	}
	channels := make([]notification.Channel, 0, len(templates))
	for channel := range templates {
		channels = append(channels, channel)
	}
	sourceIP, err := accountrecoverycontext.NewSourceIPResolver(config.TrustedProxyCIDRs, config.MaxProxyHops)
	if err != nil {
		return nil, err
	}
	captchaSecrets, err := loadAccountLoginCaptchaSecrets(os.LookupEnv)
	if err != nil {
		return nil, err
	}
	human, err := accountloginchallenge.NewExternalCaptchaVerifier(accountloginchallenge.ExternalCaptchaConfig{
		Settings: settings, Secrets: captchaSecrets, Client: &http.Client{Transport: &http.Transport{
			Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		}},
	})
	if err != nil {
		return nil, err
	}
	service, err := accountloginchallenge.NewService(pool, accountloginchallenge.Config{
		DigestKey: config.DigestKey, Policy: settings, Templates: settings, Human: human, Issuer: issuer, Contacts: contacts, AvailableChannels: channels,
		RegistrationMounted: registrationMounted,
		RateWindow:          config.RateWindow, SourceLimit: config.SourceLimit, SubjectLimit: config.SubjectLimit,
	})
	if err != nil {
		return nil, err
	}
	handler, err := accountloginchallengehttp.NewHandler(
		service,
		accountloginchallengehttp.TrustedContextResolverFunc(func(request *http.Request) (accountloginchallengehttp.TrustedContext, error) {
			resolved, err := trusted.Resolve(request)
			if err != nil {
				return accountloginchallengehttp.TrustedContext{}, err
			}
			return accountloginchallengehttp.TrustedContext{ScopeID: resolved.ScopeID, SourceIP: resolved.SourceIP}, nil
		}),
		accountloginchallengehttp.Config{CookieSecure: cookieSecure, CookieDomain: cookieDomain, Timeout: config.HandlerTimeout,
			RetryAfter: config.RateWindow, SourceIPResolver: sourceIP},
	)
	if err != nil {
		return nil, err
	}
	dispatcher, err := accountloginchallenge.NewDispatcher(pool, config.LoginDispatchKeys, provider, config.DigestKey)
	if err != nil {
		return nil, err
	}
	issuer.SetLoginChallengeConsumer(service)
	providerOwned = false
	return &accountLoginRuntime{handler: handler, dispatcher: dispatcher, provider: provider,
		shutdownPeriod: notificationConfig.ShutdownTimeout}, nil
}

// loadAccountLoginCaptchaSecrets reads the Tencent/GeeTest secrets that the
// system settings page references (vault:// or kms-envelope://). The settings
// store only references; ACCOUNT_LOGIN_CAPTCHA_SECRETS_JSON maps each reference
// to its secret. When it is absent, external CAPTCHA modes fail closed.
func loadAccountLoginCaptchaSecrets(lookup accountRecoveryEnvLookup) (accountloginchallenge.StaticSecretResolver, error) {
	raw, exists := lookup("ACCOUNT_LOGIN_CAPTCHA_SECRETS_JSON")
	if !exists || raw == "" {
		return accountloginchallenge.StaticSecretResolver{}, nil
	}
	secrets, err := accountloginchallenge.ParseCaptchaSecretsJSON(raw)
	if err != nil {
		return nil, errors.New("ACCOUNT_LOGIN_CAPTCHA_SECRETS_JSON must map vault:// or kms-envelope:// references to secrets")
	}
	return secrets, nil
}

func accountLoginTemplates(config notificationRuntimeConfig) map[notification.Channel]notification.TemplateRef {
	templates := make(map[notification.Channel]notification.TemplateRef, 2)
	if config.EmailProvider == notificationEmailProviderSMTPTLS || config.EmailProvider == notificationEmailProviderSMTPSTARTTLS {
		templates[notification.ChannelEmail] = accountLoginFallbackTemplates[notification.ChannelEmail]
	}
	if notificationSMSConfigured(config) {
		templates[notification.ChannelSMS] = accountLoginFallbackTemplates[notification.ChannelSMS]
	}
	return templates
}

func (runtime *accountLoginRuntime) HandlerFactory() httpapi.MountedHandlerFactory {
	if runtime == nil || runtime.handler == nil {
		return nil
	}
	return func() (http.Handler, error) { return runtime.handler, nil }
}

func (runtime *accountLoginRuntime) Dispatcher() notification.AnonymousDispatcher {
	if runtime == nil {
		return nil
	}
	return runtime.dispatcher
}

func (runtime *accountLoginRuntime) Close() error {
	if runtime == nil || runtime.provider == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), runtime.shutdownPeriod)
	defer cancel()
	return runtime.provider.Close(ctx)
}

var _ accountloginchallenge.SessionIssuer = (*identity.Service)(nil)
