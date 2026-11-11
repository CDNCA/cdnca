package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallengehttp"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationproof"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// built-in registration (no Turnstile runtime) can send
// email / SMS verification codes while the notification runtime is on. The
// human check is the built-in image CAPTCHA; the digest, envelope and proof
// keys derive from the access secret (as the built-in registration digest
// key), so no extra secret is needed. Codes use the default template of
// migration 660 unless the platform published its own.

// builtInRegistrationTemplates are the default verification templates.
var builtInRegistrationTemplates = map[notification.Channel]notification.TemplateRef{
	notification.ChannelEmail: {ID: "account_registration_verification", Version: 1, Channel: notification.ChannelEmail},
	notification.ChannelSMS:   {ID: "account_registration_verification", Version: 1, Channel: notification.ChannelSMS},
}

// builtInRegistrationKey derives one built-in registration key per purpose.
func builtInRegistrationKey(accessSecret, purpose string) []byte {
	key := sha256.Sum256(append([]byte("cdnca.account-registration.builtin.v1\x00"+purpose), accessSecret...))
	return key[:]
}

type builtInRegistrationVerification struct {
	handler        http.Handler
	dispatcher     notification.AnonymousDispatcher
	provider       *accountRegistrationContactProvider
	channels       map[notification.Channel]bool
	registration   accountRecoveryDispatcherRegistration
	shutdownPeriod time.Duration
}

// builtInRegistrationChannels are the channels the notification runtime can
// send with; the challenge service also needs their templates.
func builtInRegistrationChannels(config notificationRuntimeConfig) map[notification.Channel]notification.TemplateRef {
	templates := map[notification.Channel]notification.TemplateRef{}
	transports := notificationChannelTransports(config)
	if transports.Email {
		templates[notification.ChannelEmail] = builtInRegistrationTemplates[notification.ChannelEmail]
	}
	if transports.SMS {
		templates[notification.ChannelSMS] = builtInRegistrationTemplates[notification.ChannelSMS]
	}
	return templates
}

// openBuiltInRegistrationVerification returns nil (codes unavailable) when
// the notification runtime cannot send email or SMS.
func openBuiltInRegistrationVerification(
	ctx context.Context,
	pool *pgxpool.Pool,
	notificationConfig notificationRuntimeConfig,
	settings *systemusersettings.Service,
	captcha *identity.Service,
	service *accountregistration.BuiltInService,
	accessSecret string,
	logger *slog.Logger,
) (*builtInRegistrationVerification, error) {
	templates := builtInRegistrationChannels(notificationConfig)
	if !notificationConfig.Enabled || len(templates) == 0 {
		return nil, nil
	}
	if ctx == nil || pool == nil || settings == nil || captcha == nil || service == nil || logger == nil {
		return nil, errors.New("built-in registration verification dependencies are incomplete")
	}
	provider, err := newAccountRegistrationContactProvider(ctx, pool, templates, notificationConfig)
	if err != nil {
		return nil, runtimeStageError{stage: "configure built-in registration notification provider", err: err}
	}
	owned := true
	defer func() {
		if owned {
			closeCtx, cancel := context.WithTimeout(context.Background(), notificationConfig.ShutdownTimeout)
			defer cancel()
			_ = provider.Close(closeCtx)
		}
	}()
	digestKey := builtInRegistrationKey(accessSecret, "")
	dispatchKeys, err := accountregistrationchallenge.NewEnvelopeKeyring("builtin-dispatch-v1",
		map[string][]byte{"builtin-dispatch-v1": builtInRegistrationKey(accessSecret, "dispatch")})
	if err != nil {
		return nil, err
	}
	proofKeys, err := accountregistrationchallenge.NewEnvelopeKeyring("builtin-proof-v1",
		map[string][]byte{"builtin-proof-v1": builtInRegistrationKey(accessSecret, "proof")})
	if err != nil {
		return nil, err
	}
	notificationStore, err := notification.NewStore(pool)
	if err != nil {
		return nil, err
	}
	proofAuthority, err := accountregistrationproof.NewAuthority(pool, accountregistrationproof.Config{DigestKey: digestKey})
	if err != nil {
		return nil, err
	}
	contactSender, err := accountregistrationchallenge.NewNotificationContactSender(notificationStore, dispatchKeys, templates)
	if err != nil {
		return nil, err
	}
	challengeService, err := accountregistrationchallenge.NewService(
		pool, accountregistrationchallenge.CaptchaHumanVerifier{Captcha: captcha}, contactSender, proofAuthority, proofKeys,
		accountregistrationchallenge.Config{DigestKey: digestKey, PublicSettings: settings, TemplateSettings: settings},
	)
	if err != nil {
		return nil, err
	}
	var platformScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL
		ORDER BY created_at, id LIMIT 1`).Scan(&platformScope); err != nil {
		return nil, runtimeStageError{stage: "resolve built-in registration platform scope", err: err}
	}
	handler, err := accountregistrationchallengehttp.NewHandler(challengeService,
		accountregistrationchallengehttp.TrustedContextResolverFunc(func(request *http.Request) (
			accountregistrationchallengehttp.TrustedContext, error,
		) {
			source := httpapi.BuiltInRegistrationSource(request.Context())
			if source == "" {
				return accountregistrationchallengehttp.TrustedContext{}, errors.New("registration source is unavailable")
			}
			return accountregistrationchallengehttp.TrustedContext{ScopeID: platformScope, SourceIP: source}, nil
		}), accountregistrationchallengehttp.Config{})
	if err != nil {
		return nil, err
	}
	dispatcher, err := accountregistrationchallenge.NewDispatcher(pool, dispatchKeys, provider, digestKey)
	if err != nil {
		return nil, err
	}
	service.EnableContactVerification(proofAuthority)
	channels := map[notification.Channel]bool{}
	for channel := range templates {
		channels[channel] = true
	}
	owned = false
	return &builtInRegistrationVerification{
		handler: handler, dispatcher: dispatcher, provider: provider, channels: channels,
		shutdownPeriod: notificationConfig.ShutdownTimeout,
	}, nil
}

// Handler serves the two challenge routes (nil: not mounted).
func (verification *builtInRegistrationVerification) Handler() http.Handler {
	if verification == nil {
		return nil
	}
	return verification.handler
}

// Dispatcher is handed to the account recovery runtime when it runs.
func (verification *builtInRegistrationVerification) Dispatcher() notification.AnonymousDispatcher {
	if verification == nil {
		return nil
	}
	return verification.dispatcher
}

// Channels reports which channels can carry a code.
func (verification *builtInRegistrationVerification) Channels() (email, sms bool) {
	if verification == nil {
		return false, false
	}
	return verification.channels[notification.ChannelEmail], verification.channels[notification.ChannelSMS]
}

// RegisterAlone registers the dispatcher with the notification runtime
// when no account recovery runtime does it (its mux's recovery slot is the
// registration dispatcher too: a recovery event reaching it is rejected).
func (verification *builtInRegistrationVerification) RegisterAlone(ctx context.Context, notifications accountRecoveryNotificationBridge) error {
	if verification == nil || notifications == nil {
		return nil
	}
	mux, err := accountregistrationchallenge.NewAnonymousDispatchMux(verification.dispatcher, verification.dispatcher)
	if err != nil {
		return err
	}
	registration, err := notifications.RegisterAnonymousDispatcher(ctx, mux)
	if err != nil {
		return err
	}
	verification.registration = registration
	return nil
}

func (verification *builtInRegistrationVerification) Close() error {
	if verification == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), verification.shutdownPeriod)
	defer cancel()
	var err error
	if verification.registration != nil {
		err = verification.registration.Close(ctx)
	}
	return errors.Join(err, verification.provider.Close(ctx))
}
