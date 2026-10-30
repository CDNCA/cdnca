package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmehttp01"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeserving"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginproviders"
	"github.com/cdnca/cdnca/services/control-api/internal/theme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	errNotificationChannelsDisabled    = errors.New("notification_runtime_channels_disabled")
	errNotificationTemplateUnavailable = errors.New("notification_runtime_template_unavailable")
)

type notificationRuntimeDependencies struct {
	Logger   *slog.Logger
	NewStore func(*pgxpool.Pool) (*notification.Store, error)
	NewSMTP  func(smtpTLSConfig) (notificationruntime.ProviderTransport, error)
	NewSMS   func(smsHTTPSJSONConfig) (notificationruntime.ProviderTransport, error)
	// MailPlugins resolves a chosen mail plugin (nil: never usable).
	MailPlugins pluginproviders.Clients
	Verify      func(context.Context, *pgxpool.Pool, map[notification.Channel]notification.TemplateRef) (notification.ChannelSwitches, error)
	Build       func(notificationruntime.RuntimeConfig, notificationruntime.Dependencies) (notificationRuntimeCore, error)
}

type postgresMemberContactResolver struct {
	pool *pgxpool.Pool
}

func openNotificationProcessRuntime(
	ctx context.Context,
	config notificationRuntimeConfig,
	pool *pgxpool.Pool,
	dependencies notificationRuntimeDependencies,
) (*notificationProcessRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	emailConfigured := notificationEmailConfigured(config)
	smsConfigured := notificationSMSConfigured(config)
	if ctx == nil || pool == nil || !emailConfigured && !smsConfigured ||
		config.EmailProvider != "" && !emailConfigured || config.SMSProvider != "" && !smsConfigured {
		return nil, errors.New("notification runtime production dependencies are required")
	}
	if dependencies.Logger == nil {
		dependencies.Logger = slog.Default()
	}
	if dependencies.NewStore == nil {
		dependencies.NewStore = notification.NewStore
	}
	if dependencies.NewSMTP == nil {
		dependencies.NewSMTP = func(config smtpTLSConfig) (notificationruntime.ProviderTransport, error) {
			return newThemedSMTPTLSTransport(config, pool)
		}
	}
	if dependencies.NewSMS == nil {
		dependencies.NewSMS = func(config smsHTTPSJSONConfig) (notificationruntime.ProviderTransport, error) {
			return newHTTPSJSONSMSTransport(config)
		}
	}
	if dependencies.Verify == nil {
		dependencies.Verify = verifyNotificationRuntimeDatabaseConfiguration
	}
	if dependencies.Build == nil {
		dependencies.Build = func(
			config notificationruntime.RuntimeConfig,
			dependencies notificationruntime.Dependencies,
		) (notificationRuntimeCore, error) {
			return notificationruntime.Build(config, dependencies)
		}
	}

	store, err := dependencies.NewStore(pool)
	if err != nil {
		return nil, runtimeStageError{stage: "configure notification runtime store", err: err}
	}
	if err := nodeserving.RegisterAvailabilityAlertReplayGuards(store); err != nil {
		return nil, runtimeStageError{stage: "register notification replay guards", err: err}
	}
	if err := nodeserving.RegisterLineBackupReplayGuards(store); err != nil {
		return nil, runtimeStageError{stage: "register notification replay guards", err: err}
	}
	if err := acmehttp01.RegisterEpochDriftReplayGuard(store); err != nil {
		return nil, runtimeStageError{stage: "register notification replay guards", err: err}
	}
	verificationContext, cancelVerification := context.WithTimeout(ctx, config.StartupTimeout)
	switches, err := dependencies.Verify(verificationContext, pool, config.RecoveryTemplates)
	cancelVerification()
	if err != nil {
		return nil, runtimeStageError{stage: "verify notification runtime database configuration", err: err}
	}
	providers := make(map[notification.Channel]notificationruntime.ProviderTransport, 2)
	if emailConfigured {
		provider, providerErr := newConfiguredEmailTransport(config, dependencies.NewSMTP, dependencies.MailPlugins,
			theme.NewEmailLayout(pool))
		if providerErr != nil {
			return nil, runtimeStageError{stage: "configure notification SMTP TLS provider", err: providerErr}
		}
		providers[notification.ChannelEmail] = provider
	}
	if smsConfigured {
		provider, providerErr := newConfiguredSMSTransport(config, dependencies.NewSMS)
		if providerErr != nil {
			closeNotificationProviders(providers, config.ShutdownTimeout)
			return nil, runtimeStageError{stage: "configure notification HTTPS JSON SMS provider", err: providerErr}
		}
		providers[notification.ChannelSMS] = provider
	}
	providersOwned := true
	defer func() {
		if !providersOwned {
			return
		}
		closeNotificationProviders(providers, config.ShutdownTimeout)
	}()

	core, err := dependencies.Build(notificationruntime.RuntimeConfig{
		Enabled: true, Worker: config.Worker, RecoveryTemplates: config.RecoveryTemplates,
		IdleWait: config.IdleWait, ErrorBackoffBase: config.ErrorBackoffBase,
		ErrorBackoffMax: config.ErrorBackoffMax, MaxConsecutiveFailures: config.MaxConsecutiveFailures,
		SendTimeout: config.SendTimeout, ShutdownTimeout: config.ShutdownTimeout, Logger: dependencies.Logger,
		TransientError: isTransientDBError,
	}, notificationruntime.Dependencies{
		Store: store, MemberContacts: &postgresMemberContactResolver{pool: pool},
		Providers: providers,
	})
	if err != nil {
		return nil, runtimeStageError{stage: "build notification runtime", err: err}
	}
	providersOwned = false
	runtime, err := startNotificationProcessRuntime(
		ctx, core, switches, config.StartupTimeout, config.ShutdownTimeout,
	)
	if err != nil {
		return nil, err
	}
	runtime.readinessCheck = func(ctx context.Context) (notification.ChannelSwitches, error) {
		return dependencies.Verify(ctx, pool, config.RecoveryTemplates)
	}
	return runtime, nil
}

func closeNotificationProviders(
	providers map[notification.Channel]notificationruntime.ProviderTransport,
	timeout time.Duration,
) {
	for _, provider := range providers {
		if provider == nil {
			continue
		}
		closeContext, cancel := context.WithTimeout(context.Background(), timeout)
		_ = provider.Close(closeContext)
		cancel()
	}
}

func verifyNotificationRuntimeDatabaseConfiguration(
	ctx context.Context,
	pool *pgxpool.Pool,
	templates map[notification.Channel]notification.TemplateRef,
) (notification.ChannelSwitches, error) {
	if ctx == nil || pool == nil {
		return notification.ChannelSwitches{}, errors.New("notification_runtime_database_unavailable")
	}
	var switches notification.ChannelSwitches
	if err := pool.QueryRow(ctx, `
		SELECT sms_enabled,email_enabled
		FROM notification_channel_settings WHERE singleton`).Scan(&switches.SMS, &switches.Email); err != nil {
		return notification.ChannelSwitches{}, errors.New("notification_runtime_database_unavailable")
	}
	if !switches.Email && !switches.SMS {
		return notification.ChannelSwitches{}, errNotificationChannelsDisabled
	}
	for _, channel := range []notification.Channel{notification.ChannelEmail, notification.ChannelSMS} {
		enabled := channel == notification.ChannelEmail && switches.Email ||
			channel == notification.ChannelSMS && switches.SMS
		if !enabled {
			continue
		}
		ref, exists := templates[channel]
		if !exists || ref.Channel != channel || ref.ID == "" || ref.Version == 0 {
			return notification.ChannelSwitches{}, errNotificationTemplateUnavailable
		}
		var available bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM notification_templates
			WHERE template_id=$1 AND version=$2 AND channel=$3
			  AND cardinality(variables)=0
		)`, ref.ID, ref.Version, channel).Scan(&available); err != nil {
			return notification.ChannelSwitches{}, errors.New("notification_runtime_database_unavailable")
		}
		if !available {
			return notification.ChannelSwitches{}, errNotificationTemplateUnavailable
		}
	}
	return switches, nil
}

func (resolver *postgresMemberContactResolver) Ready(ctx context.Context, channel notification.Channel) error {
	if resolver == nil || resolver.pool == nil || ctx == nil {
		return errors.New("notification_member_resolver_unavailable")
	}
	column := "email"
	if channel == notification.ChannelSMS {
		column = "phone"
	} else if channel != notification.ChannelEmail {
		return errors.New("notification_member_channel_invalid")
	}
	var count int
	if err := resolver.pool.QueryRow(ctx, `SELECT count(user_row.`+column+`)
		FROM users user_row
		JOIN memberships membership ON membership.user_id=user_row.id
		JOIN access_scopes scope ON scope.id=membership.scope_id
		WHERE false`).Scan(&count); err != nil {
		return errors.New("notification_member_resolver_unavailable")
	}
	return nil
}

func (resolver *postgresMemberContactResolver) Resolve(
	ctx context.Context,
	scopeID, userID uuid.UUID,
	channel notification.Channel,
) notificationruntime.ContactResolution {
	if resolver == nil || resolver.pool == nil || ctx == nil || scopeID == uuid.Nil || userID == uuid.Nil {
		return notificationruntime.ContactResolution{Failure: &notification.Failure{
			Class: notification.FailurePermanent, Code: "recipient_unavailable",
		}}
	}
	column := "email"
	validContact := validSMTPMailbox
	if channel == notification.ChannelSMS {
		column = "phone"
		validContact = validSMSContact
	} else if channel != notification.ChannelEmail {
		return notificationruntime.ContactResolution{Failure: &notification.Failure{
			Class: notification.FailurePermanent, Code: "recipient_unavailable",
		}}
	}
	tx, err := resolver.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return notificationruntime.ContactResolution{Failure: &notification.Failure{
			Class: notification.FailureTemporary, Code: "contact_lookup_unavailable",
		}}
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var contact *string
	lookupErr := tx.QueryRow(ctx, `
		SELECT user_row.`+column+`
		FROM access_scopes scope
		JOIN tenants tenant ON tenant.id=scope.tenant_id
		JOIN memberships membership
		  ON membership.scope_id=scope.id AND membership.user_id=$2
		JOIN users user_row ON user_row.id=membership.user_id
		WHERE scope.id=$1 AND scope.kind='tenant' AND tenant.status='active'
		  AND user_row.status='active' AND membership.status='active'
		FOR SHARE OF scope,tenant,user_row,membership`, scopeID, userID).Scan(&contact)
	if errors.Is(lookupErr, pgx.ErrNoRows) {
		// Platform members only ever hold platform operations alerts: the store
		// refuses any other event type for the platform scope (FX33).
		lookupErr = tx.QueryRow(ctx, `
			SELECT user_row.`+column+`
			FROM access_scopes scope
			JOIN memberships membership
			  ON membership.scope_id=scope.id AND membership.user_id=$2
			JOIN users user_row ON user_row.id=membership.user_id
			WHERE scope.id=$1 AND scope.kind='platform' AND scope.tenant_id IS NULL
			  AND user_row.status='active' AND membership.status='active'
			FOR SHARE OF scope,user_row,membership`, scopeID, userID).Scan(&contact)
	}
	if err := tx.Commit(ctx); err != nil {
		return notificationruntime.ContactResolution{Failure: &notification.Failure{
			Class: notification.FailureTemporary, Code: "contact_lookup_unavailable",
		}}
	}
	if errors.Is(lookupErr, pgx.ErrNoRows) || lookupErr == nil && (contact == nil || !validContact(*contact)) {
		return notificationruntime.ContactResolution{Failure: &notification.Failure{
			Class: notification.FailurePermanent, Code: "recipient_unavailable",
		}}
	}
	if lookupErr != nil {
		return notificationruntime.ContactResolution{Failure: &notification.Failure{
			Class: notification.FailureTemporary, Code: "contact_lookup_unavailable",
		}}
	}
	return notificationruntime.ContactResolution{Contact: *contact}
}

var _ notificationruntime.MemberContactResolver = (*postgresMemberContactResolver)(nil)
