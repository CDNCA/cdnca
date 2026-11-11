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

// builtInRegistrationTermsVersion is the terms version the built-in pages send
// (the console's accountRegistrationTermsVersion).
const builtInRegistrationTermsVersion = "terms-2026-08"

// registrationConfigSource is httpapi.RegistrationConfigSource
//: the settings decide what is required, the mounted
// runtimes and the notification switches decide what can be sent.
type registrationConfigSource struct {
	pool     *pgxpool.Pool
	settings *systemusersettings.Service
	// verified: the Turnstile registration runtime is mounted.
	verified         bool
	builtIn          *accountregistration.BuiltInService
	termsVersion     string
	turnstileSiteKey string
	// sendable: channels a registration code can go out by.
	sendEmail, sendSMS bool
	recovery           accountRecoveryRuntimeConfig
}

func newRegistrationConfigSource(
	pool *pgxpool.Pool,
	settings *systemusersettings.Service,
	registration accountRegistrationRuntimeConfig,
	builtIn *accountregistration.BuiltInService,
	verification *builtInRegistrationVerification,
	recovery accountRecoveryRuntimeConfig,
) *registrationConfigSource {
	source := &registrationConfigSource{pool: pool, settings: settings, builtIn: builtIn, recovery: recovery,
		termsVersion: builtInRegistrationTermsVersion}
	if registration.Enabled {
		source.verified = true
		source.termsVersion = registration.TermsVersion
		source.turnstileSiteKey = os.Getenv("ACCOUNT_REGISTRATION_TURNSTILE_SITE_KEY")
		_, source.sendEmail = registration.Templates[notification.ChannelEmail]
		_, source.sendSMS = registration.Templates[notification.ChannelSMS]
	} else {
		source.sendEmail, source.sendSMS = verification.Channels()
	}
	return source
}

func (source *registrationConfigSource) RegistrationConfig(ctx context.Context) (httpapi.RegistrationConfig, error) {
	config := httpapi.RegistrationConfig{Mode: "closed", HumanCheck: "builtin_captcha", TermsVersion: source.termsVersion,
		Recovery: httpapi.RecoveryConfig{Channels: []string{}}}
	policy, err := source.settings.GetPublic(ctx, uuid.Nil)
	if err != nil {
		return httpapi.RegistrationConfig{}, err
	}
	var switches notification.ChannelSwitches
	if err := source.pool.QueryRow(ctx, `SELECT sms_enabled,email_enabled FROM notification_channel_settings WHERE singleton`).
		Scan(&switches.SMS, &switches.Email); err != nil {
		switches = notification.ChannelSwitches{}
	}
	config.Email = httpapi.RegistrationChannel{Required: policy.EmailVerificationRequired, Available: source.sendEmail && switches.Email}
	config.SMS = httpapi.RegistrationChannel{Required: policy.PhoneVerificationRequired, Available: source.sendSMS && switches.SMS}
	config.EmailRequired, config.PhoneRequired = policy.EmailRequired, policy.PhoneRequired
	if source.verified {
		config.HumanCheck, config.TurnstileSiteKey = "turnstile", source.turnstileSiteKey
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
		// The Turnstile runtime always proves one channel, behind Turnstile.
		config.Ready = config.Ready && config.TurnstileSiteKey != "" && (config.Email.Available || config.SMS.Available)
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
	}
	return config, nil
}
