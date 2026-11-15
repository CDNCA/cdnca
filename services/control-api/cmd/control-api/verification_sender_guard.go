package main

import (
	"context"

	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
	"github.com/jackc/pgx/v5"
)

// Email (phone) verification is in effect while 要求邮箱验证
// (要求手机验证) and the email (SMS) notification channel switch are both on;
// then the channel needs a working sender. No save may leave a verification
// in effect without one: the user settings save (turning it on,
// systemusersettings.WithVerificationSenders) and the mail settings page
// (below) are checked; the channel switch cannot be turned on without a
// sender anyway (notificationcontrol ErrChannelUnsupported).

// verificationRequiredTx reads 要求邮箱验证 / 要求手机验证 of the platform.
func verificationRequiredTx(ctx context.Context, tx pgx.Tx) (email, sms bool, err error) {
	err = tx.QueryRow(ctx, `SELECT coalesce((settings.settings->>'email_verification_required')::boolean,false),
		coalesce((settings.settings->>'phone_verification_required')::boolean,false)
		FROM platform_system_user_settings settings
		JOIN access_scopes scope ON scope.id=settings.platform_scope_id AND scope.kind='platform' AND scope.tenant_id IS NULL
		ORDER BY settings.platform_scope_id LIMIT 1`).Scan(&email, &sms)
	if err == pgx.ErrNoRows {
		return false, false, nil
	}
	return email, sms, err
}

// VerificationSenderGuard is the mail settings save guard of the auto mode:
// it resolves the senders from the settings being saved (as the next rebuild
// will) and refuses the save when a verification in effect that has a sender
// now would lose it.
func (auto *notificationAutoRuntime) VerificationSenderGuard() systemmailsettings.SaveGuard {
	return func(ctx context.Context, tx pgx.Tx) error {
		emailRequired, smsRequired, err := verificationRequiredTx(ctx, tx)
		if err != nil {
			return err
		}
		var switches struct{ email, sms bool }
		if err := tx.QueryRow(ctx, `SELECT email_enabled,sms_enabled FROM notification_channel_settings WHERE singleton`).
			Scan(&switches.email, &switches.sms); err != nil && err != pgx.ErrNoRows {
			return err
		}
		emailOn, smsOn := emailRequired && switches.email, smsRequired && switches.sms
		if !emailOn && !smsOn {
			return nil
		}
		before := auto.Transports()
		after, err := auto.transportsAfter(ctx, tx)
		if err != nil {
			return err
		}
		switch {
		case emailOn && before.Email && !after.Email:
			return systemmailsettings.ErrEmailVerificationSender
		case smsOn && before.SMS && !after.SMS:
			return systemmailsettings.ErrSMSVerificationSender
		}
		return nil
	}
}

// transportsAfter is notificationChannelTransports of the settings in tx.
func (auto *notificationAutoRuntime) transportsAfter(ctx context.Context, tx pgx.Tx) (notificationcontrol.ChannelTransports, error) {
	persisted, err := systemmailsettings.ReadRuntimeTx(ctx, tx)
	if err != nil {
		return notificationcontrol.ChannelTransports{}, err
	}
	auto.mu.Lock()
	next := auto.base
	auto.mu.Unlock()
	next.SMTP.Password = append([]byte(nil), next.SMTP.Password...)
	next.SMS.AuthToken = append([]byte(nil), next.SMS.AuthToken...)
	next.NativeSMS.AccessKeySecret = append([]byte(nil), next.NativeSMS.AccessKeySecret...)
	next.Unavailable = nil
	defer next.clearSecrets()
	cipher, err := newConfiguredDNSCredentialCipher(auto.cfg)
	if err != nil {
		return notificationcontrol.ChannelTransports{}, err
	}
	mergeErr := mergePersistedNotificationMailSettings(&next, persisted, cipher)
	_ = cipher.Close()
	if mergeErr != nil {
		// the saved settings cannot build a sender
		return notificationcontrol.ChannelTransports{}, nil
	}
	resolveNotificationRuntime(&next)
	return notificationChannelTransports(next), nil
}
