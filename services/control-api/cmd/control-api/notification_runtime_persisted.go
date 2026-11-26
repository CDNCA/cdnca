package main

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
	"github.com/jackc/pgx/v5/pgxpool"
)

// mergePersistedNotificationMailSettings applies the SMTP projection saved in
// the platform settings page. An SMTP password saved there (encrypted under
// the credential keyring) replaces the environment password; otherwise the
// environment password is used and a persisted reference must match the
// reference configured for the runtime secret provider before startup can
// proceed. The HTTPS SMS gateway token works the same way.
func mergePersistedNotificationMailSettings(
	config *notificationRuntimeConfig,
	settings systemmailsettings.RuntimeSettings,
	ciphers ...systemmailsettings.SecretCipher,
) error {
	if config == nil || !settings.Configured {
		return nil
	}
	value := settings.Value
	environmentFrom := config.SMTP.From
	if value.SMTPFrom != "" {
		config.SMTP.From = value.SMTPFrom
	}
	if value.SMTPFromName != "" {
		config.SMTP.FromName = value.SMTPFromName
	}
	if value.SMTPAddress != "" {
		host := strings.TrimSpace(value.SMTPAddress)
		if host != value.SMTPAddress || strings.ContainsAny(host, "\r\n\x00") ||
			net.ParseIP(host) == nil && strings.ContainsAny(host, "/?#[]") {
			return errors.New("persisted SMTP address is invalid")
		}
		address := net.JoinHostPort(host, strconv.Itoa(value.SMTPPort))
		if !validSMTPAddress(address) {
			return errors.New("persisted SMTP address is invalid")
		}
		switch {
		case settings.HasSMTPPassword() && config.EmailProvider == "":
			// email is not enabled for this runtime; keep the password dormant
		case settings.HasSMTPPassword():
			if len(ciphers) != 1 || ciphers[0] == nil {
				return errors.New("persisted SMTP password requires the credential keyring")
			}
			password, err := settings.OpenSMTPPassword(ciphers[0])
			if err != nil {
				return errors.New("persisted SMTP password cannot be opened")
			}
			// not cleared: the previous slice may be shared with a base config
			config.SMTP.Password = password
		case value.SMTPPasswordReference != "" &&
			value.SMTPPasswordReference != config.SMTPPasswordReference:
			return errors.New("persisted SMTP password reference is not configured for the runtime")
		}
		// a missing user or sender leaves email unavailable with a reason
		// (resolveNotificationRuntime), it does not stop the start
		config.SMTP.Address = address
		config.SMTP.ServerName = host
		config.SMTP.Username = value.SMTPUser
		config.SMTP.From = systemmailsettings.SMTPSender(value, environmentFrom)
		config.SMTP.StartTLS = !value.SMTPSSL
		if config.SMTP.StartTLS {
			config.EmailProvider = notificationEmailProviderSMTPSTARTTLS
		} else {
			config.EmailProvider = notificationEmailProviderSMTPTLS
		}
	}
	var openMail func() ([]byte, error)
	if len(ciphers) == 1 && ciphers[0] != nil {
		openMail = func() ([]byte, error) { return settings.OpenMailSecret(ciphers[0]) }
	}
	if err := mergePersistedMailProvider(config, value, openMail); err != nil {
		return err
	}
	if systemmailsettings.NativeSMSProvider(value.SMSProvider) {
		return mergePersistedNativeSMS(config, settings, ciphers)
	}
	if value.SMSProvider != "" {
		if config.SMSProvider == "" {
			// the page's HTTPS gateway needs its endpoint and token from the
			// environment; without them SMS stays off with a reason
			config.unavailable("sms", "the HTTPS SMS gateway chosen on the system settings page needs NOTIFICATION_SMS_PROVIDER=https_json and its NOTIFICATION_SMS_* settings")
			return nil
		}
		if value.SMSProvider != config.SMSProvider {
			return errors.New("persisted SMS provider is not configured for the runtime")
		}
		switch {
		case settings.HasSMSAuthToken():
			// the gateway token saved on the page replaces NOTIFICATION_SMS_AUTH_TOKEN
			if len(ciphers) != 1 || ciphers[0] == nil {
				return errors.New("persisted SMS gateway token requires the credential keyring")
			}
			token, err := settings.OpenSMSAuthToken(ciphers[0])
			if err != nil {
				return errors.New("persisted SMS gateway token cannot be opened")
			}
			// not cleared: the previous slice may be shared with a base config
			config.SMS.AuthToken = token
		case value.SMSAccessKeyReference != "" && value.SMSAccessKeyReference != config.SMSAuthTokenReference:
			return errors.New("persisted SMS access key reference is not configured for the runtime")
		}
		if value.SMSAccessKeyID == "" || strings.ContainsAny(value.SMSAccessKeyID, "\r\n\x00") || len(value.SMSAccessKeyID) > 256 {
			return errors.New("persisted SMS access key ID is invalid")
		}
		if strings.ContainsAny(value.SMSSignatureName, "\r\n\x00") || len(value.SMSSignatureName) > 256 {
			return errors.New("persisted SMS signature name is invalid")
		}
		config.SMS.AccessKeyID = value.SMSAccessKeyID
		config.SMS.SignatureName = value.SMSSignatureName
	}
	return nil
}

// mergePersistedNativeSMS fills the aliyun/submail transport from the
// platform settings: the encrypted credential is opened with the control-api
// credential keyring at startup and only lives in process memory.
func mergePersistedNativeSMS(
	config *notificationRuntimeConfig,
	settings systemmailsettings.RuntimeSettings,
	ciphers []systemmailsettings.SecretCipher,
) error {
	value := settings.Value
	if config.SMSProvider == "" {
		_, smsTemplate := config.RecoveryTemplates[notification.ChannelSMS]
		if !config.Auto && !smsTemplate {
			// SMS is not enabled for this runtime; keep the setting dormant.
			return nil
		}
		// no SMS provider in the environment: the page's native provider
		config.SMSProvider, config.NativeSMS.Provider = value.SMSProvider, value.SMSProvider
	}
	if value.SMSProvider != config.SMSProvider {
		return errors.New("persisted SMS provider is not configured for the runtime")
	}
	if len(ciphers) != 1 || ciphers[0] == nil {
		return errors.New("native SMS provider requires the credential keyring")
	}
	templates, err := systemmailsettings.ParseSMSTemplateMap(value.SMSTemplateMap)
	if err != nil {
		return errors.New("persisted SMS template map is invalid")
	}
	secret, err := settings.OpenSMSSecret(ciphers[0])
	if err != nil {
		return errors.New("persisted SMS credential cannot be opened")
	}
	config.NativeSMS.Provider = value.SMSProvider
	config.NativeSMS.AccessKeyID = value.SMSAccessKeyID
	config.NativeSMS.SignName = value.SMSSignatureName
	clear(config.NativeSMS.AccessKeySecret)
	config.NativeSMS.AccessKeySecret = secret
	config.NativeSMS.Templates = make(map[string]nativeSMSTemplate, len(templates))
	for id, template := range templates {
		config.NativeSMS.Templates[id] = nativeSMSTemplate{Code: template.Code, CodeEN: template.CodeEN, Variables: template.Variables}
	}
	if !validNativeSMSConfig(withDefaultNativeEndpoint(config.NativeSMS)) {
		return errors.New("persisted native SMS settings are invalid")
	}
	return nil
}

func withDefaultNativeEndpoint(config nativeSMSConfig) nativeSMSConfig {
	if config.Endpoint == "" {
		config.Endpoint = aliyunSMSDefaultEndpoint
		if config.Provider == notificationSMSProviderSubmail {
			config.Endpoint = submailSMSDefaultEndpoint
		}
	}
	return config
}

func (config *notificationRuntimeConfig) unavailable(channel, reason string) {
	if config.Unavailable == nil {
		config.Unavailable = make(map[string]string, 2)
	}
	config.Unavailable[channel] = reason
}

// smtpMissing names what the SMTP sender lacks, as system settings save body
// fields (each may also come from NOTIFICATION_SMTP_* in smtp_tls/smtp_starttls).
func smtpMissing(config smtpTLSConfig) []string {
	var missing []string
	if config.Address == "" {
		missing = append(missing, "value.smtp_address")
	}
	if config.Username == "" {
		missing = append(missing, "value.smtp_user")
	}
	if len(config.Password) == 0 {
		missing = append(missing, "smtp_password")
	}
	if !validSMTPMailbox(config.From) {
		missing = append(missing, "value.smtp_from")
	}
	return missing
}

// resolveNotificationRuntime runs after the persisted settings are merged. A
// channel that is not complete is dropped with an operator-readable reason
// (Unavailable) instead of failing the start; the runtime is enabled exactly
// when a channel is left (auto: turned on by the page, explicit: on as long
// as it can send at all).
func resolveNotificationRuntime(config *notificationRuntimeConfig) {
	if config == nil || !config.Requested {
		return
	}
	switch config.EmailProvider {
	case notificationEmailProviderSMTPTLS, notificationEmailProviderSMTPSTARTTLS:
		if missing := smtpMissing(config.SMTP); len(missing) > 0 {
			config.unavailable("email", "SMTP lacks "+strings.Join(missing, ", ")+" (system settings page, or NOTIFICATION_SMTP_* with smtp_tls/smtp_starttls)")
			config.EmailProvider = ""
		}
	case notificationEmailProviderSettings:
		config.unavailable("email", "no complete mail sender is saved on the system settings page (SMTP address, official mail service or mail plugin)")
		config.EmailProvider = ""
	}
	if config.SMSProvider != "" && !notificationSMSConfigured(*config) {
		config.unavailable("sms", "the SMS provider "+config.SMSProvider+" has no credential")
		config.SMSProvider = ""
	}
	config.Enabled = notificationEmailConfigured(*config) || notificationSMSConfigured(*config)
}

// applyPersistedNotificationSettings merges the system settings page into the
// runtime configuration (credentials opened with the control-api keyring).
func applyPersistedNotificationSettings(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, notificationConfig *notificationRuntimeConfig) error {
	persisted, err := systemmailsettings.ReadRuntime(ctx, pool)
	if err != nil {
		return runtimeStageError{stage: "read persisted system mail settings", err: err}
	}
	cipher, err := newConfiguredDNSCredentialCipher(cfg)
	if err != nil {
		return runtimeStageError{stage: "initialize system mail credential keyring", err: err}
	}
	err = mergePersistedNotificationMailSettings(notificationConfig, persisted, cipher)
	_ = cipher.Close()
	if err != nil {
		return runtimeStageError{stage: "apply persisted system mail settings", err: err}
	}
	return nil
}
