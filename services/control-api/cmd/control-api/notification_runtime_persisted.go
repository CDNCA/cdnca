package main

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
)

// mergePersistedNotificationMailSettings applies the non-secret SMTP
// projection saved in the platform settings page. Secret material remains
// outside PostgreSQL: when a persisted reference is present it must match the
// reference configured for the runtime secret provider before startup can
// proceed.
func mergePersistedNotificationMailSettings(
	config *notificationRuntimeConfig,
	settings systemmailsettings.RuntimeSettings,
	ciphers ...systemmailsettings.SecretCipher,
) error {
	if config == nil || !settings.Configured {
		return nil
	}
	value := settings.Value
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
		if value.SMTPPasswordReference != "" &&
			value.SMTPPasswordReference != config.SMTPPasswordReference {
			return errors.New("persisted SMTP password reference is not configured for the runtime")
		}
		if value.SMTPUser == "" {
			return errors.New("persisted SMTP user is required when SMTP address is configured")
		}
		config.SMTP.Address = address
		config.SMTP.ServerName = host
		config.SMTP.Username = value.SMTPUser
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
		if config.SMSProvider == "" || value.SMSProvider != config.SMSProvider {
			return errors.New("persisted SMS provider is not configured for the runtime")
		}
		if value.SMSAccessKeyReference != "" && value.SMSAccessKeyReference != config.SMSAuthTokenReference {
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
		// SMS is not enabled for this runtime; keep the setting dormant.
		return nil
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
		config.NativeSMS.Templates[id] = nativeSMSTemplate{Code: template.Code, Variables: template.Variables}
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
