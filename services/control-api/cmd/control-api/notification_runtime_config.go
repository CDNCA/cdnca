package main

import (
	"errors"
	"net"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
)

const (
	notificationEmailProviderSMTPTLS      = "smtp_tls"
	notificationEmailProviderSMTPSTARTTLS = "smtp_starttls"
	notificationSMSProviderHTTPSJSON      = "https_json"
)

type notificationRuntimeEnvLookup func(string) (string, bool)

type notificationRuntimeConfig struct {
	Enabled               bool
	Worker                notification.WorkerConfig
	RecoveryTemplates     map[notification.Channel]notification.TemplateRef
	EmailProvider         string
	SMSProvider           string
	SMTPPasswordReference string
	SMSAuthTokenReference string
	SMTP                  smtpTLSConfig
	SMS                   smsHTTPSJSONConfig
	NativeSMS             nativeSMSConfig
	// Mail is the non-SMTP email sender chosen in the system settings.
	Mail                   notificationMailChoice
	IdleWait               time.Duration
	ErrorBackoffBase       time.Duration
	ErrorBackoffMax        time.Duration
	MaxConsecutiveFailures int
	SendTimeout            time.Duration
	StartupTimeout         time.Duration
	ShutdownTimeout        time.Duration
}

type smtpTLSConfig struct {
	Address    string
	ServerName string
	Username   string
	Password   []byte
	From       string
	CAFile     string
	StartTLS   bool
}

type smsHTTPSJSONConfig struct {
	Endpoint      string
	ReadyEndpoint string
	AccessKeyID   string
	SignatureName string
	AuthToken     []byte
	CAFile        string
}

func loadNotificationRuntimeConfig() (notificationRuntimeConfig, error) {
	return loadNotificationRuntimeConfigFromEnv(os.LookupEnv)
}

func loadNotificationRuntimeConfigFromEnv(lookup notificationRuntimeEnvLookup) (notificationRuntimeConfig, error) {
	if lookup == nil {
		return notificationRuntimeConfig{}, errors.New("notification runtime environment lookup is required")
	}
	enabled, err := notificationEnvBool(lookup, "NOTIFICATION_RUNTIME_ENABLED", false)
	if err != nil {
		return notificationRuntimeConfig{}, err
	}
	if !enabled {
		return notificationRuntimeConfig{}, nil
	}

	config := notificationRuntimeConfig{Enabled: true}
	failed := true
	defer func() {
		if failed {
			config.clearSecrets()
		}
	}()
	if config.Worker.BatchSize, err = notificationRequiredInt(lookup, "NOTIFICATION_WORKER_BATCH_SIZE", 1, 256); err != nil {
		return notificationRuntimeConfig{}, err
	}
	if config.Worker.LeaseDuration, err = notificationRequiredDuration(lookup, "NOTIFICATION_WORKER_LEASE_DURATION", time.Second, 15*time.Minute); err != nil {
		return notificationRuntimeConfig{}, err
	}
	if config.Worker.LeaseSafetyMargin, err = notificationRequiredDuration(lookup, "NOTIFICATION_WORKER_LEASE_SAFETY_MARGIN", 100*time.Millisecond, 5*time.Minute); err != nil {
		return notificationRuntimeConfig{}, err
	}
	if config.Worker.MaxAttempts, err = notificationRequiredInt(lookup, "NOTIFICATION_WORKER_MAX_ATTEMPTS", 1, 100); err != nil {
		return notificationRuntimeConfig{}, err
	}
	if config.Worker.BaseDelay, err = notificationRequiredDuration(lookup, "NOTIFICATION_WORKER_BASE_DELAY", 100*time.Millisecond, 24*time.Hour); err != nil {
		return notificationRuntimeConfig{}, err
	}
	if config.Worker.MaxDelay, err = notificationRequiredDuration(lookup, "NOTIFICATION_WORKER_MAX_DELAY", 100*time.Millisecond, 24*time.Hour); err != nil {
		return notificationRuntimeConfig{}, err
	}
	if config.IdleWait, err = notificationRequiredDuration(lookup, "NOTIFICATION_RUNTIME_IDLE_WAIT", 10*time.Millisecond, time.Minute); err != nil {
		return notificationRuntimeConfig{}, err
	}
	if config.ErrorBackoffBase, err = notificationRequiredDuration(lookup, "NOTIFICATION_RUNTIME_ERROR_BACKOFF_BASE", 10*time.Millisecond, time.Minute); err != nil {
		return notificationRuntimeConfig{}, err
	}
	if config.ErrorBackoffMax, err = notificationRequiredDuration(lookup, "NOTIFICATION_RUNTIME_ERROR_BACKOFF_MAX", 10*time.Millisecond, 5*time.Minute); err != nil {
		return notificationRuntimeConfig{}, err
	}
	if config.MaxConsecutiveFailures, err = notificationRequiredInt(lookup, "NOTIFICATION_RUNTIME_MAX_CONSECUTIVE_FAILURES", 1, 100); err != nil {
		return notificationRuntimeConfig{}, err
	}
	if config.SendTimeout, err = notificationRequiredDuration(lookup, "NOTIFICATION_RUNTIME_SEND_TIMEOUT", 100*time.Millisecond, 30*time.Second); err != nil {
		return notificationRuntimeConfig{}, err
	}
	if config.StartupTimeout, err = notificationRequiredDuration(lookup, "NOTIFICATION_RUNTIME_STARTUP_TIMEOUT", 100*time.Millisecond, time.Minute); err != nil {
		return notificationRuntimeConfig{}, err
	}
	if config.ShutdownTimeout, err = notificationRequiredDuration(lookup, "NOTIFICATION_RUNTIME_SHUTDOWN_TIMEOUT", 100*time.Millisecond, 30*time.Second); err != nil {
		return notificationRuntimeConfig{}, err
	}
	if config.Worker.LeaseSafetyMargin >= config.Worker.LeaseDuration ||
		config.Worker.BaseDelay > config.Worker.MaxDelay ||
		config.ErrorBackoffBase > config.ErrorBackoffMax ||
		config.SendTimeout+config.Worker.LeaseSafetyMargin >= config.Worker.LeaseDuration {
		return notificationRuntimeConfig{}, errors.New("notification runtime worker duration ordering is invalid")
	}

	config.RecoveryTemplates, err = loadNotificationRecoveryTemplates(lookup)
	if err != nil {
		return notificationRuntimeConfig{}, err
	}
	if _, enabled := config.RecoveryTemplates[notification.ChannelEmail]; enabled {
		if err := loadNotificationEmailProvider(lookup, &config); err != nil {
			return notificationRuntimeConfig{}, err
		}
		if reference, exists := lookup("NOTIFICATION_SMTP_PASSWORD_REFERENCE"); exists {
			if reference == "" || strings.TrimSpace(reference) != reference || !notificationSecretReference(reference) {
				return notificationRuntimeConfig{}, errors.New("NOTIFICATION_SMTP_PASSWORD_REFERENCE is invalid")
			}
			config.SMTPPasswordReference = reference
		}
	}
	if _, enabled := config.RecoveryTemplates[notification.ChannelSMS]; enabled {
		if err := loadNotificationSMSProvider(lookup, &config); err != nil {
			return notificationRuntimeConfig{}, err
		}
		if reference, exists := lookup("NOTIFICATION_SMS_AUTH_TOKEN_REFERENCE"); exists {
			if reference == "" || strings.TrimSpace(reference) != reference || !notificationSecretReference(reference) {
				return notificationRuntimeConfig{}, errors.New("NOTIFICATION_SMS_AUTH_TOKEN_REFERENCE is invalid")
			}
			config.SMSAuthTokenReference = reference
		}
	}
	failed = false
	return config, nil
}

func notificationSecretReference(value string) bool {
	return (strings.HasPrefix(value, "vault://") && len(value) > len("vault://")) ||
		(strings.HasPrefix(value, "kms-envelope://") && len(value) > len("kms-envelope://"))
}

func (config *notificationRuntimeConfig) clearSecrets() {
	if config == nil {
		return
	}
	clear(config.SMTP.Password)
	config.SMTP.Password = nil
	clear(config.SMS.AuthToken)
	config.SMS.AuthToken = nil
	clear(config.NativeSMS.AccessKeySecret)
	config.NativeSMS.AccessKeySecret = nil
	config.Mail.clearSecrets()
}

// notificationSMSConfigured reports whether an SMS transport can be built.
// Native providers additionally need the credential merged from the platform
// settings (mergePersistedNotificationMailSettings).
func notificationSMSConfigured(config notificationRuntimeConfig) bool {
	switch config.SMSProvider {
	case notificationSMSProviderHTTPSJSON:
		return true
	case notificationSMSProviderAliyun, notificationSMSProviderSubmail:
		return len(config.NativeSMS.AccessKeySecret) > 0
	default:
		return false
	}
}

// newConfiguredSMSTransport builds the transport for the configured provider.
func newConfiguredSMSTransport(
	config notificationRuntimeConfig,
	newHTTPSJSON func(smsHTTPSJSONConfig) (notificationruntime.ProviderTransport, error),
) (notificationruntime.ProviderTransport, error) {
	if config.SMSProvider == notificationSMSProviderAliyun || config.SMSProvider == notificationSMSProviderSubmail {
		return newNativeSMSTransport(config.NativeSMS)
	}
	return newHTTPSJSON(config.SMS)
}

func loadNotificationRecoveryTemplates(
	lookup notificationRuntimeEnvLookup,
) (map[notification.Channel]notification.TemplateRef, error) {
	templates := make(map[notification.Channel]notification.TemplateRef, 2)
	for _, candidate := range []struct {
		channel     notification.Channel
		idName      string
		versionName string
	}{
		{notification.ChannelEmail, "ACCOUNT_RECOVERY_EMAIL_TEMPLATE_ID", "ACCOUNT_RECOVERY_EMAIL_TEMPLATE_VERSION"},
		{notification.ChannelSMS, "ACCOUNT_RECOVERY_SMS_TEMPLATE_ID", "ACCOUNT_RECOVERY_SMS_TEMPLATE_VERSION"},
	} {
		id, idSet := lookup(candidate.idName)
		version, versionSet := lookup(candidate.versionName)
		if !idSet && !versionSet {
			continue
		}
		if !idSet || id == "" || strings.TrimSpace(id) != id || !accountRecoveryTemplateIDPattern.MatchString(id) {
			return nil, errors.New(candidate.idName + " is required and invalid")
		}
		if !versionSet {
			return nil, errors.New(candidate.versionName + " is required")
		}
		parsed, parseErr := strconv.ParseUint(version, 10, 64)
		if parseErr != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != version {
			return nil, errors.New(candidate.versionName + " must be a positive canonical integer")
		}
		templates[candidate.channel] = notification.TemplateRef{
			ID: id, Version: parsed, Channel: candidate.channel,
		}
	}
	if len(templates) == 0 {
		return nil, errors.New("at least one account recovery notification template is required")
	}
	return templates, nil
}

func loadNotificationEmailProvider(
	lookup notificationRuntimeEnvLookup,
	config *notificationRuntimeConfig,
) error {
	var err error
	if config.EmailProvider, err = notificationRequiredEnv(lookup, "NOTIFICATION_EMAIL_PROVIDER"); err != nil {
		return err
	}
	if config.EmailProvider == notificationEmailProviderSettings {
		// The sender comes from the system settings page (official mail
		// service or mail plugin); no SMTP environment is read.
		return nil
	}
	if config.EmailProvider != notificationEmailProviderSMTPTLS &&
		config.EmailProvider != notificationEmailProviderSMTPSTARTTLS {
		return errors.New("NOTIFICATION_EMAIL_PROVIDER must be smtp_tls, smtp_starttls or settings")
	}
	config.SMTP.StartTLS = config.EmailProvider == notificationEmailProviderSMTPSTARTTLS
	if config.SMTP.Address, err = notificationRequiredEnv(lookup, "NOTIFICATION_SMTP_ADDRESS"); err != nil {
		return err
	}
	if !validSMTPAddress(config.SMTP.Address) {
		return errors.New("NOTIFICATION_SMTP_ADDRESS must be a host:port without credentials")
	}
	if config.SMTP.ServerName, err = notificationRequiredEnv(lookup, "NOTIFICATION_SMTP_SERVER_NAME"); err != nil {
		return err
	}
	if !validSMTPServerName(config.SMTP.ServerName) {
		return errors.New("NOTIFICATION_SMTP_SERVER_NAME is invalid")
	}
	if config.SMTP.Username, err = notificationRequiredEnv(lookup, "NOTIFICATION_SMTP_USERNAME"); err != nil {
		return err
	}
	if len(config.SMTP.Username) > 256 || strings.ContainsAny(config.SMTP.Username, ":\r\n\x00") {
		return errors.New("NOTIFICATION_SMTP_USERNAME is invalid")
	}
	password, err := notificationRequiredEnv(lookup, "NOTIFICATION_SMTP_PASSWORD")
	if err != nil {
		return err
	}
	if len(password) > 4096 || strings.ContainsAny(password, "\r\n\x00") {
		return errors.New("NOTIFICATION_SMTP_PASSWORD is invalid")
	}
	config.SMTP.Password = []byte(password)
	if config.SMTP.From, err = notificationRequiredEnv(lookup, "NOTIFICATION_SMTP_FROM"); err != nil {
		return err
	}
	if !validSMTPMailbox(config.SMTP.From) {
		return errors.New("NOTIFICATION_SMTP_FROM must be one canonical email address")
	}
	if caFile, exists := lookup("NOTIFICATION_SMTP_CA_FILE"); exists {
		if caFile == "" || strings.TrimSpace(caFile) != caFile || strings.ContainsRune(caFile, '\x00') {
			return errors.New("NOTIFICATION_SMTP_CA_FILE is invalid")
		}
		config.SMTP.CAFile = caFile
	}
	return nil
}

func loadNotificationSMSProvider(
	lookup notificationRuntimeEnvLookup,
	config *notificationRuntimeConfig,
) error {
	var err error
	if config.SMSProvider, err = notificationRequiredEnv(lookup, "NOTIFICATION_SMS_PROVIDER"); err != nil {
		return err
	}
	if config.SMSProvider == notificationSMSProviderAliyun || config.SMSProvider == notificationSMSProviderSubmail {
		// Credential, sign name and template map come from the platform
		// settings; only an endpoint override and CA may be set here.
		config.NativeSMS.Provider = config.SMSProvider
		if endpoint, exists := lookup("NOTIFICATION_SMS_ENDPOINT"); exists {
			if parsed, ok := canonicalSMSHTTPSURL(endpoint); !ok || parsed == nil {
				return errors.New("NOTIFICATION_SMS_ENDPOINT must be an HTTPS URL without credentials, query, or fragment")
			}
			config.NativeSMS.Endpoint = endpoint
		}
		if caFile, exists := lookup("NOTIFICATION_SMS_CA_FILE"); exists {
			if caFile == "" || strings.TrimSpace(caFile) != caFile || strings.ContainsRune(caFile, '\x00') {
				return errors.New("NOTIFICATION_SMS_CA_FILE is invalid")
			}
			config.NativeSMS.CAFile = caFile
		}
		return nil
	}
	if config.SMSProvider != notificationSMSProviderHTTPSJSON {
		return errors.New("NOTIFICATION_SMS_PROVIDER must be https_json, aliyun or submail")
	}
	if config.SMS.Endpoint, err = notificationRequiredEnv(lookup, "NOTIFICATION_SMS_ENDPOINT"); err != nil {
		return err
	}
	if config.SMS.ReadyEndpoint, err = notificationRequiredEnv(lookup, "NOTIFICATION_SMS_READY_ENDPOINT"); err != nil {
		return err
	}
	authToken, err := notificationRequiredEnv(lookup, "NOTIFICATION_SMS_AUTH_TOKEN")
	if err != nil {
		return err
	}
	if len(authToken) > 4096 || strings.ContainsAny(authToken, "\r\n\x00") {
		return errors.New("NOTIFICATION_SMS_AUTH_TOKEN is invalid")
	}
	config.SMS.AuthToken = []byte(authToken)
	if caFile, exists := lookup("NOTIFICATION_SMS_CA_FILE"); exists {
		if caFile == "" || strings.TrimSpace(caFile) != caFile || strings.ContainsRune(caFile, '\x00') {
			return errors.New("NOTIFICATION_SMS_CA_FILE is invalid")
		}
		config.SMS.CAFile = caFile
	}
	if !validSMSHTTPSJSONConfig(config.SMS) {
		return errors.New("NOTIFICATION_SMS_ENDPOINT and NOTIFICATION_SMS_READY_ENDPOINT must be same-origin HTTPS URLs without credentials, query, or fragment")
	}
	return nil
}

func notificationRequiredEnv(lookup notificationRuntimeEnvLookup, name string) (string, error) {
	value, exists := lookup(name)
	if !exists || value == "" || strings.TrimSpace(value) != value {
		return "", errors.New(name + " is required and must not contain surrounding whitespace")
	}
	return value, nil
}

func notificationEnvBool(lookup notificationRuntimeEnvLookup, name string, fallback bool) (bool, error) {
	value, exists := lookup(name)
	if !exists || value == "" {
		return fallback, nil
	}
	if value == "true" {
		return true, nil
	}
	if value == "false" {
		return false, nil
	}
	return false, errors.New(name + " must be true or false")
}

func notificationRequiredDuration(
	lookup notificationRuntimeEnvLookup,
	name string,
	minimum, maximum time.Duration,
) (time.Duration, error) {
	value, err := notificationRequiredEnv(lookup, name)
	if err != nil {
		return 0, err
	}
	parsed, parseErr := time.ParseDuration(value)
	if parseErr != nil || parsed < minimum || parsed > maximum {
		return 0, errors.New(name + " is outside the supported duration range")
	}
	return parsed, nil
}

func notificationRequiredInt(
	lookup notificationRuntimeEnvLookup,
	name string,
	minimum, maximum int,
) (int, error) {
	value, err := notificationRequiredEnv(lookup, name)
	if err != nil {
		return 0, err
	}
	parsed, parseErr := strconv.Atoi(value)
	if parseErr != nil || parsed < minimum || parsed > maximum || strconv.Itoa(parsed) != value {
		return 0, errors.New(name + " is outside the supported integer range")
	}
	return parsed, nil
}

func notificationRequiredUint64(lookup notificationRuntimeEnvLookup, name string) (uint64, error) {
	value, err := notificationRequiredEnv(lookup, name)
	if err != nil {
		return 0, err
	}
	parsed, parseErr := strconv.ParseUint(value, 10, 64)
	if parseErr != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != value {
		return 0, errors.New(name + " must be a positive canonical integer")
	}
	return parsed, nil
}

func validSMTPAddress(value string) bool {
	if strings.ContainsAny(value, "@/\\\r\n\x00") {
		return false
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port > 0 && port <= 65535
}

func validSMTPServerName(value string) bool {
	if net.ParseIP(value) != nil {
		return true
	}
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validSMTPMailbox(value string) bool {
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value && strings.ContainsRune(value, '@') &&
		!strings.ContainsAny(value, "\r\n\x00")
}
