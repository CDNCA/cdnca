package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrolruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

const (
	defaultAccountRecoveryTokenTTL       = 15 * time.Minute
	defaultAccountRecoveryRateWindow     = 15 * time.Minute
	defaultAccountRecoverySubjectLimit   = 5
	defaultAccountRecoverySourceLimit    = 20
	defaultAccountRecoveryHandlerTimeout = 10 * time.Second
	defaultAccountRecoveryStartupTimeout = 5 * time.Second
	defaultAccountRecoveryShutdownPeriod = 5 * time.Second
	defaultAccountRecoveryMaxProxyHops   = 16
	maximumAccountRecoveryKeys           = 16
	maximumAccountRecoveryTrustedProxies = 64
	maximumAccountRecoveryPlatformHosts  = 16
)

var accountRecoveryTemplateIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,95}$`)
var accountRecoveryHostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

type accountRecoveryRuntimeConfig struct {
	Enabled              bool
	DigestKey            []byte
	DispatchKeys         *accountrecovery.DispatchKeyring
	LoginDispatchKeys    *accountregistrationchallenge.EnvelopeKeyring
	RecoveryURL          string
	TokenTTL             time.Duration
	RateWindow           time.Duration
	SubjectLimit         int
	SourceLimit          int
	HandlerTimeout       time.Duration
	StartupTimeout       time.Duration
	ShutdownPeriod       time.Duration
	TrustedProxyCIDRs    []string
	PlatformHosts        []string
	AllowPrivateSourceIP bool
	MaxProxyHops         int
	Templates            map[notification.Channel]notification.TemplateRef
}

type accountRecoveryEnvLookup func(string) (string, bool)

type cacheControlProductionConfig struct {
	Runtime            cacheControlRuntimeConfig
	NATSURL            string
	NATSName           string
	NATSConnectTimeout time.Duration
	NATSReconnectWait  time.Duration
	NATSDrainTimeout   time.Duration
}

func loadAccountRecoveryRuntimeConfig() (accountRecoveryRuntimeConfig, error) {
	return loadAccountRecoveryRuntimeConfigFromEnv(os.LookupEnv)
}

func loadAccountRecoveryRuntimeConfigFromEnv(lookup accountRecoveryEnvLookup) (accountRecoveryRuntimeConfig, error) {
	if lookup == nil {
		return accountRecoveryRuntimeConfig{}, errors.New("account recovery environment lookup is required")
	}
	enabled, err := accountRecoveryEnvBool(lookup, "ACCOUNT_RECOVERY_ENABLED", false)
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	if !enabled {
		return accountRecoveryRuntimeConfig{}, nil
	}

	digestKey, err := accountRecoveryEnvKey(lookup, "ACCOUNT_RECOVERY_HMAC_KEY_BASE64")
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	failed := true
	defer func() {
		if failed {
			clear(digestKey)
		}
	}()

	activeKeyID, err := accountRecoveryRequiredEnv(lookup, "ACCOUNT_RECOVERY_KEK_ACTIVE_KEY_ID")
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	encodedKeys, err := accountRecoveryRequiredEnv(lookup, "ACCOUNT_RECOVERY_KEK_KEYS_JSON")
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	keys, err := decodeAccountRecoveryKeyring(encodedKeys)
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	dispatchKeys, keyringErr := accountrecovery.NewDispatchKeyring(activeKeyID, keys)
	loginDispatchKeys, loginKeyringErr := accountregistrationchallenge.NewEnvelopeKeyring(activeKeyID, keys)
	for keyID, key := range keys {
		clear(key)
		delete(keys, keyID)
	}
	if keyringErr != nil || loginKeyringErr != nil {
		return accountRecoveryRuntimeConfig{}, errors.New("account recovery KEK keyring is invalid")
	}

	recoveryURL, err := accountRecoveryRequiredEnv(lookup, "ACCOUNT_RECOVERY_BASE_URL")
	if err != nil || !validAccountRecoveryBaseURL(recoveryURL) {
		return accountRecoveryRuntimeConfig{}, errors.New("ACCOUNT_RECOVERY_BASE_URL must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	tokenTTL, err := accountRecoveryEnvDuration(
		lookup, "ACCOUNT_RECOVERY_TOKEN_TTL", defaultAccountRecoveryTokenTTL, time.Second, time.Hour,
	)
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	rateWindow, err := accountRecoveryEnvDuration(
		lookup, "ACCOUNT_RECOVERY_RATE_WINDOW", defaultAccountRecoveryRateWindow, time.Second, 24*time.Hour,
	)
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	handlerTimeout, err := accountRecoveryEnvDuration(
		lookup, "ACCOUNT_RECOVERY_HANDLER_TIMEOUT", defaultAccountRecoveryHandlerTimeout, time.Millisecond, 30*time.Second,
	)
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	startupTimeout, err := accountRecoveryEnvDuration(
		lookup, "ACCOUNT_RECOVERY_STARTUP_TIMEOUT", defaultAccountRecoveryStartupTimeout, time.Millisecond, 30*time.Second,
	)
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	shutdownPeriod, err := accountRecoveryEnvDuration(
		lookup, "ACCOUNT_RECOVERY_SHUTDOWN_PERIOD", defaultAccountRecoveryShutdownPeriod, time.Millisecond, 30*time.Second,
	)
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	subjectLimit, err := accountRecoveryEnvInt(
		lookup, "ACCOUNT_RECOVERY_SUBJECT_LIMIT", defaultAccountRecoverySubjectLimit, 1, 100_000,
	)
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	sourceLimit, err := accountRecoveryEnvInt(
		lookup, "ACCOUNT_RECOVERY_SOURCE_LIMIT", defaultAccountRecoverySourceLimit, 1, 100_000,
	)
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	trustedProxyCIDRs, err := accountRecoveryEnvList(
		lookup, "ACCOUNT_RECOVERY_TRUSTED_PROXY_CIDRS", maximumAccountRecoveryTrustedProxies,
	)
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	platformHosts, err := accountRecoveryHostList(
		lookup, "ACCOUNT_RECOVERY_PLATFORM_HOSTS", maximumAccountRecoveryPlatformHosts,
	)
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	allowPrivateSourceIP, err := accountRecoveryEnvBool(
		lookup, "ACCOUNT_RECOVERY_ALLOW_PRIVATE_SOURCE_IP", false,
	)
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	maxProxyHops, err := accountRecoveryEnvInt(
		lookup, "ACCOUNT_RECOVERY_MAX_PROXY_HOPS", defaultAccountRecoveryMaxProxyHops, 1, 64,
	)
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}
	templates, err := loadAccountRecoveryTemplates(lookup)
	if err != nil {
		return accountRecoveryRuntimeConfig{}, err
	}

	failed = false
	return accountRecoveryRuntimeConfig{
		Enabled: true, DigestKey: digestKey, DispatchKeys: dispatchKeys, LoginDispatchKeys: loginDispatchKeys, RecoveryURL: recoveryURL,
		TokenTTL: tokenTTL, RateWindow: rateWindow, SubjectLimit: subjectLimit, SourceLimit: sourceLimit,
		HandlerTimeout: handlerTimeout, StartupTimeout: startupTimeout, ShutdownPeriod: shutdownPeriod,
		TrustedProxyCIDRs: trustedProxyCIDRs, PlatformHosts: platformHosts,
		AllowPrivateSourceIP: allowPrivateSourceIP,
		MaxProxyHops:         maxProxyHops,
		Templates:            templates,
	}, nil
}

func (config *accountRecoveryRuntimeConfig) clearSecrets() {
	if config == nil {
		return
	}
	clear(config.DigestKey)
	config.DigestKey = nil
	config.DispatchKeys = nil
	config.LoginDispatchKeys = nil
}

func loadCacheControlProductionConfig() (cacheControlProductionConfig, error) {
	return loadCacheControlProductionConfigFromEnv(os.LookupEnv)
}

func loadCacheControlProductionConfigFromEnv(
	lookup accountRecoveryEnvLookup,
) (cacheControlProductionConfig, error) {
	if lookup == nil {
		return cacheControlProductionConfig{}, errors.New("cache control environment lookup is required")
	}
	enabled, err := accountRecoveryEnvBool(lookup, "CACHE_CONTROL_RUNTIME_ENABLED", false)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	if !enabled {
		return cacheControlProductionConfig{}, nil
	}

	result := cacheControlProductionConfig{}
	result.Runtime.Enabled = true
	result.NATSURL, err = accountRecoveryRequiredEnv(lookup, "CACHE_CONTROL_RUNTIME_NATS_URL")
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	result.NATSName, err = accountRecoveryRequiredEnv(lookup, "CACHE_CONTROL_RUNTIME_NATS_NAME")
	if err != nil || len(result.NATSName) > 128 {
		return cacheControlProductionConfig{}, errors.New("CACHE_CONTROL_RUNTIME_NATS_NAME is invalid")
	}

	encodedKey, err := accountRecoveryRequiredEnv(lookup, "CACHE_CONTROL_RUNTIME_CURSOR_KEY_BASE64")
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	result.Runtime.CursorKey, err = base64.StdEncoding.Strict().DecodeString(encodedKey)
	if err != nil || len(result.Runtime.CursorKey) != 32 ||
		base64.StdEncoding.EncodeToString(result.Runtime.CursorKey) != encodedKey {
		clear(result.Runtime.CursorKey)
		return cacheControlProductionConfig{}, errors.New("CACHE_CONTROL_RUNTIME_CURSOR_KEY_BASE64 is invalid")
	}
	failed := true
	defer func() {
		if failed {
			result.clearSecrets()
		}
	}()

	worker := cachecontrolruntime.DefaultConfig()
	for _, field := range []struct {
		target *string
		name   string
	}{
		{&worker.CommandStream, "CACHE_CONTROL_RUNTIME_COMMAND_STREAM"},
		{&worker.StatusStream, "CACHE_CONTROL_RUNTIME_STATUS_STREAM"},
		{&worker.CommandSubjectPrefix, "CACHE_CONTROL_RUNTIME_COMMAND_SUBJECT_PREFIX"},
		{&worker.StatusSubjectPrefix, "CACHE_CONTROL_RUNTIME_STATUS_SUBJECT_PREFIX"},
		{&worker.DLQSubjectPrefix, "CACHE_CONTROL_RUNTIME_DLQ_SUBJECT_PREFIX"},
		{&worker.Durable, "CACHE_CONTROL_RUNTIME_DURABLE"},
		{&worker.WorkerID, "CACHE_CONTROL_RUNTIME_WORKER_ID"},
	} {
		*field.target, err = accountRecoveryRequiredEnv(lookup, field.name)
		if err != nil {
			return cacheControlProductionConfig{}, err
		}
	}
	result.NATSConnectTimeout, err = accountRecoveryEnvDuration(
		lookup, "CACHE_CONTROL_RUNTIME_NATS_CONNECT_TIMEOUT", 5*time.Second, 50*time.Millisecond, 30*time.Second,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	result.NATSReconnectWait, err = accountRecoveryEnvDuration(
		lookup, "CACHE_CONTROL_RUNTIME_NATS_RECONNECT_WAIT", time.Second, 50*time.Millisecond, 30*time.Second,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	result.NATSDrainTimeout, err = accountRecoveryEnvDuration(
		lookup, "CACHE_CONTROL_RUNTIME_NATS_DRAIN_TIMEOUT", 5*time.Second, 100*time.Millisecond, 30*time.Second,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	worker.PollInterval, err = accountRecoveryEnvDuration(
		lookup, "CACHE_CONTROL_RUNTIME_POLL_INTERVAL", worker.PollInterval, 10*time.Millisecond, time.Minute,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	worker.FetchTimeout, err = accountRecoveryEnvDuration(
		lookup, "CACHE_CONTROL_RUNTIME_FETCH_TIMEOUT", worker.FetchTimeout, 10*time.Millisecond, 30*time.Second,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	worker.OperationTimeout, err = accountRecoveryEnvDuration(
		lookup, "CACHE_CONTROL_RUNTIME_OPERATION_TIMEOUT", worker.OperationTimeout, 10*time.Millisecond, 30*time.Second,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	worker.LeaseDuration, err = accountRecoveryEnvDuration(
		lookup, "CACHE_CONTROL_RUNTIME_LEASE_DURATION", worker.LeaseDuration, time.Second, time.Hour,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	worker.AckWait, err = accountRecoveryEnvDuration(
		lookup, "CACHE_CONTROL_RUNTIME_ACK_WAIT", worker.AckWait, 100*time.Millisecond, time.Hour,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	worker.NakBaseDelay, err = accountRecoveryEnvDuration(
		lookup, "CACHE_CONTROL_RUNTIME_NAK_BASE_DELAY", worker.NakBaseDelay, 10*time.Millisecond, 10*time.Minute,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	worker.NakMaximumDelay, err = accountRecoveryEnvDuration(
		lookup, "CACHE_CONTROL_RUNTIME_NAK_MAXIMUM_DELAY", worker.NakMaximumDelay, 10*time.Millisecond, 10*time.Minute,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	worker.ClaimBatch, err = accountRecoveryEnvInt(
		lookup, "CACHE_CONTROL_RUNTIME_CLAIM_BATCH", worker.ClaimBatch, 1, 16,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	worker.MaxDeliver, err = accountRecoveryEnvInt(
		lookup, "CACHE_CONTROL_RUNTIME_MAX_DELIVER", worker.MaxDeliver, 2, 100,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	worker.MaxAckPending, err = accountRecoveryEnvInt(
		lookup, "CACHE_CONTROL_RUNTIME_MAX_ACK_PENDING", worker.MaxAckPending, 1, 10_000,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	worker.MaxWaiting, err = accountRecoveryEnvInt(
		lookup, "CACHE_CONTROL_RUNTIME_MAX_WAITING", worker.MaxWaiting, 1, 10_000,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	worker.MaxPayloadBytes, err = accountRecoveryEnvInt(
		lookup, "CACHE_CONTROL_RUNTIME_MAX_PAYLOAD_BYTES", worker.MaxPayloadBytes, 1, 1<<20,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	// Minimum replicas of the shared Agent streams: 1 matches the single-host
	// native NATS; clustered compose/helm deployments set 3.
	worker.Replicas, err = accountRecoveryEnvInt(
		lookup, "CACHE_CONTROL_RUNTIME_STREAM_REPLICAS", worker.Replicas, 1, 5,
	)
	if err != nil {
		return cacheControlProductionConfig{}, err
	}
	if worker.MaxAckPending < worker.ClaimBatch {
		return cacheControlProductionConfig{}, errors.New("CACHE_CONTROL_RUNTIME_MAX_ACK_PENDING is smaller than CACHE_CONTROL_RUNTIME_CLAIM_BATCH")
	}
	if worker.NakMaximumDelay < worker.NakBaseDelay {
		return cacheControlProductionConfig{}, errors.New("CACHE_CONTROL_RUNTIME_NAK_MAXIMUM_DELAY is smaller than CACHE_CONTROL_RUNTIME_NAK_BASE_DELAY")
	}
	if worker.CommandStream == worker.StatusStream {
		return cacheControlProductionConfig{}, errors.New("CACHE_CONTROL_RUNTIME_COMMAND_STREAM and CACHE_CONTROL_RUNTIME_STATUS_STREAM must differ")
	}
	if worker.CommandSubjectPrefix == worker.StatusSubjectPrefix ||
		worker.CommandSubjectPrefix == worker.DLQSubjectPrefix ||
		worker.StatusSubjectPrefix == worker.DLQSubjectPrefix {
		return cacheControlProductionConfig{}, errors.New("CACHE_CONTROL_RUNTIME subject prefixes must differ")
	}
	result.Runtime.Worker = worker
	failed = false
	return result, nil
}

func (config *cacheControlProductionConfig) clearSecrets() {
	if config == nil {
		return
	}
	clear(config.Runtime.CursorKey)
	config.Runtime.CursorKey = nil
}

func decodeAccountRecoveryKeyring(encoded string) (map[string][]byte, error) {
	values, err := decodeUniqueStringMap(encoded)
	if err != nil || len(values) == 0 || len(values) > maximumAccountRecoveryKeys {
		return nil, errors.New("ACCOUNT_RECOVERY_KEK_KEYS_JSON must be a bounded JSON object of canonical base64 keys")
	}
	keys := make(map[string][]byte, len(values))
	for keyID, value := range values {
		key, decodeErr := decodeCanonicalAccountRecoveryKey(value)
		if decodeErr != nil {
			for existingID, existing := range keys {
				clear(existing)
				delete(keys, existingID)
			}
			return nil, errors.New("ACCOUNT_RECOVERY_KEK_KEYS_JSON contains an invalid key")
		}
		keys[keyID] = key
	}
	return keys, nil
}

func decodeUniqueStringMap(raw string) (map[string]string, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("JSON object is required")
	}
	values := make(map[string]string)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("JSON object key is invalid")
		}
		if _, duplicate := values[key]; duplicate {
			return nil, errors.New("duplicate JSON object key")
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		values[key] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, errors.New("JSON object is incomplete")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("JSON object has trailing content")
	}
	return values, nil
}

func loadAccountRecoveryTemplates(lookup accountRecoveryEnvLookup) (map[notification.Channel]notification.TemplateRef, error) {
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
		if !idSet || !versionSet || strings.TrimSpace(id) != id || !accountRecoveryTemplateIDPattern.MatchString(id) {
			return nil, errors.New("account recovery template ID and version must be configured together")
		}
		parsedVersion, err := strconv.ParseUint(version, 10, 64)
		if err != nil || parsedVersion == 0 {
			return nil, errors.New("account recovery template version must be a positive integer")
		}
		templates[candidate.channel] = notification.TemplateRef{
			ID: id, Version: parsedVersion, Channel: candidate.channel,
		}
	}
	if len(templates) == 0 {
		return nil, errors.New("at least one account recovery notification template is required")
	}
	return templates, nil
}

func accountRecoveryEnvKey(lookup accountRecoveryEnvLookup, name string) ([]byte, error) {
	encoded, err := accountRecoveryRequiredEnv(lookup, name)
	if err != nil {
		return nil, err
	}
	key, err := decodeCanonicalAccountRecoveryKey(encoded)
	if err != nil {
		return nil, errors.New(name + " must encode exactly 32 bytes using canonical padded base64")
	}
	return key, nil
}

func decodeCanonicalAccountRecoveryKey(encoded string) ([]byte, error) {
	if strings.TrimSpace(encoded) != encoded {
		return nil, errors.New("key is not canonical")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != encoded {
		clear(key)
		return nil, errors.New("key is invalid")
	}
	return key, nil
}

func accountRecoveryRequiredEnv(lookup accountRecoveryEnvLookup, name string) (string, error) {
	value, exists := lookup(name)
	if !exists || value == "" || strings.TrimSpace(value) != value {
		return "", errors.New(name + " is required and must not contain surrounding whitespace")
	}
	return value, nil
}

func accountRecoveryEnvBool(lookup accountRecoveryEnvLookup, name string, fallback bool) (bool, error) {
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

func accountRecoveryEnvDuration(
	lookup accountRecoveryEnvLookup,
	name string,
	fallback, minimum, maximum time.Duration,
) (time.Duration, error) {
	value, exists := lookup(name)
	if !exists || value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, errors.New(name + " is outside the supported duration range")
	}
	return parsed, nil
}

func accountRecoveryEnvInt(
	lookup accountRecoveryEnvLookup,
	name string,
	fallback, minimum, maximum int,
) (int, error) {
	value, exists := lookup(name)
	if !exists || value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum || strconv.Itoa(parsed) != value {
		return 0, errors.New(name + " is outside the supported integer range")
	}
	return parsed, nil
}

func accountRecoveryEnvList(
	lookup accountRecoveryEnvLookup,
	name string,
	maximum int,
) ([]string, error) {
	value, exists := lookup(name)
	if !exists || value == "" {
		return nil, nil
	}
	items := strings.Split(value, ",")
	if len(items) > maximum {
		return nil, errors.New(name + " contains too many values")
	}
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item == "" || strings.TrimSpace(item) != item {
			return nil, errors.New(name + " must be a canonical comma-separated list")
		}
		prefix, err := netip.ParsePrefix(item)
		if err != nil || prefix != prefix.Masked() || prefix.String() != item || prefix.Bits() == 0 ||
			prefix.Addr().Zone() != "" || prefix.Addr() != prefix.Addr().Unmap() {
			return nil, errors.New(name + " contains an invalid network prefix")
		}
		if _, duplicate := seen[item]; duplicate {
			return nil, errors.New(name + " contains duplicate values")
		}
		seen[item] = struct{}{}
	}
	return items, nil
}

func accountRecoveryHostList(
	lookup accountRecoveryEnvLookup,
	name string,
	maximum int,
) ([]string, error) {
	value, exists := lookup(name)
	if !exists || value == "" {
		return nil, nil
	}
	items := strings.Split(value, ",")
	if len(items) > maximum {
		return nil, errors.New(name + " contains too many values")
	}
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item == "" || strings.TrimSpace(item) != item || !validAccountRecoveryHost(item) {
			return nil, errors.New(name + " contains an invalid host")
		}
		if _, duplicate := seen[item]; duplicate {
			return nil, errors.New(name + " contains duplicate values")
		}
		seen[item] = struct{}{}
	}
	return items, nil
}

func validAccountRecoveryHost(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == "" && address == address.Unmap() &&
			address.String() == value && !address.IsUnspecified()
	}
	return len(value) <= 253 && value == strings.ToLower(value) &&
		accountRecoveryHostPattern.MatchString(value) &&
		!strings.HasSuffix(value, ".local") && !strings.HasSuffix(value, ".internal")
}

func validAccountRecoveryBaseURL(value string) bool {
	if strings.TrimSpace(value) != value {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.Hostname() != "" &&
		parsed.Opaque == "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}
