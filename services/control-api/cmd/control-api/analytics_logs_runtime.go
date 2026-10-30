package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/jackc/pgx/v5/pgxpool"
)

type analyticsLogsHandlerFactory func(
	analyticslog.RuntimeConfig,
	analyticslog.HTTPDependencies,
) (http.Handler, error)

func openAnalyticsLogsRuntime(
	cfg config.Config,
	pool *pgxpool.Pool,
	identityService *identity.Service,
	tokens *identity.TokenManager,
	factory analyticsLogsHandlerFactory,
	blockActivations ...analyticslog.BlockActivationStarter,
) (http.Handler, error) {
	if !cfg.AnalyticsQueryEnabled {
		return nil, nil
	}
	if len(blockActivations) > 1 {
		return nil, runtimeStageError{stage: "initialize analytics logs handler", err: errors.New("multiple block activation runtimes")}
	}
	cursorKeyring, err := loadAnalyticsLogsCursorKeyring(true, os.LookupEnv)
	if err != nil {
		return nil, runtimeStageError{stage: "load analytics logs cursor keyring", err: err}
	}
	defer clearAnalyticsLogsCursorKeyring(&cursorKeyring)
	if factory == nil {
		factory = analyticslog.NewRuntimeHandler
	}
	apiKeyPepper := cfg.APIKeyPepperKeyring
	if !apiKeyPepper.Configured() {
		apiKeyPepper, err = apikeycredential.NewPepperKeyring(apikeycredential.PepperKeyringConfig{
			ActiveVersion: apikeycredential.LegacyPepperVersion,
			Active:        cfg.APIKeyPepper,
		})
		if err != nil {
			return nil, runtimeStageError{stage: "initialize analytics logs API key pepper", err: err}
		}
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		return nil, runtimeStageError{stage: "initialize analytics logs session verifier", err: err}
	}
	apiKeys, err := apikeycredential.NewVerifierWithKeyring(
		apiKeyPepper,
		time.Now,
		apikeycredential.NewPostgresDenialRecorder(pool, time.Now),
	)
	if err != nil {
		return nil, runtimeStageError{stage: "initialize analytics logs API key verifier", err: err}
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		return nil, runtimeStageError{stage: "initialize analytics logs IAM", err: err}
	}
	var blockActivation analyticslog.BlockActivationStarter
	if len(blockActivations) == 1 {
		blockActivation = blockActivations[0]
	}
	handler, err := factory(analyticslog.RuntimeConfig{
		Enabled: true,
		HTTP: analyticslog.HTTPConfig{
			ConnectTimeout: cfg.AnalyticsConnectTimeout,
			Client: analyticslog.ClientConfig{
				Endpoint:         cfg.ClickHouseURL,
				Database:         cfg.ClickHouseDatabase,
				Username:         cfg.ClickHouseUsername,
				Password:         cfg.ClickHousePassword,
				QueryTimeout:     cfg.AnalyticsQueryTimeout,
				MaxResponseBytes: cfg.AnalyticsQueryMaxResponse,
				CursorKeyring:    cursorKeyring,
			},
			Handler: analyticslog.HandlerConfig{
				QueryTimeout:     cfg.AnalyticsHandlerTimeout,
				MaxResponseBytes: cfg.AnalyticsHandlerMaxResponse,
			},
		},
	}, analyticslog.HTTPDependencies{
		Identity:        identityService,
		APIKeys:         apikey.NewServiceWithPepperKeyring(pool, apiKeyPepper, time.Now),
		Pool:            pool,
		IAM:             authorizer,
		BlockActivation: blockActivation,
	})
	if err != nil {
		return nil, runtimeStageError{stage: "initialize analytics logs handler", err: err}
	}
	if nilHTTPHandler(handler) {
		return nil, runtimeStageError{
			stage: "initialize analytics logs handler",
			err:   errors.New("analytics logs factory returned nil handler"),
		}
	}
	return handler, nil
}

func loadAnalyticsLogsCursorKeyring(
	enabled bool,
	lookup func(string) (string, bool),
) (analyticslog.CursorKeyring, error) {
	if !enabled {
		return analyticslog.CursorKeyring{}, nil
	}
	if lookup == nil {
		return analyticslog.CursorKeyring{}, errors.New("analytics logs environment lookup is required")
	}
	active, ok := lookup("ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID")
	if !ok || !validAnalyticsLogsCursorKID(active) {
		return analyticslog.CursorKeyring{}, errors.New("ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID must be a valid key identifier")
	}
	raw, ok := lookup("ANALYTICS_LOGS_CURSOR_KEYS_JSON")
	if !ok || raw == "" || strings.TrimSpace(raw) != raw {
		return analyticslog.CursorKeyring{}, errors.New("ANALYTICS_LOGS_CURSOR_KEYS_JSON must be a non-empty JSON object")
	}
	encoded, err := decodeAnalyticsLogsCursorKeys(raw)
	if err != nil || len(encoded) == 0 || len(encoded) > 8 {
		return analyticslog.CursorKeyring{}, errors.New("ANALYTICS_LOGS_CURSOR_KEYS_JSON must be a non-empty JSON object with at most 8 keys")
	}
	keys := make(map[string][]byte, len(encoded))
	success := false
	defer func() {
		if !success {
			for kid, key := range keys {
				clear(key)
				delete(keys, kid)
			}
		}
	}()
	for kid, value := range encoded {
		if !validAnalyticsLogsCursorKID(kid) {
			return analyticslog.CursorKeyring{}, errors.New("ANALYTICS_LOGS_CURSOR_KEYS_JSON contains an invalid key identifier")
		}
		key, decodeErr := base64.StdEncoding.Strict().DecodeString(value)
		if decodeErr != nil || len(key) < 32 || len(key) > 64 || base64.StdEncoding.EncodeToString(key) != value {
			clear(key)
			return analyticslog.CursorKeyring{}, errors.New("ANALYTICS_LOGS_CURSOR_KEYS_JSON values must encode 32 to 64 bytes using canonical padded base64")
		}
		keys[kid] = key
	}
	if _, ok := keys[active]; !ok {
		return analyticslog.CursorKeyring{}, errors.New("ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID must exist in ANALYTICS_LOGS_CURSOR_KEYS_JSON")
	}
	success = true
	return analyticslog.CursorKeyring{ActiveKID: active, Keys: keys}, nil
}

func decodeAnalyticsLogsCursorKeys(raw string) (map[string]string, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("invalid analytics logs cursor key object")
	}
	keys := make(map[string]string)
	for decoder.More() {
		keyToken, err := decoder.Token()
		kid, ok := keyToken.(string)
		if err != nil || !ok {
			return nil, errors.New("invalid analytics logs cursor key identifier")
		}
		if _, duplicate := keys[kid]; duplicate {
			return nil, errors.New("duplicate analytics logs cursor key identifier")
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("invalid analytics logs cursor key value")
		}
		keys[kid] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, errors.New("invalid analytics logs cursor key object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid analytics logs cursor key object")
	}
	return keys, nil
}

func validAnalyticsLogsCursorKID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index, character := range value {
		alphaNumeric := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9'
		if !(alphaNumeric || character == '.' || character == '_' || character == '-') || index == 0 && !alphaNumeric {
			return false
		}
	}
	return true
}

func clearAnalyticsLogsCursorKeyring(keyring *analyticslog.CursorKeyring) {
	if keyring == nil {
		return
	}
	for kid, key := range keyring.Keys {
		clear(key)
		delete(keyring.Keys, kid)
	}
	*keyring = analyticslog.CursorKeyring{}
}

func nilHTTPHandler(handler http.Handler) bool {
	if handler == nil {
		return true
	}
	value := reflect.ValueOf(handler)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
