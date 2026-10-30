package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgradehttp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	controlUpgradePlanEnabledEnv   = "CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_ENABLED"
	controlUpgradePlanTokenFileEnv = "CONTROL_UPGRADE_INTERNAL_TOKEN_FILE"
	controlUpgradePlanMaxBodyBytes = int64(256 << 10)
	controlUpgradePlanReadyTimeout = 2 * time.Second

	controlUpgradePlanMigrationUpSHA256   = "b3925e3c4a28ad73a9487aae6356c39dddc11291064d2f691d4d76a58ad7278a"
	controlUpgradePlanMigrationDownSHA256 = "85c925f408b65ce15c79a4bab9fb81ad6d9e2e8fb0feeb99c612426cbd35070f"
)

type controlUpgradePlanRuntimeConfig struct {
	Enabled        bool
	InstallationID string
	Operation      string
	TokenFile      string
	MaxBodyBytes   int64
}

type controlUpgradePlanRuntimeDatabase interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type controlUpgradePlanRuntime struct {
	mu          sync.RWMutex
	database    controlUpgradePlanRuntimeDatabase
	handler     http.Handler
	tokenDigest [sha256.Size]byte
	relayToken  []byte
	closed      bool
}

func loadControlUpgradePlanRuntimeConfig(installationID string) (controlUpgradePlanRuntimeConfig, error) {
	return loadControlUpgradePlanRuntimeConfigFromEnv(os.Environ(), installationID)
}

func loadControlUpgradePlanRuntimeConfigFromEnv(environment []string,
	installationID string) (controlUpgradePlanRuntimeConfig, error) {
	values, err := runtimeEnvEntries(environment, "CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_", map[string]struct{}{
		controlUpgradePlanEnabledEnv: {},
	})
	if err != nil {
		return controlUpgradePlanRuntimeConfig{}, err
	}
	enabled, err := strictRuntimeBool(values, controlUpgradePlanEnabledEnv)
	if err != nil || !enabled {
		return controlUpgradePlanRuntimeConfig{}, err
	}
	tokenFile, found, valid, duplicate := "", false, false, false
	for _, entry := range environment {
		name, value, present := strings.Cut(entry, "=")
		if name != controlUpgradePlanTokenFileEnv {
			continue
		}
		if found {
			duplicate = true
		}
		found, valid, tokenFile = true, present, value
	}
	parsed, parseErr := uuid.Parse(installationID)
	if duplicate || !found || !valid || tokenFile == "" || !filepath.IsAbs(tokenFile) || filepath.Clean(tokenFile) != tokenFile ||
		parseErr != nil || parsed == uuid.Nil || parsed.String() != installationID {
		return controlUpgradePlanRuntimeConfig{}, errors.New("control upgrade systemd plan source configuration is invalid")
	}
	return controlUpgradePlanRuntimeConfig{Enabled: true, InstallationID: installationID,
		Operation: controlplaneupgrade.SystemdControlUpgradeOperation, TokenFile: tokenFile,
		MaxBodyBytes: controlUpgradePlanMaxBodyBytes}, nil
}

func openControlUpgradePlanRuntime(ctx context.Context, config controlUpgradePlanRuntimeConfig,
	database controlUpgradePlanRuntimeDatabase) (*controlUpgradePlanRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	parsed, err := uuid.Parse(config.InstallationID)
	if ctx == nil || nilRuntimeDependency(database) || err != nil || parsed == uuid.Nil ||
		parsed.String() != config.InstallationID || config.Operation != controlplaneupgrade.SystemdControlUpgradeOperation ||
		config.TokenFile == "" || !filepath.IsAbs(config.TokenFile) || filepath.Clean(config.TokenFile) != config.TokenFile ||
		config.MaxBodyBytes != controlUpgradePlanMaxBodyBytes {
		return nil, errors.New("control upgrade systemd plan source configuration is incomplete")
	}
	if err := requireControlUpgradePlanSchema(ctx, database); err != nil {
		return nil, err
	}
	encoded, err := controlUpgradeReadFile(config.TokenFile, 258, true)
	if err != nil {
		return nil, errors.New("control upgrade systemd plan source token is unavailable")
	}
	defer clear(encoded)
	token, err := controlUpgradePlanToken(encoded)
	if err != nil {
		return nil, err
	}
	tokenDigest := sha256.Sum256(token)
	relayBytes := make([]byte, 32)
	if _, err := rand.Read(relayBytes); err != nil {
		clear(relayBytes)
		return nil, errors.New("control upgrade systemd plan source authentication is unavailable")
	}
	relayToken := []byte(base64.RawURLEncoding.EncodeToString(relayBytes))
	clear(relayBytes)
	repository, err := controlplaneupgrade.NewPostgresSecretRepository(database, config.InstallationID, config.Operation)
	if err != nil {
		clear(relayToken)
		return nil, errors.New("initialize control upgrade systemd plan repository")
	}
	handler, err := controlplaneupgradehttp.NewSystemdPlanSourceHandler(repository, config.InstallationID,
		config.Operation, relayToken, config.MaxBodyBytes)
	if err != nil {
		clear(relayToken)
		return nil, errors.New("initialize control upgrade systemd plan handler")
	}
	return &controlUpgradePlanRuntime{database: database, handler: handler,
		tokenDigest: tokenDigest, relayToken: relayToken}, nil
}

func (runtime *controlUpgradePlanRuntime) HandlerFactory() func() (http.Handler, error) {
	return func() (http.Handler, error) {
		if runtime == nil {
			return nil, errors.New("control upgrade systemd plan source is unavailable")
		}
		runtime.mu.RLock()
		defer runtime.mu.RUnlock()
		if runtime.closed || runtime.handler == nil {
			return nil, errors.New("control upgrade systemd plan source is unavailable")
		}
		return runtime, nil
	}
}

func (runtime *controlUpgradePlanRuntime) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if runtime == nil {
		http.Error(response, "plan unavailable", http.StatusServiceUnavailable)
		return
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if runtime.closed || runtime.handler == nil || request == nil {
		http.Error(response, "plan unavailable", http.StatusServiceUnavailable)
		return
	}
	forward := request
	if controlUpgradePlanAuthorized(request, runtime.tokenDigest) {
		forward = request.Clone(request.Context())
		forward.Header = request.Header.Clone()
		forward.Header.Set("Authorization", "Bearer "+string(runtime.relayToken))
	}
	runtime.handler.ServeHTTP(response, forward)
}

func (runtime *controlUpgradePlanRuntime) Ready() error {
	if runtime == nil {
		return errors.New("control upgrade systemd plan source readiness is unavailable")
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if runtime.closed || runtime.database == nil {
		return errors.New("control upgrade systemd plan source readiness is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlUpgradePlanReadyTimeout)
	defer cancel()
	return requireControlUpgradePlanSchema(ctx, runtime.database)
}

func (runtime *controlUpgradePlanRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closed {
		return nil
	}
	clear(runtime.tokenDigest[:])
	clear(runtime.relayToken)
	runtime.relayToken = nil
	runtime.handler = nil
	runtime.database = nil
	runtime.closed = true
	return nil
}

func requireControlUpgradePlanSchema(ctx context.Context, database controlUpgradePlanRuntimeDatabase) error {
	if ctx == nil || nilRuntimeDependency(database) {
		return errors.New("control upgrade systemd plan source schema is unavailable")
	}
	var ready bool
	err := database.QueryRow(ctx, `SELECT
	to_regclass('control_upgrade_systemd_repository_154') IS NOT NULL AND
	to_regprocedure('guard_control_upgrade_systemd_repository_154()') IS NOT NULL AND
	to_regprocedure('prevent_control_upgrade_systemd_repository_truncate_154()') IS NOT NULL AND
	has_table_privilege(current_user,'control_upgrade_systemd_repository_154','SELECT') AND
	has_table_privilege(current_user,'control_upgrade_systemd_repository_154','INSERT') AND
	has_table_privilege(current_user,'control_upgrade_systemd_repository_154','UPDATE') AND EXISTS (
		SELECT 1 FROM schema_migrations WHERE version=154 AND
		migration_id='154_control_upgrade_systemd_repository' AND
		checksum_sha256='`+controlUpgradePlanMigrationUpSHA256+`' AND
		down_checksum_sha256='`+controlUpgradePlanMigrationDownSHA256+`' AND
		integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
	)`).Scan(&ready)
	if err != nil || !ready {
		return errors.New("control upgrade systemd plan source schema is unavailable")
	}
	return nil
}

func controlUpgradePlanToken(encoded []byte) ([]byte, error) {
	token := encoded
	if len(token) > 0 && token[len(token)-1] == '\n' {
		token = token[:len(token)-1]
		if len(token) > 0 && token[len(token)-1] == '\r' {
			token = token[:len(token)-1]
		}
	}
	if len(token) < 32 || len(token) > 256 || !bytes.Equal(bytes.TrimSpace(token), token) {
		return nil, errors.New("control upgrade systemd plan source token is invalid")
	}
	for index, character := range token {
		valid := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("-._~+/", rune(character))
		if valid {
			continue
		}
		if character != '=' || index == 0 || !bytes.Equal(bytes.Trim(token[index:], "="), nil) {
			return nil, errors.New("control upgrade systemd plan source token is invalid")
		}
		break
	}
	return token, nil
}

func controlUpgradePlanAuthorized(request *http.Request, expected [sha256.Size]byte) bool {
	if request == nil {
		return false
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return false
	}
	scheme, raw, found := strings.Cut(values[0], " ")
	if !found || scheme != "Bearer" || strings.TrimSpace(raw) != raw {
		return false
	}
	provided := []byte(raw)
	digest := sha256.Sum256(provided)
	clear(provided)
	return subtle.ConstantTimeCompare(digest[:], expected[:]) == 1
}
