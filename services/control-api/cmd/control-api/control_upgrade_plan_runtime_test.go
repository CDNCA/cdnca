package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgradehttp"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const ops06PlanToken = "ops06-internal-token-32-bytes-long-value"

func TestOPS06ControlUpgradePlanMigrationChecksumsMatchEmbeddedSQL(t *testing.T) {
	database := &ops06PlanRuntimeDatabase{schemaReady: true}
	if err := requireControlUpgradePlanSchema(t.Context(), database); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		direction string
		column    string
	}{
		{direction: "up", column: "checksum_sha256"},
		{direction: "down", column: "down_checksum_sha256"},
	} {
		t.Run(test.direction, func(t *testing.T) {
			name := "154_control_upgrade_systemd_repository." + test.direction + ".sql"
			encoded, err := controlmigrations.FS.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			expected := fmt.Sprintf("%s='%x'", test.column, sha256.Sum256(encoded))
			if !strings.Contains(database.schemaSQL, expected) {
				t.Fatalf("schema gate does not require the embedded %s digest: want %s", name, expected)
			}
		})
	}
}

func TestOPS06ControlUpgradePlanRuntimeConfigFailsClosed(t *testing.T) {
	installationID := uuid.NewString()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(root, "internal-token")
	if err := os.WriteFile(tokenFile, []byte(ops06PlanToken), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := loadControlUpgradePlanRuntimeConfigFromEnv([]string{
		controlUpgradePlanEnabledEnv + "=true",
		controlUpgradePlanTokenFileEnv + "=" + tokenFile,
	}, installationID)
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || config.InstallationID != installationID ||
		config.Operation != controlplaneupgrade.SystemdControlUpgradeOperation || config.TokenFile != tokenFile ||
		config.MaxBodyBytes != 256<<10 {
		t.Fatalf("runtime config = %+v", config)
	}

	for _, test := range []struct {
		name         string
		environment  []string
		installation string
	}{
		{name: "non canonical boolean", environment: []string{controlUpgradePlanEnabledEnv + "=TRUE", controlUpgradePlanTokenFileEnv + "=" + tokenFile}, installation: installationID},
		{name: "unknown namespaced value", environment: []string{controlUpgradePlanEnabledEnv + "=true", "CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_EXTRA=x", controlUpgradePlanTokenFileEnv + "=" + tokenFile}, installation: installationID},
		{name: "duplicate enable", environment: []string{controlUpgradePlanEnabledEnv + "=true", controlUpgradePlanEnabledEnv + "=true", controlUpgradePlanTokenFileEnv + "=" + tokenFile}, installation: installationID},
		{name: "malformed then valid token file", environment: []string{controlUpgradePlanEnabledEnv + "=true", controlUpgradePlanTokenFileEnv, controlUpgradePlanTokenFileEnv + "=" + tokenFile}, installation: installationID},
		{name: "missing token file", environment: []string{controlUpgradePlanEnabledEnv + "=true"}, installation: installationID},
		{name: "relative token file", environment: []string{controlUpgradePlanEnabledEnv + "=true", controlUpgradePlanTokenFileEnv + "=token"}, installation: installationID},
		{name: "wrong installation", environment: []string{controlUpgradePlanEnabledEnv + "=true", controlUpgradePlanTokenFileEnv + "=" + tokenFile}, installation: strings.ToUpper(installationID)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := loadControlUpgradePlanRuntimeConfigFromEnv(test.environment, test.installation); err == nil {
				t.Fatal("invalid production configuration was accepted")
			}
		})
	}
	disabled, err := loadControlUpgradePlanRuntimeConfigFromEnv([]string{controlUpgradePlanEnabledEnv + "=false"}, "")
	if err != nil || disabled.Enabled {
		t.Fatalf("disabled config = (%+v, %v)", disabled, err)
	}
}

func TestOPS06ControlUpgradePlanRuntimeServesOnlyDurableApprovedIdentity(t *testing.T) {
	installationID := uuid.NewString()
	tokenFile := ops06PlanTokenFile(t, 0o600)
	database := &ops06PlanRuntimeDatabase{schemaReady: true}
	ops06SeedPlan(t, database, installationID, []byte(`{"signed":"approved-plan"}`))
	runtime, err := openControlUpgradePlanRuntime(t.Context(), controlUpgradePlanRuntimeConfig{
		Enabled: true, InstallationID: installationID,
		Operation: controlplaneupgrade.SystemdControlUpgradeOperation,
		TokenFile: tokenFile, MaxBodyBytes: 256 << 10,
	}, database)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(database.schemaSQL, "to_regclass('control_upgrade_systemd_repository_154')") ||
		!strings.Contains(database.schemaSQL, "migration_id='154_control_upgrade_systemd_repository'") ||
		!strings.Contains(database.schemaSQL, controlUpgradePlanMigrationUpSHA256) ||
		!strings.Contains(database.schemaSQL, controlUpgradePlanMigrationDownSHA256) {
		t.Fatalf("schema preflight SQL = %q", database.schemaSQL)
	}
	factory := runtime.HandlerFactory()
	handler, err := factory()
	if err != nil || handler == nil {
		t.Fatalf("HandlerFactory() = (%v, %v)", handler, err)
	}
	request := httptest.NewRequest(http.MethodGet, controlplaneupgradehttp.SystemdPlanSourcePath, nil)
	request.Header.Set("Authorization", "Bearer "+ops06PlanToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != `{"signed":"approved-plan"}` ||
		response.Header().Get(controlplaneupgradehttp.SystemdPlanInstallationHeader) != installationID ||
		response.Header().Get(controlplaneupgradehttp.SystemdPlanOperationHeader) !=
			controlplaneupgrade.SystemdControlUpgradeOperation || database.reads != 1 {
		t.Fatalf("approved response status=%d headers=%v body=%q reads=%d",
			response.Code, response.Header(), response.Body.String(), database.reads)
	}
	unauthorized := httptest.NewRequest(http.MethodGet, controlplaneupgradehttp.SystemdPlanSourcePath, nil)
	unauthorized.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 40))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, unauthorized)
	if response.Code != http.StatusUnauthorized || database.reads != 1 {
		t.Fatalf("unauthorized status=%d reads=%d", response.Code, database.reads)
	}

	database.planID = uuid.NewString()
	request = httptest.NewRequest(http.MethodGet, controlplaneupgradehttp.SystemdPlanSourcePath, nil)
	request.Header.Set("Authorization", "Bearer "+ops06PlanToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "approved-plan") {
		t.Fatalf("cross-bound publication status=%d body=%q", response.Code, response.Body.String())
	}
	database.schemaReady = false
	if err := runtime.Ready(); err == nil {
		t.Fatal("runtime remained ready after the authoritative schema disappeared")
	}
	database.schemaReady = true
	if bytes.Equal(runtime.tokenDigest[:], make([]byte, sha256.Size)) || len(runtime.relayToken) == 0 {
		t.Fatal("runtime did not retain bounded authentication state")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if !bytes.Equal(runtime.tokenDigest[:], make([]byte, sha256.Size)) || runtime.relayToken != nil {
		t.Fatal("Close() did not zero authentication state")
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed handler status=%d", response.Code)
	}
	if _, err := factory(); err == nil {
		t.Fatal("closed runtime returned a handler")
	}
}

func TestOPS06ControlUpgradePlanRuntimeRejectsUnsafeSecretSchemaAndOversizePlan(t *testing.T) {
	installationID := uuid.NewString()
	config := controlUpgradePlanRuntimeConfig{Enabled: true, InstallationID: installationID,
		Operation: controlplaneupgrade.SystemdControlUpgradeOperation, MaxBodyBytes: 256 << 10}
	database := &ops06PlanRuntimeDatabase{schemaReady: false}
	config.TokenFile = ops06PlanTokenFile(t, 0o600)
	if _, err := openControlUpgradePlanRuntime(t.Context(), config, database); err == nil {
		t.Fatal("missing migration schema was accepted")
	}
	database.schemaReady = true
	unsafe := ops06PlanTokenFile(t, 0o644)
	config.TokenFile = unsafe
	if _, err := openControlUpgradePlanRuntime(t.Context(), config, database); err == nil {
		t.Fatal("group-readable token was accepted")
	}

	config.TokenFile = ops06PlanTokenFile(t, 0o600)
	ops06SeedPlan(t, database, installationID, bytes.Repeat([]byte("x"), (256<<10)+1))
	runtime, err := openControlUpgradePlanRuntime(t.Context(), config, database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	handler, err := runtime.HandlerFactory()()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, controlplaneupgradehttp.SystemdPlanSourcePath, nil)
	request.Header.Set("Authorization", "Bearer "+ops06PlanToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Body.Len() > 128 {
		t.Fatalf("oversize plan status=%d body=%q", response.Code, response.Body.String())
	}
}

func ops06PlanTokenFile(t *testing.T, mode os.FileMode) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "internal-token")
	if err := os.WriteFile(path, []byte(ops06PlanToken+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func ops06SeedPlan(t *testing.T, database *ops06PlanRuntimeDatabase, installationID string, bundle []byte) {
	t.Helper()
	repository, err := controlplaneupgrade.NewPostgresSecretRepository(database, installationID,
		controlplaneupgrade.SystemdControlUpgradeOperation)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(bundle))
	document := controlplaneupgrade.SecretDocument{ResourceVersion: "0", Bundle: bundle, Data: map[string][]byte{},
		Publication: &controlplaneupgrade.PublicationReceipt{
			Schema: "cdnca.control-plane-upgrade-publication/v1", ReceiptID: uuid.NewString() + ":1",
			PlanID: uuid.NewString(), BundleSHA256: digest, PublicationRevision: 1, ExpectedRevision: 0,
			ChannelRevision: 1, ReleaseSequence: 2, InstallationID: installationID, Component: "control-api",
			CurrentVersion: "1.0.0", CurrentDigest: strings.Repeat("a", 64), TargetVersion: "1.1.0",
			TargetDigest: strings.Repeat("b", 64), RollbackVersion: "1.0.0", RollbackDigest: strings.Repeat("a", 64),
			ProtocolVersion: 1, IdempotencySHA256: strings.Repeat("c", 64), RequestID: uuid.NewString(),
			ActorUserID: uuid.New(), ActorScopeID: uuid.New(), PublishedAt: 1,
		}}
	if _, err := repository.CompareAndSwap(t.Context(), "0", document); err != nil {
		t.Fatal(err)
	}
}

type ops06PlanRuntimeDatabase struct {
	schemaReady    bool
	schemaSQL      string
	reads          int
	revision       int64
	planID         string
	publication    int64
	bundle         []byte
	bundleSHA256   []byte
	snapshot       []byte
	snapshotSHA256 []byte
}

func (database *ops06PlanRuntimeDatabase) QueryRow(_ context.Context, sql string, arguments ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "to_regclass('control_upgrade_systemd_repository_154')"):
		database.schemaSQL = sql
		return ops06PlanRuntimeRow(func(destinations ...any) error {
			*destinations[0].(*bool) = database.schemaReady
			return nil
		})
	case strings.Contains(sql, "WITH updated AS"):
		database.revision = arguments[3].(int64)
		database.planID = arguments[4].(string)
		database.publication = arguments[5].(int64)
		database.bundle = bytes.Clone(arguments[6].([]byte))
		database.bundleSHA256 = bytes.Clone(arguments[7].([]byte))
		database.snapshot = bytes.Clone(arguments[8].([]byte))
		database.snapshotSHA256 = bytes.Clone(arguments[9].([]byte))
		return ops06PlanRuntimeRow(func(destinations ...any) error {
			*destinations[0].(*int64) = database.revision
			return nil
		})
	case strings.Contains(sql, "SELECT revision,plan_id,publication_revision"):
		database.reads++
		if database.revision == 0 {
			return ops06PlanRuntimeRow(func(...any) error { return pgx.ErrNoRows })
		}
		return ops06PlanRuntimeRow(func(destinations ...any) error {
			*destinations[0].(*int64) = database.revision
			*destinations[1].(*string) = database.planID
			*destinations[2].(*int64) = database.publication
			*destinations[3].(*[]byte) = bytes.Clone(database.bundle)
			*destinations[4].(*[]byte) = bytes.Clone(database.bundleSHA256)
			*destinations[5].(*[]byte) = bytes.Clone(database.snapshot)
			*destinations[6].(*[]byte) = bytes.Clone(database.snapshotSHA256)
			return nil
		})
	default:
		return ops06PlanRuntimeRow(func(...any) error { return errors.New("unexpected query") })
	}
}

type ops06PlanRuntimeRow func(...any) error

func (row ops06PlanRuntimeRow) Scan(destinations ...any) error { return row(destinations...) }
