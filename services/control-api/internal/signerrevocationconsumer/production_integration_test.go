//go:build integration

package signerrevocationconsumer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/signercheckpoint"
	"github.com/cdnca/cdnca/services/control-api/internal/signerrevocation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestProductionOpenFailClosedAndRestoresRevisionAboveOne(t *testing.T) {
	pool := productionIntegrationPool(t, true, 4)
	fixture := newProductionIntegrationFixture(t)

	// An empty LKG must not block startup: Open succeeds with no installed
	// snapshot, so the revocation gate allows until a checkpoint is accepted.
	empty, err := OpenProductionRuntime(t.Context(), fixture.config, ProductionDependencies{
		Pool: pool, EntitlementTrust: fixture.entitlementTrust, Now: fixture.now,
	})
	if err != nil || empty == nil {
		t.Fatalf("empty database Open = (%#v, %v)", empty, err)
	}
	if _, found := empty.runtime.Snapshot(); found {
		t.Fatal("empty database installed a snapshot")
	}
	if err := empty.RevocationGate(nil).CheckSigner("lease", "any-key"); err != nil {
		t.Fatalf("empty LKG gate = %v", err)
	}
	if err := empty.Close(); err != nil {
		t.Fatal(err)
	}

	encoded := productionCheckpointRevision(t, fixture.encoded, 4, 3, strings.Repeat("A", 43))
	store := productionIntegrationStore(t, pool, fixture)
	if accepted, err := store.AcceptV2(t.Context(), uuid.New(), encoded, productionIntegrationETag(encoded), fixture.now()); err != nil || accepted.Checkpoint.Revision != 4 {
		t.Fatalf("seed revision 4 = (%#v, %v)", accepted, err)
	}
	opened, err := OpenProductionRuntime(t.Context(), fixture.config, ProductionDependencies{
		Pool: pool, EntitlementTrust: fixture.entitlementTrust, Now: fixture.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, found := opened.runtime.Snapshot()
	if !found || snapshot.Revision != 4 {
		t.Fatalf("restored runtime snapshot = (%#v, %t)", snapshot, found)
	}
	if err := opened.Ready(); !errors.Is(err, ErrProductionNotReady) {
		t.Fatalf("Ready before Run = %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	assertProductionPrivateKeyCleared(t, opened)

	if _, err := pool.Exec(t.Context(), `ALTER TABLE control_signer_checkpoint_snapshots
		DISABLE TRIGGER control_signer_checkpoint_snapshots_immutable_077`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE control_signer_checkpoint_snapshots
		SET signed_checkpoint=set_byte(signed_checkpoint,0,get_byte(signed_checkpoint,0)#1) WHERE revision=4`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE control_signer_checkpoint_snapshots
		ENABLE ALWAYS TRIGGER control_signer_checkpoint_snapshots_immutable_077`); err != nil {
		t.Fatal(err)
	}
	if runtime, err := OpenProductionRuntime(t.Context(), fixture.config, ProductionDependencies{
		Pool: pool, EntitlementTrust: fixture.entitlementTrust, Now: fixture.now,
	}); !errors.Is(err, signerrevocation.ErrInvalidStoredState) || runtime != nil {
		t.Fatalf("tampered database Open = (%#v, %v)", runtime, err)
	}
}

func TestProductionOpenFailsWhenMigration077IsMissing(t *testing.T) {
	pool := productionIntegrationPool(t, true, 4)
	fixture := newProductionIntegrationFixture(t)
	if _, err := pool.Exec(t.Context(), `DROP TABLE control_signer_checkpoint_audit,
		control_signer_checkpoint_manifests, control_signer_checkpoint_snapshots CASCADE`); err != nil {
		t.Fatal(err)
	}
	if runtime, err := OpenProductionRuntime(t.Context(), fixture.config, ProductionDependencies{
		Pool: pool, EntitlementTrust: fixture.entitlementTrust, Now: fixture.now,
	}); err == nil || runtime != nil {
		t.Fatalf("missing migration 077 Open = (%#v, %v)", runtime, err)
	}
}

func TestProductionOpenStartupTimeoutCancelsPostgres(t *testing.T) {
	pool := productionIntegrationPool(t, true, 1)
	fixture := newProductionIntegrationFixture(t)
	fixture.config.StartupTimeout = time.Second
	connection, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	started := time.Now()
	opened, err := OpenProductionRuntime(t.Context(), fixture.config, ProductionDependencies{
		Pool: pool, EntitlementTrust: fixture.entitlementTrust, Now: fixture.now,
	})
	if !errors.Is(err, context.DeadlineExceeded) || opened != nil {
		t.Fatalf("blocked startup Open = (%#v, %v)", opened, err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("startup timeout took %s", elapsed)
	}
}

func TestProductionRefreshPersistsBeforeInstallAndRestartUsesLKG(t *testing.T) {
	pool := productionIntegrationPool(t, true, 4)
	fixture := newProductionIntegrationFixture(t)
	store := productionIntegrationStore(t, pool, fixture)
	first, err := store.AcceptV2(t.Context(), uuid.New(), fixture.encoded,
		productionIntegrationETag(fixture.encoded), fixture.now())
	if err != nil {
		t.Fatal(err)
	}
	secondEncoded := productionCheckpointRevision(t, fixture.encoded, 2, 1, first.Checkpoint.CheckpointSHA256)
	secondETag := productionIntegrationETag(secondEncoded)
	requests := make(chan uint64, 4)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		known := request.Header.Get("X-CDNCA-Known-Checkpoint-Revision")
		switch known {
		case "1":
			requests <- 1
			writer.Header().Set("Content-Type", CheckpointMediaType)
			writer.Header().Set("ETag", secondETag)
			_, _ = writer.Write(secondEncoded)
		case "2":
			requests <- 2
			writer.Header().Set("ETag", secondETag)
			writer.WriteHeader(http.StatusNotModified)
		default:
			requests <- 0
			writer.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	fixture.config.BaseURL = server.URL
	fixture.config.TLSConfig = productionIntegrationTLS(server)

	opened, err := OpenProductionRuntime(t.Context(), fixture.config, ProductionDependencies{
		Pool: pool, EntitlementTrust: fixture.entitlementTrust, Now: fixture.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- opened.Run(context.Background()) }()
	if got := <-requests; got != 1 {
		t.Fatalf("first request known revision = %d", got)
	}
	waitForProduction(t, func() bool {
		snapshot, found := opened.runtime.Snapshot()
		return found && snapshot.Revision == 2
	})
	var durableRevision uint64
	if err := pool.QueryRow(t.Context(), `SELECT max(revision) FROM control_signer_checkpoint_snapshots`).Scan(&durableRevision); err != nil || durableRevision != 2 {
		t.Fatalf("durable revision = %d, error=%v", durableRevision, err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenProductionRuntime(t.Context(), fixture.config, ProductionDependencies{
		Pool: pool, EntitlementTrust: fixture.entitlementTrust, Now: fixture.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	restored, found := restarted.runtime.Snapshot()
	if !found || restored.Revision != 2 {
		t.Fatalf("restart restored = (%#v, %t)", restored, found)
	}
	restartDone := make(chan error, 1)
	go func() { restartDone <- restarted.Run(context.Background()) }()
	if got := <-requests; got != 2 {
		t.Fatalf("restart request known revision = %d", got)
	}
	waitForProduction(t, func() bool {
		var count int
		err := pool.QueryRow(t.Context(), `SELECT count(*) FROM control_signer_checkpoint_audit
			WHERE event_type='outage' AND reason_code=$1`, ReasonNotModified).Scan(&count)
		return err == nil && count == 1
	})
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-restartDone; err != nil {
		t.Fatal(err)
	}
}

func TestProductionCloseCancelsRealPostgresWaitWithoutClosingPool(t *testing.T) {
	pool := productionIntegrationPool(t, true, 2)
	fixture := newProductionIntegrationFixture(t)
	store := productionIntegrationStore(t, pool, fixture)
	if _, err := store.AcceptV2(t.Context(), uuid.New(), fixture.encoded,
		productionIntegrationETag(fixture.encoded), fixture.now()); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenProductionRuntime(t.Context(), fixture.config, ProductionDependencies{
		Pool: pool, EntitlementTrust: fixture.entitlementTrust, Now: fixture.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	transaction, err := blocker.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback(context.Background())
	if _, err := transaction.Exec(t.Context(), `LOCK TABLE control_signer_checkpoint_snapshots IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- opened.Run(context.Background()) }()
	waitForProduction(t, func() bool { return pool.Stat().AcquiredConns() == 2 })
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run after PostgreSQL cancellation = %v", err)
	}
	if err := transaction.Rollback(t.Context()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}
	if err := pool.Ping(t.Context()); err != nil {
		t.Fatalf("Close closed the shared pool: %v", err)
	}
}

type productionIntegrationFixture struct {
	config           Config
	entitlementTrust *entitlementguard.TrustStore
	encoded          []byte
	now              func() time.Time
}

func newProductionIntegrationFixture(t *testing.T) productionIntegrationFixture {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	encoded, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../tests/contracts/signer-revocation-checkpoint-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Signed json.RawMessage `json:"signed"`
	}
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	var signed signercheckpoint.SignedCheckpoint
	if err := json.Unmarshal(fixture.Signed, &signed); err != nil {
		t.Fatal(err)
	}
	var keyset struct {
		Keys []struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(signed.Checkpoint.Keyset, &keyset); err != nil || len(keyset.Keys) == 0 {
		t.Fatalf("decode keyset pins: %v", err)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(keyset.Keys[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: keyset.Keys[0].KeyID, PublicKey: publicKey,
	}})
	if err != nil {
		t.Fatal(err)
	}
	rootSeed := sha256.Sum256([]byte("cdnca-checkpoint-golden-offline-root"))
	rootPrivate := ed25519.NewKeyFromSeed(rootSeed[:])
	_, installationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(installationPrivate)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(t.TempDir(), "installation-private-key.pem")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	fixedNow := time.Date(2026, 7, 23, 1, 10, 0, 123456000, time.UTC)
	return productionIntegrationFixture{
		config: Config{
			Enabled: true, BaseURL: "https://license.example.test", InstallationID: uuid.New(),
			InstallationPrivateKeyFile: privatePath, RefreshInterval: time.Hour, RequestTimeout: time.Second,
			StartupTimeout: time.Second, ShutdownTimeout: time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			OfflineRootKeyID: "offline-root", OfflineRootGeneration: 7,
			OfflineRootPublicKey: rootPrivate.Public().(ed25519.PublicKey),
		},
		entitlementTrust: trust,
		encoded:          fixture.Signed,
		now:              func() time.Time { return fixedNow },
	}
}

func productionIntegrationStore(t *testing.T, pool *pgxpool.Pool,
	fixture productionIntegrationFixture) *signerrevocation.CheckpointStore {
	t.Helper()
	trust, err := NewDeploymentTrust(fixture.entitlementTrust, fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	return signerrevocation.NewCheckpointStore(pool, trust, fixture.now)
}

func productionCheckpointRevision(t *testing.T, encoded []byte, revision, previousRevision uint64,
	previousDigest string) []byte {
	t.Helper()
	var signed signercheckpoint.SignedCheckpoint
	if err := json.Unmarshal(encoded, &signed); err != nil {
		t.Fatal(err)
	}
	signed.Checkpoint.Revision = revision
	signed.Checkpoint.PreviousRevision = &previousRevision
	signed.Checkpoint.PreviousCheckpointSHA256 = &previousDigest
	canonical, err := signercheckpoint.CanonicalCheckpoint(signed.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	signed.Envelope.CheckpointSHA256 = base64.RawURLEncoding.EncodeToString(digest[:])
	envelope, err := signercheckpoint.CanonicalEnvelope(signed.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("cdnca-checkpoint-golden-offline-root"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	signed.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, envelope))
	result, err := signercheckpoint.Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func productionIntegrationETag(encoded []byte) string {
	digest := sha256.Sum256(encoded)
	return `"` + base64.RawURLEncoding.EncodeToString(digest[:]) + `"`
}

func productionIntegrationTLS(server *httptest.Server) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
}

func productionIntegrationPool(t *testing.T, migrate bool, maxConnections int32) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	adminConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	adminConfig.MaxConns = 2
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	schema := "signer_revocation_consumer_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^signer_revocation_consumer_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema name %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.MaxConns = maxConnections
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	if migrate {
		if err := database.Migrate(ctx, pool, "up"); err != nil {
			pool.Close()
			_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
			admin.Close()
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop signer revocation consumer schema: %v", err)
		}
		admin.Close()
	})
	return pool
}
