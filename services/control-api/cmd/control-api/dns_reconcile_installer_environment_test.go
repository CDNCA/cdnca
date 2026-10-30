package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The native installer writes DNS_RECONCILE_* and CNAME_ALLOCATION_* into
// control.env. Load exactly those lines through the production loaders so the
// installer and the runtime cannot drift apart.
func TestNativeInstallerDNSReconcileEnvironmentLoads(t *testing.T) {
	environment := installerDNSReconcileEnvironment(t)
	config, err := loadDNSReconcileRuntimeConfigFromEnv(mapAccountRecoveryEnv(environment))
	if err != nil {
		t.Fatalf("installer DNS reconcile environment rejected: %v", err)
	}
	if !config.Enabled || config.WorkloadMTLS != nil || config.Checker != nil ||
		len(config.PropagationPublic) < 3 || config.PropagationPublicQuorum != len(config.PropagationPublic)-1 {
		t.Fatalf("installer DNS reconcile runtime = %+v", config)
	}
	for _, name := range []string{"CNAME_ALLOCATION_HMAC_KEY_ID", "CNAME_ALLOCATION_HMAC_KEY"} {
		t.Setenv(name, environment[name])
	}
	if _, err := loadCNAMEAllocationKeyring(); err != nil {
		t.Fatalf("installer CNAME allocation key rejected: %v", err)
	}
}

func installerDNSReconcileEnvironment(t *testing.T) map[string]string {
	t.Helper()
	script, err := os.ReadFile("../../../../scripts/install-control.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	start := strings.Index(text, "\nwrite_environment() {\n")
	if start < 0 {
		t.Fatal("installer write_environment is missing")
	}
	block := text[start:]
	block = block[:strings.Index(block, "\n}\n")]
	// Same length/alphabet as `openssl rand -base64 32`.
	replacer := strings.NewReplacer("${CNAME_ALLOCATION_HMAC_KEY_BASE64}", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	environment := map[string]string{}
	for _, line := range strings.Split(block, "\n") {
		if !strings.HasPrefix(line, "DNS_RECONCILE_") && !strings.HasPrefix(line, "CNAME_ALLOCATION_") {
			continue
		}
		resolved := replacer.Replace(line)
		if strings.Contains(resolved, "${") {
			t.Fatalf("installer DNS setting has an unbound placeholder: %s", line)
		}
		name, value, _ := strings.Cut(resolved, "=")
		if _, duplicate := environment[name]; duplicate {
			t.Fatalf("installer DNS setting %s is written twice", name)
		}
		environment[name] = value
	}
	return environment
}

// The native configuration opens the full production runtime (propagation,
// reconcile worker, CNAME worker, tenant handler) against migrated PG with no
// workload mTLS listener, and reports ready.
func TestNativeInstallerDNSReconcileRuntimeOpensAgainstMigratedDatabase(t *testing.T) {
	environment := installerDNSReconcileEnvironment(t)
	for _, name := range []string{"CNAME_ALLOCATION_HMAC_KEY_ID", "CNAME_ALLOCATION_HMAC_KEY"} {
		t.Setenv(name, environment[name])
	}
	pool := newDNSReconcilePublicSchemaTestPool(t)
	config, err := loadDNSReconcileRuntimeConfigFromEnv(mapAccountRecoveryEnv(environment))
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager(strings.Repeat("d", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("dns-native", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "native", PublicKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)).Public().(ed25519.PublicKey),
	}})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := openDNSReconcileProductionRuntime(t.Context(), config, pool, identityService, cipher, trust)
	if err != nil {
		t.Fatalf("native DNS reconcile runtime did not open: %v", err)
	}
	defer runtime.Close()
	if runtime.workloadServer != nil || runtime.worker == nil || runtime.cnameWorker == nil || runtime.tenantHandler == nil {
		t.Fatalf("native runtime = %+v", runtime)
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("native runtime not ready: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	for name, run := range map[string]func(context.Context) error{
		"reconcile": runtime.worker.Run, "cname": runtime.cnameWorker.Run,
	} {
		if err := run(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s worker stopped on an empty migrated database: %v", name, err)
		}
	}
}

// verifyDNSPropagationSchema checks public.dns_provider_retry_states exactly as
// production does, so this test migrates a throwaway database's public schema.
func newDNSReconcilePublicSchemaTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	name := "dns_native_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := databasetest.CleanupContext()
		defer cancel()
		_, _ = admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		_ = admin.Close(cleanup)
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.Database, config.MaxConns = name, 4
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// Same public-schema preparation as install-control.sh prepare_database.
	if _, err := pool.Exec(ctx, "ALTER SCHEMA public OWNER TO CURRENT_USER"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "REVOKE ALL ON SCHEMA public FROM PUBLIC"); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}
