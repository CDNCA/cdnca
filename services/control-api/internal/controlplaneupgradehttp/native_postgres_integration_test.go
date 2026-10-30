//go:build integration

package controlplaneupgradehttp

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNativePostgresPublicationConcurrencyReplayIsolationAndRestart(t *testing.T) {
	handler, _, request, status := nativeFixture(t)
	pool := nativePostgresDatabase(t)
	if _, err := pool.Exec(t.Context(), `INSERT INTO control_installation_entitlement(installation_id) VALUES($1)`, handler.config.InstallationID); err != nil {
		t.Fatal(err)
	}
	repository, err := controlplaneupgrade.NewPostgresSecretRepository(pool, handler.config.InstallationID,
		controlplaneupgrade.SystemdControlUpgradeOperation)
	if err != nil {
		t.Fatal(err)
	}
	handler.config.Repository = repository
	const workers = 8
	receipts := make(chan controlplaneupgrade.PublicationReceipt, workers)
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			receipt, err := handler.Publish(t.Context(), request)
			receipts <- receipt
			errors <- err
		}()
	}
	wait.Wait()
	close(receipts)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent publication: %v", err)
		}
	}
	created := 0
	for receipt := range receipts {
		if receipt.PublicationRevision != 1 || receipt.BundleSHA256 != nativeDigest(request.Bundle) {
			t.Fatalf("concurrent receipt=%+v", receipt)
		}
		if !receipt.Replayed {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("created=%d; wanted exactly one CAS write", created)
	}
	document, err := repository.Read(t.Context())
	if err != nil || document.ResourceVersion != "1" || !bytes.Equal(document.Bundle, request.Bundle) || document.Publication == nil {
		t.Fatalf("durable document revision=%q err=%v", document.ResourceVersion, err)
	}
	status.Ready, status.Busy, status.Phase = false, true, "draining"
	status.CurrentVersion = "1.5.0"
	if receipt, err := handler.Publish(t.Context(), request); err != nil || !receipt.Replayed || receipt.PublicationRevision != 1 {
		t.Fatalf("busy exact replay=%+v err=%v", receipt, err)
	}
	other, err := controlplaneupgrade.NewPostgresSecretRepository(pool, uuid.NewString(), controlplaneupgrade.SystemdControlUpgradeOperation)
	if err != nil {
		t.Fatal(err)
	}
	if hidden, err := other.Read(t.Context()); err != nil || hidden.Publication != nil || len(hidden.Bundle) != 0 || hidden.ResourceVersion != "0" {
		t.Fatalf("installation isolation failed: err=%v", err)
	}
	restarted, err := NewNative(handler.config)
	if err != nil {
		t.Fatal(err)
	}
	// This verifies PostgreSQL publication projection, not root /proc liveness.
	restarted.readStatus = handler.readStatus
	restarted.readState = handler.readState
	response := httptest.NewRecorder()
	restarted.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, nativePlanPath, nil))
	var projected NativePlanStatus
	decodeBody(t, response, &projected)
	if response.Code != http.StatusOK || projected.Publication == nil || projected.PublicationRevision != 1 ||
		projected.Publication.ReceiptID != document.Publication.ReceiptID || projected.Runtime.Ready || projected.Execution.State != "unavailable" {
		t.Fatalf("restart projection status=%d body=%s", response.Code, response.Body.String())
	}
	var revision, count int
	if err := pool.QueryRow(t.Context(), `SELECT max(revision),count(*) FROM control_upgrade_systemd_repository_154`).Scan(&revision, &count); err != nil || revision != 1 || count != 1 {
		t.Fatalf("rows=%d revision=%d err=%v", count, revision, err)
	}
}

func nativePostgresDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "native_upgrade_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated native test schema: %v", err)
		}
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}
