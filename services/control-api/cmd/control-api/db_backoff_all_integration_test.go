//go:build integration

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Runs a subset of control-api's background runtimes against PostgreSQL the
// way main.go does (runWithDBBackoff + a terminal error channel), kills every
// connection of the test database with pg_terminate_backend, waits 5 seconds
// and asserts that nothing was reported as terminal (the process would have
// exited) and that the runtimes work again.
//
// Needs TEST_DATABASE_URL and TEST_DATABASE_TEMPLATE (verify-int-batch.sh).
func TestBackgroundRuntimesSurvivePGTerminateBackendPostgreSQL(t *testing.T) {
	// pg_terminate_backend kills every connection of the database, so the test
	// needs its own clone (a shared schema database would break other tests).
	pool := databasetest.ClonedMigratedPool(t, func(config *pgxpool.Config) {
		config.ConnConfig.RuntimeParams["timezone"] = "UTC"
	})
	if pool == nil {
		t.Skip("TEST_DATABASE_TEMPLATE is not set: the test terminates every backend of its database")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// A worker whose Run returns on the first database error, like the
	// security activation worker and the entitlement revocation runtime.
	var polls atomic.Int64
	pollingWorker := func(ctx context.Context) error {
		for {
			var one int
			if err := pool.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
				return fmt.Errorf("poll: %w", err)
			}
			polls.Add(1)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}

	notificationRuntime := openNotificationRuntimeForDBBackoff(t, ctx, pool)
	announcementRuntime, err := openAnnouncementRuntime(ctx, pool, integrationAnnouncementRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	terminal := make(chan error, 8)
	var background sync.WaitGroup
	start := func(name string, run func(context.Context) error) {
		background.Add(1)
		go func() {
			defer background.Done()
			err := runWithDBBackoff(ctx, logger, name, 5*time.Minute, run)
			if ctx.Err() == nil {
				terminal <- fmt.Errorf("%s stopped: %w", name, err)
			}
		}()
	}
	start("polling worker", pollingWorker)
	// The notification and announcement runtimes back off inside their
	// supervisors, as main.go runs them.
	supervise := func(name string, run func(context.Context, chan<- error)) {
		background.Add(1)
		go func() {
			defer background.Done()
			failures := make(chan error, 1)
			run(ctx, failures)
			select {
			case err := <-failures:
				terminal <- fmt.Errorf("%s: %w", name, err)
			default:
			}
		}()
	}
	supervise("notification runtime", func(ctx context.Context, failures chan<- error) {
		runRequiredNotificationRuntime(ctx, notificationRuntime, failures)
	})
	supervise("announcement runtime", func(ctx context.Context, failures chan<- error) {
		runRequiredAnnouncementRuntime(ctx, announcementRuntime, failures)
	})
	t.Cleanup(func() {
		cancel()
		background.Wait()
		_ = notificationRuntime.Close()
		_ = announcementRuntime.Close()
	})

	waitForDBBackoff(t, 30*time.Second, "runtimes ready before termination", func() bool {
		return polls.Load() > 0 &&
			notificationRuntime.ReadinessProbe().Ready() == nil && announcementRuntime.Ready() == nil
	})
	announcementAttempts := announcementRuntime.publishAttempts.Load()

	terminated := terminateDatabaseBackends(t, pool)
	if terminated == 0 {
		t.Fatal("pg_terminate_backend terminated no connection")
	}
	before := polls.Load()
	select {
	case err := <-terminal:
		t.Fatalf("a runtime was reported terminal after pg_terminate_backend (process would exit): %v", err)
	case <-time.After(5 * time.Second):
	}

	waitForDBBackoff(t, 60*time.Second, "runtimes working again after termination", func() bool {
		return polls.Load() > before &&
			notificationRuntime.ReadinessProbe().Ready() == nil && notificationRuntime.Health().Ready &&
			announcementRuntime.Ready() == nil && announcementRuntime.publishAttempts.Load() > announcementAttempts &&
			announcementRuntime.Health().LastErrorCode == ""
	})
	select {
	case err := <-terminal:
		t.Fatalf("a runtime was reported terminal: %v", err)
	default:
	}
}

// openNotificationRuntimeForDBBackoff starts a production notification runtime
// (PostgreSQL outbox + HTTPS JSON SMS provider) on pool.
func openNotificationRuntimeForDBBackoff(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *notificationProcessRuntime {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/ready" {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(writer, request)
	}))
	t.Cleanup(server.Close)
	template := notification.TemplateRef{ID: "account_recovery_sms", Version: 1, Channel: notification.ChannelSMS}
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTemplate(ctx, notification.TemplateDefinition{
		Ref: template, Body: "退避用例短信", Variables: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(ctx, notification.ChannelSwitches{SMS: true}); err != nil {
		t.Fatal(err)
	}
	config := notificationRuntimeConfig{
		Enabled: true, Worker: notification.WorkerConfig{
			BatchSize: 1, LeaseDuration: 2 * time.Second, LeaseSafetyMargin: 250 * time.Millisecond,
			MaxAttempts: 3, BaseDelay: 20 * time.Millisecond, MaxDelay: 100 * time.Millisecond,
		},
		RecoveryTemplates: map[notification.Channel]notification.TemplateRef{notification.ChannelSMS: template},
		SMSProvider:       notificationSMSProviderHTTPSJSON,
		SMS:               smsTestConfig(t, server, "db-backoff-sms-auth"),
		// Fail fast on non-database errors so a miscounted database error
		// would make this test report a terminal error.
		IdleWait: 5 * time.Millisecond, ErrorBackoffBase: 10 * time.Millisecond,
		ErrorBackoffMax: 50 * time.Millisecond, MaxConsecutiveFailures: 3,
		SendTimeout: time.Second, StartupTimeout: 5 * time.Second, ShutdownTimeout: 5 * time.Second,
	}
	runtime, err := openNotificationProcessRuntime(ctx, config, pool, notificationRuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

// terminateDatabaseBackends kills every other connection to the pool's
// database from a dedicated connection and returns how many it killed.
func terminateDatabaseBackends(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	connection, err := pgx.ConnectConfig(t.Context(), pool.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	var terminated int
	if err := connection.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE pg_terminate_backend(pid))
		FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()`).
		Scan(&terminated); err != nil {
		t.Fatal(err)
	}
	return terminated
}

func waitForDBBackoff(t *testing.T, timeout time.Duration, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
