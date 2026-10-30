//go:build integration

package notification

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// shutdownAfterCheckContext models a worker shutdown that lands right after the worker
// checked for cancellation: once the provider has answered, the next Err() still reports
// nil (the worker's check passes) and the context is cancelled immediately afterwards.
type shutdownAfterCheckContext struct {
	context.Context
	mu       sync.Mutex
	answered bool
	checked  bool
	done     chan struct{}
}

func newShutdownAfterCheckContext(parent context.Context) *shutdownAfterCheckContext {
	return &shutdownAfterCheckContext{Context: parent, done: make(chan struct{})}
}

func (c *shutdownAfterCheckContext) Done() <-chan struct{} { return c.done }

func (c *shutdownAfterCheckContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.answered {
		return nil
	}
	if !c.checked {
		c.checked = true
		close(c.done)
		return nil
	}
	return context.Canceled
}

func (c *shutdownAfterCheckContext) providerAnswered() {
	c.mu.Lock()
	c.answered = true
	c.mu.Unlock()
}

type answerThenShutdownSender struct {
	ctx    *shutdownAfterCheckContext
	result SendResult
}

func (s *answerThenShutdownSender) Send(context.Context, DeliveryAttempt) SendResult {
	s.ctx.providerAnswered()
	return s.result
}

func TestWorkerSettlesProviderAnswerWhenShutdownFollowsTheCheck(t *testing.T) {
	fixture := seedNotificationFixture(t, headMigratedNotificationPool(t))
	fixture.enableSMS(t)
	outboxID := mustEnqueue(t, fixture, "shutdown-after-provider-answer")
	ctx := newShutdownAfterCheckContext(t.Context())
	worker, err := NewWorker(fixture.store, &answerThenShutdownSender{ctx: ctx, result: SendResult{
		Disposition: SendAccepted, Provider: "smtp", ProviderDeliveryID: "smtp-shutdown-accepted",
	}}, DefaultWorkerConfig())
	if err != nil {
		t.Fatal(err)
	}
	// After the shutdown the batch stops before claiming another delivery (worker.go
	// checks ctx.Err() per claim), so only context.Canceled may surface here.
	if batch, err := worker.ProcessBatch(ctx); (err != nil && !errors.Is(err, context.Canceled)) || batch.Accepted != 1 {
		t.Fatalf("ProcessBatch() = (%+v, %v)", batch, err)
	}
	// The provider accepted the message: that outcome must be settled, not left
	// dispatching until the lease expires and recovery downgrades it to unknown.
	assertSettlement108(t, fixture.pool, outboxID, "accepted", 2)
	assertOutboxStatusAttempt(t, fixture.pool, outboxID, OutboxAccepted, 1)
}

// headMigratedNotificationPool is a schema migrated to the release head (template clone
// first), so the worker runs against the production delivery policy and settlement tables.
func headMigratedNotificationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := pgx.Identifier{"notification_head_" + strings.ReplaceAll(uuid.NewString(), "-", "")}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = strings.Trim(schema, `"`)
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		ctx, cancel := databasetest.CleanupContext()
		defer cancel()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}
