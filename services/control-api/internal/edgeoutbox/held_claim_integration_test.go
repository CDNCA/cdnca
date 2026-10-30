//go:build integration

package edgeoutbox

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPostgresClaimExcludesHeldCohortCommands(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	fixture := newIntegrationFixture(t, databaseURL)
	defer fixture.close(t)
	deployment := fixture.seedDeployment(t, uuid.New())
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE edge_command_outbox
		SET status='held',updated_at=CURRENT_TIMESTAMP WHERE id=$1`, deployment.outboxID); err != nil {
		t.Fatal(err)
	}
	claimed, err := (&postgresStore{pool: fixture.pool}).claim(context.Background(), 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 0 {
		t.Fatalf("claimed held commands=%d want=0", len(claimed))
	}
	assertOutboxState(t, fixture.pool, deployment.outboxID, "held", 0, false, "")
}
