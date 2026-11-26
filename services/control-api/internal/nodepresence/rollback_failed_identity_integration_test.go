//go:build integration

package nodepresence

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/jackc/pgx/v5"
)

// an agent keeps the release of an apply whose
// compensation failed as its current one when the generation verifiably
// still serves, and reports that identity without an active deployment. The
// identity binds to the rollback_failed apply of that version and artifact
// on this node; a failed apply (never activated) still does not bind.
func TestHeartbeatIdentityBindsToARollbackFailedApplyThatStillServes(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	pool, admin, schema := openPresenceTestDatabase(t, databaseURL)
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	validator := newTestValidator(t, now)
	store, err := NewStore(pool, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		state string
		binds bool
	}{
		{state: "rollback_failed", binds: true},
		{state: "failed", binds: false},
	} {
		t.Run(test.state, func(t *testing.T) {
			nodeID, _, configurationScopeID := seedPresencePlatformNode(t, pool, true)
			configID, artifactID, digest := seedPresenceScopedIdentityArtifact(t, pool, configurationScopeID)
			deploymentID := seedPresenceScopedIdentityDeployment(t, pool, nodeID, configurationScopeID, configID, artifactID, test.state)
			heartbeat := platformPresenceIdentityHeartbeat(now, configID, digest, deploymentID)
			heartbeat.ActiveDeployments = nil
			envelope, err := validator.Decode("cdnca.agent.heartbeats."+nodeID.String(), marshalHeartbeat(t, heartbeat))
			if err != nil {
				t.Fatal(err)
			}
			result, err := store.Project(t.Context(), envelope)
			if test.binds {
				if err != nil || result.Outcome != OutcomeAdvanced {
					t.Fatalf("heartbeat naming the serving release = (%+v, %v)", result, err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidHeartbeat) {
				t.Fatalf("heartbeat naming a failed apply's release error = %v, want ErrInvalidHeartbeat", err)
			}
		})
	}
}
