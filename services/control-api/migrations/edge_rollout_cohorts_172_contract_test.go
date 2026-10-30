package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestOPS08EdgeRolloutCohorts172Contract(t *testing.T) {
	predecessor, err := controlmigrations.FS.ReadFile("171_recharge_payment_approval.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	upBytes, err := controlmigrations.FS.ReadFile("172_edge_rollout_cohorts.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("172_edge_rollout_cohorts.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	predecessorSHA := fmt.Sprintf("%x", sha256.Sum256(predecessor))
	for _, required := range []string{
		"migration 172 requires the exact verified 171 release head", predecessorSHA,
		"strategy", "canary_size", "batch_size", "failure_threshold", "released_cohort",
		"pause_reason", "started_at", "paused_at", "cohort", "'held'",
		"edge_rollout.start", "edge_rollout.pause", "edge_rollout.resume",
		"contract_version IN (0, 1, 2)",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("172 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 172 requires the exact verified 171 release head"),
		strings.Index(up, "ALTER TABLE rollouts"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("172 predecessor guard must precede the first mutation")
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 172 rollback requires the exact verified 172 head", upSHA,
		"migration 172 rollback would discard rollout cohort facts",
		"contract_version=2", "status='held'", "cohort<>0",
		"edge_rollout.start", "edge_rollout.pause", "edge_rollout.resume",
		"DROP COLUMN cohort", "DROP COLUMN strategy",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("172 down missing %q", required)
		}
	}
	if refusal, mutation := strings.Index(down, "migration 172 rollback would discard rollout cohort facts"),
		strings.Index(down, "DROP COLUMN cohort"); refusal < 0 || mutation < 0 || refusal > mutation {
		t.Fatal("172 fact refusal must precede destructive rollback")
	}
}
