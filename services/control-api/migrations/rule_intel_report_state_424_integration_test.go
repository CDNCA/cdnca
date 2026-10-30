//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// TestRuleIntelReportState416: up/down/up；sent 必须带收据；未知状态被拒。
func TestRuleIntelReportState416(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_rule_intel_report_state.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("rule intel report migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up: %v", err)
	}
	insert := `INSERT INTO rule_intel_report_state(installation_id,sequence,request_id,observed_at,report,report_digest,report_bytes,
		section_counts,status,sent_at,receipt_id,next_attempt_at,updated_at) VALUES($1,1,'r',now(),'{}',decode(repeat('00',32),'hex'),2,'{}',$2,$3,$4,now(),now())`
	if _, err := pool.Exec(ctx, insert, uuid.New(), "sent", nil, nil); sqlState(err) != "23514" {
		t.Fatalf("sent without receipt: %v, want 23514", err)
	}
	if _, err := pool.Exec(ctx, insert, uuid.New(), "truncated", nil, nil); sqlState(err) != "23514" {
		t.Fatalf("unknown status: %v, want 23514", err)
	}
	mustExec(t, pool, insert, uuid.New(), "deferred_too_large", nil, nil)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
