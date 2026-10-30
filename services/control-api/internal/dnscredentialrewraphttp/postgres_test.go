package dnscredentialrewraphttp

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestIntentOperationDurablyBindsSessionJobOrdinalProviderAndRevision(t *testing.T) {
	owner := testOwner()
	jobID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	item := BatchItem{
		ProviderID: uuid.MustParse("44444444-4444-4444-4444-444444444444"), ExpectedRevision: 17,
	}
	operation := itemOperation(owner.SessionID, jobID, 9, item)
	record, err := parseIntentOperation(operation, owner, jobID)
	if err != nil || record.ordinal != 9 || record.item != item {
		t.Fatalf("record=%+v error=%v", record, err)
	}
	other := owner
	other.SessionID = uuid.New()
	if _, err := parseIntentOperation(operation, other, jobID); err == nil {
		t.Fatal("cross-session operation parsed")
	}
	if batchOperation(owner.SessionID) == batchOperation(other.SessionID) {
		t.Fatal("batch operation is not session-bound")
	}
}

func TestPostgresCoordinatorUsesOnlyDurableWriteReceiptFacts(t *testing.T) {
	source, err := os.ReadFile("postgres.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"INSERT INTO dns_acme_write_requests", "itemOperation(request.Owner.SessionID, jobID, ordinal, item)",
		"completed_at IS NULL AND resource_id IS NULL AND response_body IS NULL",
		"SET resource_id=$5,response_body=$6,completed_at=$7",
		"WHERE id=$1 AND actor_user_id=$2 AND target_scope_id=$3 AND operation=$4",
		"loadIntents(ctx, repository.pool, request.Owner, request.JobID, false)",
		"pg_try_advisory_lock",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("PostgreSQL coordinator missing durable contract %q", required)
		}
	}
	for _, forbidden := range []string{"map[uuid.UUID]Job", "sync.Map", "no-op", "noop"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("PostgreSQL coordinator contains non-durable state %q", forbidden)
		}
	}
}
