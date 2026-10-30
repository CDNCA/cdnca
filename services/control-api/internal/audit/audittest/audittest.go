// Package audittest reads audit events back in integration tests. Since the
// unified log (migration 361) the before -> after summary lives only in the
// changes column ([{field,before,after}]), not in payload["changes"].
package audittest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Event is one audit_events row as tests assert it.
type Event struct {
	Action       string
	Result       string
	ResourceType string
	ResourceID   string
	RequestID    string
	ActorUserID  *uuid.UUID
	ReasonCode   string
	Payload      map[string]any
	Changes      []audit.Change
}

// Querier is a pool, connection or transaction.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Query returns the events matching where (a condition over audit_events),
// oldest first.
func Query(t testing.TB, db Querier, where string, args ...any) []Event {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT action,result,resource_type,resource_id,request_id,
		actor_user_id,reason_code,payload,changes FROM audit_events WHERE `+where+`
		ORDER BY occurred_at,stream_position`, args...)
	if err != nil {
		t.Fatalf("query audit events: %v", err)
	}
	defer rows.Close()
	var events []Event
	for rows.Next() {
		var event Event
		var payload, changes []byte
		if err := rows.Scan(&event.Action, &event.Result, &event.ResourceType, &event.ResourceID, &event.RequestID,
			&event.ActorUserID, &event.ReasonCode, &payload, &changes); err != nil {
			t.Fatalf("scan audit event: %v", err)
		}
		if err := json.Unmarshal(payload, &event.Payload); err != nil {
			t.Fatalf("decode audit payload: %v", err)
		}
		event.Changes = DecodeChanges(t, changes)
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	return events
}

// Last returns the newest event matching where; the test fails if none does.
func Last(t testing.TB, db Querier, where string, args ...any) Event {
	t.Helper()
	events := Query(t, db, where, args...)
	if len(events) == 0 {
		t.Fatalf("no audit event where %s %v", where, args)
	}
	return events[len(events)-1]
}

// DecodeChanges decodes a changes column value.
func DecodeChanges(t testing.TB, raw []byte) []audit.Change {
	t.Helper()
	changes := []audit.Change{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &changes); err != nil {
			t.Fatalf("decode audit changes %s: %v", raw, err)
		}
	}
	return changes
}

// Change returns the change of field.
func (event Event) Change(field string) (audit.Change, bool) {
	return Find(event.Changes, field)
}

// Find returns the change of field in changes.
func Find(changes []audit.Change, field string) (audit.Change, bool) {
	for _, change := range changes {
		if change.Field == field {
			return change, true
		}
	}
	return audit.Change{}, false
}
