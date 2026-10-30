package cachecontrolhttp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
)

// CACHE-ADD-09b: a system follow-up names its parent operation; a user's
// operation leaves parent_operation_id out of the body.
func TestOperationViewProjectsParentOperation(t *testing.T) {
	now := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	parentID := uuid.MustParse("66666666-6666-4666-8666-666666666666")
	operation := cachecontrol.Operation{
		ID: uuid.MustParse("67777777-7777-4777-8777-777777777777"), DisplayID: "21",
		SiteID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), SiteDisplayID: "3",
		Action: cachecontrol.ActionPurge, TargetType: cachecontrol.TargetExactURL, State: cachecontrol.StateQueued,
		MaxAttempts: 1, AutoNodes: true, ParentOperationID: &parentID, CreatedAt: now, UpdatedAt: now,
	}
	encoded, err := json.Marshal(operationView(operation))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"parent_operation_id":"`+parentID.String()+`"`) {
		t.Fatalf("follow-up view = %s", encoded)
	}
	operation.ParentOperationID = nil
	encoded, err = json.Marshal(operationView(operation))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "parent_operation_id") {
		t.Fatalf("user operation view = %s", encoded)
	}
	summary, err := json.Marshal(OperationSummary{ID: operation.ID, ParentOperationID: &parentID})
	if err != nil || !strings.Contains(string(summary), `"parent_operation_id":"`+parentID.String()+`"`) {
		t.Fatalf("summary = %s, %v", summary, err)
	}
}
