//go:build integration

package nodescheduler

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestLineEndpointDisplayIDPersistence(t *testing.T) {
	f := newIntegrationFixture(t)
	ctx := t.Context()
	ids := func(group LineGroupRevision) map[uuid.UUID]string {
		t.Helper()
		raw, err := json.Marshal(group.Endpoints)
		if err != nil {
			t.Fatal(err)
		}
		var values []struct {
			ID        uuid.UUID `json:"id"`
			DisplayID string    `json:"display_id"`
		}
		if err := json.Unmarshal(raw, &values); err != nil {
			t.Fatal(err)
		}
		result := make(map[uuid.UUID]string, len(values))
		seen := map[string]bool{}
		for _, value := range values {
			if value.DisplayID == "" || seen[value.DisplayID] {
				t.Fatalf("missing or duplicate persisted endpoint display ID: %q", value.DisplayID)
			}
			seen[value.DisplayID], result[value.ID] = true, value.DisplayID
		}
		return result
	}
	request := f.putRequest(uuid.New(), 0, "display-id-cloud", "display-id-create")
	created, err := f.service.PutGroup(ctx, f.actor, request)
	if err != nil {
		t.Fatal(err)
	}
	want := ids(created.Group)
	read, err := f.service.GetCurrent(ctx, f.actor, request.GroupID)
	if err != nil || !reflect.DeepEqual(ids(read), want) {
		t.Fatalf("display IDs not read back: %v", err)
	}
	replay, err := f.service.PutGroup(ctx, f.actor, request)
	if err != nil || !replay.Replayed || !reflect.DeepEqual(ids(replay.Group), want) {
		t.Fatalf("display ID replay: %v", err)
	}
	request.ExpectedRevision, request.IdempotencyKey, request.RequestID = 1, "display-id-update", "display-id-update-request"
	request.Endpoints[0].SortOrder, request.Endpoints[1].SortOrder = 300, 1
	updated, err := f.service.PutGroup(ctx, f.actor, request)
	if err != nil || !reflect.DeepEqual(ids(updated.Group), want) {
		t.Fatalf("display IDs changed with sort: %v", err)
	}
	rolled, err := f.service.Rollback(ctx, f.actor, request.GroupID, 1, 2, "display-id-rollback", "display-id-rollback-request")
	if err != nil || !reflect.DeepEqual(ids(rolled.Group), want) {
		t.Fatalf("display IDs changed with rollback: %v", err)
	}
	other := f.putRequest(uuid.New(), 0, "display-id-other", "display-id-other-create")
	other.Endpoints = request.Endpoints
	otherCreated, err := f.service.PutGroup(ctx, f.actor, other)
	if err != nil {
		t.Fatal(err)
	}
	for endpoint, value := range ids(otherCreated.Group) {
		if want[endpoint] == value {
			t.Fatal("distinct group endpoint identities share a display ID")
		}
	}
}
