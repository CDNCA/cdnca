package observabilitylog

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type namingRepository struct {
	fakeRepository09
	names    map[ResourceRef]string
	err      error
	calls    int
	lastRefs []ResourceRef
	scope    uuid.UUID
}

func (repository *namingRepository) ResourceNames(_ context.Context, scopeID uuid.UUID, refs []ResourceRef) (map[ResourceRef]string, error) {
	repository.calls++
	repository.scope, repository.lastRefs = scopeID, append([]ResourceRef(nil), refs...)
	return repository.names, repository.err
}

// tp-b6b: one name lookup per page, deduplicated, only for nameable types
// with a UUID id, in the caller's scope; a missing answer = deleted.
func TestListAttachesObjectNamesInOneLookup(t *testing.T) {
	now := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	scopeID, userID := uuid.New(), uuid.New()
	site, gone, node := uuid.New(), uuid.New(), uuid.New()
	row := func(id, resourceType, resourceID string, minutes int) Fact {
		return Fact{ID: id, ScopeID: scopeID, Kind: KindOperation, ActorUserID: &userID, Action: "site.update",
			ReasonCode: "site.update", ResultCode: "success", ResourceType: resourceType, ResourceID: resourceID,
			SourceIP: "unknown", GeoCode: "unknown", OccurredAt: now.Add(-time.Duration(minutes) * time.Minute)}
	}
	repository := &namingRepository{names: map[ResourceRef]string{{"site", site}: "live.example.test", {"node", node}: "edge-01"}}
	repository.rows = []Fact{row("e5", "site", site.String(), 1), row("e4", "site", site.String(), 2),
		row("e3", "site", gone.String(), 3), row("e2", "node", node.String(), 4), row("e1", "site", "legacy-7", 5),
		row("e0", "package_product", uuid.NewString(), 6)}
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, SessionID: uuid.New(), ScopeKind: ScopeTenant, Permissions: []string{"identity.self.read"}}
	page, err := service.List(context.Background(), actor, Query{Kinds: []Kind{KindOperation}})
	if err != nil {
		t.Fatal(err)
	}
	if repository.calls != 1 || repository.scope != scopeID || len(repository.lastRefs) != 3 {
		t.Fatalf("lookup calls %d scope %s refs %+v", repository.calls, repository.scope, repository.lastRefs)
	}
	type want struct {
		name    string
		deleted bool
	}
	for index, w := range []want{{"live.example.test", false}, {"live.example.test", false}, {"", true}, {"edge-01", false},
		{"", false}, {"", false}} {
		if got := page.Items[index]; got.ResourceName != w.name || got.ResourceDeleted != w.deleted {
			t.Errorf("row %s name %q deleted %v, want %+v", got.ID, got.ResourceName, got.ResourceDeleted, w)
		}
	}

	// A failing lookup keeps the page (rows show resource_id), nothing marked deleted.
	repository.err, repository.names = errors.New("down"), nil
	page, err = service.List(context.Background(), actor, Query{Kinds: []Kind{KindOperation}})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		if item.ResourceName != "" || item.ResourceDeleted {
			t.Fatalf("row after failed lookup = %+v", item)
		}
	}
}
