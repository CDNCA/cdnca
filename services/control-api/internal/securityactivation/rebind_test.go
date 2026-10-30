package securityactivation

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// fakeRebindStore stands in for the database: loadRebindItems returns the
// stale bindings left (a started one is no longer stale, as its open
// candidate excludes it in SQL), Start records the input.
type fakeRebindStore struct {
	stale      []rebindItem
	startErr   map[uuid.UUID]error
	starts     []StartInput
	actors     []securitypolicy.Actor
	savedUntil time.Time
}

func (store *fakeRebindStore) loadRebindItems(_ context.Context, savedBefore time.Time, after uuid.UUID, limit int) ([]rebindItem, error) {
	store.savedUntil = savedBefore
	sort.Slice(store.stale, func(i, j int) bool { return store.stale[i].bindingID.String() < store.stale[j].bindingID.String() })
	var items []rebindItem
	for _, item := range store.stale {
		if (after == uuid.Nil || item.bindingID.String() > after.String()) && len(items) < limit {
			items = append(items, item)
		}
	}
	return items, nil
}

func (store *fakeRebindStore) Start(_ context.Context, actor securitypolicy.Actor, input StartInput) (StartResult, error) {
	store.starts = append(store.starts, input)
	store.actors = append(store.actors, actor)
	if err := store.startErr[input.SiteID]; err != nil {
		return StartResult{}, err
	}
	kept := store.stale[:0]
	for _, item := range store.stale {
		if item.siteID != input.SiteID {
			kept = append(kept, item)
		}
	}
	store.stale = kept
	return StartResult{}, nil
}

func staleItem(scopeID uuid.UUID, revision int64) rebindItem {
	return rebindItem{bindingID: uuid.New(), scopeID: scopeID, siteID: uuid.New(), policyID: uuid.New(),
		policyRevision: revision, bindingRevision: 4, activePolicyVersion: revision - 1,
		actor: securitypolicy.Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: "tenant"}}
}

// A library saved on the general rules page is bound to two sites of one
// tenant and one of another: every stale binding starts once, as its own
// tenant's saver, with no nodes (the site's package line groups) and the
// binding's CAS; a second pass starts nothing (the open candidates merge
// later saves into the next release).
func TestRebindStartsEveryStaleBindingOnceWithDefaultTargets(t *testing.T) {
	now := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	tenantA, tenantB := uuid.New(), uuid.New()
	store := &fakeRebindStore{stale: []rebindItem{staleItem(tenantA, 7), staleItem(tenantA, 7), staleItem(tenantB, 3)}}
	want := append([]rebindItem(nil), store.stale...)
	r := newRebinder(store, func() time.Time { return now }, 15*time.Minute)
	if err := r.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !store.savedUntil.Equal(now.Add(-rebindGrace)) {
		t.Fatalf("grace = %v", now.Sub(store.savedUntil))
	}
	if len(store.starts) != 3 {
		t.Fatalf("starts = %d, want 3", len(store.starts))
	}
	bySite := map[uuid.UUID]rebindItem{}
	for _, item := range want {
		bySite[item.siteID] = item
	}
	for index, input := range store.starts {
		item := bySite[input.SiteID]
		if input.TenantScopeID != item.scopeID || input.SiteID != item.siteID || input.PolicyID != item.policyID ||
			input.PolicyVersion != item.policyRevision || input.ExpectedBindingRevision != 4 ||
			input.ExpectedActivePolicyVersion != item.policyRevision-1 {
			t.Fatalf("start %d = %+v, want binding %+v", index, input, item)
		}
		if len(input.TargetNodeIDs) != 0 || input.CanarySize != 0 {
			t.Fatalf("start %d names targets %v canary %d; the site's line groups must be resolved", index, input.TargetNodeIDs, input.CanarySize)
		}
		if store.actors[index] != item.actor || store.actors[index].ScopeID != input.TenantScopeID {
			t.Fatalf("start %d actor %+v crosses tenants", index, store.actors[index])
		}
		if !activationIdempotencyPattern.MatchString(input.IdempotencyKey) || !validRequestID(input.RequestID) ||
			!input.ExpiresAt.After(now) || input.ExpiresAt.After(now.Add(15*time.Minute)) {
			t.Fatalf("start %d metadata invalid: %+v", index, input)
		}
	}
	if store.starts[0].IdempotencyKey == store.starts[1].IdempotencyKey {
		t.Fatal("two bindings share an idempotency key")
	}
	again := rebindInput(bySite[store.starts[0].SiteID], now.Add(time.Minute), 15*time.Minute)
	if again.IdempotencyKey != store.starts[0].IdempotencyKey {
		t.Fatal("the same binding revision must keep its key across passes and controllers")
	}
	if err := r.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(store.starts) != 3 {
		t.Fatalf("second pass started %d more", len(store.starts)-3)
	}
}

// A site whose package does not include the feature is skipped without
// blocking the others and retried only after the backoff (it publishes once
// the package is enabled); a newer save of it is tried at once.
func TestRebindBacksOffRefusedSitesWithoutBlockingOthers(t *testing.T) {
	now := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	scopeID := uuid.New()
	denied, other := staleItem(scopeID, 5), staleItem(scopeID, 5)
	store := &fakeRebindStore{stale: []rebindItem{denied, other},
		startErr: map[uuid.UUID]error{denied.siteID: errors.Join(ErrPermissionDenied, packageaddon.ErrFeatureDenied)}}
	clock := now
	r := newRebinder(store, func() time.Time { return clock }, 15*time.Minute)
	if err := r.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(store.starts) != 2 || len(store.stale) != 1 || store.stale[0].siteID != denied.siteID {
		t.Fatalf("starts = %+v", store.starts)
	}
	clock = now.Add(rebindBackoff - time.Second)
	if err := r.run(t.Context()); err != nil || len(store.starts) != 2 {
		t.Fatalf("retried inside the backoff: %d starts, err %v", len(store.starts), err)
	}
	store.stale[0].policyRevision = 6
	if err := r.run(t.Context()); err != nil || len(store.starts) != 3 || store.starts[2].PolicyVersion != 6 {
		t.Fatalf("newer save not tried at once: %+v err %v", store.starts, err)
	}
	clock = now.Add(2 * rebindBackoff)
	delete(store.startErr, denied.siteID)
	if err := r.run(t.Context()); err != nil || len(store.starts) != 4 || len(store.stale) != 0 {
		t.Fatalf("not retried after the backoff: %d starts, %d stale, err %v", len(store.starts), len(store.stale), err)
	}
}

// More stale bindings than one batch continue from the cursor next pass.
func TestRebindPagesThroughLargeBindingSets(t *testing.T) {
	now := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	scopeID := uuid.New()
	store := &fakeRebindStore{startErr: map[uuid.UUID]error{}}
	for range rebindBatchSize + 5 {
		item := staleItem(scopeID, 2)
		store.stale = append(store.stale, item)
		store.startErr[item.siteID] = ErrNoTargetNodes
	}
	r := newRebinder(store, func() time.Time { return now }, 15*time.Minute)
	if err := r.run(t.Context()); err != nil || len(store.starts) != rebindBatchSize || r.cursor == uuid.Nil {
		t.Fatalf("first batch: %d starts cursor %v err %v", len(store.starts), r.cursor, err)
	}
	if err := r.run(t.Context()); err != nil || len(store.starts) != rebindBatchSize+5 || r.cursor != uuid.Nil {
		t.Fatalf("second batch: %d starts cursor %v err %v", len(store.starts), r.cursor, err)
	}
}

// 13:55 补充: an ACL library saved on the general rules page follows its
// bound sites too. The scan selects acl bindings, and an acl binding is
// started like any other (no nodes, its own tenant's saver).
func TestRebindIncludesACLBindings(t *testing.T) {
	if !strings.Contains(staleBindingsWhere, "binding.policy_kind IN ('waf','cc','acl')") {
		t.Fatalf("stale binding scan does not select acl: %s", staleBindingsWhere)
	}
	now := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	scopeID := uuid.New()
	acl := staleItem(scopeID, 9)
	store := &fakeRebindStore{stale: []rebindItem{acl}}
	if err := newRebinder(store, func() time.Time { return now }, 15*time.Minute).run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(store.starts) != 1 || store.starts[0].PolicyID != acl.policyID || store.starts[0].PolicyVersion != 9 ||
		len(store.starts[0].TargetNodeIDs) != 0 || store.actors[0].ScopeID != scopeID || len(store.stale) != 0 {
		t.Fatalf("acl binding not started once with default targets: %+v", store.starts)
	}
}
