package certificateasset

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
)

func TestCertificateAssetListPaginationSearchAndTenantIsolation(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "asset-list")
	foreign := createCertificateTenant(t, pool, "asset-list-foreign")
	store, err := NewStoreWithDependencies(pool, &testEnvelopeCipher{}, audit.New(pool), func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}

	newest := certificateTestNow.Add(-time.Hour)
	ids := []uuid.UUID{
		uuid.MustParse("10000000-0000-4000-8000-000000000001"),
		uuid.MustParse("20000000-0000-4000-8000-000000000002"),
		uuid.MustParse("30000000-0000-4000-8000-000000000003"),
	}
	insert := func(actor Actor, id uuid.UUID, name string, createdAt time.Time) {
		t.Helper()
		_, err := pool.Exec(context.Background(), `INSERT INTO certificate_assets (
			tenant_scope_id,id,name,source,created_by_scope_id,created_by_user_id,
			updated_by_scope_id,updated_by_user_id,created_at,updated_at
		) VALUES($1,$2,$3,'uploaded',$1,$4,$1,$4,$5,$5)`, actor.ScopeID, id, name, actor.UserID, createdAt)
		if err != nil {
			t.Fatal(err)
		}
	}
	insert(tenant.actor, ids[0], "Alpha older", newest.Add(-time.Hour))
	insert(tenant.actor, ids[1], "Alpha newest low", newest)
	insert(tenant.actor, ids[2], "Alpha newest high", newest)
	insert(tenant.actor, uuid.New(), "unrelated", newest.Add(time.Hour))
	insert(foreign.actor, uuid.New(), "Alpha foreign", newest.Add(2*time.Hour))

	first, err := store.ListPage(context.Background(), tenant.actor, ListRequest{
		TenantScopeID: tenant.actor.ScopeID, Page: 1, Limit: 2, Search: "alpha",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Total != 3 || len(first.Items) != 2 || first.Items[0].ID != ids[2] || first.Items[1].ID != ids[1] {
		t.Fatalf("first page = %#v", first)
	}
	second, err := store.ListPage(context.Background(), tenant.actor, ListRequest{
		TenantScopeID: tenant.actor.ScopeID, Page: 2, Limit: 2, Search: "alpha",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Total != 3 || len(second.Items) != 1 || second.Items[0].ID != ids[0] {
		t.Fatalf("second page = %#v", second)
	}
	empty, err := store.ListPage(context.Background(), tenant.actor, ListRequest{
		TenantScopeID: tenant.actor.ScopeID, Page: 1, Limit: 10, Search: "missing",
	})
	if err != nil || empty.Total != 0 || empty.Items == nil || len(empty.Items) != 0 {
		t.Fatalf("empty page = %#v, err=%v", empty, err)
	}
	if _, err := store.ListPage(context.Background(), tenant.actor, ListRequest{
		TenantScopeID: foreign.actor.ScopeID, Page: 1, Limit: 10,
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-tenant list error = %v", err)
	}
	for _, request := range []ListRequest{
		{TenantScopeID: tenant.actor.ScopeID, Page: 0, Limit: 10},
		{TenantScopeID: tenant.actor.ScopeID, Page: 1, Limit: 0},
		{TenantScopeID: tenant.actor.ScopeID, Page: 1, Limit: 101},
		{TenantScopeID: tenant.actor.ScopeID, Page: 1, Limit: 10, Search: "bad\nsearch"},
		{TenantScopeID: tenant.actor.ScopeID, Page: 1, Limit: 10, Search: strings.Repeat("a", 129)},
	} {
		if _, err := store.ListPage(context.Background(), tenant.actor, request); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid request %#v error = %v", request, err)
		}
	}
}
