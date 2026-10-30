package analytics

import (
	"context"
	"errors"
	"testing"
)

func TestServiceBindsPlatformAdminOverrideToPlatformScope(t *testing.T) {
	t.Parallel()

	tenantAdmin := Actor{
		ScopeKind:   "tenant",
		TenantID:    testTenantID,
		Permissions: []string{"platform.admin"},
	}
	tenantRequest := serviceQueryRequest(AudienceTenant)

	t.Run("summary rejects tenant platform admin", func(t *testing.T) {
		store := &recordingQueryStore{summary: Summary{MetricVersion: MetricVersion, RequestCount: 1}}
		service, err := NewService(store)
		if err != nil {
			t.Fatal(err)
		}

		got, err := service.Summary(context.Background(), tenantAdmin, tenantRequest)
		if !errors.Is(err, ErrPermissionDenied) || got != (Summary{}) {
			t.Fatalf("Summary() = %#v, %v; want zero result and ErrPermissionDenied", got, err)
		}
		if store.queryCalled {
			t.Fatal("Summary store called after permission denial")
		}
	})

	t.Run("trend rejects tenant platform admin", func(t *testing.T) {
		store := &recordingQueryStore{trend: []TrendPoint{{MetricVersion: MetricVersion, RequestCount: 1}}}
		service, err := NewService(store)
		if err != nil {
			t.Fatal(err)
		}

		got, err := service.Trend(context.Background(), tenantAdmin, tenantRequest)
		if !errors.Is(err, ErrPermissionDenied) || got != nil {
			t.Fatalf("Trend() = %#v, %v; want nil result and ErrPermissionDenied", got, err)
		}
		if store.queryCalled {
			t.Fatal("Trend store called after permission denial")
		}
	})

	t.Run("rank rejects tenant platform admin", func(t *testing.T) {
		store := &recordingQueryStore{rank: RankPage{Items: []RankItem{{Key: "/forbidden", RequestCount: 1}}}}
		service, err := NewService(store)
		if err != nil {
			t.Fatal(err)
		}

		got, err := service.Rank(context.Background(), tenantAdmin, tenantRequest, RankByURL, 10, "")
		if !errors.Is(err, ErrPermissionDenied) || len(got.Items) != 0 || got.NextCursor != "" || !got.SnapshotAt.IsZero() {
			t.Fatalf("Rank() = %#v, %v; want zero result and ErrPermissionDenied", got, err)
		}
		if store.queryCalled {
			t.Fatal("Rank store called after permission denial")
		}
	})

	t.Run("platform admin retains platform audience", func(t *testing.T) {
		store := &recordingQueryStore{}
		service, err := NewService(store)
		if err != nil {
			t.Fatal(err)
		}

		_, err = service.Summary(context.Background(), Actor{
			ScopeKind: "platform", Permissions: []string{"platform.admin"},
		}, serviceQueryRequest(AudiencePlatform))
		if err != nil {
			t.Fatalf("Summary() error = %v", err)
		}
		if !store.queryCalled || store.scope.kind != scopeAdmin {
			t.Fatalf("store called = %t, scope = %#v; want platform query", store.queryCalled, store.scope)
		}
	})

	t.Run("tenant reader ignores unrelated platform admin", func(t *testing.T) {
		store := &recordingQueryStore{}
		service, err := NewService(store)
		if err != nil {
			t.Fatal(err)
		}

		_, err = service.Summary(context.Background(), Actor{
			ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission, "platform.admin"},
		}, tenantRequest)
		if err != nil {
			t.Fatalf("Summary() error = %v", err)
		}
		if !store.queryCalled || store.scope.kind != scopeTenant || store.scope.tenantID != testTenantID {
			t.Fatalf("store called = %t, scope = %#v; want tenant query", store.queryCalled, store.scope)
		}
	})
}
