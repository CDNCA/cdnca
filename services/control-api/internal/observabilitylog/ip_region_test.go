package observabilitylog

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/google/uuid"
)

type fixedRegionLookup struct {
	answers map[string]*analyticslog.IPInfo
	asked   [][]string
}

func (lookup *fixedRegionLookup) Lookup(_ context.Context, addresses []string) map[string]*analyticslog.IPInfo {
	lookup.asked = append(lookup.asked, append([]string(nil), addresses...))
	return lookup.answers
}

// B6: rows get 国家-省-市 from the IP library by source IP when served; a
// miss, an unknown address or no library keeps the stored geo (unknown).
func TestListAttachesIPLibraryRegions(t *testing.T) {
	now := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	scopeID, userID := uuid.New(), uuid.New()
	rows := func() []Fact {
		return []Fact{
			{ID: "e3", ScopeID: scopeID, Kind: KindLogin, ActorUserID: &userID, Action: "auth.login", ReasonCode: "credentials_accepted",
				ResultCode: "success", SourceIP: "203.0.113.61", GeoCode: "unknown", GeoResolution: "unknown", OccurredAt: now.Add(-time.Second)},
			{ID: "e2", ScopeID: scopeID, Kind: KindOperation, ActorUserID: &userID, Action: "site.update", ReasonCode: "site.update",
				ResultCode: "success", SourceIP: "198.51.100.9", GeoCode: "unknown", Category: "site", OccurredAt: now.Add(-2 * time.Second)},
			{ID: "e1", ScopeID: scopeID, Kind: KindOperation, ActorUserID: &userID, Action: "site.create", ReasonCode: "site.create",
				ResultCode: "success", SourceIP: "unknown", GeoCode: "unknown", Category: "site", OccurredAt: now.Add(-3 * time.Second)},
		}
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, SessionID: uuid.New(), ScopeKind: ScopeTenant, Permissions: []string{"identity.self.read"}}
	newService := func(t *testing.T) *Service {
		t.Helper()
		service, err := NewService(&fakeRepository09{list: func(StoreQuery) []Fact { return rows() }},
			[]byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		return service
	}

	t.Run("hit and miss", func(t *testing.T) {
		service := newService(t)
		lookup := &fixedRegionLookup{answers: map[string]*analyticslog.IPInfo{
			"203.0.113.61": {Country: "CN", ProvinceName: "山东省", CityName: "潍坊市", Revision: 1},
		}}
		service.SetIPIntelLookup(lookup)
		page, err := service.List(t.Context(), actor, Query{})
		if err != nil {
			t.Fatal(err)
		}
		hit, miss, unknown := page.Items[0], page.Items[1], page.Items[2]
		if hit.GeoCode != "CN" || hit.GeoRegion != "山东省" || hit.GeoCity != "潍坊市" || hit.GeoResolution != "matched" {
			t.Fatalf("hit row = %+v", hit)
		}
		if miss.GeoCode != "unknown" || miss.GeoRegion != "" || miss.GeoCity != "" {
			t.Fatalf("miss row = %+v", miss)
		}
		if unknown.GeoCode != "unknown" {
			t.Fatalf("unknown-address row = %+v", unknown)
		}
		if len(lookup.asked) != 1 || len(lookup.asked[0]) != 2 {
			t.Fatalf("lookup asked %v, want the two real addresses once", lookup.asked)
		}
	})

	t.Run("library not loaded", func(t *testing.T) {
		service := newService(t)
		// PostgresIPIntelLookup answers nil for every address without a library.
		service.SetIPIntelLookup(&fixedRegionLookup{})
		page, err := service.List(t.Context(), actor, Query{})
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page.Items {
			if row.GeoCode != "unknown" || row.GeoRegion != "" || row.GeoCity != "" {
				t.Fatalf("row without library = %+v", row)
			}
		}
	})

	t.Run("no lookup configured", func(t *testing.T) {
		page, err := newService(t).List(t.Context(), actor, Query{})
		if err != nil || page.Items[0].GeoCode != "unknown" {
			t.Fatalf("page=%+v err=%v", page, err)
		}
	})

	t.Run("unsafe answer ignored", func(t *testing.T) {
		service := newService(t)
		service.SetIPIntelLookup(&fixedRegionLookup{answers: map[string]*analyticslog.IPInfo{
			"203.0.113.61": {Country: "cn", ProvinceName: "山东省"},
			"198.51.100.9": {Country: "US", CityName: " bad\n"},
		}})
		page, err := service.List(t.Context(), actor, Query{})
		if err != nil {
			t.Fatal(err)
		}
		if page.Items[0].GeoCode != "unknown" || page.Items[1].GeoCode != "unknown" {
			t.Fatalf("unsafe answers applied: %+v", page.Items[:2])
		}
	})
}

func TestListCategoryFilter(t *testing.T) {
	now := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	scopeID, userID := uuid.New(), uuid.New()
	repository := &fakeRepository09{list: func(query StoreQuery) []Fact {
		return []Fact{{ID: "e1", ScopeID: scopeID, Kind: KindOperation, ActorUserID: &userID, Action: "site.update",
			ReasonCode: "site.update", ResultCode: "success", SourceIP: "unknown", GeoCode: "unknown", Category: "cert",
			OccurredAt: now.Add(-time.Second)}}
	}}
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, SessionID: uuid.New(), ScopeKind: ScopeTenant, Permissions: []string{"identity.self.read"}}
	if _, err := service.List(t.Context(), actor, Query{Category: "nope"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown category err=%v, want invalid input", err)
	}
	if _, err := service.List(t.Context(), actor, Query{Category: "site"}); !errors.Is(err, ErrUnsafeFact) {
		t.Fatalf("row outside the requested category err=%v, want unsafe fact", err)
	}
	if repository.query.Category != "site" {
		t.Fatalf("store category=%q", repository.query.Category)
	}
	if _, err := service.List(t.Context(), actor, Query{Category: "cert"}); err != nil {
		t.Fatal(err)
	}
}
