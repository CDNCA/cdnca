//go:build integration

package site

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// 管理员在本页给指定用户新增默认设置，
// 列表带「用户」列；租户只看到自己的；「跟随协议和端口」默认落到新站源站池。
func TestSiteDefaultsAdminForUserAndFollowPort(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	admin, a, b := f.admin.siteActor(), f.a.siteActor(), f.b.siteActor()
	groupID := uuid.New()
	f.exec(`INSERT INTO site_groups(id,scope_id,name) VALUES($1,$2,'g1')`, groupID, f.a.scopeID)
	save := func(fields SiteUserDefaultFields) SiteUserDefault {
		t.Helper()
		key := f.key("admin-parity")
		item, err := f.sites.CreateUserDefault(ctx, admin, SiteUserDefaultCreateRequest{
			TargetScopeID: f.a.scopeID, OwnerUserID: f.a.userID, Fields: fields, IdempotencyKey: key, RequestID: key})
		if err != nil {
			t.Fatalf("admin save %s: %v", fields.SettingName, err)
		}
		return item
	}
	follow := save(SiteUserDefaultFields{SettingName: SiteDefaultOriginProtocol, Value: SiteDefaultOriginFollowPort})
	port := save(SiteUserDefaultFields{SettingName: SiteDefaultBackendHTTPPort, Value: "8080"})
	grouped := save(SiteUserDefaultFields{SettingName: SiteDefaultOriginProtocol, Value: OriginSchemeHTTPS,
		ScopeName: SiteDefaultScopeGroup, GroupID: &groupID})
	if follow.Owner == nil || follow.Owner.ID != f.a.userID || follow.Owner.DisplayName != "trust-a" || follow.Owner.DisplayID == "" {
		t.Fatalf("created owner: %+v", follow.Owner)
	}
	// A group of another tenant cannot be the admin's target for this user.
	foreign := uuid.New()
	f.exec(`INSERT INTO site_groups(id,scope_id,name) VALUES($1,$2,'gb')`, foreign, f.b.scopeID)
	key := f.key("admin-parity-foreign")
	if _, err := f.sites.CreateUserDefault(ctx, admin, SiteUserDefaultCreateRequest{TargetScopeID: f.a.scopeID, OwnerUserID: f.a.userID,
		Fields: SiteUserDefaultFields{SettingName: SiteDefaultHSTS, Value: "1", ScopeName: SiteDefaultScopeGroup, GroupID: &foreign},
		IdempotencyKey: key, RequestID: key}); err == nil {
		t.Fatal("another tenant's group accepted")
	}

	list := func(actor Actor) SiteUserDefaultListResult {
		t.Helper()
		result, err := f.sites.ListUserDefaults(ctx, actor, SiteUserDefaultListFilter{Page: 1, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	adminList := list(admin)
	seen := map[uuid.UUID]bool{}
	for _, item := range adminList.Items {
		if item.Owner == nil || item.Owner.DisplayName == "" {
			t.Fatalf("admin row without owner: %+v", item)
		}
		seen[item.ID] = item.Owner.ID == f.a.userID
	}
	if !seen[follow.ID] || !seen[port.ID] || !seen[grouped.ID] {
		t.Fatalf("admin list misses rows: %+v", adminList.Items)
	}
	if got := list(a); got.Total != 3 || got.Items[0].Owner == nil || got.Items[0].Owner.ID != f.a.userID {
		t.Fatalf("tenant list: %+v", got)
	}
	if got := list(b); got.Total != 0 {
		t.Fatalf("other tenant sees %d rows", got.Total)
	}

	pool := func(id uuid.UUID) (string, bool, int) {
		t.Helper()
		var scheme string
		var followPort bool
		var httpPort int
		if err := f.pool.QueryRow(ctx, `SELECT origin_scheme, follow_port, http_port FROM site_origin_pools WHERE site_id=$1`, id).
			Scan(&scheme, &followPort, &httpPort); err != nil {
			t.Fatal(err)
		}
		return scheme, followPort, httpPort
	}
	// 全局默认「跟随协议和端口」：协议跟随、按入口端口回源，回源 HTTP 端口默认不适用。
	created, err := f.createSite(f.admin, f.a, "follow-port.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if scheme, followPort, httpPort := pool(created.Site.ID); scheme != OriginSchemeFollow || !followPort || httpPort != 80 {
		t.Fatalf("follow_port default: scheme %s follow %v http %d", scheme, followPort, httpPort)
	}
	// 分组范围的值优先于全局：分组里新建的网站回源 HTTPS。
	key = f.key("admin-parity-group-site")
	inGroup, err := f.sites.Create(ctx, a, CreateRequest{IdempotencyKey: key, RequestID: key, Fields: SiteFields{
		Domains: []string{"follow-group.example.test"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
		GroupID: &groupID, GroupName: "g1", Enabled: true, Status: StatusActive}})
	if err != nil {
		t.Fatal(err)
	}
	if scheme, followPort, _ := pool(inGroup.Site.ID); scheme != OriginSchemeHTTPS || followPort {
		t.Fatalf("group default: scheme %s follow %v", scheme, followPort)
	}
	// 禁用后不再作用于之后新建的网站，已建网站不变。
	key = f.key("admin-parity-disable")
	off := false
	if _, err := f.sites.UpdateUserDefault(ctx, admin, SiteUserDefaultUpdateRequest{ID: follow.ID, ExpectedRevision: follow.Revision,
		Enabled: &off, IdempotencyKey: key, RequestID: key}); err != nil {
		t.Fatal(err)
	}
	later, err := f.createSite(f.admin, f.a, "follow-off.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if scheme, followPort, httpPort := pool(later.Site.ID); scheme != OriginSchemeHTTP || followPort || httpPort != 8080 {
		t.Fatalf("after disable: scheme %s follow %v http %d", scheme, followPort, httpPort)
	}
	if _, followPort, _ := pool(created.Site.ID); !followPort {
		t.Fatal("existing site changed by disabling the default")
	}
}
