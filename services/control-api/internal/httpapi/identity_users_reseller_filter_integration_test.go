package httpapi

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// RS-06b：GET /v1/admin/users 的代理商投影（include=reseller）与 type/parent 服务端筛选+分页。
func TestManagedUserListResellerProjectionAndFilters(t *testing.T) {
	f := newUserMetadataHTTPFixture(t)
	owner := map[string]any{"role": identity.UserRoleOwner}
	reseller, _ := f.create(t, "rs-reseller", owner, true)
	customerA, _ := f.create(t, "rs-customer-a", owner, true)
	customerB, _ := f.create(t, "rs-customer-b", owner, true)
	direct, _ := f.create(t, "rs-direct", owner, true)
	addPlatformUser(t, f, "rs-platform-admin", identity.UserRolePlatformAdmin, "identity.users.manage")
	resellerScope := reseller["scope_id"].(string)

	if _, err := f.pool.Exec(t.Context(), `
		INSERT INTO reseller_profiles(scope_id,status,revision,created_by_user_id,created_at,updated_by_user_id,updated_at)
		SELECT $1::uuid,'active',1,u.id,now(),u.id,now() FROM users u WHERE u.username='metadata-admin'`, resellerScope); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `
		UPDATE tenants SET parent_scope_id=$1::uuid
		WHERE id IN (SELECT tenant_id FROM access_scopes WHERE id = ANY($2::uuid[]))`,
		resellerScope, []string{customerA["scope_id"].(string), customerB["scope_id"].(string)}); err != nil {
		t.Fatal(err)
	}
	var resellerName string
	if err := f.pool.QueryRow(t.Context(), `
		SELECT tenant.display_name FROM access_scopes scope JOIN tenants tenant ON tenant.id=scope.tenant_id WHERE scope.id=$1`,
		resellerScope).Scan(&resellerName); err != nil {
		t.Fatal(err)
	}

	ids := func(page map[string]any) map[string]map[string]any {
		out := map[string]map[string]any{}
		for _, raw := range page["items"].([]any) {
			item := raw.(map[string]any)
			out[item["id"].(string)] = item
		}
		return out
	}

	// 默认不带投影；include=reseller 给每行（含平台管理员）四个字段。
	plain := f.request(t, http.MethodGet, "/v1/admin/users?include=user_metadata", "rs-plain", nil, http.StatusOK)
	for _, item := range ids(plain) {
		if _, ok := item["reseller"]; ok {
			t.Fatalf("reseller projection must be opt-in: %v", item)
		}
	}
	all := f.request(t, http.MethodGet, "/v1/admin/users?limit=100&include=user_metadata,platform_admins,reseller", "rs-all", nil, http.StatusOK)
	items := ids(all)
	if got := items[reseller["id"].(string)]["reseller"].(map[string]any); got["is_reseller"] != true || got["status"] != "active" || got["parent_scope_id"] != nil {
		t.Fatalf("reseller projection = %v", got)
	}
	if got := items[customerA["id"].(string)]["reseller"].(map[string]any); got["is_reseller"] != false ||
		got["parent_scope_id"] != resellerScope || got["parent_name"] != resellerName {
		t.Fatalf("customer projection = %v", got)
	}
	if got := items[direct["id"].(string)]["reseller"].(map[string]any); got["is_reseller"] != false || got["parent_scope_id"] != nil || got["parent_name"] != nil {
		t.Fatalf("direct projection = %v", got)
	}
	for _, item := range items {
		if item["tenant_id"] == nil && item["reseller"].(map[string]any)["is_reseller"] != false {
			t.Fatalf("platform admin projection = %v", item)
		}
	}

	expect := func(name, query string, want ...map[string]any) {
		t.Helper()
		page := f.request(t, http.MethodGet, "/v1/admin/users?limit=100&include=platform_admins,reseller&"+query, "rs-"+name, nil, http.StatusOK)
		got := ids(page)
		if page["total"] != float64(len(want)) || len(got) != len(want) {
			t.Fatalf("%s: total=%v items=%d want %d", name, page["total"], len(got), len(want))
		}
		for _, user := range want {
			if _, ok := got[user["id"].(string)]; !ok {
				t.Fatalf("%s: missing %v", name, user["username"])
			}
		}
	}
	expect("type-reseller", "type=reseller", reseller)
	expect("type-customer", "type=customer", customerA, customerB)
	expect("type-direct", "type=direct", direct)
	expect("parent-reseller", "parent="+url.QueryEscape(resellerScope), customerA, customerB)
	// parent=none = 不属于任何代理商的租户（代理商自己与直客），平台管理员不在内。
	expect("parent-none", "parent=none", reseller, direct)
	expect("type-and-parent", "type=customer&parent=none")

	// 分页在筛选之后：两位客户每页 1 条，total 恒为 2。
	first := f.request(t, http.MethodGet, "/v1/admin/users?limit=1&page=1&type=customer", "rs-page-1", nil, http.StatusOK)
	second := f.request(t, http.MethodGet, "/v1/admin/users?limit=1&page=2&type=customer", "rs-page-2", nil, http.StatusOK)
	if first["total"] != float64(2) || second["total"] != float64(2) || len(first["items"].([]any)) != 1 || len(second["items"].([]any)) != 1 ||
		first["items"].([]any)[0].(map[string]any)["id"] == second["items"].([]any)[0].(map[string]any)["id"] {
		t.Fatalf("filtered pages = %v / %v", first, second)
	}

	for name, query := range map[string]string{
		"bad-type": "type=agent", "bad-parent": "parent=platform", "dup-type": "type=reseller&type=direct",
		"dup-include": "include=reseller,reseller",
	} {
		f.request(t, http.MethodGet, "/v1/admin/users?"+query, "rs-"+name, nil, http.StatusBadRequest)
	}
}
