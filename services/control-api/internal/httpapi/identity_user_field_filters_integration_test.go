package httpapi

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestIdentityUserFieldFiltersHTTP(t *testing.T) {
	f := newUserMetadataHTTPFixture(t)
	group := f.request(t, http.MethodPost, "/v1/admin/user-groups", "filter-group", map[string]any{"name": "Filter group"}, http.StatusCreated)
	first, _ := f.create(t, "field-first", map[string]any{
		"username": "filter_alpha", "display_name": "Bravo %_ 简體", "email": "Target_%@Example.test", "phone": "+8613800000011",
		"remark": "North %_", "qq": "00Contact", "group_id": group["id"], "role": identity.UserRoleOwner,
	}, true)
	second, _ := f.create(t, "field-second", map[string]any{
		"username": "filter_beta", "display_name": "filter_alpha target_%@example.test +8613800000011",
		"email": "other@example.test", "phone": "+8613800000022",
	}, false)
	third, _ := f.create(t, "field-third", map[string]any{
		"username": "filter.alpha", "display_name": "Bravo ANY简體", "email": nil, "phone": nil,
	}, false)
	ids := func(users ...map[string]any) []string {
		result := make([]string, 0, len(users))
		for _, user := range users {
			result = append(result, user["id"].(string))
		}
		slices.Sort(result)
		return result
	}
	check := func(t *testing.T, query url.Values, expected []string, total int) {
		t.Helper()
		page := f.request(t, http.MethodGet, "/v1/admin/users?"+query.Encode(), "field-filter", nil, http.StatusOK)
		items := page["items"].([]any)
		actual := make([]string, 0, len(items))
		for _, raw := range items {
			item := raw.(map[string]any)
			actual = append(actual, item["id"].(string))
			if query.Get("include") == "user_metadata" {
				assertUserMetadata(t, item, "North %_", "00Contact")
			} else {
				assertLegacyMetadataUser(t, item)
			}
		}
		slices.Sort(actual)
		if page["total"] != float64(total) || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("query=%v total=%v IDs=%v; want total=%d IDs=%v", query, page["total"], actual, total, expected)
		}
	}

	t.Run("separate columns and AND predicates", func(t *testing.T) {
		cases := []struct {
			name     string
			query    url.Values
			expected []string
		}{
			{"username excludes display name", url.Values{"username": {"filter_alpha"}}, ids(first)},
			{"display name excludes username", url.Values{"display_name": {"filter_alpha"}}, ids(second)},
			{"email excludes display name", url.Values{"email": {"target_%"}}, ids(first)},
			{"phone excludes display name", url.Values{"phone": {"0000011"}}, ids(first)},
			{"four independent filters", url.Values{"username": {"ALPHA"}, "display_name": {"bravo"}, "email": {"TARGET_%"}, "phone": {"13800000011"}}, ids(first)},
			{"cross user AND does not match", url.Values{"username": {"filter_alpha"}, "email": {"other"}}, ids()},
			{"cross column AND does not match", url.Values{"username": {"filter_beta"}, "email": {"target_%"}, "phone": {"0000011"}}, ids()},
			{"legacy search still finds display name", url.Values{"search": {"filter_alpha"}}, ids(first, second)},
			{"legacy concatenation remains compatible", url.Values{"search": {"filter_alpha Bravo"}}, ids(first)},
			{"legacy search intersects", url.Values{"username": {"filter"}, "search": {"ANY简體"}}, ids(third)},
			{"underscore is literal", url.Values{"username": {"filter_"}}, ids(first, second)},
			{"percent is literal", url.Values{"display_name": {"Bravo %"}}, ids(first)},
			{"percent underscore is literal", url.Values{"email": {"_%"}}, ids(first)},
			{"leading trailing Unicode spaces", url.Values{"username": {"\u3000FILTER_ALPHA\u00a0"}, "display_name": {"  bRaVo %_  "}, "email": {" TARGET_% "}, "phone": {" 0000011 "}}, ids(first)},
			{"empty fields ignore SQL NULL", url.Values{"username": {" "}, "display_name": {"\u3000"}, "email": {""}, "phone": {"\u00a0"}}, ids(first, second, third)},
			{"nonempty email excludes NULL", url.Values{"email": {"example.test"}}, ids(first, second)},
			{"nonempty phone excludes NULL", url.Values{"phone": {"138"}}, ids(first, second)},
			{"nonmatching literal text", url.Values{"phone": {"null"}}, ids()},
			{"all existing predicates intersect", url.Values{"username": {"filter_alpha"}, "display_name": {"Bravo"}, "email": {"example.test"}, "phone": {"0011"}, "search": {"简體"}, "remark": {"north %_"}, "qq": {"00contact"}, "display_id": {first["display_id"].(string)}, "role": {identity.UserRoleOwner}, "status": {identity.UserStatusActive}, "group_id": {group["id"].(string)}, "include": {"user_metadata"}}, ids(first)},
			{"status intersection", url.Values{"username": {"filter_alpha"}, "status": {identity.UserStatusDisabled}}, ids()},
			{"role intersection", url.Values{"username": {"filter_alpha"}, "role": {identity.UserRoleViewer}}, ids()},
			{"group intersection", url.Values{"username": {"filter_alpha"}, "group_id": {uuid.NewString()}}, ids()},
			{"display id intersection", url.Values{"username": {"filter_alpha"}, "display_id": {second["display_id"].(string)}}, ids()},
			{"remark intersection", url.Values{"username": {"filter_alpha"}, "remark": {"south"}}, ids()},
			{"QQ intersection", url.Values{"username": {"filter_alpha"}, "qq": {"another"}}, ids()},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) { check(t, tc.query, tc.expected, len(tc.expected)) })
		}
	})
	t.Run("out of range and stable pagination totals", func(t *testing.T) {
		check(t, url.Values{"display_name": {"Bravo"}, "page": {"99"}, "limit": {"1"}}, ids(), 2)
		check(t, url.Values{"email": {"absent"}, "page": {"99"}, "limit": {"1"}}, ids(), 0)
		var seen []string
		for page := 1; page <= 2; page++ {
			result := f.request(t, http.MethodGet, fmt.Sprintf("/v1/admin/users?display_name=Bravo&limit=1&page=%d", page), "field-page", nil, 200)
			items := result["items"].([]any)
			if len(items) != 1 || result["total"] != float64(2) {
				t.Fatal(result)
			}
			seen = append(seen, items[0].(map[string]any)["id"].(string))
		}
		slices.Sort(seen)
		if !reflect.DeepEqual(seen, ids(first, third)) {
			t.Fatalf("pagination repeated or lost users: %v", seen)
		}
	})
	t.Run("raw control Unicode length and query shape validation", func(t *testing.T) {
		for _, field := range []string{"username", "display_name", "email", "phone"} {
			for _, value := range []string{strings.Repeat("😀", 128), "\u3000" + strings.Repeat("界", 128) + "\u00a0"} {
				check(t, url.Values{field: {value}}, ids(), 0)
			}
			for _, value := range []string{strings.Repeat("😀", 129), "\u3000" + strings.Repeat("界", 129), "\x00", "a\x01b", "\talpha", "alpha\n", "\ralpha", "\valpha", "\u0085alpha", "a\u007fb", "a\u009fb", string([]byte{0xff})} {
				f.request(t, http.MethodGet, "/v1/admin/users?"+url.Values{field: {value}}.Encode(), "field-invalid", nil, 400)
			}
			for _, query := range []string{field + "=a&" + field + "=a", field + "=a&" + field + "=b", field + "[]=a", field + "[value]=a", field + "=%ZZ"} {
				f.request(t, http.MethodGet, "/v1/admin/users?"+query, "field-query-invalid", nil, 400)
			}
		}
		f.request(t, http.MethodGet, "/v1/admin/users?unknown=value", "field-unknown", nil, 400)
		unchanged := f.request(t, http.MethodGet, metadataUserPath(first)+"?include=user_metadata", "field-unchanged", nil, 200)
		if !reflect.DeepEqual(unchanged, first) {
			t.Fatal("read filters changed user data")
		}
	})
	t.Run("permission checks prevent reading managed users", func(t *testing.T) {
		auth, _ := loginWithPassword(t, f.server.Client(), f.server.URL, "filter_alpha", tenantPassword)
		tenant := f
		tenant.admin = auth.AccessToken
		tenant.request(t, http.MethodGet, "/v1/admin/users?username=filter_alpha&email=target", "field-tenant-denied", nil, 403)
		_, err := f.pool.Exec(t.Context(), `WITH inserted AS (
		 INSERT INTO users(id,username,display_name,password_hash)
		 SELECT $1,'filter-reader','Filter reader',password_hash FROM users WHERE username='metadata-admin' RETURNING id
		) INSERT INTO memberships(scope_id,user_id) SELECT scope.id,inserted.id FROM inserted CROSS JOIN access_scopes scope WHERE scope.kind='platform'`, uuid.New())
		if err != nil {
			t.Fatal(err)
		}
		auth, _ = loginWithPassword(t, f.server.Client(), f.server.URL, "filter-reader", testPassword)
		reader := f
		reader.admin = auth.AccessToken
		reader.request(t, http.MethodGet, "/v1/admin/users?username=filter_alpha", "field-reader-denied", nil, 403)
		anonymous := f
		anonymous.admin = ""
		anonymous.request(t, http.MethodGet, "/v1/admin/users?username=filter_alpha", "field-anonymous-denied", nil, 401)
	})
}
