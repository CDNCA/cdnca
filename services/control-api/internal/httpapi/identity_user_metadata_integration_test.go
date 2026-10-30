package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"errors"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type userMetadataHTTPFixture struct {
	pool    *pgxpool.Pool
	server  *httptest.Server
	admin   string
	service *identity.Service
}

func newUserMetadataHTTPFixture(t *testing.T) userMetadataHTTPFixture {
	t.Helper()
	pool := isolatedTestPool(t)
	var head, count int
	if err := pool.QueryRow(t.Context(), `SELECT max(version),count(*) FROM schema_migrations`).Scan(&head, &count); err != nil || head < 250 || count != head {
		t.Fatalf("complete migration head=%d count=%d: %v", head, count, err)
	}
	t.Logf("complete migration head=%d", head)
	hash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	if _, err := store.BootstrapPlatformUser(t.Context(), "metadata-admin", "Metadata admin", hash, "metadata-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("metadata-test-signing-key-at-least-thirty-two-bytes", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	api := New(pool, service, Config{CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x6d}, 32)})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	admin, _ := loginWithPassword(t, server.Client(), server.URL, "metadata-admin", testPassword)
	return userMetadataHTTPFixture{pool, server, admin.AccessToken, service}
}

func (f userMetadataHTTPFixture) request(t *testing.T, method, path, key string, body any, status int) map[string]any {
	t.Helper()
	response := identityRequest(t, f.server.Client(), method, f.server.URL+path, body, f.admin, key, "metadata-"+key)
	defer response.Body.Close()
	var result map[string]any
	decodeResponse(t, response, status, &result)
	return result
}

func (f userMetadataHTTPFixture) create(t *testing.T, name string, fields map[string]any, include bool) (map[string]any, map[string]any) {
	t.Helper()
	body := map[string]any{"username": "metadata-" + name, "password": tenantPassword, "display_name": "Metadata user", "email": nil, "phone": nil, "role": identity.UserRoleViewer}
	for key, value := range fields {
		body[key] = value
	}
	path := "/v1/admin/users"
	if include {
		path += "?include=user_metadata"
	}
	return f.request(t, http.MethodPost, path, "create-"+name, body, http.StatusCreated), body
}

func metadataUserPath(user map[string]any) string { return "/v1/admin/users/" + user["id"].(string) }
func metadataUpdateBody(user map[string]any) map[string]any {
	return map[string]any{"expected_revision": user["revision"], "display_name": user["display_name"], "email": user["email"], "phone": user["phone"], "status": user["status"], "role": user["role"]}
}
func assertUserMetadata(t *testing.T, user map[string]any, remark, qq any) {
	t.Helper()
	value, ok := user["metadata"].(map[string]any)
	if len(user) != 16 || !ok || !reflect.DeepEqual(value, map[string]any{"remark": remark, "qq": qq}) {
		t.Fatalf("metadata projection=%#v", user)
	}
}
func assertLegacyMetadataUser(t *testing.T, user map[string]any) {
	t.Helper()
	keys := []string{"id", "display_id", "scope_id", "tenant_id", "username", "display_name", "email", "phone", "status", "role", "group_id", "group_name", "revision", "created_at", "updated_at"}
	if len(user) != len(keys) {
		t.Fatalf("legacy user keys=%v", user)
	}
	for _, key := range keys {
		if _, ok := user[key]; !ok {
			t.Fatalf("legacy key missing: %s", key)
		}
	}
}
func (f userMetadataHTTPFixture) assertDigest(t *testing.T, key, legacyJSON string) {
	t.Helper()
	var actual []byte
	if err := f.pool.QueryRow(t.Context(), `SELECT request_digest FROM identity_write_requests WHERE idempotency_key=$1`, key).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256([]byte(legacyJSON))
	if !bytes.Equal(actual, expected[:]) {
		t.Fatalf("legacy digest changed for %s: got%x want%x", key, actual, expected)
	}
}

func TestIdentityUserMetadataHTTP(t *testing.T) {
	f := newUserMetadataHTTPFixture(t)
	t.Run("legacy shapes digests and historical receipt", func(t *testing.T) {
		user, create := f.create(t, "legacy", nil, false)
		assertLegacyMetadataUser(t, user)
		fields := `{"DisplayName":"Metadata user","Email":"","Phone":""}`
		f.assertDigest(t, "create-legacy", `{"username":"metadata-legacy","fields":`+fields+`,"role":"tenant_viewer"}`)
		assertUserMetadata(t, f.request(t, http.MethodGet, metadataUserPath(user)+"?include=user_metadata", "get-legacy", nil, 200), nil, nil)
		update := metadataUpdateBody(user)
		user = f.request(t, http.MethodPatch, metadataUserPath(user), "legacy-update", update, 200)
		assertLegacyMetadataUser(t, user)
		f.assertDigest(t, "legacy-update", fmt.Sprintf(`{"id":%q,"expected_revision":1,"fields":%s,"status":"active","role":"tenant_viewer"}`, user["id"], fields))
		batch := metadataUpdateBody(user)
		batch["id"], batch["group_id"] = user["id"], nil
		result := f.request(t, http.MethodPatch, "/v1/admin/users", "legacy-batch", []any{batch}, 200)
		assertLegacyMetadataUser(t, result["items"].([]any)[0].(map[string]any))
		f.assertDigest(t, "legacy-batch", fmt.Sprintf(`[{"id":%q,"expected_revision":2,"fields":%s,"status":"active","role":"tenant_viewer"}]`, user["id"], fields))
		page := f.request(t, http.MethodGet, "/v1/admin/users?search=metadata-legacy", "legacy-list", nil, 200)
		assertLegacyMetadataUser(t, page["items"].([]any)[0].(map[string]any))
		// An immutable legacy receipt fixture uses facts from the actual create, without changing its original receipt.
		_, err := f.pool.Exec(t.Context(), `INSERT INTO identity_write_requests(id,actor_user_id,actor_scope_id,operation,idempotency_key,request_digest,secret_hash,resource_id,response_status,response_body,created_at,completed_at)
   SELECT $1,actor_user_id,actor_scope_id,operation,'historical-create',request_digest,secret_hash,resource_id,response_status,response_body-'metadata',created_at,completed_at FROM identity_write_requests WHERE idempotency_key='create-legacy'`, uuid.New())
		if err != nil {
			t.Fatal(err)
		}
		replay := f.request(t, http.MethodPost, "/v1/admin/users?include=user_metadata", "historical-create", create, 201)
		assertLegacyMetadataUser(t, replay)
		if replay["id"] != user["id"] || replay["revision"] != float64(1) {
			t.Fatalf("historical receipt changed: %v", replay)
		}
		auth, _ := loginWithPassword(t, f.server.Client(), f.server.URL, "metadata-legacy", tenantPassword)
		tenant := f
		tenant.admin = auth.AccessToken
		profile := tenant.request(t, http.MethodGet, "/v1/account/profile", "profile", nil, 200)
		profile = tenant.request(t, http.MethodPatch, "/v1/account/profile", "legacy-profile", map[string]any{"expected_revision": profile["revision"], "display_name": "Metadata user", "email": nil, "phone": nil}, 200)
		if len(profile) != 8 || profile["metadata"] != nil {
			t.Fatalf("profile projection=%v", profile)
		}
		f.assertDigest(t, "legacy-profile", `{"expected_revision":3,"fields":`+fields+`}`)
	})
	t.Run("canonical metadata create read update clear and preserve", func(t *testing.T) {
		user, body := f.create(t, "crud", map[string]any{"remark": "  简体/繁體\nEnglish\tZ\rR  ", "qq": "  00Ab_%联络  "}, true)
		assertUserMetadata(t, user, "简体/繁體\nEnglish\tZ\rR", "00Ab_%联络")
		replay := f.request(t, http.MethodPost, "/v1/admin/users", "create-crud", body, 201)
		assertLegacyMetadataUser(t, replay)
		if replay["id"] != user["id"] {
			t.Fatal("create replay changed identity")
		}
		changed := cloneBody(body)
		changed["qq"] = "other"
		result := f.request(t, http.MethodPost, "/v1/admin/users?include=user_metadata", "create-crud", changed, 409)
		if result["error"].(map[string]any)["code"] != "idempotency_conflict" {
			t.Fatal(result)
		}
		update := metadataUpdateBody(user)
		update["remark"] = " 第二版 "
		updated := f.request(t, http.MethodPatch, metadataUserPath(user)+"?include=user_metadata", "update-crud", update, 200)
		assertUserMetadata(t, updated, "第二版", "00Ab_%联络")
		if updated["revision"] != float64(2) {
			t.Fatal(updated)
		}
		replay = f.request(t, http.MethodPatch, metadataUserPath(user)+"?include=user_metadata", "update-crud", update, 200)
		if !reflect.DeepEqual(updated, replay) {
			t.Fatal("update replay differs")
		}
		changed = cloneBody(update)
		changed["qq"] = "another"
		f.request(t, http.MethodPatch, metadataUserPath(user), "update-crud", changed, 409)
		f.request(t, http.MethodPatch, metadataUserPath(user), "stale-crud", update, 409)
		var audits, receipts int
		if err := f.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM audit_events WHERE request_id='metadata-update-crud'),(SELECT count(*) FROM identity_write_requests WHERE idempotency_key='update-crud')`).Scan(&audits, &receipts); err != nil || audits != 1 || receipts != 1 {
			t.Fatalf("exact write evidence=%d/%d %v", audits, receipts, err)
		}
		update = metadataUpdateBody(updated)
		update["remark"], update["qq"] = nil, " \u3000 "
		cleared := f.request(t, http.MethodPatch, metadataUserPath(user)+"?include=user_metadata", "clear-crud", update, 200)
		assertUserMetadata(t, cleared, nil, nil)
		var empty bool
		if err := f.pool.QueryRow(t.Context(), `SELECT remark IS NULL AND qq IS NULL FROM users WHERE id=$1`, user["id"]).Scan(&empty); err != nil || !empty {
			t.Fatalf("clear was not stored as NULL: %v", err)
		}
		update = metadataUpdateBody(cleared)
		update["remark"], update["qq"] = "new", "00-text"
		updated = f.request(t, http.MethodPatch, metadataUserPath(user)+"?include=user_metadata", "set-crud", update, 200)
		batch := metadataUpdateBody(updated)
		batch["id"], batch["group_id"], batch["status"] = user["id"], nil, "disabled"
		result = f.request(t, http.MethodPatch, "/v1/admin/users?include=user_metadata", "batch-preserve", []any{batch}, 200)
		updated = result["items"].([]any)[0].(map[string]any)
		assertUserMetadata(t, updated, "new", "00-text")
		batch = metadataUpdateBody(updated)
		batch["id"], batch["group_id"], batch["status"], batch["remark"], batch["qq"] = user["id"], nil, "active", "batch", nil
		result = f.request(t, http.MethodPatch, "/v1/admin/users?include=user_metadata", "batch-metadata", []any{batch}, 200)
		updated = result["items"].([]any)[0].(map[string]any)
		assertUserMetadata(t, updated, "batch", nil)
		assertUserMetadata(t, f.request(t, http.MethodGet, metadataUserPath(user)+"?include=user_metadata", "reread", nil, 200), "batch", nil)
		var payload string
		if err := f.pool.QueryRow(t.Context(), `SELECT payload::text FROM audit_events WHERE request_id='metadata-update-crud'`).Scan(&payload); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(payload, `"remark_changed": true`) || strings.Contains(payload, "第二版") || strings.Contains(payload, "00Ab") {
			t.Fatalf("audit leaked or missed change: %s", payload)
		}
	})
	t.Run("independent literal filters and out of range totals", func(t *testing.T) {
		first, _ := f.create(t, "filter-a", map[string]any{"remark": "Area Alpha %_", "qq": "00Ab_%"}, true)
		f.create(t, "filter-b", map[string]any{"remark": "Area Beta", "qq": "00Ab_%"}, true)
		f.create(t, "filter-c", map[string]any{"remark": "Area Alpha %_", "qq": "other"}, true)
		cases := []struct {
			values       url.Values
			total, items int
		}{
			{url.Values{"remark": {" area "}}, 3, 3},
			{url.Values{"qq": {" 00aB_% "}}, 2, 2},
			{url.Values{"remark": {"%_"}, "qq": {"_%"}}, 1, 1},
			{url.Values{"remark": {"area alpha"}, "qq": {"OTHER"}}, 1, 1},
			{url.Values{"remark": {"area"}, "qq": {"00ab"}, "search": {"filter-c"}}, 0, 0},
			{url.Values{"remark": {"area"}, "display_id": {first["display_id"].(string)}}, 1, 1},
			{url.Values{"remark": {"area"}, "status": {"disabled"}}, 0, 0},
			{url.Values{"remark": {"area"}, "role": {"tenant_owner"}}, 0, 0},
			{url.Values{"remark": {"area"}, "group_id": {uuid.NewString()}}, 0, 0},
			{url.Values{"remark": {"area"}, "page": {"99"}, "limit": {"1"}}, 3, 0},
			{url.Values{"remark": {"no such remark"}, "page": {"99"}}, 0, 0},
		}
		for i, tc := range cases {
			tc.values.Set("include", "user_metadata")
			page := f.request(t, http.MethodGet, "/v1/admin/users?"+tc.values.Encode(), fmt.Sprintf("filter-%d", i), nil, 200)
			if page["total"] != float64(tc.total) || len(page["items"].([]any)) != tc.items {
				t.Fatalf("filter %v page=%v", tc.values, page)
			}
			for _, item := range page["items"].([]any) {
				if _, ok := item.(map[string]any)["metadata"]; !ok {
					t.Fatal("list lost metadata")
				}
			}
		}
		seen := map[string]bool{}
		for page := 1; page <= 3; page++ {
			result := f.request(t, http.MethodGet, fmt.Sprintf("/v1/admin/users?remark=area&limit=1&page=%d", page), fmt.Sprintf("pagination-%d", page), nil, 200)
			item := result["items"].([]any)[0].(map[string]any)
			assertLegacyMetadataUser(t, item)
			id := item["id"].(string)
			if seen[id] || result["total"] != float64(3) {
				t.Fatal("pagination repeated/lost users")
			}
			seen[id] = true
		}
	})
	t.Run("validation include and permission boundaries", func(t *testing.T) {
		user, _ := f.create(t, "validation", map[string]any{"remark": strings.Repeat("中", 512), "qq": strings.Repeat("😀", 32)}, true)
		assertUserMetadata(t, user, strings.Repeat("中", 512), strings.Repeat("😀", 32))
		for _, field := range []string{"remark", "qq"} {
			for i, value := range []any{true, 13, []string{"bad"}, map[string]string{"bad": "value"}, "x\x00y", "x\x01y", "x\u0085y", "\vtrimmed", "\u0085trimmed", strings.Repeat("界", 513)} {
				body := metadataUpdateBody(user)
				body[field] = value
				f.request(t, http.MethodPatch, metadataUserPath(user)+"?include=user_metadata", fmt.Sprintf("invalid-%s-%d", field, i), body, 400)
			}
		}
		body := metadataUpdateBody(user)
		body["qq"] = "x\ny"
		f.request(t, http.MethodPatch, metadataUserPath(user), "invalid-qq-newline", body, 400)
		body["qq"] = strings.Repeat("界", 33)
		f.request(t, http.MethodPatch, metadataUserPath(user), "invalid-qq-long", body, 400)
		for _, route := range []struct{ method, path string }{{http.MethodGet, "/v1/admin/users"}, {http.MethodPost, "/v1/admin/users"}, {http.MethodPatch, "/v1/admin/users"}, {http.MethodGet, metadataUserPath(user)}, {http.MethodPatch, metadataUserPath(user)}} {
			for _, query := range []string{"include=unknown", "include=", "include=user_metadata&include=user_metadata", "include=user_metadata;ignored"} {
				f.request(t, route.method, route.path+"?"+query, "invalid-include", nil, 400)
			}
		}
		for _, query := range []string{"remark=a&remark=b", "qq=a&qq=b", "qq=" + url.QueryEscape("a\tb"), "qq=" + url.QueryEscape("\ta"), "remark=" + url.QueryEscape("\va"), "remark=" + url.QueryEscape("a\x01b")} {
			f.request(t, http.MethodGet, "/v1/admin/users?"+query, "invalid-query", nil, 400)
		}
		var receipts int
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM identity_write_requests WHERE idempotency_key LIKE 'invalid-%'`).Scan(&receipts); err != nil || receipts != 0 {
			t.Fatalf("invalid write left %d receipts: %v", receipts, err)
		}
		got := f.request(t, http.MethodGet, metadataUserPath(user)+"?include=user_metadata", "unchanged-invalid", nil, 200)
		if !reflect.DeepEqual(got, user) {
			t.Fatal("invalid write changed user")
		}
		auth, _ := loginWithPassword(t, f.server.Client(), f.server.URL, "metadata-validation", tenantPassword)
		tenant := f
		tenant.admin = auth.AccessToken
		for _, route := range []struct {
			method, path string
			body         any
		}{
			{http.MethodGet, "/v1/admin/users?include=user_metadata", nil}, {http.MethodGet, metadataUserPath(user) + "?include=user_metadata", nil},
			{http.MethodPost, "/v1/admin/users?include=user_metadata", map[string]any{}}, {http.MethodPatch, metadataUserPath(user) + "?include=user_metadata", metadataUpdateBody(user)},
			{http.MethodPatch, "/v1/admin/users?include=user_metadata", []any{}},
		} {
			result := tenant.request(t, route.method, route.path, "tenant-denied", route.body, 403)
			if result["error"].(map[string]any)["code"] != "permission_denied" {
				t.Fatal(result)
			}
		}
		for _, path := range []string{"/v1/auth/me", "/v1/account/profile"} {
			result := tenant.request(t, http.MethodGet, path, "self-no-metadata", nil, 200)
			raw, _ := json.Marshal(result)
			if bytes.Contains(raw, []byte(`"metadata"`)) || bytes.Contains(raw, []byte(`"remark"`)) || bytes.Contains(raw, []byte(`"qq"`)) {
				t.Fatalf("metadata leaked to %s", path)
			}
		}
		for _, field := range []string{"remark", "qq"} {
			body := map[string]any{"expected_revision": user["revision"], "display_name": "Metadata user", "email": nil, "phone": nil, field: "private"}
			tenant.request(t, http.MethodPatch, "/v1/account/profile", "self-metadata-denied", body, 400)
		}
	})
	t.Run("concurrent CAS and atomic batch metadata", func(t *testing.T) {
		first, _ := f.create(t, "atomic-first", map[string]any{"remark": "before", "qq": "retain"}, true)
		second, _ := f.create(t, "atomic-second", map[string]any{"remark": "second", "qq": "retain"}, true)
		var wait sync.WaitGroup
		statuses := make(chan int, 2)
		for i := 0; i < 2; i++ {
			body := metadataUpdateBody(first)
			body["remark"] = fmt.Sprintf("winner-%d", i)
			wait.Add(1)
			go func(index int, body map[string]any) {
				defer wait.Done()
				response := identityRequest(t, f.server.Client(), http.MethodPatch, f.server.URL+metadataUserPath(first)+"?include=user_metadata", body, f.admin, fmt.Sprintf("cas-%d", index), fmt.Sprintf("cas-%d", index))
				defer response.Body.Close()
				statuses <- response.StatusCode
			}(i, body)
		}
		wait.Wait()
		close(statuses)
		counts := map[int]int{}
		for status := range statuses {
			counts[status]++
		}
		if counts[200] != 1 || counts[409] != 1 {
			t.Fatalf("CAS status counts=%v", counts)
		}
		current := f.request(t, http.MethodGet, metadataUserPath(first)+"?include=user_metadata", "cas-read", nil, 200)
		left := metadataUpdateBody(current)
		left["id"], left["group_id"], left["remark"] = first["id"], nil, "batch-winner"
		right := metadataUpdateBody(second)
		right["id"], right["group_id"], right["expected_revision"], right["qq"] = second["id"], nil, 0, "new"
		f.request(t, http.MethodPatch, "/v1/admin/users?include=user_metadata", "batch-invalid", []any{left, right}, 400)
		right["expected_revision"] = 2
		f.request(t, http.MethodPatch, "/v1/admin/users?include=user_metadata", "batch-stale", []any{left, right}, 409)
		if got := f.request(t, http.MethodGet, metadataUserPath(first)+"?include=user_metadata", "after-batch-failure", nil, 200); !reflect.DeepEqual(got, current) {
			t.Fatal("batch partially changed first user")
		}
		right["expected_revision"] = 1
		result := f.request(t, http.MethodPatch, "/v1/admin/users?include=user_metadata", "batch-success", []any{left, right}, 200)
		replay := f.request(t, http.MethodPatch, "/v1/admin/users?include=user_metadata", "batch-success", []any{left, right}, 200)
		if !reflect.DeepEqual(result, replay) {
			t.Fatal("batch replay changed result")
		}
		right["qq"] = "changed"
		f.request(t, http.MethodPatch, "/v1/admin/users", "batch-success", []any{left, right}, 409)
		items := result["items"].([]any)
		assertUserMetadata(t, items[0].(map[string]any), "batch-winner", "retain")
		assertUserMetadata(t, items[1].(map[string]any), "second", "new")
	})
	t.Run("platform member without user permission is denied", func(t *testing.T) {
		_, err := f.pool.Exec(t.Context(), `WITH inserted AS (
		 INSERT INTO users(id,username,display_name,password_hash)
		 SELECT $1,'metadata-reader','Metadata reader',password_hash FROM users WHERE username='metadata-admin' RETURNING id
		) INSERT INTO memberships(scope_id,user_id) SELECT scope.id,inserted.id FROM inserted CROSS JOIN access_scopes scope WHERE scope.kind='platform'`, uuid.New())
		if err != nil {
			t.Fatal(err)
		}
		auth, _ := loginWithPassword(t, f.server.Client(), f.server.URL, "metadata-reader", testPassword)
		reader := f
		reader.admin = auth.AccessToken
		reader.request(t, http.MethodGet, "/v1/admin/users?include=user_metadata", "reader-list", nil, 403)
		reader.request(t, http.MethodPost, "/v1/admin/users?include=user_metadata", "reader-create", map[string]any{}, 403)
	})

	t.Run("password reset exclusion and expanded response", func(t *testing.T) {
		user, _ := f.create(t, "reset", map[string]any{"remark": "reset notes", "qq": "00reset"}, true)
		stepUp := &httpManagedPasswordResetStepUp{}
		f.service.SetManagedPasswordResetStepUpConsumer(stepUp)
		body := map[string]any{"expected_revision": user["revision"], "password_reset": map[string]any{"tenant_scope_id": user["scope_id"], "new_password": newTenantPassword, "step_up_token": "metadata-reset-proof"}}
		for _, field := range []string{"remark", "qq"} {
			mixed := cloneBody(body)
			mixed[field] = nil
			result := f.request(t, http.MethodPatch, metadataUserPath(user)+"?include=user_metadata", "mixed-reset-"+field, mixed, 400)
			if result["error"].(map[string]any)["code"] != "validation_error" {
				t.Fatal(result)
			}
		}
		if stepUp.calls != 0 {
			t.Fatal("mixed reset consumed proof")
		}
		updated := f.request(t, http.MethodPatch, metadataUserPath(user)+"?include=user_metadata", "metadata-reset", body, 200)
		assertUserMetadata(t, updated, "reset notes", "00reset")
		assertLegacyMetadataUser(t, f.request(t, http.MethodPatch, metadataUserPath(user), "metadata-reset", body, 200))
		if stepUp.calls != 1 {
			t.Fatal("reset replay consumed second proof")
		}
		loginWithPassword(t, f.server.Client(), f.server.URL, "metadata-reset", newTenantPassword)
	})
}

func TestIdentityUserMetadataMigration(t *testing.T) {
	// This test exercises migration 251 with only 1..251 loaded: rolling the
	// release head back crosses migration 268's one-way down gate (P2682).
	pool := migrationRoundTripPool(t, 251)
	atMetadataHead := func() {
		t.Helper()
		var head int
		if err := pool.QueryRow(t.Context(), `SELECT max(version) FROM schema_migrations`).Scan(&head); err != nil || head != 251 {
			t.Fatalf("metadata migration head=%d: %v", head, err)
		}
	}
	atMetadataHead()
	if err := database.Migrate(t.Context(), pool, "down"); err != nil {
		t.Fatal(err)
	}
	// The old binary's INSERT omits both new columns; a pre-upgrade user remains valid.
	id := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'metadata-before-upgrade','Before upgrade','unused')`, id); err != nil {
		t.Fatal(err)
	}
	if err := databasetest.MigrateThrough(t.Context(), pool, "up", 251); err != nil {
		t.Fatal(err)
	}
	atMetadataHead()
	var empty bool
	if err := pool.QueryRow(t.Context(), `SELECT remark IS NULL AND qq IS NULL FROM users WHERE id=$1`, id).Scan(&empty); err != nil || !empty {
		t.Fatalf("migration changed legacy user: %v", err)
	}
	for _, field := range []string{"remark", "qq"} {
		for _, value := range []string{"", " padded ", "\u3000padded", "x\x01y", "x\u0085y", strings.Repeat("字", 513)} {
			_, err := pool.Exec(t.Context(), `UPDATE users SET `+field+`=$2 WHERE id=$1`, id, value)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
				t.Fatalf("DB %s=%q constraint: %v", field, value, err)
			}
		}
	}
	for _, value := range []string{"x\ny", strings.Repeat("界", 33)} {
		if _, err := pool.Exec(t.Context(), `UPDATE users SET qq=$2 WHERE id=$1`, id, value); err == nil {
			t.Fatalf("DB accepted QQ %q", value)
		}
	}
	if _, err := pool.Exec(t.Context(), `UPDATE users SET remark=$2,qq=$3 WHERE id=$1`, id, "简体\t繁體\nEnglish\rnext", "00Text😀"); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(t.Context(), pool, "down"); err == nil {
		t.Fatal("rollback discarded user metadata")
	}
	var head int
	if err := pool.QueryRow(t.Context(), `SELECT max(version) FROM schema_migrations`).Scan(&head); err != nil || head != 251 {
		t.Fatalf("rollback changed head=%d %v", head, err)
	}
	var remark, qq string
	if err := pool.QueryRow(t.Context(), `UPDATE users SET display_name='Old client update' WHERE id=$1 RETURNING remark,qq`, id).Scan(&remark, &qq); err != nil || remark != "简体\t繁體\nEnglish\rnext" || qq != "00Text😀" {
		t.Fatalf("old SQL lost metadata: %s/%s %v", remark, qq, err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE users SET remark=NULL,qq=NULL WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(t.Context(), pool, "down"); err != nil {
		t.Fatal(err)
	}
	if err := databasetest.MigrateThrough(t.Context(), pool, "up", 251); err != nil {
		t.Fatal(err)
	}
	atMetadataHead()
}
