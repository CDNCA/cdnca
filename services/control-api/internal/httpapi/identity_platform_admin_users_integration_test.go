package httpapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// addPlatformUser inserts an extra platform-scope account holding the named
// system role; it reuses the bootstrap administrator's password hash.
func addPlatformUser(t *testing.T, f userMetadataHTTPFixture, username, role string, permissions ...string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.pool.Exec(t.Context(), `
		WITH inserted AS (
			INSERT INTO users(id,username,display_name,password_hash)
			SELECT $1,$2,$2,password_hash FROM users WHERE username='metadata-admin' RETURNING id
		) INSERT INTO memberships(scope_id,user_id)
		SELECT scope.id,inserted.id FROM inserted CROSS JOIN access_scopes scope WHERE scope.kind='platform'`,
		id, username); err != nil {
		t.Fatal(err)
	}
	if role == identity.UserRolePlatformAdmin {
		if _, err := f.pool.Exec(t.Context(), `
			WITH scope AS (SELECT id FROM access_scopes WHERE kind='platform'),
			role AS (
				INSERT INTO roles(id,scope_id,name,description,system_role)
				SELECT $1,scope.id,'platform_admin','test platform admin',true FROM scope RETURNING id
			) INSERT INTO role_permissions(role_id,permission_name) SELECT role.id,unnest($2::text[]) FROM role`,
			uuid.New(), permissions); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.pool.Exec(t.Context(), `
		INSERT INTO role_assignments(scope_id,user_id,role_id)
		SELECT r.scope_id,$1,r.id FROM roles r JOIN access_scopes scope ON scope.id=r.scope_id AND scope.kind='platform'
		WHERE r.name=$2`, id, role); err != nil {
		t.Fatal(err)
	}
	return id
}

func platformUserByName(t *testing.T, f userMetadataHTTPFixture, username string) map[string]any {
	t.Helper()
	page := f.request(t, http.MethodGet, "/v1/admin/users?include=user_metadata,platform_admins&username="+url.QueryEscape(username),
		"platform-lookup-"+username, nil, http.StatusOK)
	for _, raw := range page["items"].([]any) {
		if item := raw.(map[string]any); item["username"] == username {
			return item
		}
	}
	t.Fatalf("user %q not listed: %v", username, page)
	return nil
}

func platformUserUpdateBody(user map[string]any, status, role string) map[string]any {
	return map[string]any{
		"expected_revision": user["revision"], "display_name": user["display_name"],
		"email": user["email"], "phone": user["phone"], "status": status, "role": role,
	}
}

func TestManagedUserListIncludesPlatformAdministrators(t *testing.T) {
	f := newUserMetadataHTTPFixture(t)
	tenant, _ := f.create(t, "platform-list-tenant", map[string]any{"role": identity.UserRoleOwner}, true)

	// Owner pickers keep the tenant-only default projection.
	tenantOnly := f.request(t, http.MethodGet, "/v1/admin/users", "platform-default", nil, http.StatusOK)
	if tenantOnly["total"] != float64(1) || tenantOnly["items"].([]any)[0].(map[string]any)["id"] != tenant["id"] {
		t.Fatalf("default list must stay tenant-only: %v", tenantOnly)
	}
	page := f.request(t, http.MethodGet, "/v1/admin/users?include=user_metadata,user_verification,platform_admins", "platform-list", nil, http.StatusOK)
	items := page["items"].([]any)
	if page["total"] != float64(2) || len(items) != 2 {
		t.Fatalf("list total/items = %v", page)
	}
	if items[0].(map[string]any)["id"] != tenant["id"] {
		t.Fatalf("newest user must stay first: %v", items)
	}
	admin := items[1].(map[string]any)
	if admin["username"] != "metadata-admin" || admin["role"] != identity.UserRolePlatformOwner ||
		admin["tenant_id"] != nil || admin["status"] != identity.UserStatusActive || admin["group_id"] != nil {
		t.Fatalf("platform administrator row = %v", admin)
	}
	if len(admin) != 17 {
		t.Fatalf("platform administrator row must keep the list shape: %v", admin)
	}

	for _, tc := range []struct {
		query string
		total float64
	}{
		{"role=platform_owner", 1},
		{"role=tenant_owner", 1},
		{"role=tenant_viewer", 0},
		{"username=metadata-admin", 1},
		{"display_id=" + admin["display_id"].(string), 1},
		{"status=disabled", 0},
		{"group_id=" + uuid.NewString(), 0},
		{"real_name_status=unverified", 2},
		{"limit=1&page=2", 2},
	} {
		result := f.request(t, http.MethodGet, "/v1/admin/users?include=platform_admins&"+tc.query, "platform-filter", nil, http.StatusOK)
		if result["total"] != tc.total {
			t.Fatalf("query %s total = %v, want %v", tc.query, result["total"], tc.total)
		}
	}
	paged := f.request(t, http.MethodGet, "/v1/admin/users?include=platform_admins&limit=1&page=2", "platform-page", nil, http.StatusOK)
	if paged["items"].([]any)[0].(map[string]any)["id"] != admin["id"] {
		t.Fatalf("second page = %v", paged)
	}
	f.request(t, http.MethodGet, "/v1/admin/users?include=platform_admins,platform_admins", "platform-dup", nil, http.StatusBadRequest)
	got := f.request(t, http.MethodGet, "/v1/admin/users/"+admin["id"].(string)+"?include=user_metadata", "platform-get", nil, http.StatusOK)
	if got["role"] != identity.UserRolePlatformOwner || got["tenant_id"] != nil {
		t.Fatalf("platform administrator detail = %v", got)
	}
}

// platformSend issues an identity write as the given bearer and returns the
// HTTP status plus the API error code, if any.
func platformSend(t *testing.T, f userMetadataHTTPFixture, token, method, path, key string, body any) (int, string) {
	t.Helper()
	response := identityRequest(t, f.server.Client(), method, f.server.URL+path, body, token, key, "platform-"+key)
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return response.StatusCode, ""
	}
	var envelope testErrorEnvelope
	_ = json.NewDecoder(response.Body).Decode(&envelope)
	return response.StatusCode, envelope.Error.Code
}

func expectSend(t *testing.T, label string, status int, code string, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus || code != wantCode {
		t.Fatalf("%s = %d %q, want %d %q", label, status, code, wantStatus, wantCode)
	}
}

func TestManagedUserPlatformAdministratorProtections(t *testing.T) {
	f := newUserMetadataHTTPFixture(t)
	admin := platformUserByName(t, f, "metadata-admin")
	adminPath := "/v1/admin/users/" + admin["id"].(string)
	revision := map[string]any{"expected_revision": admin["revision"]}

	status, code := platformSend(t, f, f.admin, http.MethodDelete, adminPath, "self-delete", revision)
	expectSend(t, "delete self", status, code, http.StatusConflict, "user_protected")
	status, code = platformSend(t, f, f.admin, http.MethodPatch, adminPath, "self-demote",
		platformUserUpdateBody(admin, identity.UserStatusActive, identity.UserRolePlatformAdmin))
	expectSend(t, "change own administrator type", status, code, http.StatusConflict, "user_protected")
	status, code = platformSend(t, f, f.admin, http.MethodPatch, adminPath, "self-tenant-role",
		platformUserUpdateBody(admin, identity.UserStatusActive, identity.UserRoleViewer))
	expectSend(t, "demote self to tenant viewer", status, code, http.StatusConflict, "user_protected")
	group := f.request(t, http.MethodPost, "/v1/admin/user-groups", "platform-group", map[string]any{"name": "Platform group"}, http.StatusCreated)
	grouped := platformUserUpdateBody(admin, identity.UserStatusActive, identity.UserRolePlatformOwner)
	grouped["group_id"] = group["id"]
	status, code = platformSend(t, f, f.admin, http.MethodPatch, adminPath, "self-group", grouped)
	expectSend(t, "group platform administrator", status, code, http.StatusConflict, "user_protected")
	status, code = platformSend(t, f, f.admin, http.MethodPatch, adminPath, "self-disable-last",
		platformUserUpdateBody(admin, identity.UserStatusDisabled, identity.UserRolePlatformOwner))
	expectSend(t, "disable last platform owner", status, code, http.StatusConflict, "user_protected")
	status, code = platformSend(t, f, f.admin, http.MethodPatch, "/v1/admin/users", "batch-disable-last",
		[]map[string]any{{"id": admin["id"], "expected_revision": admin["revision"], "display_name": admin["display_name"],
			"email": nil, "phone": nil, "status": identity.UserStatusDisabled, "role": identity.UserRolePlatformOwner, "group_id": nil}})
	expectSend(t, "batch disable last platform owner", status, code, http.StatusConflict, "user_protected")

	// Profile fields stay editable and the revision guard still applies.
	edited := platformUserUpdateBody(admin, identity.UserStatusActive, identity.UserRolePlatformOwner)
	edited["phone"], edited["remark"] = "+8613800000099", "platform remark"
	updated := f.request(t, http.MethodPatch, adminPath+"?include=user_metadata", "self-profile", edited, http.StatusOK)
	if updated["phone"] != "+8613800000099" || updated["role"] != identity.UserRolePlatformOwner || updated["revision"] != float64(2) {
		t.Fatalf("platform administrator profile update = %v", updated)
	}
	status, code = platformSend(t, f, f.admin, http.MethodPatch, adminPath, "self-stale", edited)
	expectSend(t, "stale platform administrator update", status, code, http.StatusConflict, "version_conflict")

	// A tenant user cannot be promoted into the platform role family.
	tenant, _ := f.create(t, "platform-protect-tenant", nil, false)
	status, code = platformSend(t, f, f.admin, http.MethodPatch, metadataUserPath(tenant), "tenant-promote",
		platformUserUpdateBody(tenant, identity.UserStatusActive, identity.UserRolePlatformOwner))
	expectSend(t, "promote tenant user", status, code, http.StatusBadRequest, "validation_error")

	// A platform_admin manager may not remove the only platform_owner either.
	addPlatformUser(t, f, "platform-manager", identity.UserRolePlatformAdmin, "identity.users.manage")
	manager, _ := loginWithPassword(t, f.server.Client(), f.server.URL, "platform-manager", testPassword)
	admin = platformUserByName(t, f, "metadata-admin")
	status, code = platformSend(t, f, manager.AccessToken, http.MethodDelete, adminPath, "manager-delete-last",
		map[string]any{"expected_revision": admin["revision"]})
	expectSend(t, "delete last platform owner", status, code, http.StatusConflict, "user_protected")
	status, code = platformSend(t, f, manager.AccessToken, http.MethodPatch, adminPath, "manager-disable-last",
		platformUserUpdateBody(admin, identity.UserStatusDisabled, identity.UserRolePlatformOwner))
	expectSend(t, "disable last platform owner as manager", status, code, http.StatusConflict, "user_protected")
	managerRow := platformUserByName(t, f, "platform-manager")
	if managerRow["role"] != identity.UserRolePlatformAdmin || managerRow["tenant_id"] != nil {
		t.Fatalf("platform manager row = %v", managerRow)
	}

	// With a second platform_owner the first may be disabled and deleted.
	addPlatformUser(t, f, "platform-owner-two", identity.UserRolePlatformOwner)
	second, _ := loginWithPassword(t, f.server.Client(), f.server.URL, "platform-owner-two", testPassword)
	secondRow := platformUserByName(t, f, "platform-owner-two")
	status, code = platformSend(t, f, f.admin, http.MethodPatch, "/v1/admin/users", "batch-disable-both",
		[]map[string]any{
			{"id": admin["id"], "expected_revision": admin["revision"], "display_name": admin["display_name"], "email": nil,
				"phone": admin["phone"], "status": identity.UserStatusDisabled, "role": identity.UserRolePlatformOwner, "group_id": nil},
			{"id": secondRow["id"], "expected_revision": secondRow["revision"], "display_name": secondRow["display_name"], "email": nil,
				"phone": nil, "status": identity.UserStatusDisabled, "role": identity.UserRolePlatformOwner, "group_id": nil},
		})
	expectSend(t, "batch disable every platform owner", status, code, http.StatusConflict, "user_protected")
	status, code = platformSend(t, f, f.admin, http.MethodPatch, adminPath, "self-disable",
		platformUserUpdateBody(admin, identity.UserStatusDisabled, identity.UserRolePlatformOwner))
	expectSend(t, "disable self with another owner", status, code, http.StatusOK, "")
	f.admin = second.AccessToken
	admin = platformUserByName(t, f, "metadata-admin")
	if admin["status"] != identity.UserStatusDisabled {
		t.Fatalf("disabled platform owner row = %v", admin)
	}
	secondPath := "/v1/admin/users/" + secondRow["id"].(string)
	status, code = platformSend(t, f, f.admin, http.MethodPatch, secondPath, "second-disable-last",
		platformUserUpdateBody(secondRow, identity.UserStatusDisabled, identity.UserRolePlatformOwner))
	expectSend(t, "disable the remaining active owner", status, code, http.StatusConflict, "user_protected")
	status, code = platformSend(t, f, f.admin, http.MethodDelete, secondPath, "second-self-delete",
		map[string]any{"expected_revision": secondRow["revision"]})
	expectSend(t, "delete self as second owner", status, code, http.StatusConflict, "user_protected")
	status, code = platformSend(t, f, f.admin, http.MethodDelete, adminPath, "delete-first-owner",
		map[string]any{"expected_revision": admin["revision"]})
	expectSend(t, "delete disabled first owner", status, code, http.StatusNoContent, "")
	remaining := f.request(t, http.MethodGet, "/v1/admin/users?include=platform_admins&role=platform_owner", "platform-remaining", nil, http.StatusOK)
	if remaining["total"] != float64(1) || remaining["items"].([]any)[0].(map[string]any)["id"] != secondRow["id"] {
		t.Fatalf("remaining platform owners = %v", remaining)
	}
}
