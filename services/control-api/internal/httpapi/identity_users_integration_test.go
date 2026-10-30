package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

const (
	tenantPassword    = "tenant-password-long-enough"
	newTenantPassword = "new-tenant-password-long-enough"
)

func TestIdentityUserManagementHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	adminHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	bootstrap, err := store.BootstrapPlatformUser(
		context.Background(), "admin", "Platform Admin", adminHash, "users-bootstrap",
	)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("identity-users-test-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CookieSecure: false}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	admin, _ := loginWithPassword(t, client, server.URL, "admin", testPassword)

	aliceBody := map[string]any{
		"username": "alice", "password": tenantPassword, "display_name": "Alice User",
		"email": "alice@example.com", "phone": "+8613800000000", "role": identity.UserRoleOwner,
	}
	alice := createManagedUser(t, client, server.URL, admin.AccessToken, "create-alice", aliceBody)
	if alice.DisplayID == "" || alice.ScopeID == bootstrap.ScopeID || alice.TenantID.String() == "" ||
		alice.Status != identity.UserStatusActive || alice.Revision != 1 {
		t.Fatalf("created Alice = %#v", alice)
	}

	t.Run("create is idempotent and password-sensitive", func(t *testing.T) {
		replayed := createManagedUser(t, client, server.URL, admin.AccessToken, "create-alice", aliceBody)
		if replayed.ID != alice.ID || replayed.ScopeID != alice.ScopeID {
			t.Fatalf("replayed user = %#v, original = %#v", replayed, alice)
		}
		changedPassword := cloneBody(aliceBody)
		changedPassword["password"] = "different-password-long-enough"
		response := identityRequest(
			t, client, http.MethodPost, server.URL+"/v1/admin/users", changedPassword,
			admin.AccessToken, "create-alice", "create-alice-password-conflict",
		)
		assertError(t, response, http.StatusConflict, "idempotency_conflict", "create-alice-password-conflict")
		response.Body.Close()
		var users, tenants int
		if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM users WHERE username = 'alice'").Scan(&users); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM tenants WHERE id = $1", alice.TenantID).Scan(&tenants); err != nil {
			t.Fatal(err)
		}
		if users != 1 || tenants != 1 {
			t.Fatalf("idempotent create counts = users:%d tenants:%d", users, tenants)
		}
	})

	t.Run("invalid create is rejected", func(t *testing.T) {
		invalid := cloneBody(aliceBody)
		invalid["username"] = "bad user"
		response := identityRequest(
			t, client, http.MethodPost, server.URL+"/v1/admin/users", invalid,
			admin.AccessToken, "create-invalid", "create-invalid-request",
		)
		assertError(t, response, http.StatusBadRequest, "validation_error", "create-invalid-request")
		response.Body.Close()
	})

	bobBody := map[string]any{
		"username": "bob", "password": tenantPassword, "display_name": "Bob Viewer",
		"email": nil, "phone": nil, "role": identity.UserRoleViewer,
	}
	bob := createManagedUser(t, client, server.URL, admin.AccessToken, "create-bob", bobBody)
	if bob.DisplayID == "" || bob.DisplayID == alice.DisplayID {
		t.Fatalf("user display IDs = alice:%q bob:%q", alice.DisplayID, bob.DisplayID)
	}

	t.Run("user groups are scoped CAS writes with durable exact replay", func(t *testing.T) {
		member := createManagedUser(t, client, server.URL, admin.AccessToken, "create-group-member", map[string]any{
			"username": "group-member", "password": tenantPassword, "display_name": "Group Member",
			"email": nil, "phone": nil, "role": identity.UserRoleViewer,
		})
		createBody := map[string]any{"name": "Support"}
		response := identityRequest(
			t, client, http.MethodPost, server.URL+"/v1/admin/user-groups", createBody,
			admin.AccessToken, "create-support-group", "create-support-group-request",
		)
		var group identity.UserGroup
		decodeResponse(t, response, http.StatusCreated, &group)
		response.Body.Close()
		if group.Name != "Support" || group.ScopeID != bootstrap.ScopeID || group.Revision != 1 || group.MemberCount != 0 {
			t.Fatalf("created group = %#v", group)
		}
		response = identityRequest(
			t, client, http.MethodPost, server.URL+"/v1/admin/user-groups", createBody,
			admin.AccessToken, "create-support-group", "create-support-group-replay",
		)
		var createReplay identity.UserGroup
		decodeResponse(t, response, http.StatusCreated, &createReplay)
		response.Body.Close()
		if createReplay.ID != group.ID || createReplay.Revision != group.Revision {
			t.Fatalf("create group replay = %#v, original = %#v", createReplay, group)
		}
		response = identityRequest(
			t, client, http.MethodPost, server.URL+"/v1/admin/user-groups", map[string]any{"name": "Changed"},
			admin.AccessToken, "create-support-group", "create-support-group-conflict",
		)
		assertError(t, response, http.StatusConflict, "idempotency_conflict", "create-support-group-conflict")
		response.Body.Close()

		response = identityRequest(
			t, client, http.MethodGet, server.URL+"/v1/admin/user-groups?page=1&limit=20&search=support", nil,
			admin.AccessToken, "", "list-support-group",
		)
		var groups identity.UserGroupList
		decodeResponse(t, response, http.StatusOK, &groups)
		response.Body.Close()
		if groups.Total != 1 || len(groups.Items) != 1 || groups.Items[0].ID != group.ID {
			t.Fatalf("group list = %#v", groups)
		}

		updateBody := map[string]any{"expected_revision": 1, "name": "Operations"}
		response = identityRequest(
			t, client, http.MethodPatch, server.URL+"/v1/admin/user-groups/"+group.ID.String(), updateBody,
			admin.AccessToken, "update-support-group", "update-support-group-request",
		)
		decodeResponse(t, response, http.StatusOK, &group)
		response.Body.Close()
		if group.Name != "Operations" || group.Revision != 2 {
			t.Fatalf("updated group = %#v", group)
		}
		response = identityRequest(
			t, client, http.MethodPatch, server.URL+"/v1/admin/user-groups/"+group.ID.String(), updateBody,
			admin.AccessToken, "update-support-group", "update-support-group-replay",
		)
		var updateReplay identity.UserGroup
		decodeResponse(t, response, http.StatusOK, &updateReplay)
		response.Body.Close()
		if updateReplay.Name != group.Name || updateReplay.Revision != group.Revision {
			t.Fatalf("update group replay = %#v, original = %#v", updateReplay, group)
		}
		response = identityRequest(
			t, client, http.MethodPatch, server.URL+"/v1/admin/user-groups/"+group.ID.String(),
			map[string]any{"expected_revision": 1, "name": "Changed"},
			admin.AccessToken, "update-support-group", "update-support-group-conflict",
		)
		assertError(t, response, http.StatusConflict, "idempotency_conflict", "update-support-group-conflict")
		response.Body.Close()

		assignBody := map[string]any{
			"expected_revision": member.Revision, "display_name": member.DisplayName, "email": member.Email,
			"phone": member.Phone, "status": member.Status, "role": member.Role, "group_id": group.ID,
		}
		response = identityRequest(
			t, client, http.MethodPatch, server.URL+"/v1/admin/users/"+member.ID.String(), assignBody,
			admin.AccessToken, "assign-support-group", "assign-support-group-request",
		)
		decodeResponse(t, response, http.StatusOK, &member)
		response.Body.Close()
		if member.GroupID == nil || *member.GroupID != group.ID || member.GroupName == nil || *member.GroupName != group.Name {
			t.Fatalf("assigned group member = %#v", member)
		}

		deleteBody := map[string]any{"expected_revision": group.Revision}
		response = identityRequest(
			t, client, http.MethodDelete, server.URL+"/v1/admin/user-groups/"+group.ID.String(), deleteBody,
			admin.AccessToken, "delete-support-in-use", "delete-support-in-use",
		)
		assertError(t, response, http.StatusConflict, "user_group_in_use", "delete-support-in-use")
		response.Body.Close()

		unassignBody := map[string]any{
			"expected_revision": member.Revision, "display_name": member.DisplayName, "email": member.Email,
			"phone": member.Phone, "status": member.Status, "role": member.Role, "group_id": nil,
		}
		response = identityRequest(
			t, client, http.MethodPatch, server.URL+"/v1/admin/users/"+member.ID.String(), unassignBody,
			admin.AccessToken, "unassign-support-group", "unassign-support-group-request",
		)
		decodeResponse(t, response, http.StatusOK, &member)
		response.Body.Close()
		if member.GroupID != nil || member.GroupName != nil {
			t.Fatalf("unassigned group member = %#v", member)
		}

		response = identityRequest(
			t, client, http.MethodDelete, server.URL+"/v1/admin/user-groups/"+group.ID.String(), deleteBody,
			admin.AccessToken, "delete-support-group", "delete-support-group-request",
		)
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("delete group status = %d", response.StatusCode)
		}
		response.Body.Close()
		response = identityRequest(
			t, client, http.MethodDelete, server.URL+"/v1/admin/user-groups/"+group.ID.String(), deleteBody,
			admin.AccessToken, "delete-support-group", "delete-support-group-replay",
		)
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("delete group replay status = %d", response.StatusCode)
		}
		response.Body.Close()
		response = identityRequest(
			t, client, http.MethodDelete, server.URL+"/v1/admin/user-groups/"+group.ID.String(),
			map[string]any{"expected_revision": group.Revision + 1},
			admin.AccessToken, "delete-support-group", "delete-support-group-conflict",
		)
		assertError(t, response, http.StatusConflict, "idempotency_conflict", "delete-support-group-conflict")
		response.Body.Close()

		var groupAudits int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events
			WHERE action IN ('identity.user_group.create','identity.user_group.update','identity.user_group.delete')
			  AND resource_id=$1`, group.ID.String()).Scan(&groupAudits); err != nil {
			t.Fatal(err)
		}
		if groupAudits != 3 {
			t.Fatalf("group audit count = %d, want 3", groupAudits)
		}
	})

	t.Run("batch update is atomic idempotent audited and revokes disabled sessions", func(t *testing.T) {
		carol := createManagedUser(t, client, server.URL, admin.AccessToken, "create-carol", map[string]any{
			"username": "carol", "password": tenantPassword, "display_name": "Carol Owner",
			"email": "carol@example.com", "phone": nil, "role": identity.UserRoleOwner,
		})
		dave := createManagedUser(t, client, server.URL, admin.AccessToken, "create-dave", map[string]any{
			"username": "dave", "password": tenantPassword, "display_name": "Dave Viewer",
			"email": nil, "phone": "+8613900000001", "role": identity.UserRoleViewer,
		})
		_, carolCookie := loginWithPassword(t, client, server.URL, "carol", tenantPassword)
		batch := []map[string]any{
			{
				"id": carol.ID, "expected_revision": carol.Revision, "display_name": carol.DisplayName,
				"email": carol.Email, "phone": carol.Phone, "status": identity.UserStatusDisabled,
				"role": identity.UserRoleViewer, "group_id": nil,
			},
			{
				"id": dave.ID, "expected_revision": dave.Revision, "display_name": dave.DisplayName,
				"email": dave.Email, "phone": dave.Phone, "status": identity.UserStatusDisabled,
				"role": identity.UserRoleOwner, "group_id": nil,
			},
		}
		response := identityRequest(
			t, client, http.MethodPatch, server.URL+"/v1/admin/users", batch,
			admin.AccessToken, "batch-disable-users", "batch-disable-users-request",
		)
		var result struct {
			Items []identity.ManagedUser `json:"items"`
		}
		decodeResponse(t, response, http.StatusOK, &result)
		response.Body.Close()
		if len(result.Items) != 2 || result.Items[0].ID != carol.ID || result.Items[1].ID != dave.ID ||
			result.Items[0].Revision != 2 || result.Items[1].Revision != 2 ||
			result.Items[0].Status != identity.UserStatusDisabled || result.Items[1].Status != identity.UserStatusDisabled {
			t.Fatalf("batch result = %#v", result.Items)
		}

		response = identityRequest(
			t, client, http.MethodPatch, server.URL+"/v1/admin/users", batch,
			admin.AccessToken, "batch-disable-users", "batch-disable-users-replay",
		)
		var replay struct {
			Items []identity.ManagedUser `json:"items"`
		}
		decodeResponse(t, response, http.StatusOK, &replay)
		response.Body.Close()
		if len(replay.Items) != 2 || replay.Items[0].Revision != 2 || replay.Items[1].Revision != 2 {
			t.Fatalf("batch replay = %#v", replay.Items)
		}

		response = doRequest(t, client, http.MethodPost, server.URL+"/v1/auth/refresh", nil, carolCookie, "", "batch-disabled-refresh")
		assertError(t, response, http.StatusUnauthorized, "invalid_session", "batch-disabled-refresh")
		response.Body.Close()
		var auditCount int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events
			WHERE action='identity.user.update' AND request_id='batch-disable-users-request'
			  AND resource_id = ANY($1::text[])`, []string{carol.ID.String(), dave.ID.String()},
		).Scan(&auditCount); err != nil {
			t.Fatal(err)
		}
		if auditCount != 2 {
			t.Fatalf("batch audit count = %d, want 2", auditCount)
		}

		conflict := []map[string]any{
			{
				"id": carol.ID, "expected_revision": 2, "display_name": "Carol must roll back",
				"email": carol.Email, "phone": carol.Phone, "status": identity.UserStatusActive,
				"role": identity.UserRoleOwner, "group_id": nil,
			},
			{
				"id": dave.ID, "expected_revision": 1, "display_name": "Dave stale",
				"email": dave.Email, "phone": dave.Phone, "status": identity.UserStatusActive,
				"role": identity.UserRoleViewer, "group_id": nil,
			},
		}
		response = identityRequest(
			t, client, http.MethodPatch, server.URL+"/v1/admin/users", conflict,
			admin.AccessToken, "batch-conflict-users", "batch-conflict-users-request",
		)
		assertError(t, response, http.StatusConflict, "version_conflict", "batch-conflict-users-request")
		response.Body.Close()
		for _, item := range []identity.ManagedUser{carol, dave} {
			var displayName string
			var revision int64
			if err := pool.QueryRow(context.Background(), `SELECT display_name,revision FROM users WHERE id=$1`, item.ID).Scan(&displayName, &revision); err != nil {
				t.Fatal(err)
			}
			if displayName != item.DisplayName || revision != 2 {
				t.Fatalf("batch conflict left %s display=%q revision=%d", item.Username, displayName, revision)
			}
		}
	})

	t.Run("list paginates and searches tenant users only", func(t *testing.T) {
		response := identityRequest(
			t, client, http.MethodGet,
			server.URL+"/v1/admin/users?page=1&limit=1&search=alice&status=active&role=tenant_owner",
			nil, admin.AccessToken, "", "list-users",
		)
		var result identity.UserList
		decodeResponse(t, response, http.StatusOK, &result)
		response.Body.Close()
		if result.Total != 1 || len(result.Items) != 1 || result.Items[0].ID != alice.ID {
			t.Fatalf("filtered user page = %#v", result)
		}
		response = identityRequest(
			t, client, http.MethodGet,
			server.URL+"/v1/admin/users?page=1&limit=20&display_id="+alice.DisplayID,
			nil, admin.AccessToken, "", "list-user-display-id",
		)
		decodeResponse(t, response, http.StatusOK, &result)
		response.Body.Close()
		if result.Total != 1 || len(result.Items) != 1 || result.Items[0].ID != alice.ID ||
			result.Items[0].DisplayID != alice.DisplayID {
			t.Fatalf("display ID filtered user page = %#v", result)
		}
		for index, value := range []string{"0", "-1", "01", "1.5", "10000000000000000000"} {
			response = identityRequest(
				t, client, http.MethodGet,
				server.URL+"/v1/admin/users?page=1&limit=20&display_id="+value,
				nil, admin.AccessToken, "", "invalid-user-display-id-"+strconv.Itoa(index),
			)
			assertError(t, response, http.StatusBadRequest, "validation_error", "invalid-user-display-id-"+strconv.Itoa(index))
			response.Body.Close()
		}
		response = identityRequest(
			t, client, http.MethodGet,
			server.URL+"/v1/admin/users?page=1&limit=20&display_id=1&display_id=2",
			nil, admin.AccessToken, "", "duplicate-user-display-id",
		)
		assertError(t, response, http.StatusBadRequest, "validation_error", "duplicate-user-display-id")
		response.Body.Close()
		response = identityRequest(
			t, client, http.MethodGet, server.URL+"/v1/admin/users/"+bootstrap.UserID.String(),
			nil, admin.AccessToken, "", "platform-user-detail",
		)
		// 98725edbd 起详情可定位平台管理员（tenant_id 为空），列表默认仍只含租户用户。
		var platformUser identity.ManagedUser
		decodeResponse(t, response, http.StatusOK, &platformUser)
		response.Body.Close()
		if platformUser.ID != bootstrap.UserID || platformUser.TenantID != nil || platformUser.Role != identity.UserRolePlatformOwner {
			t.Fatalf("platform user detail = %#v", platformUser)
		}
	})

	aliceAuth, aliceCookie := loginWithPassword(t, client, server.URL, "alice", tenantPassword)
	if aliceAuth.Principal.ScopeKind != "tenant" || aliceAuth.Principal.ScopeID != alice.ScopeID {
		t.Fatalf("Alice principal = %#v", aliceAuth.Principal)
	}
	if !contains(aliceAuth.Principal.Permissions, "streams.read") || !contains(aliceAuth.Principal.Permissions, "streams.manage") {
		t.Fatalf("Alice owner stream grants = %v", aliceAuth.Principal.Permissions)
	}
	bobAuth, _ := loginWithPassword(t, client, server.URL, "bob", tenantPassword)
	if !contains(bobAuth.Principal.Roles, identity.UserRoleViewer) || contains(bobAuth.Principal.Permissions, "sites.manage") ||
		!contains(bobAuth.Principal.Permissions, "streams.read") || contains(bobAuth.Principal.Permissions, "streams.manage") {
		t.Fatalf("Bob viewer grants = roles:%v permissions:%v", bobAuth.Principal.Roles, bobAuth.Principal.Permissions)
	}
	response := identityRequest(
		t, client, http.MethodPost, server.URL+"/v1/streams", map[string]any{},
		bobAuth.AccessToken, "viewer-stream-write", "viewer-stream-write",
	)
	assertError(t, response, http.StatusForbidden, "permission_denied", "viewer-stream-write")
	response.Body.Close()

	t.Run("tenant cannot probe administrator user APIs", func(t *testing.T) {
		for _, target := range []string{bob.ID.String(), bootstrap.UserID.String()} {
			response := identityRequest(
				t, client, http.MethodGet, server.URL+"/v1/admin/users/"+target,
				nil, aliceAuth.AccessToken, "", "tenant-admin-denied",
			)
			assertError(t, response, http.StatusForbidden, "permission_denied", "tenant-admin-denied")
			response.Body.Close()
		}
		for _, request := range []struct {
			method string
			path   string
			body   any
			key    string
		}{
			{http.MethodGet, "/v1/admin/users?page=1&limit=20&display_id=" + bob.DisplayID, nil, ""},
			{http.MethodGet, "/v1/admin/user-groups?page=1&limit=20", nil, ""},
			{http.MethodPost, "/v1/admin/user-groups", map[string]any{"name": "forbidden"}, "tenant-group-create"},
			{http.MethodPatch, "/v1/admin/user-groups/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", map[string]any{
				"expected_revision": 1, "name": "forbidden",
			}, "tenant-group-update"},
			{http.MethodDelete, "/v1/admin/user-groups/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", map[string]any{
				"expected_revision": 1,
			}, "tenant-group-delete"},
		} {
			response := identityRequest(
				t, client, request.method, server.URL+request.path, request.body,
				aliceAuth.AccessToken, request.key, "tenant-group-denied",
			)
			assertError(t, response, http.StatusForbidden, "permission_denied", "tenant-group-denied")
			response.Body.Close()
		}
	})

	t.Run("tenant reads and idempotently updates display name without reauthentication", func(t *testing.T) {
		response := identityRequest(
			t, client, http.MethodGet, server.URL+"/v1/account/profile", nil,
			aliceAuth.AccessToken, "", "profile-read",
		)
		var profile identity.AccountProfile
		decodeResponse(t, response, http.StatusOK, &profile)
		response.Body.Close()
		if profile.ID != alice.ID || profile.Revision != 1 {
			t.Fatalf("Alice profile = %#v", profile)
		}
		update := map[string]any{
			"expected_revision": 1, "display_name": "Alice Updated",
			"email": "alice@example.com", "phone": "+8613800000000",
		}
		response = identityRequest(
			t, client, http.MethodPatch, server.URL+"/v1/account/profile", update,
			aliceAuth.AccessToken, "profile-alice", "profile-update",
		)
		decodeResponse(t, response, http.StatusOK, &profile)
		response.Body.Close()
		if profile.DisplayName != "Alice Updated" || profile.Revision != 2 {
			t.Fatalf("updated Alice profile = %#v", profile)
		}
		response = identityRequest(
			t, client, http.MethodPatch, server.URL+"/v1/account/profile", update,
			aliceAuth.AccessToken, "profile-alice", "profile-replay",
		)
		var replay identity.AccountProfile
		decodeResponse(t, response, http.StatusOK, &replay)
		response.Body.Close()
		if replay.Revision != 2 || replay.DisplayName != "Alice Updated" {
			t.Fatalf("profile replay = %#v", replay)
		}
	})

	t.Run("contact changes require reauthentication and audit only change metadata", func(t *testing.T) {
		for index, invalid := range []map[string]any{
			{
				"expected_revision": 2, "display_name": "Alice Updated",
				"email": "not-an-email", "phone": "+8613800000000",
			},
			{
				"expected_revision": 2, "display_name": "Alice Updated",
				"email": "alice@example.com", "phone": "not-a-phone",
			},
		} {
			response := identityRequest(
				t, client, http.MethodPatch, server.URL+"/v1/account/profile", invalid,
				aliceAuth.AccessToken, "profile-invalid-"+string(rune('a'+index)), "profile-invalid",
			)
			assertError(t, response, http.StatusBadRequest, "validation_error", "profile-invalid")
			response.Body.Close()
		}

		var auditBefore int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events WHERE action = 'identity.self.update'`,
		).Scan(&auditBefore); err != nil {
			t.Fatal(err)
		}
		contactUpdate := map[string]any{
			"expected_revision": 2, "display_name": "Alice Updated",
			"email": "alice.updated@example.com", "phone": "+8613900000000",
		}
		for _, attempt := range []struct {
			key      string
			password any
		}{
			{key: "profile-contact-missing", password: nil},
			{key: "profile-contact-wrong", password: "wrong-password"},
		} {
			body := cloneBody(contactUpdate)
			if attempt.password != nil {
				body["current_password"] = attempt.password
			}
			response := identityRequest(
				t, client, http.MethodPatch, server.URL+"/v1/account/profile", body,
				aliceAuth.AccessToken, attempt.key, attempt.key,
			)
			assertError(t, response, http.StatusUnauthorized, "invalid_credentials", attempt.key)
			response.Body.Close()
		}

		var email, phone string
		var revision int64
		if err := pool.QueryRow(context.Background(), `
			SELECT email, phone, revision FROM users WHERE id = $1`, alice.ID,
		).Scan(&email, &phone, &revision); err != nil {
			t.Fatal(err)
		}
		if email != "alice@example.com" || phone != "+8613800000000" || revision != 2 {
			t.Fatalf("profile changed after rejected reauthentication: email=%q phone=%q revision=%d", email, phone, revision)
		}
		var rejectedAudits, rejectedWrites int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events
			WHERE request_id IN ('profile-contact-missing', 'profile-contact-wrong')`,
		).Scan(&rejectedAudits); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM identity_write_requests
			WHERE operation = 'identity.self.update'
			  AND idempotency_key IN ('profile-contact-missing', 'profile-contact-wrong')`,
		).Scan(&rejectedWrites); err != nil {
			t.Fatal(err)
		}
		var auditAfter int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events WHERE action = 'identity.self.update'`,
		).Scan(&auditAfter); err != nil {
			t.Fatal(err)
		}
		if rejectedAudits != 0 || rejectedWrites != 0 || auditAfter != auditBefore {
			t.Fatalf("rejected contact write persisted state: audits=%d writes=%d before=%d after=%d", rejectedAudits, rejectedWrites, auditBefore, auditAfter)
		}

		contactUpdate["current_password"] = tenantPassword
		response := identityRequest(
			t, client, http.MethodPatch, server.URL+"/v1/account/profile", contactUpdate,
			aliceAuth.AccessToken, "profile-contact-correct", "profile-contact-correct",
		)
		var updated identity.AccountProfile
		decodeResponse(t, response, http.StatusOK, &updated)
		response.Body.Close()
		if updated.Revision != 3 || updated.Email == nil || *updated.Email != "alice.updated@example.com" ||
			updated.Phone == nil || *updated.Phone != "+8613900000000" {
			t.Fatalf("reauthenticated profile = %#v", updated)
		}

		var encodedAudit []byte
		if err := pool.QueryRow(context.Background(), `
			SELECT payload FROM audit_events
			WHERE action = 'identity.self.update' AND request_id = 'profile-contact-correct'`,
		).Scan(&encodedAudit); err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Revision        int64 `json:"revision"`
			EmailChanged    bool  `json:"email_changed"`
			PhoneChanged    bool  `json:"phone_changed"`
			Reauthenticated bool  `json:"reauthenticated"`
		}
		if err := json.Unmarshal(encodedAudit, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Revision != 3 || !payload.EmailChanged || !payload.PhoneChanged || !payload.Reauthenticated {
			t.Fatalf("contact update audit payload = %s", encodedAudit)
		}
		for _, secret := range []string{tenantPassword, "alice.updated@example.com", "+8613900000000"} {
			if bytes.Contains(encodedAudit, []byte(secret)) {
				t.Fatalf("contact update audit contains sensitive value %q: %s", secret, encodedAudit)
			}
		}

		replayBody := cloneBody(contactUpdate)
		replayBody["current_password"] = "not-the-original-secret"
		response = identityRequest(
			t, client, http.MethodPatch, server.URL+"/v1/account/profile", replayBody,
			aliceAuth.AccessToken, "profile-contact-correct", "profile-contact-replay",
		)
		var replay identity.AccountProfile
		decodeResponse(t, response, http.StatusOK, &replay)
		response.Body.Close()
		if replay.Revision != updated.Revision || replay.Email == nil || *replay.Email != *updated.Email {
			t.Fatalf("contact update replay = %#v, original = %#v", replay, updated)
		}
	})

	t.Run("optimistic updates allow one concurrent winner", func(t *testing.T) {
		bodies := []map[string]any{
			{
				"expected_revision": bob.Revision, "display_name": "Bob Concurrent A", "email": nil,
				"phone": nil, "status": "active", "role": identity.UserRoleViewer,
			},
			{
				"expected_revision": bob.Revision, "display_name": "Bob Concurrent B", "email": nil,
				"phone": nil, "status": "active", "role": identity.UserRoleOwner,
			},
		}
		statuses := make([]int, len(bodies))
		start := make(chan struct{})
		var wait sync.WaitGroup
		for index := range bodies {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				<-start
				response := identityRequest(
					t, client, http.MethodPatch, server.URL+"/v1/admin/users/"+bob.ID.String(), bodies[index],
					admin.AccessToken, "concurrent-bob-"+string(rune('a'+index)), "concurrent-bob-request",
				)
				statuses[index] = response.StatusCode
				response.Body.Close()
			}(index)
		}
		close(start)
		wait.Wait()
		sort.Ints(statuses)
		if statuses[0] != http.StatusOK || statuses[1] != http.StatusConflict {
			t.Fatalf("concurrent update statuses = %v", statuses)
		}
	})

	t.Run("disable revokes refresh and access sessions", func(t *testing.T) {
		body := map[string]any{
			"expected_revision": 3, "display_name": "Alice Updated", "email": "alice.updated@example.com",
			"phone": "+8613900000000", "status": identity.UserStatusDisabled, "role": identity.UserRoleOwner,
		}
		response := identityRequest(
			t, client, http.MethodPatch, server.URL+"/v1/admin/users/"+alice.ID.String(), body,
			admin.AccessToken, "disable-alice", "disable-alice",
		)
		var disabled identity.ManagedUser
		decodeResponse(t, response, http.StatusOK, &disabled)
		response.Body.Close()
		if disabled.Status != identity.UserStatusDisabled || disabled.Revision != 4 {
			t.Fatalf("disabled Alice = %#v", disabled)
		}
		response = identityRequest(
			t, client, http.MethodPatch, server.URL+"/v1/admin/users/"+alice.ID.String(), body,
			admin.AccessToken, "disable-alice", "disable-alice-replay",
		)
		decodeResponse(t, response, http.StatusOK, &disabled)
		response.Body.Close()
		if disabled.Revision != 4 {
			t.Fatalf("disable replay revision = %d", disabled.Revision)
		}
		access := identityRequest(
			t, client, http.MethodGet, server.URL+"/v1/account/profile", nil,
			aliceAuth.AccessToken, "", "disabled-access",
		)
		assertError(t, access, http.StatusUnauthorized, "invalid_session", "disabled-access")
		access.Body.Close()
		refresh := doRequest(t, client, http.MethodPost, server.URL+"/v1/auth/refresh", nil, aliceCookie, "", "disabled-refresh")
		assertError(t, refresh, http.StatusUnauthorized, "invalid_session", "disabled-refresh")
		refresh.Body.Close()
		login := postLogin(t, client, server.URL, map[string]any{"username": "alice", "password": tenantPassword}, "disabled-login")
		assertError(t, login, http.StatusForbidden, "account_disabled", "disabled-login")
		login.Body.Close()
	})

	t.Run("password change reauthenticates and revokes every session", func(t *testing.T) {
		current, cookie := loginWithPassword(t, client, server.URL, "bob", tenantPassword)
		second, secondCookie := loginWithPassword(t, client, server.URL, "bob", tenantPassword)
		wrong := identityRequest(
			t, client, http.MethodPost, server.URL+"/v1/account/password",
			map[string]any{"current_password": "wrong-password", "new_password": newTenantPassword},
			current.AccessToken, "", "password-wrong",
		)
		assertError(t, wrong, http.StatusUnauthorized, "invalid_credentials", "password-wrong")
		wrong.Body.Close()
		changed := identityRequest(
			t, client, http.MethodPost, server.URL+"/v1/account/password",
			map[string]any{"current_password": tenantPassword, "new_password": newTenantPassword},
			current.AccessToken, "", "password-change",
		)
		if changed.StatusCode != http.StatusNoContent {
			t.Fatalf("password change status = %d", changed.StatusCode)
		}
		changed.Body.Close()
		for index, accessToken := range []string{current.AccessToken, second.AccessToken} {
			requestID := "password-old-access-" + string(rune('a'+index))
			access := identityRequest(
				t, client, http.MethodGet, server.URL+"/v1/account/profile", nil,
				accessToken, "", requestID,
			)
			assertError(t, access, http.StatusUnauthorized, "invalid_session", requestID)
			access.Body.Close()
		}
		for index, refreshCookie := range []*http.Cookie{cookie, secondCookie} {
			requestID := "password-old-refresh-" + string(rune('a'+index))
			refresh := doRequest(t, client, http.MethodPost, server.URL+"/v1/auth/refresh", nil, refreshCookie, "", requestID)
			assertError(t, refresh, http.StatusUnauthorized, "invalid_session", requestID)
			refresh.Body.Close()
		}
		oldLogin := postLogin(t, client, server.URL, map[string]any{"username": "bob", "password": tenantPassword}, "password-old-login")
		assertError(t, oldLogin, http.StatusUnauthorized, "invalid_credentials", "password-old-login")
		oldLogin.Body.Close()
		newLogin, _ := loginWithPassword(t, client, server.URL, "bob", newTenantPassword)
		if newLogin.Principal.UserID != bob.ID {
			t.Fatalf("new password principal = %#v", newLogin.Principal)
		}
		var encodedAudit []byte
		if err := pool.QueryRow(context.Background(), `
			SELECT payload FROM audit_events
			WHERE action = 'identity.password.change' AND request_id = 'password-change'`,
		).Scan(&encodedAudit); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(encodedAudit, []byte(`"sessions_revoked": true`)) &&
			!bytes.Contains(encodedAudit, []byte(`"sessions_revoked":true`)) {
			t.Fatalf("password change audit payload = %s", encodedAudit)
		}
		for _, secret := range []string{tenantPassword, newTenantPassword} {
			if bytes.Contains(encodedAudit, []byte(secret)) {
				t.Fatalf("password change audit contains password: %s", encodedAudit)
			}
		}
	})

	t.Run("sensitive writes are audited", func(t *testing.T) {
		for _, action := range []string{
			"identity.user.create", "identity.user.update", "identity.self.update", "identity.password.change",
		} {
			var count int
			if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_events WHERE action = $1", action).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count < 1 {
				t.Fatalf("audit action %q count = %d", action, count)
			}
		}
	})
}

func createManagedUser(
	t *testing.T,
	client *http.Client,
	baseURL string,
	accessToken string,
	key string,
	body map[string]any,
) identity.ManagedUser {
	t.Helper()
	response := identityRequest(
		t, client, http.MethodPost, baseURL+"/v1/admin/users", body,
		accessToken, key, "request-"+key,
	)
	var result identity.ManagedUser
	decodeResponse(t, response, http.StatusCreated, &result)
	response.Body.Close()
	return result
}

func loginWithPassword(
	t *testing.T,
	client *http.Client,
	baseURL string,
	username string,
	password string,
) (testAuthResponse, *http.Cookie) {
	t.Helper()
	response := postLogin(t, client, baseURL, map[string]any{"username": username, "password": password}, "")
	var result testAuthResponse
	decodeResponse(t, response, http.StatusOK, &result)
	cookie := responseCookie(t, response)
	response.Body.Close()
	return result, cookie
}

func identityRequest(
	t *testing.T,
	client *http.Client,
	method string,
	url string,
	body any,
	accessToken string,
	idempotencyKey string,
	requestID string,
) *http.Response {
	t.Helper()
	var requestBody []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		requestBody = encoded
	}
	request, err := http.NewRequest(method, url, bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if requestID != "" {
		request.Header.Set("X-Request-ID", requestID)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func cloneBody(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
