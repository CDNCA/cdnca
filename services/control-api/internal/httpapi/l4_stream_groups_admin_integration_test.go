package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	"github.com/google/uuid"
)

func TestL4StreamAdminGroupAndDefaultHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	hash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := identity.NewStore(pool).BootstrapPlatformUser(t.Context(), "cross-group-admin", "Group administrator", hash, "cross-group-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	tenant := insertL4Tenant(t, pool, "Group target", "cross-group-owner", hash, []string{"streams.read", "streams.manage"})
	other := insertL4Tenant(t, pool, "Group foreign", "cross-group-other", hash, []string{"streams.read", "streams.manage"})
	tokens, err := identity.NewTokenManager("cross-scope-group-integration-secret-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x5a}, 32)}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	adminAuth, _ := loginOK(t, client, server.URL, "cross-group-admin")
	ownerAuth, _ := loginOK(t, client, server.URL, "cross-group-owner")
	otherAuth, _ := loginOK(t, client, server.URL, "cross-group-other")
	assertActor := func(t *testing.T, resource uuid.UUID, action string) {
		t.Helper()
		var count int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
			WHERE scope_id=$1 AND actor_user_id=$2 AND resource_id=$3 AND action=$4 AND result='success'`,
			tenant.scopeID, admin.UserID, resource.String(), action).Scan(&count); err != nil || count != 1 {
			t.Fatalf("real administrator audit %s: count=%d err=%v", action, count, err)
		}
	}
	t.Run("administrator create and replay preserve actor", func(t *testing.T) {
		request := streamGroupRequest{TargetScopeID: tenant.scopeID.String(), OwnerID: tenant.userID.String(), Name: "云端分组增删验收", Remark: "真实数据库浏览器保存"}
		created := createStreamGroup(t, client, server.URL, adminAuth.AccessToken, "admin-group-create", request)
		replayed := createStreamGroup(t, client, server.URL, adminAuth.AccessToken, "admin-group-create", request)
		if created.ID != replayed.ID || created.ScopeID != tenant.scopeID || created.Owner == nil || created.Owner.ID != tenant.userID {
			t.Fatalf("cross-scope group identity changed: %+v %+v", created, replayed)
		}
		var creator, updater uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT created_by_user_id,updated_by_user_id FROM l4_stream_groups WHERE id=$1`, created.ID).Scan(&creator, &updater); err != nil || creator != admin.UserID || updater != admin.UserID {
			t.Fatalf("group actor=(%s,%s) err=%v", creator, updater, err)
		}
		assertActor(t, created.ID, "stream_group.create")
	})
	t.Run("administrator updates and deletes tenant group", func(t *testing.T) {
		created := createStreamGroup(t, client, server.URL, ownerAuth.AccessToken, "owner-group-create", streamGroupRequest{Name: "Tenant group"})
		request := streamGroupRequest{ExpectedRevision: 1, Name: "Administrator edit", Remark: "Real administrator"}
		updated := updateStreamGroup(t, client, server.URL, created.ID, adminAuth.AccessToken, "admin-group-update", request, 1)
		replayed := updateStreamGroup(t, client, server.URL, created.ID, adminAuth.AccessToken, "admin-group-update", request, 1)
		if updated.Revision != 2 || replayed.Revision != 2 {
			t.Fatal("group update replay changed revision")
		}
		var creator, updater uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT created_by_user_id,updated_by_user_id FROM l4_stream_groups WHERE id=$1`, created.ID).Scan(&creator, &updater); err != nil || creator != tenant.userID || updater != admin.UserID {
			t.Fatalf("group actors changed: creator=%s updater=%s err=%v", creator, updater, err)
		}
		assertActor(t, created.ID, "stream_group.update")
		deleteStreamGroup(t, client, server.URL, adminAuth.AccessToken, "admin-group-delete", created.ID, 2)
		assertActor(t, created.ID, "stream_group.delete")
	})
	t.Run("administrator creates and deletes tenant default", func(t *testing.T) {
		request := streamDefaultRequest{TargetScopeID: tenant.scopeID.String(), OwnerID: tenant.userID.String(), SettingName: l4forward.SettingListenProtocol, Value: l4forward.ProtocolUDP, ScopeName: l4forward.DefaultScopeGlobal}
		created := createStreamDefault(t, client, server.URL, adminAuth.AccessToken, "admin-default-create", request)
		replayed := createStreamDefault(t, client, server.URL, adminAuth.AccessToken, "admin-default-create", request)
		if created.ID != replayed.ID || created.ScopeID != tenant.scopeID || created.Owner == nil || created.Owner.ID != tenant.userID {
			t.Fatal("cross-scope default identity changed")
		}
		var creator uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT created_by_user_id FROM l4_stream_user_defaults WHERE id=$1`, created.ID).Scan(&creator); err != nil || creator != admin.UserID {
			t.Fatalf("default creator=%s err=%v", creator, err)
		}
		assertActor(t, created.ID, "stream_default.create")
		deleteStreamDefault(t, client, server.URL, adminAuth.AccessToken, "admin-default-delete", created.ID)
		assertActor(t, created.ID, "stream_default.delete")
	})
	t.Run("ordinary tenant cannot target another scope", func(t *testing.T) {
		for _, request := range []struct {
			path string
			body any
		}{
			{"/v1/stream-groups", streamGroupRequest{TargetScopeID: tenant.scopeID.String(), OwnerID: tenant.userID.String(), Name: "Forbidden group"}},
			{"/v1/user-configs", streamDefaultRequest{TargetScopeID: tenant.scopeID.String(), OwnerID: tenant.userID.String(), SettingName: l4forward.SettingListenProtocol, Value: l4forward.ProtocolTCP, ScopeName: l4forward.DefaultScopeGlobal}},
		} {
			response := l4Request(t, client, http.MethodPost, server.URL+request.path, request.body, otherAuth.AccessToken, "foreign-create", "")
			response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("%s foreign create status=%d", request.path, response.StatusCode)
			}
		}
		if groups := listStreamGroups(t, client, server.URL+"/v1/stream-groups", otherAuth.AccessToken); groups.Total != 0 {
			t.Fatal("foreign scope can see target groups")
		}
		var writes int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM l4_write_requests WHERE actor_user_id=$1 AND target_scope_id=$2`, other.userID, tenant.scopeID).Scan(&writes); err != nil || writes != 0 {
			t.Fatalf("denied actor left receipts: count=%d err=%v", writes, err)
		}
	})
	var memberships int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM memberships WHERE scope_id=$1 AND user_id=$2`, tenant.scopeID, admin.UserID).Scan(&memberships); err != nil || memberships != 0 {
		t.Fatalf("administrator gained target membership: %d %v", memberships, err)
	}
}
