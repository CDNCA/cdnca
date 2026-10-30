//go:build integration

package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/cdnca/cdnca/services/control-api/internal/sitegroup"
	"github.com/google/uuid"
)

func TestSiteGroupAdminHTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	password, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	admin, err := store.BootstrapPlatformUser(t.Context(), "groups-admin", "Admin", password, "groups-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("site-group-http-tests-only-32-byte-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := identity.NewService(store, tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	managed, err := auth.CreateUser(t.Context(), identity.Actor{UserID: admin.UserID, ScopeID: admin.ScopeID, ScopeKind: "platform"}, identity.CreateUserInput{
		Username: "groups-tenant", Password: testPassword, Fields: identity.UserFields{DisplayName: "Tenant"}, Role: identity.UserRoleOwner,
		IdempotencyKey: "create-groups-tenant", RequestID: "create-groups-tenant",
	})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x72}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, keys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := sitegroup.NewService(pool, iam, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	api := New(pool, auth, Config{SiteGroupService: service, APIKeyPepper: bytes.Repeat([]byte{0x72}, 32)})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	adminSession, err := auth.Login(t.Context(), identity.LoginInput{Username: "groups-admin", Password: testPassword}, identity.RequestInfo{RequestID: "groups-admin-login"})
	if err != nil {
		t.Fatal(err)
	}
	tenantSession, err := auth.Login(t.Context(), identity.LoginInput{Username: "groups-tenant", Password: testPassword}, identity.RequestInfo{RequestID: "groups-tenant-login"})
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(method, path, token, key, match string, body any) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(encoded))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Idempotency-Key", key)
		if match != "" {
			r.Header.Set("If-Match", match)
		}
		w := httptest.NewRecorder()
		api.Handler().ServeHTTP(w, r)
		return w
	}
	path := "/v1/admin/site-groups"
	for _, denied := range []struct {
		token  string
		status int
	}{{"invalid", 401}, {tenantSession.AccessToken, 403}} {
		w := invoke("GET", path, denied.token, "", "", nil)
		if w.Code != denied.status {
			t.Fatalf("global read accepted forbidden identity: %d", w.Code)
		}
	}
	for _, query := range []string{"?scope_id=" + managed.ScopeID.String(), "?page=0", "?limit=101", "?page=1&page=2"} {
		if w := invoke("GET", path+query, adminSession.AccessToken, "", "", nil); w.Code != 400 {
			t.Fatalf("query %s: %d", query, w.Code)
		}
	}
	for _, rawRemark := range []any{nil, 123, map[string]string{}} {
		w := invoke("POST", "/v1/site-groups", adminSession.AccessToken, "invalid-remark", "", map[string]any{"target_scope_id": managed.ScopeID, "name": "new", "remark": rawRemark})
		if w.Code != 400 {
			t.Fatalf("invalid remark status %d", w.Code)
		}
	}
	body := map[string]any{"target_scope_id": managed.ScopeID, "name": "new", "remark": "真实\n备注"}
	w := invoke("POST", "/v1/site-groups", adminSession.AccessToken, "create-group", "", body)
	if w.Code != 201 || w.Header().Get("ETag") != `"1"` {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var created sitegroup.Group
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.DisplayID == "" || created.Remark != "真实\n备注" {
		t.Fatalf("new write metadata missing: %s", w.Body)
	}
	createdRaw := append([]byte(nil), w.Body.Bytes()...)
	var createdFields, replayedFields map[string]json.RawMessage
	if err := json.Unmarshal(createdRaw, &createdFields); err != nil {
		t.Fatal(err)
	}
	w = invoke("POST", "/v1/site-groups", adminSession.AccessToken, "create-group", "", body)
	if err := json.Unmarshal(w.Body.Bytes(), &replayedFields); err != nil || w.Code != 201 || !reflect.DeepEqual(replayedFields, createdFields) {
		t.Fatalf("new write replay changed: %d %s %v", w.Code, w.Body, err)
	}
	replayedRaw := append([]byte(nil), w.Body.Bytes()...)
	w = invoke("POST", "/v1/site-groups", adminSession.AccessToken, "create-group", "", body)
	if w.Code != 201 || !bytes.Equal(w.Body.Bytes(), replayedRaw) {
		t.Fatalf("repeated replay bytes changed: %d %s", w.Code, w.Body)
	}
	w = invoke("GET", path, adminSession.AccessToken, "", "", nil)
	var page sitegroup.AdminGroupList
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || page.Total != 1 || page.Limit != 10 || len(page.Items) != 1 || page.Items[0].User == nil || page.Items[0].User.ID != managed.ID || page.Items[0].Remark != "真实\n备注" {
		t.Fatalf("global read: %d %s %v", w.Code, w.Body, err)
	}
	itemPath := "/v1/site-groups/" + created.ID.String() + "?scope_id=" + managed.ScopeID.String()
	w = invoke("GET", itemPath, tenantSession.AccessToken, "", "", nil)
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"display_id"`)) {
		t.Fatalf("exact get: %d %s", w.Code, w.Body)
	}
	if !bytes.Equal(w.Body.Bytes(), createdRaw) {
		t.Fatalf("new write and exact GET differ: %s", w.Body)
	}
	w = invoke("PATCH", itemPath, adminSession.AccessToken, "rename-group", `"1"`, map[string]any{"expected_revision": 1, "name": "renamed"})
	if w.Code != 200 || w.Header().Get("ETag") != `"2"` || !bytes.Contains(w.Body.Bytes(), []byte(`真实\n备注`)) {
		t.Fatalf("rename preserving omitted remark: %d %s", w.Code, w.Body)
	}
	var renamed sitegroup.Group
	if err := json.Unmarshal(w.Body.Bytes(), &renamed); err != nil || renamed.DisplayID != created.DisplayID {
		t.Fatalf("rename display ID changed: %s %v", w.Body, err)
	}

	// Seed the immutable pre-272 wire receipt exactly, without mutating any completed receipt.
	legacyBody, _ := json.Marshal(struct {
		TargetScopeID uuid.UUID `json:"target_scope_id"`
		Name          string    `json:"name"`
	}{managed.ScopeID, "legacy"})
	digest := sha256.Sum256(legacyBody)
	legacy := map[string]any{"id": created.ID, "scope_id": managed.ScopeID, "name": "legacy", "revision": 1, "created_at": created.CreatedAt, "updated_at": created.UpdatedAt}
	legacyJSON, _ := json.Marshal(legacy)
	if _, err := pool.Exec(t.Context(), `INSERT INTO site_group_write_requests(id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,request_digest,resource_id,response_status,response_body,completed_at) VALUES($1,$2,$3,$4,'site_group.create','legacy-replay',$5,$6,201,$7,now())`, uuid.New(), admin.UserID, admin.ScopeID, managed.ScopeID, digest[:], created.ID, legacyJSON); err != nil {
		t.Fatal(err)
	}
	w = invoke("POST", "/v1/site-groups", adminSession.AccessToken, "legacy-replay", "", map[string]any{"target_scope_id": managed.ScopeID, "name": "legacy"})
	var replay map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &replay); err != nil || w.Code != 201 {
		t.Fatalf("legacy replay: %d %v", w.Code, err)
	}
	if _, exists := replay["remark"]; exists {
		t.Fatal("replay fabricated a remark not present in the original receipt")
	}
	if _, exists := replay["display_id"]; exists {
		t.Fatal("replay fabricated current metadata")
	}
	if replay["name"] != "legacy" || replay["revision"] != float64(1) {
		t.Fatalf("legacy replay changed: %v", replay)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, admin.ScopeID, admin.UserID); err != nil {
		t.Fatal(err)
	}
	w = invoke("GET", path, adminSession.AccessToken, "", "", nil)
	if w.Code != 401 {
		t.Fatalf("revoked platform read: %d %s", w.Code, w.Body)
	}
}
