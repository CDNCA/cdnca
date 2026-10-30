package certificateassethttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestHandlerPlatformListAndUploadOwner(t *testing.T) {
	pool := isolatedCertificateHTTPPool(t)
	tenantID, scopeID, platformScopeID := uuid.New(), uuid.New(), uuid.New()
	ownerID, platformID := uuid.New(), uuid.New()
	ownerRole, platformRole := uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'certificate-owner-test')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'platform',NULL)`, []any{scopeID, tenantID, platformScopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'certificate-http-owner','Owner','test-hash'),($2,'certificate-http-platform','Platform','test-hash')`, []any{ownerID, platformID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($3,$4)`, []any{scopeID, ownerID, platformScopeID, platformID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','Owner',true),($3,$4,'platform_owner','Platform',true)`, []any{ownerRole, scopeID, platformRole, platformScopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'certificates.read'),($1,'certificates.manage'),($2,'certificates.read'),($2,'certificates.manage')`, []any{ownerRole, platformRole}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3),($4,$5,$6)`, []any{scopeID, ownerID, ownerRole, platformScopeID, platformID, platformRole}},
	} {
		if _, err := pool.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	store, err := certificateasset.NewStoreWithDependencies(pool, certificateHTTPEnveloper{}, audit.New(pool), func() time.Time { return certificateHTTPNow })
	if err != nil {
		t.Fatal(err)
	}
	principals := map[string]identity.Principal{
		"owner":    {UserID: ownerID, ScopeID: scopeID, ScopeKind: "tenant", TenantID: &tenantID, Permissions: []string{"certificates.read", "certificates.manage"}},
		"platform": {UserID: platformID, ScopeID: platformScopeID, ScopeKind: "platform", Permissions: []string{"certificates.read", "certificates.manage"}},
	}
	handler, err := NewHandler(Dependencies{Service: store, AuthenticateSession: func(_ context.Context, token string) (identity.AuthenticatedSession, error) {
		principal, ok := principals[token]
		if !ok {
			return identity.AuthenticatedSession{}, identity.ErrInvalidSession
		}
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: principal}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	cert, key := generateCertificateHTTPKeypair(t)
	fixture := certificateHTTPIntegrationFixture{pool: pool, handler: handler, scopeID: scopeID, ownerUserID: ownerID, ownerRoleID: ownerRole, platformScopeID: platformScopeID, platformUserID: platformID, certificatePEM: cert, privateKeyPEM: key}
	target := "?target_scope_id=" + fixture.scopeID.String()
	t.Run("platform collection needs no target but detail and writes do", func(t *testing.T) {
		list := fixture.request(http.MethodGet, "/v1/certificate-assets", "", "platform", "", "")
		assertIntegrationResponse(t, list, http.StatusOK, "")
		for _, method := range []string{http.MethodPost, http.MethodGet} {
			path, body := "/v1/certificate-assets", fixture.uploadBody(t, "missing target")
			if method == http.MethodGet {
				path, body = path+"/"+uuid.NewString(), ""
			}
			response := fixture.request(method, path, body, "platform", "missing-target", "missing-target")
			assertIntegrationResponse(t, response, http.StatusBadRequest, "certificate_asset_invalid_request")
		}
	})
	t.Run("tenant upload records actor not creator inference", func(t *testing.T) {
		created := fixture.request(http.MethodPost, "/v1/certificate-assets", fixture.uploadBody(t, "tenant certificate"), "owner", "tenant-owner", "tenant-owner")
		assertIntegrationResponse(t, created, http.StatusCreated, "")
		var detail struct {
			Asset struct {
				OwnerStatus string `json:"owner_status"`
				Owner       *struct {
					ID        uuid.UUID `json:"id"`
					DisplayID string    `json:"display_id"`
					Username  string    `json:"username"`
				} `json:"owner"`
			} `json:"asset"`
		}
		if err := json.Unmarshal(created.Body.Bytes(), &detail); err != nil {
			t.Fatal(err)
		}
		if detail.Asset.OwnerStatus != "recorded" || detail.Asset.Owner == nil || detail.Asset.Owner.ID != fixture.ownerUserID || detail.Asset.Owner.DisplayID == "" || detail.Asset.Owner.Username != "certificate-http-owner" {
			t.Fatalf("missing factual owner: %s", created.Body.String())
		}
	})
	t.Run("platform upload accepts explicit active member and retains actor", func(t *testing.T) {
		fixture.certificatePEM, fixture.privateKeyPEM = generateCertificateHTTPKeypair(t)
		var body map[string]string
		if err := json.Unmarshal([]byte(fixture.uploadBody(t, "platform certificate")), &body); err != nil {
			t.Fatal(err)
		}
		body["owner_user_id"] = fixture.ownerUserID.String()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		created := fixture.request(http.MethodPost, "/v1/certificate-assets"+target, string(encoded), "platform", "platform-owner", "platform-owner")
		assertIntegrationResponse(t, created, http.StatusCreated, "")
		var detail struct {
			Asset struct {
				ID          uuid.UUID `json:"id"`
				CreatedBy   uuid.UUID `json:"created_by"`
				OwnerStatus string    `json:"owner_status"`
				Owner       *struct {
					ID uuid.UUID `json:"id"`
				} `json:"owner"`
			} `json:"asset"`
		}
		if err := json.Unmarshal(created.Body.Bytes(), &detail); err != nil {
			t.Fatal(err)
		}
		if detail.Asset.OwnerStatus != "recorded" || detail.Asset.Owner == nil || detail.Asset.Owner.ID != fixture.ownerUserID || detail.Asset.CreatedBy != fixture.platformUserID {
			t.Fatalf("owner/actor mixed: %s", created.Body.String())
		}
		read := fixture.request(http.MethodGet, "/v1/certificate-assets/"+detail.Asset.ID.String()+target, "", "platform", "", "")
		assertIntegrationResponse(t, read, http.StatusOK, "")
		if read.Body.String() != created.Body.String() {
			t.Fatal("create/read receipt differs")
		}
		replay := fixture.request(http.MethodPost, "/v1/certificate-assets"+target, string(encoded), "platform", "platform-owner", "platform-owner")
		assertIntegrationResponse(t, replay, http.StatusCreated, "")
		if replay.Header().Get("Idempotency-Replayed") != "true" || replay.Body.String() != created.Body.String() {
			t.Fatal("owner replay differs")
		}
		fixture.assertNoPrivateMaterial(t, read.Body.String())
	})
	foreignTenant, foreignScope, foreignUser, secondMember := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name) VALUES($1,'Second active tenant');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
		INSERT INTO users(id,username,display_name,password_hash) VALUES($3,'certificate-foreign-owner','Foreign owner','test-hash'),($4,'certificate-second-member','Second member','test-hash');
		INSERT INTO memberships(scope_id,user_id) VALUES($2,$3),($5,$4)`, pgx.QueryExecModeSimpleProtocol, foreignTenant, foreignScope, foreignUser, secondMember, scopeID); err != nil {
		t.Fatal(err)
	}
	upload := func(t *testing.T, target uuid.UUID, owner *uuid.UUID, token, key string) *httptest.ResponseRecorder {
		t.Helper()
		fixture.certificatePEM, fixture.privateKeyPEM = generateCertificateHTTPKeypair(t)
		body := map[string]string{"name": key, "certificate_pem": string(fixture.certificatePEM), "private_key_pem": string(fixture.privateKeyPEM)}
		if owner != nil {
			body["owner_user_id"] = owner.String()
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return fixture.request(http.MethodPost, "/v1/certificate-assets?target_scope_id="+target.String(), string(encoded), token, key, key)
	}
	t.Run("two tenants multiple members and tenant-local display IDs", func(t *testing.T) {
		foreign := upload(t, foreignScope, &foreignUser, "platform", "foreign-cert")
		assertIntegrationResponse(t, foreign, http.StatusCreated, "")
		second := upload(t, scopeID, &secondMember, "platform", "second-member-cert")
		assertIntegrationResponse(t, second, http.StatusCreated, "")
		list := fixture.request(http.MethodGet, "/v1/certificate-assets?limit=100", "", "platform", "", "")
		assertIntegrationResponse(t, list, http.StatusOK, "")
		var result assetList
		if err := json.Unmarshal(list.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Total != 4 || len(result.Items) != 4 {
			t.Fatalf("cross-tenant count %d/%d", result.Total, len(result.Items))
		}
		owners := map[uuid.UUID]bool{}
		localIDs := 0
		for _, asset := range result.Items {
			if asset.Tenant == nil || asset.Tenant.ID == asset.TenantScopeID || asset.Tenant.DisplayID == "" || asset.Tenant.Name == "" {
				t.Fatal("tenant projection missing or confused with access scope")
			}
			if asset.TenantScopeID == scopeID && asset.Tenant.ID != tenantID || asset.TenantScopeID == foreignScope && asset.Tenant.ID != foreignTenant {
				t.Fatal("tenant projection does not match stored tenant identity")
			}
			if asset.Owner != nil {
				owners[asset.Owner.ID] = true
			}
			if asset.DisplayID == "1" {
				localIDs++
			}
		}
		if !owners[ownerID] || !owners[foreignUser] || !owners[secondMember] || localIDs != 2 {
			t.Fatalf("incorrect owner or display ID projection: %v %d", owners, localIDs)
		}
		tenantList := fixture.request(http.MethodGet, "/v1/certificate-assets", "", "owner", "", "")
		assertIntegrationResponse(t, tenantList, http.StatusOK, "")
		if strings.Contains(tenantList.Body.String(), foreignScope.String()) {
			t.Fatal("tenant collection leaked foreign asset")
		}
		assertIntegrationResponse(t, fixture.request(http.MethodGet, "/v1/certificate-assets?target_scope_id="+foreignScope.String(), "", "owner", "", ""), http.StatusForbidden, "certificate_asset_permission_denied")
	})
	t.Run("owner failures do not create facts", func(t *testing.T) {
		var before int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM certificate_assets`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		missing := uuid.New()
		for _, test := range []struct {
			name, token string
			user        uuid.UUID
		}{
			{"missing", "platform", missing}, {"foreign", "platform", foreignUser}, {"platform-actor", "platform", platformID}, {"tenant-impersonation", "owner", secondMember},
		} {
			assertIntegrationResponse(t, upload(t, scopeID, &test.user, test.token, test.name), http.StatusForbidden, "certificate_asset_permission_denied")
		}
		for _, test := range []struct{ sql, restore, key string }{
			{`UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, `UPDATE memberships SET status='active' WHERE scope_id=$1 AND user_id=$2`, "suspended-member"},
			{`UPDATE users SET status='disabled' WHERE id=$2 AND EXISTS(SELECT 1 FROM memberships WHERE scope_id=$1 AND user_id=$2)`, `UPDATE users SET status='active' WHERE id=$2 AND EXISTS(SELECT 1 FROM memberships WHERE scope_id=$1 AND user_id=$2)`, "disabled-user"},
		} {
			if _, err := pool.Exec(t.Context(), test.sql, scopeID, secondMember); err != nil {
				t.Fatal(err)
			}
			assertIntegrationResponse(t, upload(t, scopeID, &secondMember, "platform", test.key), http.StatusForbidden, "certificate_asset_permission_denied")
			if _, err := pool.Exec(t.Context(), test.restore, scopeID, secondMember); err != nil {
				t.Fatal(err)
			}
		}
		var after int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM certificate_assets`).Scan(&after); err != nil || before != after {
			t.Fatalf("denied writes changed asset count: %d/%d %v", before, after, err)
		}
	})
	t.Run("legacy clients remain unknown and immutable exact replay", func(t *testing.T) {
		created := upload(t, scopeID, nil, "platform", "legacy-platform")
		assertIntegrationResponse(t, created, http.StatusCreated, "")
		var detail assetDetail
		if err := json.Unmarshal(created.Body.Bytes(), &detail); err != nil {
			t.Fatal(err)
		}
		if detail.Asset.Owner != nil || detail.Asset.OwnerStatus != "legacy_unknown" {
			t.Fatal("legacy owner was inferred")
		}
		// Seed one old-shape receipt through the original pending -> completed protocol, never mutate a completed receipt.
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `INSERT INTO certificate_asset_write_requests(id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at)
			SELECT $1,tenant_scope_id,actor_scope_id,actor_user_id,operation,'old-shape-replay',request_digest,created_at FROM certificate_asset_write_requests WHERE idempotency_key='legacy-platform'`, uuid.New())
			if err != nil {
				return err
			}
			_, err = tx.Exec(t.Context(), `INSERT INTO certificate_asset_write_requests(id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at)
			SELECT $1,tenant_scope_id,$2,$3,operation,'old-tenant-replay',request_digest,created_at FROM certificate_asset_write_requests WHERE idempotency_key='legacy-platform'`, uuid.New(), scopeID, ownerID)
			if err != nil {
				return err
			}
			_, err = tx.Exec(t.Context(), `UPDATE certificate_asset_write_requests pending SET resource_id=original.resource_id,
			response_body=jsonb_set(original.response_body,'{asset}',(original.response_body->'asset')-'owner'-'owner_status'-'tenant'),completed_at=original.completed_at
			FROM certificate_asset_write_requests original WHERE pending.idempotency_key IN ('old-shape-replay','old-tenant-replay') AND original.idempotency_key='legacy-platform'`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		replay := fixture.request(http.MethodPost, "/v1/certificate-assets"+target, fixture.uploadBody(t, "legacy-platform"), "platform", "old-shape-replay", "legacy-platform")
		assertIntegrationResponse(t, replay, http.StatusCreated, "")
		if replay.Header().Get("Idempotency-Replayed") != "true" || replay.Body.String() != created.Body.String() {
			t.Fatal("legacy wire replay lost original fields or invented ownership")
		}
		tenantReplay := fixture.request(http.MethodPost, "/v1/certificate-assets", fixture.uploadBody(t, "legacy-platform"), "owner", "old-tenant-replay", "legacy-platform")
		assertIntegrationResponse(t, tenantReplay, http.StatusCreated, "")
		if tenantReplay.Header().Get("Idempotency-Replayed") != "true" || tenantReplay.Body.String() != created.Body.String() {
			t.Fatal("legacy tenant omitted-owner receipt was defaulted to the actor")
		}
		var body map[string]string
		if err := json.Unmarshal([]byte(fixture.uploadBody(t, "legacy-platform")), &body); err != nil {
			t.Fatal(err)
		}
		body["owner_user_id"] = ownerID.String()
		encoded, _ := json.Marshal(body)
		conflict := fixture.request(http.MethodPost, "/v1/certificate-assets"+target, string(encoded), "platform", "old-shape-replay", "legacy-platform")
		assertIntegrationResponse(t, conflict, http.StatusConflict, "certificate_asset_idempotency_conflict")
		conflict = fixture.request(http.MethodPost, "/v1/certificate-assets"+target, string(encoded), "platform", "new-owner-same-cert", "new-owner-same-cert")
		assertIntegrationResponse(t, conflict, http.StatusConflict, "certificate_asset_idempotency_conflict")
	})
	t.Run("list rechecks active tenants and live IAM", func(t *testing.T) {
		if _, err := pool.Exec(t.Context(), `UPDATE tenants SET status='suspended' WHERE id=$1`, foreignTenant); err != nil {
			t.Fatal(err)
		}
		list := fixture.request(http.MethodGet, "/v1/certificate-assets", "", "platform", "", "")
		assertIntegrationResponse(t, list, http.StatusOK, "")
		if strings.Contains(list.Body.String(), foreignScope.String()) {
			t.Fatal("inactive tenant remained in global list")
		}
		unprivilegedID := uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'certificate-unprivileged-platform','Unprivileged','unused');
			INSERT INTO memberships(scope_id,user_id) VALUES($2,$1)`, pgx.QueryExecModeSimpleProtocol, unprivilegedID, platformScopeID); err != nil {
			t.Fatal(err)
		}
		stale := principals["platform"]
		stale.UserID = unprivilegedID
		principals["stale-permission"] = stale
		assertIntegrationResponse(t, fixture.request(http.MethodGet, "/v1/certificate-assets", "", "stale-permission", "", ""), http.StatusForbidden, "certificate_asset_permission_denied")
		if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, platformScopeID, platformID); err != nil {
			t.Fatal(err)
		}
		assertIntegrationResponse(t, fixture.request(http.MethodGet, "/v1/certificate-assets", "", "platform", "", ""), http.StatusForbidden, "certificate_asset_permission_denied")
	})
}
