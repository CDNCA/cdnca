package certificateassethttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	controldatabase "github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var certificateHTTPNow = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

func TestCertificateAssetHTTPIntegrationLifecycleReplayAndLiveRBAC(t *testing.T) {
	fixture := newCertificateHTTPIntegrationFixture(t)
	uploadBody := fixture.uploadBody(t, "边缘站点 \\\"证书\\\" \\\\ production")

	created := fixture.request(http.MethodPost, "/v1/certificate-assets", uploadBody,
		"owner", "asset-upload", "request-asset-upload")
	assertIntegrationResponse(t, created, http.StatusCreated, "")
	var detail assetDetail
	if err := json.Unmarshal(created.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Asset.TenantScopeID != fixture.scopeID || len(detail.Versions) != 1 ||
		detail.Versions[0].TenantScopeID != fixture.scopeID {
		t.Fatalf("created detail = %#v", detail)
	}
	fixture.assertNoPrivateMaterial(t, created.Body.String())

	replayed := fixture.request(http.MethodPost, "/v1/certificate-assets", uploadBody,
		"owner", "asset-upload", "request-asset-upload")
	assertIntegrationResponse(t, replayed, http.StatusCreated, "")
	if replayed.Header().Get("Idempotency-Replayed") != "true" || replayed.Body.String() != created.Body.String() {
		t.Fatalf("replay headers/body = %v/%s", replayed.Header(), replayed.Body.String())
	}
	fixture.assertFactCounts(t, 1, 1, 1, 1)

	conflict := fixture.request(http.MethodPost, "/v1/certificate-assets",
		fixture.uploadBody(t, "不同名称"), "owner", "asset-upload", "request-asset-upload")
	assertIntegrationResponse(t, conflict, http.StatusConflict, "certificate_asset_idempotency_conflict")
	fixture.assertFactCounts(t, 1, 1, 1, 1)

	list := fixture.request(http.MethodGet, "/v1/certificate-assets", "", "owner", "", "")
	assertIntegrationResponse(t, list, http.StatusOK, "")
	if !strings.Contains(list.Body.String(), detail.Asset.ID.String()) {
		t.Fatalf("owner list = %s", list.Body.String())
	}
	viewerList := fixture.request(http.MethodGet, "/v1/certificate-assets", "", "viewer", "", "")
	assertIntegrationResponse(t, viewerList, http.StatusOK, "")
	viewerWrite := fixture.request(http.MethodPost, "/v1/certificate-assets", uploadBody,
		"viewer", "viewer-upload", "request-viewer-upload")
	assertIntegrationResponse(t, viewerWrite, http.StatusForbidden, "certificate_asset_permission_denied")

	get := fixture.request(http.MethodGet, "/v1/certificate-assets/"+detail.Asset.ID.String(), "", "owner", "", "")
	assertIntegrationResponse(t, get, http.StatusOK, "")
	fixture.assertNoPrivateMaterial(t, get.Body.String())

	activated := fixture.request(http.MethodPost, fmt.Sprintf("/v1/certificate-assets/%s/versions/%s/activate",
		detail.Asset.ID, detail.Versions[0].ID), `{"expected_revision":1}`,
		"owner", "asset-activate", "request-asset-activate")
	assertIntegrationResponse(t, activated, http.StatusOK, "")
	if !strings.Contains(activated.Body.String(), `"status":"active"`) {
		t.Fatalf("activate = %s", activated.Body.String())
	}

	bound := fixture.request(http.MethodPost, "/v1/certificate-assets/"+detail.Asset.ID.String()+"/bindings",
		fmt.Sprintf(`{"site_id":"%s","version_id":"%s","expected_revision":0,"default":true}`,
			fixture.siteID, detail.Versions[0].ID), "owner", "asset-bind", "request-asset-bind")
	assertIntegrationResponse(t, bound, http.StatusOK, "")
	bindings := fixture.request(http.MethodGet, "/v1/certificate-assets/"+detail.Asset.ID.String()+"/bindings",
		"", "owner", "", "")
	assertIntegrationResponse(t, bindings, http.StatusOK, "")
	if !strings.Contains(bindings.Body.String(), fixture.siteID.String()) {
		t.Fatalf("bindings = %s", bindings.Body.String())
	}
	unbound := fixture.request(http.MethodDelete,
		"/v1/certificate-assets/"+detail.Asset.ID.String()+"/bindings/"+fixture.siteID.String(),
		`{"expected_revision":1}`, "owner", "asset-unbind", "request-asset-unbind")
	assertIntegrationResponse(t, unbound, http.StatusOK, "")

	if _, err := fixture.pool.Exec(t.Context(), `UPDATE memberships SET status='suspended'
		WHERE scope_id=$1 AND user_id=$2`, fixture.scopeID, fixture.ownerUserID); err != nil {
		t.Fatal(err)
	}
	replayAfterRevoke := fixture.request(http.MethodPost, "/v1/certificate-assets", uploadBody,
		"owner", "asset-upload", "request-asset-upload")
	assertIntegrationResponse(t, replayAfterRevoke, http.StatusForbidden, "certificate_asset_permission_denied")
	fixture.assertFactCounts(t, 1, 1, 4, 4)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE memberships SET status='active'
		WHERE scope_id=$1 AND user_id=$2`, fixture.scopeID, fixture.ownerUserID); err != nil {
		t.Fatal(err)
	}

	// 资产吊销接口已下线，不写任何事实。
	revoked := fixture.request(http.MethodPost, fmt.Sprintf("/v1/certificate-assets/%s/versions/%s/revoke",
		detail.Asset.ID, detail.Versions[0].ID), `{"expected_revision":2,"reason":"密钥轮换"}`, "owner", "asset-revoke", "request-asset-revoke")
	assertIntegrationResponse(t, revoked, http.StatusNotFound, "certificate_asset_not_found")
	fixture.assertFactCounts(t, 1, 1, 4, 4)

	deleted := fixture.request(http.MethodDelete, "/v1/certificate-assets/"+detail.Asset.ID.String(),
		`{"expected_revision":2}`, "owner", "asset-delete", "request-asset-delete")
	assertIntegrationResponse(t, deleted, http.StatusOK, "")
	if !strings.Contains(deleted.Body.String(), `"deleted_at":`) {
		t.Fatalf("delete = %s", deleted.Body.String())
	}
	fixture.assertFactCounts(t, 1, 1, 5, 5)

	empty := fixture.request(http.MethodGet, "/v1/certificate-assets", "", "owner", "", "")
	assertIntegrationResponse(t, empty, http.StatusOK, "")
	// 085db73f4 起列表带各状态计数（删除后全为 0）。
	if empty.Body.String() != `{"items":[],"total":0,"counts":{"all":0,"normal":0,"expiring":0,"expired":0,"auto_renew":0,"manual_renew":0}}`+"\n" {
		t.Fatalf("post-delete list = %s", empty.Body.String())
	}
	missing := fixture.request(http.MethodGet, "/v1/certificate-assets/"+detail.Asset.ID.String(), "", "owner", "", "")
	assertIntegrationResponse(t, missing, http.StatusNotFound, "certificate_asset_not_found")
}

func TestCertificateAssetHTTPIntegrationInvalidAndExplicitPlatformTarget(t *testing.T) {
	fixture := newCertificateHTTPIntegrationFixture(t)
	invalid := fixture.request(http.MethodPost, "/v1/certificate-assets",
		`{"name":"invalid","certificate_pem":"private parser detail","private_key_pem":"secret"}`,
		"owner", "invalid-upload", "request-invalid-upload")
	assertIntegrationResponse(t, invalid, http.StatusBadRequest, "certificate_asset_invalid_certificate_pem")
	if strings.Contains(invalid.Body.String(), "private parser detail") || strings.Contains(invalid.Body.String(), "secret") {
		t.Fatalf("invalid response leaked input or parser detail: %s", invalid.Body.String())
	}

	unknown := fixture.request(http.MethodGet, "/v1/certificate-assets/"+uuid.NewString(), "", "owner", "", "")
	assertIntegrationResponse(t, unknown, http.StatusNotFound, "certificate_asset_not_found")
	platformRead := fixture.request(http.MethodGet, "/v1/certificate-assets", "", "platform", "", "")
	assertIntegrationResponse(t, platformRead, http.StatusOK, "")
	platformWrite := fixture.request(http.MethodPost,
		"/v1/certificate-assets?target_scope_id="+fixture.scopeID.String(), fixture.uploadBody(t, "platform"),
		"platform", "platform-upload", "request-platform-upload")
	assertIntegrationResponse(t, platformWrite, http.StatusCreated, "")
	var forgedTenantMembership bool
	if err := fixture.pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM memberships WHERE scope_id=$1 AND user_id=$2
	)`, fixture.scopeID, fixture.platformUserID).Scan(&forgedTenantMembership); err != nil || forgedTenantMembership {
		t.Fatalf("platform actor tenant membership exists=%t err=%v", forgedTenantMembership, err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE memberships SET status='suspended'
		WHERE scope_id=$1 AND user_id=$2`, fixture.platformScopeID, fixture.platformUserID); err != nil {
		t.Fatal(err)
	}
	denied := fixture.request(http.MethodGet,
		"/v1/certificate-assets?target_scope_id="+fixture.scopeID.String(), "", "platform", "", "")
	assertIntegrationResponse(t, denied, http.StatusForbidden, "certificate_asset_permission_denied")
	fixture.assertFactCounts(t, 1, 1, 1, 1)
}

type certificateHTTPIntegrationFixture struct {
	pool            *pgxpool.Pool
	handler         http.Handler
	scopeID         uuid.UUID
	siteID          uuid.UUID
	ownerRoleID     uuid.UUID
	ownerUserID     uuid.UUID
	platformScopeID uuid.UUID
	platformUserID  uuid.UUID
	certificatePEM  []byte
	privateKeyPEM   []byte
}

func newCertificateHTTPIntegrationFixture(t *testing.T) certificateHTTPIntegrationFixture {
	t.Helper()
	pool := isolatedCertificateHTTPPool(t)
	tenantID, scopeID := uuid.New(), uuid.New()
	ownerID, viewerID, platformID := uuid.New(), uuid.New(), uuid.New()
	ownerRoleID, viewerRoleID, platformRoleID := uuid.New(), uuid.New(), uuid.New()
	platformScopeID := uuid.New()
	siteID := uuid.New()

	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'certificate-http')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES
		($1,'tenant',$2),($3,'platform',NULL)`, scopeID, tenantID, platformScopeID); err != nil {
		t.Fatal(err)
	}
	for _, user := range []struct {
		id   uuid.UUID
		name string
	}{{ownerID, "certificate-http-owner"}, {viewerID, "certificate-http-viewer"}, {platformID, "certificate-http-platform"}} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
			VALUES($1,$2,$2,'test-password-hash')`, user.id, user.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($1,$3)`,
		scopeID, ownerID, viewerID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
		platformScopeID, platformID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
		($1,$3,'certificate-http-owner','owner',true),($2,$3,'certificate-http-viewer','viewer',true),
		($4,$5,'platform_owner','platform owner',true)`,
		ownerRoleID, viewerRoleID, scopeID, platformRoleID, platformScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name) VALUES
		($1,'certificates.read'),($1,'certificates.manage'),($2,'certificates.read'),
		($3,'certificates.read'),($3,'certificates.manage')`, ownerRoleID, viewerRoleID, platformRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES
		($1,$2,$3),($1,$4,$5),($6,$7,$8)`, scopeID, ownerID, ownerRoleID,
		viewerID, viewerRoleID, platformScopeID, platformID, platformRoleID); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var displayID int64
		if err := tx.QueryRow(t.Context(), `INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at)
			VALUES($1,2,now()) ON CONFLICT(scope_id) DO UPDATE
			SET next_value=site_display_id_sequences.next_value+1,updated_at=EXCLUDED.updated_at
			RETURNING next_value-1`, scopeID).Scan(&displayID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(
			id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,display_id
		) VALUES($1,$2,$3,'www.example.com',ARRAY['origin.example.test:443'],
			ARRAY['origin.example.test'],$3,$3,$4)`, siteID, scopeID, ownerID, displayID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port)
			VALUES($1,1,'origin.example.test',443)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	store, err := certificateasset.NewStoreWithDependencies(pool, certificateHTTPEnveloper{}, audit.New(pool),
		func() time.Time { return certificateHTTPNow })
	if err != nil {
		t.Fatal(err)
	}
	ownerTenantID, viewerTenantID := tenantID, tenantID
	sessions := map[string]identity.AuthenticatedSession{
		"owner": {
			SessionID: uuid.New(), Principal: identity.Principal{UserID: ownerID, ScopeID: scopeID,
				ScopeKind: certificateasset.ScopeTenant, TenantID: &ownerTenantID,
				Permissions: []string{"certificates.read", "certificates.manage"}},
		},
		"viewer": {
			SessionID: uuid.New(), Principal: identity.Principal{UserID: viewerID, ScopeID: scopeID,
				ScopeKind: certificateasset.ScopeTenant, TenantID: &viewerTenantID,
				Permissions: []string{"certificates.read"}},
		},
		"platform": {
			SessionID: uuid.New(), Principal: identity.Principal{UserID: platformID, ScopeID: platformScopeID,
				ScopeKind: "platform", Permissions: []string{"certificates.read", "certificates.manage"}},
		},
	}
	for _, session := range sessions {
		digest := sha256.Sum256(session.SessionID[:])
		if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$2,$3,$4,$5,now()-interval '1 minute',now()+interval '1 hour')`,
			session.SessionID, uuid.New(), session.Principal.UserID, session.Principal.ScopeID, digest[:]); err != nil {
			t.Fatal(err)
		}
	}
	handler, err := NewHandler(Dependencies{
		Service: store,
		AuthenticateSession: func(_ context.Context, raw string) (identity.AuthenticatedSession, error) {
			session, ok := sessions[raw]
			if !ok {
				return identity.AuthenticatedSession{}, identity.ErrInvalidSession
			}
			return session, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, privateKeyPEM := generateCertificateHTTPKeypair(t)
	return certificateHTTPIntegrationFixture{
		pool: pool, handler: handler, scopeID: scopeID, siteID: siteID,
		ownerRoleID: ownerRoleID, ownerUserID: ownerID,
		platformScopeID: platformScopeID, platformUserID: platformID,
		certificatePEM: certificatePEM, privateKeyPEM: privateKeyPEM,
	}
}

func (fixture certificateHTTPIntegrationFixture) uploadBody(t *testing.T, name string) string {
	t.Helper()
	encoded, err := json.Marshal(map[string]string{
		"name": name, "certificate_pem": string(fixture.certificatePEM), "private_key_pem": string(fixture.privateKeyPEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func (fixture certificateHTTPIntegrationFixture) request(method, path, body, token, key, requestID string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	if requestID != "" {
		request.Header.Set("X-Request-ID", requestID)
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func (fixture certificateHTTPIntegrationFixture) assertNoPrivateMaterial(t *testing.T, responseBody string) {
	t.Helper()
	var ciphertext []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT private_key_ciphertext
		FROM certificate_asset_private_key_envelope_facts LIMIT 1`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		string(fixture.privateKeyPEM), string(ciphertext), base64.StdEncoding.EncodeToString(ciphertext),
		"private_key_pem", "private_key_ciphertext", "private_key_nonce", "private_key_metadata",
	} {
		if forbidden != "" && strings.Contains(responseBody, forbidden) {
			t.Fatalf("response leaked private material marker %q", forbidden)
		}
	}
}

func (fixture certificateHTTPIntegrationFixture) assertFactCounts(t *testing.T, assets, versions, writes, audits int) {
	t.Helper()
	for table, want := range map[string]int{
		"certificate_assets": assets, "certificate_asset_versions": versions,
		"certificate_asset_write_requests": writes,
	} {
		var got int
		if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s count = %d, want %d", table, got, want)
		}
	}
	var gotAudits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE result='success' AND action IN ('certificate.asset.import','certificate.asset.activate','certificate.asset.bind',
			'certificate.asset.unbind','certificate.asset.delete')`).Scan(&gotAudits); err != nil {
		t.Fatal(err)
	}
	if gotAudits != audits {
		t.Fatalf("certificate audit count = %d, want %d", gotAudits, audits)
	}
}

func assertIntegrationResponse(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d body=%s, want %d", response.Code, response.Body.String(), status)
	}
	if code == "" {
		return
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error.Code != code {
		t.Fatalf("error = %#v decode=%v body=%s, want %s", envelope, err, response.Body.String(), code)
	}
}

type certificateHTTPEnveloper struct{}

func (certificateHTTPEnveloper) Seal(_ context.Context, request certificateasset.PrivateKeySealRequest) (certificateasset.PrivateKeyEnvelope, error) {
	aad, err := request.Context.CanonicalAAD()
	if err != nil {
		return certificateasset.PrivateKeyEnvelope{}, err
	}
	digest := sha256.Sum256(append(append([]byte(nil), aad...), request.PlaintextPKCS8...))
	return certificateasset.PrivateKeyEnvelope{
		KeyID: "certificate-http-test-kek", Ciphertext: digest[:], Nonce: bytes.Repeat([]byte{0x42}, 12),
		Metadata: json.RawMessage(`{"algorithm":"test-digest-envelope"}`),
	}, nil
}

func (certificateHTTPEnveloper) SealOpaque(context.Context, certificateasset.OpaquePrivateKeySealRequest) (certificateasset.PrivateKeyEnvelope, error) {
	return certificateasset.PrivateKeyEnvelope{}, errors.New("opaque key not supported by certificate HTTP test")
}

func (certificateHTTPEnveloper) Unseal(context.Context, certificateasset.PrivateKeyUnsealRequest) ([]byte, error) {
	return nil, errors.New("unseal not supported by certificate HTTP test")
}

func (certificateHTTPEnveloper) Rewrap(context.Context, certificateasset.PrivateKeyRewrapRequest) (certificateasset.PrivateKeyEnvelope, error) {
	return certificateasset.PrivateKeyEnvelope{}, errors.New("rewrap not supported by certificate HTTP test")
}

func generateCertificateHTTPKeypair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Certificate HTTP Integration Issuer"},
		NotBefore: certificateHTTPNow.Add(-48 * time.Hour), NotAfter: certificateHTTPNow.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, issuerKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "www.example.com"},
		DNSNames:  []string{"example.com", "www.example.com"},
		NotBefore: certificateHTTPNow.Add(-24 * time.Hour), NotAfter: certificateHTTPNow.Add(90 * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, leafKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})...)
	return certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
}

func isolatedCertificateHTTPPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "certificate_http_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^certificate_http_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("refusing unexpected schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	if err := controldatabase.Migrate(ctx, pool, "up"); err != nil {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("migrate certificate HTTP schema: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop certificate HTTP schema: %v", err)
		}
		admin.Close()
	})
	return pool
}
