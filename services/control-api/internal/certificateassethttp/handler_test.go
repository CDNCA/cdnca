package certificateassethttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestCertificateAssetOpenAPIFragmentMatchesRuntimeAndRedactionContract(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-certificate-assets.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	contract := string(source)
	for _, required := range []string{
		"openapi: 3.1.0",
		"package-owned contract is independently",
		"mounted only when the control-api Config factory is injected",
		"security:\n  - bearerAuth: []",
		"  /v1/certificate-assets:",
		"      operationId: listCertificateAssets",
		"      operationId: uploadCertificateAsset",
		"  /v1/certificate-assets/{asset_id}:",
		"      operationId: getCertificateAsset",
		"      operationId: deleteCertificateAsset",
		"  /v1/certificate-assets/{asset_id}/versions/{version_id}/activate:",
		"      operationId: activateCertificateAssetVersion",
		"  /v1/certificate-assets/{asset_id}/bindings:",
		"      operationId: listCertificateAssetBindings",
		"      operationId: bindCertificateAsset",
		"  /v1/certificate-assets/{asset_id}/bindings/{site_id}:",
		"      operationId: unbindCertificateAsset",
		"  /v1/sites/{site_id}/certificate-binding:",
		"      operationId: getCertificateSiteBinding",
		"    CertificateSiteBindingDetail:",
		"    SiteBindingDetailOK:",
		"name: target_scope_id",
		"name: page",
		"name: limit",
		"name: search",
		"required: [items, total, counts]",
		"required: [all, normal, expiring, expired, auto_renew, manual_renew]",
		"name: status",
		"x-required-permissions: [certificates.read]",
		"x-required-permissions: [certificates.manage]",
		"maxLength: 262144",
		"maxLength: 65536",
		"maxLength: 256",
		"x-maxUtf8Bytes: 128",
		"x-maxUtf8Bytes: 256",
		"required: [name, certificate_pem, private_key_pem]",
		"required: [expected_revision]",
		"description: Never returned by this API.",
	} {
		if !strings.Contains(contract, required) {
			t.Fatalf("OpenAPI fragment is missing %q", required)
		}
	}
	// 资产吊销接口已下线。
	if strings.Contains(contract, "/revoke:") || strings.Contains(contract, "revokeCertificateAssetVersion") {
		t.Fatal("OpenAPI fragment still documents the retired certificate asset revoke route")
	}
	if strings.Contains(contract, "cdncaKeyAuth") || strings.Contains(contract, "private_key_ciphertext") ||
		strings.Contains(contract, "wrapped_key_material") || strings.Count(contract, "        private_key_pem:") != 1 {
		t.Fatal("OpenAPI fragment broadens auth or exposes private key storage fields")
	}
}

type serviceStub struct {
	assets           []certificateasset.Asset
	assetTotal       int64
	asset            certificateasset.Asset
	versions         []certificateasset.Version
	bindings         []certificateasset.Binding
	siteBinding      certificateasset.Binding
	siteVersion      certificateasset.Version
	importResult     certificateasset.ImportResult
	listErr          error
	getErr           error
	importErr        error
	activateErr      error
	bindingsErr      error
	siteBindingErr   error
	bindErr          error
	unbindErr        error
	deleteErr        error
	actor            certificateasset.Actor
	importRequest    certificateasset.ImportRequest
	activateReq      certificateasset.ActivateRequest
	bindRequest      certificateasset.BindRequest
	unbindRequest    certificateasset.UnbindRequest
	deleteRequest    certificateasset.DeleteRequest
	listRequest      certificateasset.ListRequest
	targetScopeID    uuid.UUID
	listCalls        int
	getCalls         int
	importCalls      int
	activateCalls    int
	bindingsCalls    int
	siteBindingCalls int
	bindCalls        int
	unbindCalls      int
	deleteCalls      int
}

func (stub *serviceStub) ListPage(_ context.Context, actor certificateasset.Actor, request certificateasset.ListRequest) (certificateasset.ListResult, error) {
	stub.actor, stub.targetScopeID, stub.listRequest, stub.listCalls = actor, request.TenantScopeID, request, stub.listCalls+1
	if request.TenantScopeID == uuid.Nil && actor.ScopeKind != certificateasset.ScopePlatform || request.IncludeDeleted {
		return certificateasset.ListResult{}, certificateasset.ErrInvalidInput
	}
	return certificateasset.ListResult{Items: stub.assets, Total: stub.assetTotal}, stub.listErr
}

func (stub *serviceStub) Get(_ context.Context, actor certificateasset.Actor, tenantScopeID, assetID uuid.UUID) (certificateasset.Asset, []certificateasset.Version, error) {
	stub.actor, stub.targetScopeID, stub.getCalls = actor, tenantScopeID, stub.getCalls+1
	if tenantScopeID == uuid.Nil || assetID == uuid.Nil {
		return certificateasset.Asset{}, nil, certificateasset.ErrInvalidInput
	}
	return stub.asset, stub.versions, stub.getErr
}

func (stub *serviceStub) GetSiteBinding(_ context.Context, actor certificateasset.Actor, tenantScopeID, siteID uuid.UUID) (certificateasset.Binding, certificateasset.Version, error) {
	stub.actor, stub.targetScopeID, stub.siteBindingCalls = actor, tenantScopeID, stub.siteBindingCalls+1
	if tenantScopeID == uuid.Nil || siteID == uuid.Nil {
		return certificateasset.Binding{}, certificateasset.Version{}, certificateasset.ErrInvalidInput
	}
	return stub.siteBinding, stub.siteVersion, stub.siteBindingErr
}

func (stub *serviceStub) Import(_ context.Context, actor certificateasset.Actor, request certificateasset.ImportRequest) (certificateasset.ImportResult, error) {
	stub.actor, stub.importRequest, stub.importCalls = actor, request, stub.importCalls+1
	return stub.importResult, stub.importErr
}

func (stub *serviceStub) Activate(_ context.Context, actor certificateasset.Actor, request certificateasset.ActivateRequest) (certificateasset.Version, error) {
	stub.actor, stub.activateReq, stub.activateCalls = actor, request, stub.activateCalls+1
	return stub.versions[0], stub.activateErr
}

func (stub *serviceStub) ListBindings(_ context.Context, actor certificateasset.Actor, tenantScopeID, assetID uuid.UUID) ([]certificateasset.Binding, error) {
	stub.actor, stub.targetScopeID, stub.bindingsCalls = actor, tenantScopeID, stub.bindingsCalls+1
	return stub.bindings, stub.bindingsErr
}

func (stub *serviceStub) Bind(_ context.Context, actor certificateasset.Actor, request certificateasset.BindRequest) (certificateasset.Binding, error) {
	stub.actor, stub.bindRequest, stub.bindCalls = actor, request, stub.bindCalls+1
	return stub.bindings[0], stub.bindErr
}

func (stub *serviceStub) Unbind(_ context.Context, actor certificateasset.Actor, request certificateasset.UnbindRequest) (certificateasset.Binding, error) {
	stub.actor, stub.unbindRequest, stub.unbindCalls = actor, request, stub.unbindCalls+1
	return stub.bindings[0], stub.unbindErr
}

func (stub *serviceStub) Delete(_ context.Context, actor certificateasset.Actor, request certificateasset.DeleteRequest) (certificateasset.Asset, error) {
	stub.actor, stub.deleteRequest, stub.deleteCalls = actor, request, stub.deleteCalls+1
	return stub.asset, stub.deleteErr
}

func TestHandlerTenantAssetLifecycleAndPrivateKeyRedaction(t *testing.T) {
	fixture := newFixture()
	session := tenantSession(fixture.tenantID, "certificates.read", "certificates.manage")
	handler := fixture.handler(t, session)

	list := fixture.serve(handler, http.MethodGet, "/v1/certificate-assets", "", nil)
	assertResponse(t, list, http.StatusOK, "")
	if fixture.service.listCalls != 1 || !strings.Contains(list.Body.String(), fixture.assetID.String()) ||
		!strings.Contains(list.Body.String(), `"total":1`) {
		t.Fatalf("list calls/body = %d/%s", fixture.service.listCalls, list.Body.String())
	}
	if fixture.service.actor.SessionID != session.SessionID {
		t.Fatalf("actor session=%s want=%s", fixture.service.actor.SessionID, session.SessionID)
	}

	detail := fixture.serve(handler, http.MethodGet, "/v1/certificate-assets/"+fixture.assetID.String(), "", nil)
	assertResponse(t, detail, http.StatusOK, "")
	if fixture.service.getCalls != 1 || !strings.Contains(detail.Body.String(), fixture.versionID.String()) {
		t.Fatalf("detail calls/body = %d/%s", fixture.service.getCalls, detail.Body.String())
	}

	siteBinding := fixture.serve(handler, http.MethodGet,
		"/v1/sites/"+fixture.siteID.String()+"/certificate-binding", "", nil)
	assertResponse(t, siteBinding, http.StatusOK, "")
	if fixture.service.siteBindingCalls != 1 || !strings.Contains(siteBinding.Body.String(), `"binding"`) ||
		!strings.Contains(siteBinding.Body.String(), `"version"`) ||
		!strings.Contains(siteBinding.Body.String(), fixture.versionID.String()) {
		t.Fatalf("site binding calls/body = %d/%s", fixture.service.siteBindingCalls, siteBinding.Body.String())
	}

	upload := fixture.serve(handler, http.MethodPost, "/v1/certificate-assets",
		`{"name":"edge certificate","certificate_pem":"PUBLIC-PEM","private_key_pem":"PRIVATE-PEM"}`, writeHeaders())
	assertResponse(t, upload, http.StatusCreated, "")
	if fixture.service.importCalls != 1 || fixture.service.importRequest.TenantScopeID != fixture.tenantID ||
		fixture.service.importRequest.Source != certificateasset.SourceUploaded ||
		string(fixture.service.importRequest.PrivateKeyPEM) != "PRIVATE-PEM" {
		t.Fatalf("import request = %#v", fixture.service.importRequest)
	}
	if strings.Contains(upload.Body.String(), "PRIVATE-PEM") || strings.Contains(upload.Body.String(), "private_key") {
		t.Fatalf("upload response leaked private key: %s", upload.Body.String())
	}

	activate := fixture.serve(handler, http.MethodPost,
		"/v1/certificate-assets/"+fixture.assetID.String()+"/versions/"+fixture.versionID.String()+"/activate",
		`{"expected_revision":3}`, writeHeaders())
	assertResponse(t, activate, http.StatusOK, "")
	if fixture.service.activateCalls != 1 || fixture.service.activateReq.ExpectedRevision != 3 {
		t.Fatalf("activate request = %#v", fixture.service.activateReq)
	}

	bindings := fixture.serve(handler, http.MethodGet,
		"/v1/certificate-assets/"+fixture.assetID.String()+"/bindings", "", nil)
	assertResponse(t, bindings, http.StatusOK, "")
	if fixture.service.bindingsCalls != 1 || !strings.Contains(bindings.Body.String(), fixture.siteID.String()) {
		t.Fatalf("bindings calls/body = %d/%s", fixture.service.bindingsCalls, bindings.Body.String())
	}

	bound := fixture.serve(handler, http.MethodPost,
		"/v1/certificate-assets/"+fixture.assetID.String()+"/bindings",
		`{"site_id":"`+fixture.siteID.String()+`","version_id":"`+fixture.versionID.String()+`","expected_revision":0,"default":true}`,
		writeHeaders())
	assertResponse(t, bound, http.StatusOK, "")
	if fixture.service.bindCalls != 1 || fixture.service.bindRequest.SiteID != fixture.siteID || !fixture.service.bindRequest.Default {
		t.Fatalf("bind request = %#v", fixture.service.bindRequest)
	}

	unbound := fixture.serve(handler, http.MethodDelete,
		"/v1/certificate-assets/"+fixture.assetID.String()+"/bindings/"+fixture.siteID.String(),
		`{"expected_revision":1}`, writeHeaders())
	assertResponse(t, unbound, http.StatusOK, "")
	if fixture.service.unbindCalls != 1 || fixture.service.unbindRequest.SiteID != fixture.siteID ||
		fixture.service.unbindRequest.ExpectedRevision != 1 {
		t.Fatalf("unbind request = %#v", fixture.service.unbindRequest)
	}

	// 资产吊销只改本地状态、与禁用重叠，接口已下线。
	revoke := fixture.serve(handler, http.MethodPost,
		"/v1/certificate-assets/"+fixture.assetID.String()+"/versions/"+fixture.versionID.String()+"/revoke",
		`{"expected_revision":3,"reason":"key retired"}`, writeHeaders())
	assertResponse(t, revoke, http.StatusNotFound, "certificate_asset_not_found")

	deleted := fixture.serve(handler, http.MethodDelete, "/v1/certificate-assets/"+fixture.assetID.String(),
		`{"expected_revision":3}`, writeHeaders())
	assertResponse(t, deleted, http.StatusOK, "")
	if fixture.service.deleteCalls != 1 || fixture.service.deleteRequest.ExpectedRevision != 3 {
		t.Fatalf("delete request = %#v", fixture.service.deleteRequest)
	}
	for _, requestID := range []string{fixture.service.importRequest.RequestID, fixture.service.deleteRequest.RequestID} {
		if requestID != "request-1" {
			t.Fatalf("request id = %q, want request-1", requestID)
		}
	}
}

func TestHandlerSiteBindingUsesStableNotFoundCode(t *testing.T) {
	fixture := newFixture()
	fixture.service.siteBindingErr = certificateasset.ErrNotFound
	handler := fixture.handler(t, tenantSession(fixture.tenantID, "certificates.read"))

	response := fixture.serve(handler, http.MethodGet,
		"/v1/sites/"+fixture.siteID.String()+"/certificate-binding", "", nil)
	assertResponse(t, response, http.StatusNotFound, "certificate_site_binding_not_found")
	if fixture.service.siteBindingCalls != 1 || strings.Contains(response.Body.String(), certificateasset.ErrNotFound.Error()) {
		t.Fatalf("site binding calls/body = %d/%s", fixture.service.siteBindingCalls, response.Body.String())
	}
}

func TestHandlerListUsesStrictBoundedPagination(t *testing.T) {
	fixture := newFixture()
	fixture.service.assetTotal = 31
	handler := fixture.handler(t, tenantSession(fixture.tenantID, "certificates.read"))
	response := fixture.serve(handler, http.MethodGet,
		"/v1/certificate-assets?page=2&limit=20&search=edge", "", nil)
	assertResponse(t, response, http.StatusOK, "")
	if request := fixture.service.listRequest; request.TenantScopeID != fixture.tenantID || request.Page != 2 ||
		request.Limit != 20 || request.Search != "edge" || request.IncludeDeleted {
		t.Fatalf("list request = %#v", request)
	}
	if !strings.Contains(response.Body.String(), `"items":[`) || !strings.Contains(response.Body.String(), `"total":31`) {
		t.Fatalf("list response = %s", response.Body.String())
	}

	badQueries := []string{
		"page=0", "page=01", "page=1&page=2", "limit=0", "limit=101", "limit=10&limit=20",
		"search=", "search=bad%0Avalue", "search=" + strings.Repeat("a", 129), "unknown=1",
		"target_scope_id=" + fixture.tenantID.String() + "&target_scope_id=" + fixture.tenantID.String(),
	}
	for _, query := range badQueries {
		calls := fixture.service.listCalls
		response := fixture.serve(handler, http.MethodGet, "/v1/certificate-assets?"+query, "", nil)
		assertResponse(t, response, http.StatusBadRequest, "certificate_asset_invalid_request")
		if fixture.service.listCalls != calls {
			t.Fatalf("invalid query %q reached service", query)
		}
	}
}

func TestHandlerTenantViewerAndExplicitPlatformTarget(t *testing.T) {
	fixture := newFixture()
	viewer := fixture.handler(t, tenantSession(fixture.tenantID, "certificates.read"))
	assertResponse(t, fixture.serve(viewer, http.MethodGet, "/v1/certificate-assets", "", nil), http.StatusOK, "")
	assertResponse(t, fixture.serve(viewer, http.MethodPost, "/v1/certificate-assets", `{}`, writeHeaders()),
		http.StatusForbidden, "certificate_asset_permission_denied")
	if fixture.service.importCalls != 0 {
		t.Fatalf("viewer import calls = %d", fixture.service.importCalls)
	}

	assertResponse(t, fixture.serve(viewer, http.MethodGet,
		"/v1/certificate-assets?target_scope_id="+uuid.NewString(), "", nil),
		http.StatusForbidden, "certificate_asset_permission_denied")

	platformSession := platformSession("certificates.read", "certificates.manage")
	platform := fixture.handler(t, platformSession)
	assertResponse(t, fixture.serve(platform, http.MethodGet, "/v1/certificate-assets", "", nil),
		http.StatusOK, "")
	if fixture.service.targetScopeID != uuid.Nil {
		t.Fatal("platform collection unexpectedly chose a tenant")
	}
	assertResponse(t, fixture.serve(platform, http.MethodGet, "/v1/certificate-assets/"+fixture.service.asset.ID.String(), "", nil),
		http.StatusBadRequest, "certificate_asset_invalid_request")
	response := fixture.serve(platform, http.MethodGet,
		"/v1/certificate-assets?target_scope_id="+fixture.tenantID.String(), "", nil)
	assertResponse(t, response, http.StatusOK, "")
	if fixture.service.actor.ScopeID != platformSession.Principal.ScopeID ||
		fixture.service.actor.ScopeKind != certificateasset.ScopePlatform || fixture.service.targetScopeID != fixture.tenantID {
		t.Fatalf("platform actor/target = %#v/%s", fixture.service.actor, fixture.service.targetScopeID)
	}
}

func TestHandlerTenantIDAndScopeIDRemainDistinct(t *testing.T) {
	fixture := newFixture()
	tenantID, scopeID := uuid.New(), uuid.New()
	session := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: scopeID, ScopeKind: certificateasset.ScopeTenant,
		TenantID: &tenantID, Permissions: []string{"certificates.read"},
	}}
	handler := fixture.handler(t, session)
	assertResponse(t, fixture.serve(handler, http.MethodGet, "/v1/certificate-assets", "", nil), http.StatusOK, "")
	if fixture.service.targetScopeID != scopeID {
		t.Fatalf("implicit tenant target = %s, want scope %s", fixture.service.targetScopeID, scopeID)
	}
	assertResponse(t, fixture.serve(handler, http.MethodGet,
		"/v1/certificate-assets?target_scope_id="+scopeID.String(), "", nil), http.StatusOK, "")
	if fixture.service.targetScopeID != scopeID {
		t.Fatalf("explicit tenant target = %s, want scope %s", fixture.service.targetScopeID, scopeID)
	}
}

func TestHandlerRequiresOneBearerSessionAndRejectsSpoofedIdentity(t *testing.T) {
	fixture := newFixture()
	handler := fixture.handler(t, tenantSession(fixture.tenantID, "certificates.read"))
	tests := []struct {
		name   string
		values []string
		spoof  bool
	}{
		{name: "missing"},
		{name: "cdnca key", values: []string{"CdncaKey forbidden"}},
		{name: "basic", values: []string{"Basic forbidden"}},
		{name: "duplicate", values: []string{"Bearer session", "Bearer session"}},
		{name: "whitespace", values: []string{"Bearer bad token"}},
		{name: "spoof", values: []string{"Bearer session"}, spoof: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/v1/certificate-assets", nil)
			for _, value := range test.values {
				request.Header.Add("Authorization", value)
			}
			if test.spoof {
				request.Header.Set("X-Scope-ID", uuid.NewString())
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertResponse(t, response, http.StatusUnauthorized, "authentication_required")
		})
	}
}

func TestHandlerRejectsInvalidMediaJSONMetadataAndOversizeBeforeService(t *testing.T) {
	fixture := newFixture()
	handler := fixture.handler(t, tenantSession(fixture.tenantID, "certificates.read", "certificates.manage"))
	tests := []struct {
		name    string
		body    string
		headers http.Header
		status  int
		code    string
	}{
		{name: "missing media", body: `{}`, headers: metadataHeaders(), status: 415, code: "certificate_asset_unsupported_media_type"},
		{name: "unknown field", body: `{"name":"n","certificate_pem":"p","private_key_pem":"k","extra":true}`, headers: writeHeaders(), status: 400, code: "certificate_asset_invalid_request"},
		{name: "duplicate key", body: `{"name":"n","name":"other","certificate_pem":"p","private_key_pem":"k"}`, headers: writeHeaders(), status: 400, code: "certificate_asset_invalid_request"},
		{name: "null required", body: `{"name":null,"certificate_pem":"p","private_key_pem":"k"}`, headers: writeHeaders(), status: 400, code: "certificate_asset_invalid_request"},
		{name: "trailing", body: `{"name":"n","certificate_pem":"p","private_key_pem":"k"}{}`, headers: writeHeaders(), status: 400, code: "certificate_asset_invalid_request"},
		{name: "missing idempotency", body: `{}`, headers: requestHeaders(), status: 400, code: "certificate_asset_invalid_idempotency_key"},
		{name: "duplicate idempotency", body: `{}`, headers: duplicateIdempotencyHeaders(), status: 400, code: "certificate_asset_invalid_idempotency_key"},
		{name: "oversize", body: strings.Repeat("x", maxRequestBytes+1), headers: writeHeaders(), status: 413, code: "certificate_asset_request_too_large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertResponse(t, fixture.serve(handler, http.MethodPost, "/v1/certificate-assets", test.body, test.headers), test.status, test.code)
		})
	}
	if fixture.service.importCalls != 0 {
		t.Fatalf("invalid requests reached import %d times", fixture.service.importCalls)
	}
}

func TestHandlerMapsStableDomainErrorsWithoutInternalMessages(t *testing.T) {
	fixture := newFixture()
	handler := fixture.handler(t, tenantSession(fixture.tenantID, "certificates.read", "certificates.manage"))
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{certificateasset.ErrInvalidCertificatePEM, 400, "certificate_asset_invalid_certificate_pem"},
		{certificateasset.ErrInvalidPrivateKeyPEM, 400, "certificate_asset_invalid_private_key_pem"},
		{certificateasset.ErrKeyMismatch, 400, "certificate_asset_key_mismatch"},
		{certificateasset.ErrPermissionDenied, 403, "certificate_asset_permission_denied"},
		{certificateasset.ErrNotFound, 404, "certificate_asset_not_found"},
		{certificateasset.ErrRevisionConflict, 409, "certificate_asset_revision_conflict"},
		{certificateasset.ErrIdempotencyConflict, 409, "certificate_asset_idempotency_conflict"},
		{certificateasset.ErrReferenced, 409, "certificate_asset_referenced"},
		{errors.New("private postgres detail"), 500, "certificate_asset_internal_error"},
	}
	for _, test := range tests {
		fixture.service.importErr = test.err
		response := fixture.serve(handler, http.MethodPost, "/v1/certificate-assets",
			`{"name":"edge","certificate_pem":"PUBLIC-PEM","private_key_pem":"PRIVATE-PEM"}`, writeHeaders())
		assertResponse(t, response, test.status, test.code)
		if strings.Contains(response.Body.String(), test.err.Error()) {
			t.Fatalf("response leaked internal error: %s", response.Body.String())
		}
	}
}

type handlerFixture struct {
	tenantID  uuid.UUID
	assetID   uuid.UUID
	versionID uuid.UUID
	siteID    uuid.UUID
	service   *serviceStub
}

func newFixture() handlerFixture {
	tenantID, assetID, versionID, siteID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	asset := certificateasset.Asset{ID: assetID, TenantScopeID: tenantID, Name: "edge", Source: certificateasset.SourceUploaded, Revision: 3, CreatedAt: now, UpdatedAt: now}
	version := certificateasset.Version{ID: versionID, AssetID: assetID, TenantScopeID: tenantID, Version: 1, Status: certificateasset.StatusActive, CertificatePEM: []byte("PUBLIC-PEM"), NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour)}
	binding := certificateasset.Binding{TenantScopeID: tenantID, SiteID: siteID, AssetID: assetID,
		VersionID: versionID, Revision: 1, Default: true, Bound: true, ChangedBy: uuid.New(), ChangedAt: now}
	return handlerFixture{tenantID: tenantID, assetID: assetID, versionID: versionID, siteID: siteID, service: &serviceStub{
		assets: []certificateasset.Asset{asset}, assetTotal: 1, asset: asset, versions: []certificateasset.Version{version},
		bindings: []certificateasset.Binding{binding}, siteBinding: binding, siteVersion: version,
		importResult: certificateasset.ImportResult{Asset: asset, Version: version},
	}}
}

func (fixture handlerFixture) handler(t *testing.T, session identity.AuthenticatedSession) http.Handler {
	t.Helper()
	handler, err := NewHandler(Dependencies{
		Service: fixture.service,
		AuthenticateSession: func(_ context.Context, raw string) (identity.AuthenticatedSession, error) {
			if raw != "session" {
				return identity.AuthenticatedSession{}, identity.ErrInvalidSession
			}
			return session, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func (fixture handlerFixture) serve(handler http.Handler, method, path, body string, headers http.Header) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer session")
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func tenantSession(tenantID uuid.UUID, permissions ...string) identity.AuthenticatedSession {
	return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: tenantID, ScopeKind: certificateasset.ScopeTenant,
		TenantID: &tenantID, Permissions: permissions,
	}}
}

func platformSession(permissions ...string) identity.AuthenticatedSession {
	return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: permissions,
	}}
}

func requestHeaders() http.Header {
	return http.Header{"Content-Type": []string{"application/json"}, "X-Request-Id": []string{"request-1"}}
}

func metadataHeaders() http.Header {
	return http.Header{"Idempotency-Key": []string{"asset-key"}, "X-Request-Id": []string{"request-1"}}
}

func writeHeaders() http.Header {
	return http.Header{"Content-Type": []string{"application/json"}, "Idempotency-Key": []string{"asset-key"}, "X-Request-Id": []string{"request-1"}}
}

func duplicateIdempotencyHeaders() http.Header {
	return http.Header{"Content-Type": []string{"application/json"}, "Idempotency-Key": []string{"one", "two"}, "X-Request-Id": []string{"request-1"}}
}

func assertResponse(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), status)
	}
	if code != "" {
		var value struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil || value.Error.Code != code {
			t.Fatalf("error=%q decode=%v body=%s, want %q", value.Error.Code, err, response.Body.String(), code)
		}
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers = %v", response.Header())
	}
}

func (stub *serviceStub) SetAutoRenew(context.Context, certificateasset.Actor, certificateasset.SetAutoRenewRequest) (certificateasset.Asset, error) {
	return stub.asset, nil
}

func (stub *serviceStub) SetDisabled(context.Context, certificateasset.Actor, certificateasset.SetDisabledRequest) (certificateasset.Asset, error) {
	return stub.asset, nil
}

func (stub *serviceStub) Download(context.Context, certificateasset.Actor, certificateasset.DownloadRequest) (certificateasset.Download, error) {
	return certificateasset.Download{}, certificateasset.ErrDownloadUnavailable
}
