package certificateassethttp

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// fix-certops：PATCH /v1/certificate-assets/{id}/disabled 与 GET /v1/certificate-assets/{id}/download。
type certopsStub struct {
	*serviceStub
	disabledRequest certificateasset.SetDisabledRequest
	downloadRequest certificateasset.DownloadRequest
	disabledCalls   int
	downloadCalls   int
	err             error
	download        certificateasset.Download
}

func (stub *certopsStub) SetDisabled(_ context.Context, actor certificateasset.Actor, request certificateasset.SetDisabledRequest) (certificateasset.Asset, error) {
	stub.actor, stub.disabledRequest, stub.disabledCalls = actor, request, stub.disabledCalls+1
	asset := stub.asset
	asset.Disabled, asset.Revision = request.Disabled, request.ExpectedRevision+1
	return asset, stub.err
}

func (stub *certopsStub) Download(_ context.Context, actor certificateasset.Actor, request certificateasset.DownloadRequest) (certificateasset.Download, error) {
	stub.actor, stub.downloadRequest, stub.downloadCalls = actor, request, stub.downloadCalls+1
	if stub.err != nil {
		return certificateasset.Download{}, stub.err
	}
	material := stub.download
	material.PrivateKeyPEM = bytes.Clone(stub.download.PrivateKeyPEM)
	return material, nil
}

func certopsHandler(t *testing.T, stub *certopsStub, session string, permissions ...string) http.Handler {
	t.Helper()
	handler, err := NewHandler(Dependencies{Service: stub, AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
		if session == "platform" {
			return platformSession(permissions...), nil
		}
		return tenantSession(stub.asset.TenantScopeID, permissions...), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestHandlerSetsAssetDisabled(t *testing.T) {
	fixture := newFixture()
	stub := &certopsStub{serviceStub: fixture.service}
	path := "/v1/certificate-assets/" + fixture.assetID.String() + "/disabled"
	serve := func(session, body string, headers http.Header, permissions ...string) (int, string) {
		target := path
		if session == "platform" {
			target += "?target_scope_id=" + fixture.tenantID.String()
		}
		response := fixture.serve(certopsHandler(t, stub, session, permissions...), http.MethodPatch, target, body, headers)
		return response.Code, response.Body.String()
	}
	code, body := serve("tenant", `{"disabled":true,"expected_revision":3}`, writeHeaders(), "certificates.manage")
	if code != http.StatusOK || stub.disabledCalls != 1 || !stub.disabledRequest.Disabled ||
		stub.disabledRequest.AssetID != fixture.assetID || stub.disabledRequest.TenantScopeID != fixture.tenantID ||
		stub.disabledRequest.ExpectedRevision != 3 || stub.disabledRequest.IdempotencyKey != "asset-key" ||
		!strings.Contains(body, `"disabled":true`) || !strings.Contains(body, `"revision":4`) {
		t.Fatalf("tenant disable = %d %s request=%+v", code, body, stub.disabledRequest)
	}
	if code, _ := serve("platform", `{"disabled":false,"expected_revision":4}`, writeHeaders(), "certificates.manage"); code != http.StatusOK ||
		stub.disabledRequest.Disabled || stub.disabledRequest.TenantScopeID != fixture.tenantID {
		t.Fatalf("platform enable = %d", code)
	}
	if code, _ := serve("tenant", `{"disabled":true,"expected_revision":3}`, writeHeaders(), "certificates.read"); code != http.StatusForbidden {
		t.Fatalf("read-only disable = %d", code)
	}
	calls := stub.disabledCalls
	for _, invalid := range []string{`{"disabled":true}`, `{"expected_revision":3}`, `{"disabled":1,"expected_revision":3}`,
		`{"disabled":true,"expected_revision":0}`, `{"disabled":true,"expected_revision":3,"x":1}`} {
		if code, _ := serve("tenant", invalid, writeHeaders(), "certificates.manage"); code != http.StatusBadRequest {
			t.Fatalf("invalid body %s = %d", invalid, code)
		}
	}
	if code, _ := serve("tenant", `{"disabled":true,"expected_revision":3}`, requestHeaders(), "certificates.manage"); code != http.StatusBadRequest {
		t.Fatalf("missing idempotency key = %d", code)
	}
	if stub.disabledCalls != calls {
		t.Fatal("invalid requests reached the service")
	}
	stub.err = certificateasset.ErrReferenced
	if code, body := serve("tenant", `{"disabled":true,"expected_revision":3}`, writeHeaders(), "certificates.manage"); code != http.StatusConflict ||
		!strings.Contains(body, `"certificate_asset_referenced"`) {
		t.Fatalf("bound disable = %d %s", code, body)
	}
}

func TestHandlerDownloadsCertificateZip(t *testing.T) {
	fixture := newFixture()
	stub := &certopsStub{serviceStub: fixture.service, download: certificateasset.Download{
		AssetID: fixture.assetID, Name: "edge", SANs: []string{"*.example.com", "example.com"},
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n"),
		PrivateKeyPEM:  []byte("-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n"),
	}}
	path := "/v1/certificate-assets/" + fixture.assetID.String() + "/download"
	response := fixture.serve(certopsHandler(t, stub, "tenant", "certificates.manage"), http.MethodGet, path, "", requestHeaders())
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/zip" ||
		!strings.Contains(response.Header().Get("Content-Disposition"), `filename="_.example.com.zip"`) ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("download = %d %v %s", response.Code, response.Header(), response.Body.String())
	}
	if stub.downloadRequest.AssetID != fixture.assetID || stub.downloadRequest.TenantScopeID != fixture.tenantID ||
		stub.downloadRequest.RequestID != "request-1" {
		t.Fatalf("download request = %+v", stub.downloadRequest)
	}
	archive, err := zip.NewReader(bytes.NewReader(response.Body.Bytes()), int64(response.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, file := range archive.File {
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(reader)
		files[file.Name] = string(body)
	}
	if len(files) != 2 || files["fullchain.pem"] != string(stub.download.CertificatePEM) || files["privkey.pem"] != string(stub.download.PrivateKeyPEM) {
		t.Fatalf("zip files = %v", files)
	}
	// 只读权限不能导出私钥；跨租户与平台未指定目标拒绝。
	if response := fixture.serve(certopsHandler(t, stub, "tenant", "certificates.read"), http.MethodGet, path, "", requestHeaders()); response.Code != http.StatusForbidden {
		t.Fatalf("read-only download = %d", response.Code)
	}
	calls := stub.downloadCalls
	if response := fixture.serve(certopsHandler(t, stub, "tenant", "certificates.manage"), http.MethodGet, path+"?target_scope_id="+fixture.siteID.String(), "", requestHeaders()); response.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant download = %d", response.Code)
	}
	if response := fixture.serve(certopsHandler(t, stub, "platform", "certificates.manage"), http.MethodGet, path, "", requestHeaders()); response.Code != http.StatusBadRequest {
		t.Fatalf("platform without target = %d", response.Code)
	}
	if stub.downloadCalls != calls {
		t.Fatal("refused downloads reached the service")
	}
	if response := fixture.serve(certopsHandler(t, stub, "platform", "certificates.manage"), http.MethodGet, path+"?target_scope_id="+fixture.tenantID.String(), "", requestHeaders()); response.Code != http.StatusOK {
		t.Fatalf("platform download = %d", response.Code)
	}
	stub.err = certificateasset.ErrDownloadUnavailable
	if response := fixture.serve(certopsHandler(t, stub, "tenant", "certificates.manage"), http.MethodGet, path, "", requestHeaders()); response.Code != http.StatusConflict ||
		!strings.Contains(response.Body.String(), "certificate_asset_download_unavailable") {
		t.Fatalf("revoked download = %d %s", response.Code, response.Body.String())
	}
	if response := fixture.serve(certopsHandler(t, stub, "tenant", "certificates.manage"), http.MethodPost, path, "{}", writeHeaders()); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST download = %d", response.Code)
	}
}
