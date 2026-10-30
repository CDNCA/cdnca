package certificateassethttp

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// fix-autorenew：PATCH /v1/certificate-assets/{id}/auto-renew 切换证书自动续签。
type autoRenewStub struct {
	*serviceStub
	request certificateasset.SetAutoRenewRequest
	calls   int
	err     error
}

func (stub *autoRenewStub) SetAutoRenew(_ context.Context, actor certificateasset.Actor, request certificateasset.SetAutoRenewRequest) (certificateasset.Asset, error) {
	stub.actor, stub.request, stub.calls = actor, request, stub.calls+1
	asset := stub.asset
	asset.AutoRenew, asset.Revision = request.Enabled, request.ExpectedRevision+1
	return asset, stub.err
}

func TestHandlerSetsAssetAutoRenew(t *testing.T) {
	fixture := newFixture()
	stub := &autoRenewStub{serviceStub: fixture.service}
	path := "/v1/certificate-assets/" + fixture.assetID.String() + "/auto-renew"
	serve := func(session string, body string, headers http.Header, permissions ...string) (int, string) {
		t.Helper()
		handler, err := NewHandler(Dependencies{Service: stub, AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
			if session == "platform" {
				return platformSession(permissions...), nil
			}
			return tenantSession(fixture.tenantID, permissions...), nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		target := path
		if session == "platform" {
			target += "?target_scope_id=" + fixture.tenantID.String()
		}
		response := fixture.serve(handler, http.MethodPatch, target, body, headers)
		return response.Code, response.Body.String()
	}

	code, body := serve("tenant", `{"enabled":true,"expected_revision":3}`, writeHeaders(), "certificates.manage")
	if code != http.StatusOK || stub.calls != 1 || !stub.request.Enabled || stub.request.ExpectedRevision != 3 ||
		stub.request.AssetID != fixture.assetID || stub.request.TenantScopeID != fixture.tenantID ||
		stub.request.IdempotencyKey != "asset-key" || stub.request.RequestID != "request-1" ||
		!strings.Contains(body, `"auto_renew":true`) || !strings.Contains(body, `"revision":4`) {
		t.Fatalf("tenant toggle = %d %s request=%+v", code, body, stub.request)
	}
	// 平台管理员显式指定目标租户。
	if code, body := serve("platform", `{"enabled":false,"expected_revision":4}`, writeHeaders(), "certificates.manage"); code != http.StatusOK ||
		stub.request.Enabled || stub.request.TenantScopeID != fixture.tenantID {
		t.Fatalf("platform toggle = %d %s", code, body)
	}
	// 只读权限不能改。
	if code, _ := serve("tenant", `{"enabled":true,"expected_revision":3}`, writeHeaders(), "certificates.read"); code != http.StatusForbidden {
		t.Fatalf("read-only toggle = %d", code)
	}
	calls := stub.calls
	for _, invalid := range []string{`{"enabled":true}`, `{"expected_revision":3}`, `{"enabled":"yes","expected_revision":3}`,
		`{"enabled":true,"expected_revision":0}`, `{"enabled":true,"expected_revision":3,"extra":1}`} {
		if code, _ := serve("tenant", invalid, writeHeaders(), "certificates.manage"); code != http.StatusBadRequest {
			t.Fatalf("invalid body %s = %d", invalid, code)
		}
	}
	if code, _ := serve("tenant", `{"enabled":true,"expected_revision":3}`, requestHeaders(), "certificates.manage"); code != http.StatusBadRequest {
		t.Fatalf("missing idempotency key = %d", code)
	}
	if stub.calls != calls {
		t.Fatal("invalid requests reached the service")
	}
	// 手动上传证书：明确错误。
	stub.err = certificateasset.ErrAutoRenewUnsupported
	if code, body := serve("tenant", `{"enabled":true,"expected_revision":3}`, writeHeaders(), "certificates.manage"); code != http.StatusConflict ||
		!strings.Contains(body, `"certificate_asset_auto_renew_unsupported"`) || !strings.Contains(body, "手动上传") {
		t.Fatalf("uploaded toggle = %d %s", code, body)
	}
	stub.err = certificateasset.ErrRevisionConflict
	if code, _ := serve("tenant", `{"enabled":true,"expected_revision":3}`, writeHeaders(), "certificates.manage"); code != http.StatusConflict {
		t.Fatalf("stale toggle = %d", code)
	}
	// 其他方法不受理。
	handler, _ := NewHandler(Dependencies{Service: stub, AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
		return tenantSession(fixture.tenantID, "certificates.manage"), nil
	}})
	if response := fixture.serve(handler, http.MethodPost, path, `{}`, writeHeaders()); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST auto-renew = %d", response.Code)
	}
}
