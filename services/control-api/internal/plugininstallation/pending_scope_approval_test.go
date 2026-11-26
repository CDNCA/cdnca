package plugininstallation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// 市场待确认授权（CF 优选 1.0.4）七项 scope 全部已批准、全部敏感、全部新增，管理员只勾两项确认安装。
// 授权端只确认整组已批准 scope；主控在转发前拒绝，给独立码和缺失清单，不再走到授权端。
func TestProductionPendingConfirmRequiresTheWholeApprovedScopeSet(t *testing.T) {
	tenantID := uuid.New()
	all := []string{"dns.read", "dns.records.manage", "edge.tenant.manage", "edge.tenant.read",
		"platform.ui_pages.provide", "probes.dnspup.request", "sites.read"}
	waiting := mergeView(tenantID, "io.cdnca.cf-optimize", "1.0.4", StatusPendingConfirmation, StatusPendingConfirmation)
	waiting.Installation.EntrypointType = EntrypointUIPage
	waiting.Installation.Revision = 1
	waiting.Installation.ManifestScopes = append([]string{}, all...)
	waiting.Installation.ApprovedScopes = append([]string{}, all...)
	waiting.Installation.SensitiveScopes = append([]string{}, all...)
	waiting.NewScopes = append([]string{}, all...)
	resolver := &pendingResolver{pending: Page{Items: []InstallationView{waiting}}, newRevision: 2}
	domain, err := NewProductionDomain(mergeRepository{heads: map[uuid.UUID]InstallationView{}}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: tenantID, ScopeKind: ScopePlatform,
		RequestID: "plugin-installation-confirm-1", Username: "ctl-admin"}
	confirm := func(scopes []string, sensitive, added bool) error {
		_, err := domain.Mutate(context.Background(), actor, MutationRequest{TenantID: tenantID,
			AuthorizationID: waiting.Installation.AuthorizationID, VerificationID: waiting.Installation.VerificationID,
			Action: ActionConfirm, ExpectedRevision: 1, IdempotencyKey: "plugin-installation-confirm-1",
			RequestID: actor.RequestID, ApprovedScopes: scopes, SensitivePermissionsConfirmed: sensitive,
			NewPermissionsConfirmed: added, Targets: &Targets{TenantScopeIDs: []uuid.UUID{uuid.New()}}})
		return err
	}

	// The reported request: two of seven scopes, both confirmations given.
	err = confirm([]string{"platform.ui_pages.provide", "sites.read"}, true, true)
	if !errors.Is(err, ErrRequiredScopesMissing) || errors.Is(err, ErrConsentRequired) || len(resolver.confirmed) != 0 {
		t.Fatalf("subset err=%v confirms=%d", err, len(resolver.confirmed))
	}
	wantMissing := []string{"dns.read", "dns.records.manage", "edge.tenant.manage", "edge.tenant.read", "probes.dnspup.request"}
	if got := RefusedScopes(err); !reflect.DeepEqual(got, wantMissing) {
		t.Fatalf("missing scopes=%v", got)
	}
	if ErrorCode(err) != "plugin_installation_required_scopes_missing" {
		t.Fatalf("code=%s", ErrorCode(err))
	}
	// A scope the platform did not approve is its own refusal.
	err = confirm(append(append([]string{}, all...), "zones.manage"), true, true)
	if !errors.Is(err, ErrScopeNotApproved) || !reflect.DeepEqual(RefusedScopes(err), []string{"zones.manage"}) ||
		len(resolver.confirmed) != 0 {
		t.Fatalf("unapproved err=%v scopes=%v confirms=%d", err, RefusedScopes(err), len(resolver.confirmed))
	}
	// The whole set without the sensitive or new permission confirmation keeps the consent code.
	for _, flags := range [][2]bool{{false, true}, {true, false}} {
		err = confirm(all, flags[0], flags[1])
		if !errors.Is(err, ErrConsentRequired) || RefusedScopes(err) != nil || len(resolver.confirmed) != 0 {
			t.Fatalf("flags=%v err=%v confirms=%d", flags, err, len(resolver.confirmed))
		}
	}
	// The whole set with both confirmations goes to the license service unchanged.
	resolver.confirmErr = nil
	_ = confirm(all, true, true)
	if len(resolver.confirmed) != 1 || !reflect.DeepEqual(resolver.confirmed[0].ApprovedScopes, all) ||
		!resolver.confirmed[0].SensitivePermissionsConfirmed || !resolver.confirmed[0].NewPermissionsConfirmed ||
		resolver.resolve.KnownLifecycleRevision != 2 {
		t.Fatalf("confirmed=%+v resolve=%+v", resolver.confirmed, resolver.resolve)
	}
}

func TestRequirePendingApprovalWithoutSensitiveOrNewScopes(t *testing.T) {
	target := InstallationView{Installation: Installation{ApprovedScopes: []string{"plugin.read", "sites.read"},
		SensitiveScopes: []string{}}}
	if err := requirePendingApproval(target, MutationRequest{ApprovedScopes: []string{"plugin.read", "sites.read"}}); err != nil {
		t.Fatalf("no consent needed err=%v", err)
	}
	if err := requirePendingApproval(target, MutationRequest{ApprovedScopes: []string{}}); !errors.Is(err, ErrRequiredScopesMissing) ||
		!reflect.DeepEqual(RefusedScopes(err), []string{"plugin.read", "sites.read"}) {
		t.Fatalf("empty err=%v scopes=%v", err, RefusedScopes(err))
	}
}

func TestHandlerSplitsScopeApprovalRefusals(t *testing.T) {
	platformScope, authorizationID := uuid.New(), uuid.New()
	platform := identity.Principal{UserID: uuid.New(), ScopeID: platformScope, ScopeKind: ScopePlatform,
		Username: "platform-admin", Permissions: []string{PermissionPlatformRead, PermissionPlatformManage}}
	body := `{"verification_id":"` + uuid.NewString() + `","approved_scopes":["platform.ui_pages.provide","sites.read"],` +
		`"sensitive_permissions_confirmed":true,"new_permissions_confirmed":true,` +
		`"targets":{"all_tenants":false,"tenant_scope_ids":["` + uuid.NewString() + `"]}}`
	for name, test := range map[string]struct {
		err    error
		status int
		code   string
		scopes []string
	}{
		"missing": {scopeRefusal{err: ErrRequiredScopesMissing, scopes: []string{"dns.read", "sites.write"}},
			http.StatusUnprocessableEntity, "plugin_installation_required_scopes_missing", []string{"dns.read", "sites.write"}},
		"not approved": {scopeRefusal{err: ErrScopeNotApproved, scopes: []string{"zones.manage"}},
			http.StatusUnprocessableEntity, "plugin_installation_scope_not_approved", []string{"zones.manage"}},
		"stale":   {ErrApprovalStale, http.StatusConflict, "plugin_installation_approval_stale", nil},
		"consent": {ErrConsentRequired, http.StatusUnprocessableEntity, "plugin_installation_scope_approval_required", nil},
		"denied":  {ErrFactDenied, http.StatusUnprocessableEntity, "plugin_installation_scope_approval_required", nil},
	} {
		t.Run(name, func(t *testing.T) {
			handler, err := NewHandler(HandlerDependencies{
				AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
					return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: platform}, nil
				}, Domain: &handlerTestDomain{err: test.err}})
			if err != nil {
				t.Fatal(err)
			}
			request := authenticatedHandlerRequest(http.MethodPost,
				"/v1/platform/plugin-installations/"+authorizationID.String()+"/confirm", bytes.NewBufferString(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("If-Match", `"1"`)
			request.Header.Set("Idempotency-Key", "platform-confirm-70")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if ErrorCode(test.err) != test.code {
				t.Fatalf("contract code=%s want %s", ErrorCode(test.err), test.code)
			}
			assertHandlerError(t, response, test.status, test.code)
			var wire map[string]map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &wire); err != nil {
				t.Fatal(err)
			}
			if test.scopes == nil {
				if len(wire["error"]) != 1 {
					t.Fatalf("unexpected fields: %s", response.Body.String())
				}
				return
			}
			details, _ := wire["error"]["details"].(map[string]any)
			raw, _ := details["scopes"].([]any)
			got := make([]string, 0, len(raw))
			for _, scope := range raw {
				got = append(got, scope.(string))
			}
			if len(wire["error"]) != 2 || len(details) != 1 || !reflect.DeepEqual(got, test.scopes) {
				t.Fatalf("body=%s", response.Body.String())
			}
		})
	}
}
