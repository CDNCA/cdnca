package identityverificationhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
)

// 平台管理员也能代审。平台会话只在审核路由上、以 ?tenant_scope_id= 指定租户；
// 自助路由仍只认租户会话；租户会话不得带 tenant_scope_id。
func TestHandlerPlatformSessionReviewsWithTenantTarget(t *testing.T) {
	platformUser, platformScope, tenantScope := uuid.New(), uuid.New(), uuid.New()
	var seen []identityverification.Actor
	core := &coreStub{getReviewer: func(_ context.Context, actor identityverification.Actor,
		_ uuid.UUID,
	) (identityverification.Case, error) {
		seen = append(seen, actor)
		item := testCase(testActor(), identityverification.KindPersonalInitial, identityverification.StatusSubmitted, 2)
		item.TenantScopeID = actor.TenantScopeID()
		return item, nil
	}}
	service := testService(t, core, &readerStub{}, resolverStub{})
	platform, err := newHandler(service, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
			UserID: platformUser, ScopeID: platformScope, ScopeKind: "platform",
		}}, nil
	}, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	caseID := uuid.NewString()
	serve := func(handler http.Handler, path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		setTestAuthorization(request)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}

	ok := serve(platform, apiPrefix+"/reviewer/cases/"+caseID+"?tenant_scope_id="+tenantScope.String())
	if ok.Code != http.StatusOK || len(seen) != 1 {
		t.Fatalf("platform reviewer get = %d %s calls=%d", ok.Code, ok.Body.String(), len(seen))
	}
	if actor := seen[0]; actor.UserID != platformUser || actor.ScopeID != platformScope ||
		actor.ScopeKind != "platform" || actor.TenantScopeID() != tenantScope || !actor.PlatformReviewer() {
		t.Fatalf("platform reviewer actor user=%s scope=%s kind=%s target=%s",
			actor.UserID, actor.ScopeID, actor.ScopeKind, actor.TenantScopeID())
	}
	assertAPIError(t, serve(platform, apiPrefix+"/reviewer/cases/"+caseID), http.StatusBadRequest,
		"identity_verification_invalid_request")
	assertAPIError(t, serve(platform, apiPrefix+"/reviewer/cases/"+caseID+"?tenant_scope_id=not-a-uuid"),
		http.StatusBadRequest, "identity_verification_invalid_request")
	assertAPIError(t, serve(platform, apiPrefix+"/reviewer/cases/"+caseID+"?tenant_scope_id="+tenantScope.String()+
		"&tenant_scope_id="+uuid.NewString()), http.StatusBadRequest, "identity_verification_invalid_request")
	assertAPIError(t, serve(platform, apiPrefix+"/cases/"+caseID+"?tenant_scope_id="+tenantScope.String()),
		http.StatusUnauthorized, "identity_verification_unauthenticated")
	assertAPIError(t, serve(platform, apiPrefix+"/status"), http.StatusUnauthorized, "identity_verification_unauthenticated")

	tenant := testHandler(t, service, testActor())
	assertAPIError(t, serve(tenant, apiPrefix+"/reviewer/cases/"+caseID+"?tenant_scope_id="+tenantScope.String()),
		http.StatusBadRequest, "identity_verification_invalid_request")
	if len(seen) != 1 {
		t.Fatalf("rejected requests reached core: calls=%d", len(seen))
	}
}

func TestPlatformReviewActorRequiresDistinctTenantTarget(t *testing.T) {
	user, scope, session := uuid.New(), uuid.New(), uuid.New()
	if _, err := identityverification.NewPlatformReviewActor(user, scope, session, "raw", uuid.Nil); err == nil {
		t.Fatal("platform reviewer without tenant target accepted")
	}
	if _, err := identityverification.NewPlatformReviewActor(user, scope, session, "raw", scope); err == nil {
		t.Fatal("platform reviewer targeting its own platform scope accepted")
	}
	if _, err := identityverification.NewSessionActor(user, scope, "platform", session, "raw"); err == nil {
		t.Fatal("platform session actor without review target accepted")
	}
}
