package cachecontrolhttp

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestHandlerPublishesInheritedCachePolicyRevision(t *testing.T) {
	scopeID, userID, siteID, definitionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	control := &fakeControl{publishPolicy: func(_ context.Context, _ cachecontrol.Actor, request cachecontrol.PublishPolicyRequest) (cachecontrol.PolicyWriteResult, error) {
		if request.BindingMode != cachecontrol.BindingInherit || request.DefinitionID != definitionID ||
			request.DefinitionRevision != 7 || request.ExpectedRevision != 2 || request.Document.Mode != "" {
			t.Fatalf("inherit request=%+v", request)
		}
		return cachecontrol.PolicyWriteResult{Policy: cachecontrol.PolicyRevision{
			SiteID: siteID, ScopeID: scopeID, Revision: 3,
			BindingMode: cachecontrol.BindingInherit, DefinitionID: definitionID, DefinitionRevision: 7,
			Document: cachecontrol.PolicyDocument{Mode: cachecontrol.PolicyDisabled, Rules: []cachecontrol.Rule{},
				QueryMode: cachecontrol.QueryIgnore, QueryNames: []string{}, VaryHeaders: []string{}},
		}}, nil
	}}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", PermissionPoliciesManage), nil
	})
	body := `{"expected_revision":2,"binding_mode":"inherit","definition_id":"` + definitionID.String() + `","definition_revision":7}`
	response := serveRaw(t, handler, http.MethodPost, "/v1/cache-policies/"+siteID.String(), body, "tenant", "inherit-policy")
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	for _, fragment := range []string{
		`"binding_mode":"inherit"`, `"definition_id":"` + definitionID.String() + `"`,
		`"definition_revision":7`, `"mode":"disabled"`,
	} {
		if !strings.Contains(response.Body.String(), fragment) {
			t.Fatalf("response missing %s: %s", fragment, response.Body.String())
		}
	}
}

func TestHandlerRejectsAmbiguousInheritedCachePolicy(t *testing.T) {
	scopeID, userID, siteID, definitionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	calls := 0
	handler := testHandler(t, &fakeControl{publishPolicy: func(context.Context, cachecontrol.Actor, cachecontrol.PublishPolicyRequest) (cachecontrol.PolicyWriteResult, error) {
		calls++
		return cachecontrol.PolicyWriteResult{}, nil
	}}, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", PermissionPoliciesManage), nil
	})
	for _, body := range []string{
		`{"expected_revision":0,"binding_mode":"inherit","definition_id":"` + definitionID.String() + `"}`,
		`{"expected_revision":0,"binding_mode":"inherit","definition_id":"` + definitionID.String() + `","definition_revision":1,"document":{"mode":"disabled","rules":[],"query_mode":"ignore","query_names":[],"vary_headers":[],"disk_quota_bytes":0}}`,
	} {
		response := serveRaw(t, handler, http.MethodPost, "/v1/cache-policies/"+siteID.String(), body, "tenant", "invalid-inherit")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
	if calls != 0 {
		t.Fatalf("store called %d times", calls)
	}
}
