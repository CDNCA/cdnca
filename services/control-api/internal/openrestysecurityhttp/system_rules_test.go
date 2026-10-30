package openrestysecurityhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/openrestysecurity"
	"github.com/cdnca/cdnca/services/control-api/internal/securityrulecatalog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type fakeCatalog struct {
	viewer   securityrulecatalog.Viewer
	kind     string
	key      string
	enabled  bool
	showTo   []uuid.UUID
	calls    []string
	authzErr error
}

func (fake *fakeCatalog) List(ctx context.Context, viewer securityrulecatalog.Viewer, kind string, authorize securityrulecatalog.Authorize) ([]securityrulecatalog.Rule, error) {
	fake.viewer, fake.kind = viewer, kind
	fake.calls = append(fake.calls, "list")
	if err := authorize(ctx, nil); err != nil {
		return nil, err
	}
	return []securityrulecatalog.Rule{{SystemKey: "cc_rule:6", Kind: "cc_rule_group", Name: "宽松", Status: "active", Selectable: true, Enabled: true}}, nil
}

func (fake *fakeCatalog) SetTenantEnabled(ctx context.Context, viewer securityrulecatalog.Viewer, key string, enabled bool, authorize securityrulecatalog.Authorize) (securityrulecatalog.Rule, error) {
	fake.viewer, fake.key, fake.enabled = viewer, key, enabled
	fake.calls = append(fake.calls, "tenant")
	return securityrulecatalog.Rule{SystemKey: key, Enabled: enabled}, authorize(ctx, nil)
}

func (fake *fakeCatalog) SetVisibility(ctx context.Context, viewer securityrulecatalog.Viewer, key string, visible bool, showTo []uuid.UUID, authorize securityrulecatalog.Authorize) (securityrulecatalog.Rule, error) {
	fake.viewer, fake.key, fake.enabled, fake.showTo = viewer, key, visible, showTo
	fake.calls = append(fake.calls, "visibility")
	return securityrulecatalog.Rule{SystemKey: key}, authorize(ctx, nil)
}

func (fake *fakeCatalog) Status(ctx context.Context, authorize securityrulecatalog.Authorize) (securityrulecatalog.Status, error) {
	fake.calls = append(fake.calls, "status")
	return securityrulecatalog.Status{Synced: true, ScopeRevision: 3}, authorize(ctx, nil)
}

func (fake *fakeCatalog) Republication(ctx context.Context, viewer securityrulecatalog.Viewer, authorize securityrulecatalog.Authorize) (securityrulecatalog.Republication, error) {
	fake.viewer = viewer
	fake.calls = append(fake.calls, "republication")
	return securityrulecatalog.Republication{Pending: true, PendingScopes: 1}, authorize(ctx, nil)
}

func (fake *fakeCatalog) DefaultCrawlers(ctx context.Context, authorize securityrulecatalog.Authorize) ([]securityrulecatalog.DefaultCrawler, error) {
	fake.calls = append(fake.calls, "default-crawlers")
	return []securityrulecatalog.DefaultCrawler{{Name: "google", UserAgentTokens: []string{"Googlebot"},
		Networks: []string{}, RDNSSuffixes: []string{"googlebot.com"}, Ready: true}}, authorize(ctx, nil)
}

// The site CC page reads the default crawler list
// with the rule groups' read permission.
func TestDefaultCrawlersRoute(t *testing.T) {
	handler, catalog, authorizer, _ := systemRuleHandler(t, openrestysecurity.ScopeTenant)
	response := serve(handler, http.MethodGet, "/v1/security-system-rules/default-crawlers", "")
	var body struct {
		Items []securityrulecatalog.DefaultCrawler `json:"items"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || len(body.Items) != 1 ||
		body.Items[0].Name != "google" || strings.Join(catalog.calls, ",") != "default-crawlers" ||
		strings.Join(authorizer.checks, ",") != "rule_groups" {
		t.Fatalf("default crawlers = %d %s calls=%v checks=%v", response.Code, response.Body, catalog.calls, authorizer.checks)
	}
}

// Tenants and platform admins both read whether a CRS rule text change is
// being republished (their own scopes, or all of them).
func TestSystemRuleRepublicationRoute(t *testing.T) {
	for _, kind := range []string{openrestysecurity.ScopeTenant, openrestysecurity.ScopePlatform} {
		handler, catalog, authorizer, actor := systemRuleHandler(t, kind)
		response := serve(handler, http.MethodGet, "/v1/security-system-rules/republication", "")
		var body securityrulecatalog.Republication
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || !body.Pending ||
			body.PendingScopes != 1 || catalog.viewer.ScopeID != actor.ScopeID ||
			catalog.viewer.Platform != (kind == openrestysecurity.ScopePlatform) ||
			strings.Join(authorizer.checks, ",") != "rule_groups" {
			t.Fatalf("%s republication = %d %s viewer=%+v checks=%v", kind, response.Code, response.Body, catalog.viewer, authorizer.checks)
		}
		if response := serve(handler, http.MethodPost, "/v1/security-system-rules/republication", ""); response.Code == http.StatusOK {
			t.Fatalf("%s POST republication = %d", kind, response.Code)
		}
	}
}

type recordingAuthorizer struct{ checks []string }

func (authorizer *recordingAuthorizer) Authorize(_ context.Context, _ pgx.Tx, _ openrestysecurity.Actor, _ uuid.UUID, permission string) error {
	authorizer.checks = append(authorizer.checks, permission)
	return nil
}

func (authorizer *recordingAuthorizer) AuthorizeRuleGroups(context.Context, pgx.Tx, openrestysecurity.Actor, uuid.UUID) error {
	authorizer.checks = append(authorizer.checks, "rule_groups")
	return nil
}

func systemRuleHandler(t *testing.T, scopeKind string) (*Handler, *fakeCatalog, *recordingAuthorizer, openrestysecurity.Actor) {
	t.Helper()
	actor := openrestysecurity.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: scopeKind}
	handler, err := NewHandler(&fakeAPI{}, func(*http.Request) (openrestysecurity.Actor, error) { return actor, nil })
	if err != nil {
		t.Fatal(err)
	}
	catalog, authorizer := &fakeCatalog{}, &recordingAuthorizer{}
	handler.catalog, handler.catalogAuthorizer = catalog, authorizer
	return handler, catalog, authorizer, actor
}

func serve(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestSystemRuleRoutesForTenants(t *testing.T) {
	handler, catalog, authorizer, actor := systemRuleHandler(t, openrestysecurity.ScopeTenant)
	response := serve(handler, http.MethodGet, "/v1/security-system-rules?kind=cc_rule_group", "")
	var body struct {
		Items []securityrulecatalog.Rule `json:"items"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || len(body.Items) != 1 ||
		catalog.kind != "cc_rule_group" || catalog.viewer.Platform || catalog.viewer.ScopeID != actor.ScopeID {
		t.Fatalf("tenant list = %d %s viewer=%+v", response.Code, response.Body, catalog.viewer)
	}
	if response := serve(handler, http.MethodPost, "/v1/security-system-rules/cc_rule:6/disable", ""); response.Code != http.StatusOK ||
		catalog.key != "cc_rule:6" || catalog.enabled {
		t.Fatalf("tenant disable = %d %s", response.Code, response.Body)
	}
	for _, request := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/security-system-rules/status", ""},
		{http.MethodPut, "/v1/security-system-rules/cc_rule:6/visibility", `{"visible":false}`},
	} {
		if response := serve(handler, request.method, request.path, request.body); response.Code == http.StatusOK {
			t.Fatalf("tenant reached platform route %s", request.path)
		}
	}
	if strings.Join(authorizer.checks, ",") != "rule_groups,rule_groups" {
		t.Fatalf("authorization checks = %v", authorizer.checks)
	}
}

func TestSystemRuleRoutesForPlatform(t *testing.T) {
	handler, catalog, authorizer, _ := systemRuleHandler(t, openrestysecurity.ScopePlatform)
	scope := uuid.New()
	response := serve(handler, http.MethodPut, "/v1/security-system-rules/cc_rule:1/visibility",
		`{"visible":true,"show_to_scope_ids":["`+scope.String()+`"]}`)
	if response.Code != http.StatusOK || catalog.key != "cc_rule:1" || !catalog.enabled || len(catalog.showTo) != 1 || catalog.showTo[0] != scope {
		t.Fatalf("platform visibility = %d %s", response.Code, response.Body)
	}
	if authorizer.checks[len(authorizer.checks)-1] != openrestysecurity.PermissionManage {
		t.Fatalf("visibility must require manage permission: %v", authorizer.checks)
	}
	if response := serve(handler, http.MethodPost, "/v1/security-system-rules/cc_rule:1/enable", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("platform tenant-switch = %d", response.Code)
	}
	if response := serve(handler, http.MethodGet, "/v1/security-system-rules/status", ""); response.Code != http.StatusOK {
		t.Fatalf("platform status = %d", response.Code)
	}
}
