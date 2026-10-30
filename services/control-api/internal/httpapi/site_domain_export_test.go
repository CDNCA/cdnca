package httpapi

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

func TestSITE02SiteDomainExportIsUTF8FormulaSafeSecretFreeAndSnapshotBound(t *testing.T) {
	for raw, want := range map[string]string{
		"正常.example.test": "正常.example.test",
		"=1+1":            "'=1+1",
		"+cmd":            "'+cmd",
		"-1":              "'-1",
		"@SUM(A1:A2)":     "'@SUM(A1:A2)",
		"\t=cmd":          "'\t=cmd",
		"\r=cmd":          "'\r=cmd",
	} {
		got := sanitizeSiteDomainCSVCell(raw)
		if got != want || !utf8.ValidString(got) {
			t.Errorf("sanitizeSiteDomainCSVCell(%q) = %q, want %q", raw, got, want)
		}
	}

	for _, required := range []string{
		"sites.export",
		"text/csv; charset=utf-8",
		"SiteDomainExportSnapshot",
		"SiteDomainExportCursor",
		"actor_user_id",
		"actor_scope_id",
		"target_scope_id",
		"filter_sha256",
	} {
		if !strings.Contains(siteDomainExportContractSource(), required) {
			t.Errorf("SITE-02 HTTP export missing %q", required)
		}
	}
	for _, forbidden := range []string{"password", "secret", "private_key", "credential"} {
		if strings.Contains(siteDomainExportCSVHeader(), forbidden) {
			t.Errorf("SITE-02 CSV header exposes forbidden field %q", forbidden)
		}
	}
}

func TestSITE02SiteDomainExportRouteMountAndScopeBinding(t *testing.T) {
	serverSource, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(serverSource), `mux.HandleFunc("GET /v1/sites/export", s.handleExportSiteDomains)`) {
		t.Fatal("SITE-02 site domain export route is not mounted")
	}

	tenantScopeID := uuid.New()
	tenant := identity.Principal{UserID: uuid.New(), ScopeID: tenantScopeID, ScopeKind: "tenant"}
	request := httptest.NewRequest("GET", "/v1/sites/export", nil)
	parsed, err := parseSiteDomainExportRequest(request, tenant)
	if err != nil || parsed.TargetScopeID != tenantScopeID {
		t.Fatalf("tenant export target = (%s, %v), want (%s, nil)", parsed.TargetScopeID, err, tenantScopeID)
	}

	foreign := httptest.NewRequest("GET", "/v1/sites/export?target_scope_id="+uuid.NewString(), nil)
	if _, err := parseSiteDomainExportRequest(foreign, tenant); err != site.ErrPermissionDenied {
		t.Fatalf("foreign tenant scope error = %v, want %v", err, site.ErrPermissionDenied)
	}

	platform := identity.Principal{ScopeID: uuid.New(), ScopeKind: "platform"}
	if _, err := parseSiteDomainExportRequest(request, platform); err != site.ErrInvalidInput {
		t.Fatalf("platform export without target scope error = %v, want %v", err, site.ErrInvalidInput)
	}

	filtered := httptest.NewRequest("GET", "/v1/sites/export?domain=Example.COM&http_port=8080&enabled=true", nil)
	parsed, err = parseSiteDomainExportRequest(filtered, tenant)
	if err != nil || parsed.Filter.Domain != "example.com" || parsed.Filter.HTTPPort != "8080" ||
		parsed.Filter.Enabled == nil || !*parsed.Filter.Enabled {
		t.Fatalf("tenant export filter = (%+v, %v), want canonical domain/port/enabled", parsed.Filter, err)
	}
	if _, err := parseSiteDomainExportRequest(
		httptest.NewRequest("GET", "/v1/sites/export?page=2", nil), tenant,
	); err != site.ErrInvalidInput {
		t.Fatalf("paged export error = %v, want %v", err, site.ErrInvalidInput)
	}
}
