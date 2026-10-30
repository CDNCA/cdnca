package pluginui

import (
	"strings"
	"testing"
)

func validEntrypoint() Entrypoint {
	return Entrypoint{Type: EntrypointType, Origin: "https://ui.acme.example", APIBaseURL: "https://api.acme.example/v1",
		Pages: []Page{
			{ID: "report", Path: "/report", Mount: MountMenu, MenuParent: "monitor", Role: RoleAdmin,
				Title: Title{ZhCN: "流量报表", EnUS: "Traffic report"}, RequiredPermission: "sites.read"},
			{ID: "site-tools", Path: "/site", Mount: MountSiteTab, Role: RoleUser, Title: Title{ZhCN: "站点工具"},
				RequiredModule: "module.acme_tools"},
		}}
}

func TestValidateAcceptsDeclaration(t *testing.T) {
	if findings := Validate(validEntrypoint()); len(findings) != 0 {
		t.Fatalf("Validate() = %v", findings)
	}
}

func TestValidateRejectsUnsafeOrigins(t *testing.T) {
	for _, origin := range []string{
		"http://ui.acme.example", "https://ui.acme.example:8443", "https://ui.acme.example/app",
		"https://user@ui.acme.example", "https://127.0.0.1", "https://[::1]", "https://localhost",
		"https://app.localhost", "https://intranet", "https://ui.acme.example?x=1", "https://ui.acme.example#a",
		"javascript:alert(1)", "https://UI.acme.example", " https://ui.acme.example", "https://ui_acme.example", "",
	} {
		entrypoint := validEntrypoint()
		entrypoint.Origin = origin
		if !hasReason(Validate(entrypoint), "origin_invalid") {
			t.Errorf("origin %q accepted", origin)
		}
	}
	if origin, ok := CanonicalOrigin("https://ui.acme.example/"); !ok || origin != "https://ui.acme.example" {
		t.Fatalf("CanonicalOrigin(trailing slash) = %q, %v", origin, ok)
	}
}

func TestValidateRejectsPagesAndMounts(t *testing.T) {
	cases := map[string]func(*Entrypoint){
		"page_id_invalid":             func(e *Entrypoint) { e.Pages[1].ID = e.Pages[0].ID },
		"page_path_invalid":           func(e *Entrypoint) { e.Pages[0].Path = "/../admin" },
		"mount_invalid":               func(e *Entrypoint) { e.Pages[0].Mount = "overlay" },
		"menu_parent_invalid":         func(e *Entrypoint) { e.Pages[0].MenuParent = "account" },
		"role_invalid":                func(e *Entrypoint) { e.Pages[0].Role = "operator" },
		"title_invalid":               func(e *Entrypoint) { e.Pages[0].Title.ZhCN = "<b>x</b>" },
		"required_permission_invalid": func(e *Entrypoint) { e.Pages[0].RequiredPermission = "platform.admin" },
		"required_module_invalid":     func(e *Entrypoint) { e.Pages[0].RequiredModule = "feature.x" },
		"api_base_url_invalid":        func(e *Entrypoint) { e.APIBaseURL = "https://api.acme.example/v1?x" },
		"pages_count":                 func(e *Entrypoint) { e.Pages = nil },
	}
	for reason, mutate := range cases {
		entrypoint := validEntrypoint()
		entrypoint.Pages = append([]Page{}, entrypoint.Pages...)
		mutate(&entrypoint)
		if !hasReason(Validate(entrypoint), reason) {
			t.Errorf("%s not reported: %v", reason, Validate(entrypoint))
		}
	}
}

func TestBuildAndParseRoundTrip(t *testing.T) {
	declaration, encoded, err := Build("acme.reports", "1.2.0", []string{"sites.read", Permission}, validEntrypoint())
	if err != nil {
		t.Fatal(err)
	}
	if declaration.Origin != "https://ui.acme.example" || declaration.Pages[0].ID != "report" ||
		declaration.Permissions[0] != Permission {
		t.Fatalf("Build() = %+v", declaration)
	}
	parsed, err := Parse(encoded)
	if err != nil || parsed.PluginID != "acme.reports" || len(parsed.Pages) != 2 {
		t.Fatalf("Parse() = %+v, %v", parsed, err)
	}
	if _, err := Parse([]byte(strings.Replace(string(encoded), `"schema"`, `"extra":"1","schema"`, 1))); err == nil {
		t.Fatal("Parse accepted an unknown field")
	}
	if _, err := Parse([]byte(strings.Replace(string(encoded), "https://ui.acme.example", "http://ui.acme.example", 1))); err == nil {
		t.Fatal("Parse accepted an http origin")
	}
	if _, err := Parse(append(encoded, ' ')); err == nil {
		t.Fatal("Parse accepted non-canonical bytes")
	}
}

func hasReason(findings []Finding, reason string) bool {
	for _, finding := range findings {
		if finding.Reason == reason {
			return true
		}
	}
	return false
}
