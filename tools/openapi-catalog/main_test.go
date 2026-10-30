package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func find(c *Catalog, method, path string) *Operation {
	for _, g := range c.Groups {
		for i := range g.Operations {
			if g.Operations[i].Method == method && g.Operations[i].Path == path {
				return &g.Operations[i]
			}
		}
	}
	return nil
}

func TestBuildResolvesCrossFileRefsAndAuth(t *testing.T) {
	c, err := Build("testdata", []string{"root.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Total != 5 {
		t.Fatalf("total = %d, want 5 (internal excluded)", c.Total)
	}
	cases := []struct {
		method, path, summary, source string
		auth                          []string
		apiKey, deprecated            bool
	}{
		// inline op inherits root security
		{"GET", "/v1/sites", "列出站点", "api/openapi/v1/root.yaml", []string{"bearer"}, false, false},
		// cross-file op-level security; bearerAuth itself is a $ref inside ext
		{"GET", "/v1/sites/{id}", "查看站点", "api/ext.openapi.yaml", []string{"apiKey", "bearer"}, true, false},
		// no op security: root file's security wins, not the referenced file's root security
		{"DELETE", "/v1/sites/{id}", "删除站点", "api/ext.openapi.yaml", []string{"bearer"}, false, true},
		// security: [] means anonymous
		{"POST", "/v1/admin/analytics/top", "排行", "api/ext.openapi.yaml", []string{"none"}, false, false},
		// local $ref chained to an external $ref; summary trimmed
		{"PUT", "/v1/chain", "链式引用", "api/ext.openapi.yaml", []string{"mtls"}, false, false},
	}
	for _, tc := range cases {
		o := find(c, tc.method, tc.path)
		if o == nil {
			t.Fatalf("%s %s missing", tc.method, tc.path)
		}
		if o.Summary != tc.summary || o.Source != tc.source || !reflect.DeepEqual(o.Auth, tc.auth) || o.APIKey != tc.apiKey || o.Deprecated != tc.deprecated {
			t.Errorf("%s %s = %+v", tc.method, tc.path, *o)
		}
	}
	if find(c, "GET", "/v1/internal/secret") != nil {
		t.Error("internal operation must be excluded")
	}
	if c.APIKey != 1 {
		t.Errorf("api key count = %d", c.APIKey)
	}
}

func TestEarlierRootWins(t *testing.T) {
	c, err := Build("testdata", []string{"root.yaml", "dup.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if o := find(c, "GET", "/v1/sites"); o == nil || o.Summary != "列出站点" || c.Total != 5 {
		t.Fatalf("dup root must not override: %+v total=%d", o, c.Total)
	}
}

func TestGrouping(t *testing.T) {
	c, err := Build("testdata", []string{"root.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, g := range c.Groups {
		got = append(got, g.ID+"="+g.Prefix)
	}
	want := []string{"admin-analytics=/v1/admin/analytics", "chain=/v1/chain", "sites=/v1/sites"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("groups = %v", got)
	}
	s := c.Groups[2]
	if s.Count != 3 || s.APIKey != 1 || s.Operations[0].Path != "/v1/sites" || s.Operations[1].Method != "GET" || s.Operations[2].Method != "DELETE" {
		t.Fatalf("sites group = %+v", s)
	}
	if groupPrefix("/v1/admin") != "/v1/admin" || groupPrefix("/v1/theme/theme.{sha}.css") != "/v1/theme" {
		t.Fatal("groupPrefix")
	}
}

func TestErrors(t *testing.T) {
	for name, want := range map[string]string{
		"badref.yaml":    "not found",
		"badscheme.yaml": `security scheme "nope" not defined`,
	} {
		_, err := Build("testdata", []string{name})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
	}
}

// The committed catalogue and detail files must match the contracts (CI drift guard).
func TestRepositoryCatalogIsCurrent(t *testing.T) {
	repo := filepath.Join("..", "..")
	c, err := Build(repo, defaultRoots)
	if err != nil {
		t.Fatal(err)
	}
	files, err := Outputs(c)
	if err != nil {
		t.Fatal(err)
	}
	if stale := staleFiles(filepath.Join(repo, "apps", "www", "src", "generated"), files); len(stale) > 0 {
		t.Fatalf("stale generated files %v; run: pnpm -C apps/www catalog", stale)
	}
	for _, g := range c.Groups {
		for _, o := range g.Operations {
			if strings.HasPrefix(o.Path, "/v1/internal/") {
				t.Fatalf("internal path leaked: %s", o.Path)
			}
			if o.OperationID == "" || o.Detail == nil {
				t.Fatalf("%s %s: no operationId/detail", o.Method, o.Path)
			}
			for _, txt := range detailTexts(o.Detail) {
				if internalRef.MatchString(txt) {
					t.Fatalf("%s: internal reference in public text %q", o.OperationID, txt)
				}
			}
		}
	}
	if c.APIKey == 0 {
		t.Fatal("expected API-key operations in control.yaml")
	}
}

func detailTexts(d *Detail) []string {
	out := []string{d.Summary, d.SummaryZh, d.Description, d.DescriptionZh}
	for _, f := range d.Params {
		out = append(out, f.Description, f.DescriptionZh)
	}
	if d.Body != nil {
		for _, f := range d.Body.Fields {
			out = append(out, f.Description, f.DescriptionZh)
		}
	}
	for _, r := range d.Responses {
		out = append(out, r.Description, r.DescriptionZh)
		for _, f := range r.Fields {
			out = append(out, f.Description, f.DescriptionZh)
		}
	}
	return out
}

// DOC-API-01: Chinese text comes from x-summary-zh / x-description-zh written in the contract (operation,
// parameter, property and shared response), and permissions only from the structured extension.
func TestChineseTextFromContract(t *testing.T) {
	c, err := Build("testdata", []string{"root.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	o := find(c, "GET", "/v1/sites")
	if o.SummaryZh != "列出站点" || o.Detail.SummaryZh != "列出站点" {
		t.Errorf("summary_zh = %q / %q", o.SummaryZh, o.Detail.SummaryZh)
	}
	d := o.Detail
	if d.DescriptionZh != "需要 sites.read 权限，页码从 1 开始。" {
		t.Errorf("description_zh = %q", d.DescriptionZh)
	}
	if d.Params[0].DescriptionZh != "页码，从 1 开始" || d.Params[1].DescriptionZh != "站点类型" {
		t.Errorf("params zh = %+v", d.Params)
	}
	if d.Responses[0].DescriptionZh != "站点分页。" || d.Responses[1].DescriptionZh != "无权操作。" {
		t.Errorf("responses zh = %+v", d.Responses)
	}
	if f := d.Responses[0].Fields[1]; f.DescriptionZh != "不透明游标" {
		t.Errorf("property zh = %+v", f)
	}
}

func TestDetailFromContract(t *testing.T) {
	c, err := Build("testdata", []string{"root.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	list := find(c, "GET", "/v1/sites").Detail
	if list.OperationID != "listSites" || !reflect.DeepEqual(list.Permissions, []string{"sites.read"}) {
		t.Fatalf("listSites = %+v", list)
	}
	// the parenthetical design-record / task reference is dropped, the rest kept
	if list.Description != "Requires sites.read. Pages start at 1." {
		t.Errorf("description = %q", list.Description)
	}
	wantParams := []Field{
		{Name: "page", In: "query", Type: "integer", Required: true, Description: "1-based page", DescriptionZh: "页码，从 1 开始"},
		{Name: "kind", In: "query", Type: "string: http / l4", DescriptionZh: "站点类型"},
	}
	if !reflect.DeepEqual(list.Params, wantParams) {
		t.Errorf("params = %+v", list.Params)
	}
	if len(list.Responses) != 2 || list.Responses[0].Status != "200" || list.Responses[1].Status != "403" {
		t.Fatalf("responses = %+v", list.Responses)
	}
	wantFields := []Field{
		{Name: "items", Type: "array<Site>", Required: true},
		{Name: "next_cursor", Type: "string | null", Description: "Opaque cursor", DescriptionZh: "不透明游标"},
	}
	if !reflect.DeepEqual(list.Responses[0].Fields, wantFields) {
		t.Errorf("200 fields = %+v", list.Responses[0].Fields)
	}
	if list.Responses[1].Description != "Not allowed." {
		t.Errorf("403 description must lose the repository path: %q", list.Responses[1].Description)
	}

	del := find(c, "DELETE", "/v1/sites/{id}").Detail
	if len(del.Permissions) != 0 || !reflect.DeepEqual(del.AnyPermissions, []string{"sites.manage", "reseller.customers.manage"}) ||
		!reflect.DeepEqual(del.Features, []string{"module.sites"}) || !del.RecentReauth {
		t.Errorf("deleteSite = %+v", del)
	}
	rank := find(c, "POST", "/v1/admin/analytics/top").Detail
	wantBody := &Body{ContentTypes: []string{"application/json"}, Required: true, Fields: []Field{
		{Name: "range", Type: "string: 1h / 24h", Required: true},
		{Name: "limit", Type: "integer"},
	}}
	if !reflect.DeepEqual(rank.Body, wantBody) {
		t.Errorf("body = %+v", rank.Body)
	}

	chain := find(c, "PUT", "/v1/chain").Detail
	if len(chain.Responses) != 2 || chain.Responses[1].Status != "409" || chain.Responses[1].Description != "Conflict" {
		t.Errorf("shared responses $ref = %+v", chain.Responses)
	}

	files, err := Outputs(c)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	want := []string{"api-catalog.json", "api-operations/admin-analytics.json", "api-operations/chain.json", "api-operations/sites.json"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("outputs = %v", names)
	}
	if strings.Contains(string(files["api-catalog.json"]), "Pages start") {
		t.Error("detail must not be in the index")
	}
	dir := t.TempDir()
	for n, b := range files {
		p := filepath.Join(dir, n)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, b, 0o644)
	}
	_ = os.WriteFile(filepath.Join(dir, "api-operations", "gone.json"), []byte("{}"), 0o644)
	if got := staleFiles(dir, files); !reflect.DeepEqual(got, []string{"api-operations/gone.json (orphan)"}) {
		t.Errorf("stale = %v", got)
	}
}

func TestPublicText(t *testing.T) {
	for in, want := range map[string]string{
		"Plain text, kept.":                                      "Plain text, kept.",
		"List resellers (ADR 0018)":                              "List resellers",
		"Call the backend (PA-19). Rate limited.":                "Call the backend. Rate limited.",
		"See ADR 0013 §3.4. The gateway is listed.":              "The gateway is listed.",
		"Enforces 12 to 1024 UTF-8 bytes; stores the SHA-256.":   "Enforces 12 to 1024 UTF-8 bytes; stores the SHA-256.",
		"A field of the registry (libs/edgeconfig/x FieldSpecs)": "A field of the registry",
	} {
		if got := publicText(in); got != want {
			t.Errorf("publicText(%q) = %q, want %q", in, got, want)
		}
	}
}
