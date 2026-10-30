package edgesite

import (
	"errors"
	"strings"
	"testing"
)

func pageRef(digit byte) Ref {
	return Ref{Kind: RefErrorPageAsset, ID: testUUID, Revision: 1, SHA256: strings.Repeat(string(digit), 64)}
}

func pagesByKey(pages []ErrorPage) map[string]string {
	result := make(map[string]string, len(pages))
	for _, page := range pages {
		result[page.Category+"|"+itoa(page.Status)] = page.RuleID
	}
	return result
}

func itoa(value int) string {
	digits := []byte{}
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

// The precedence of agents/edge-agent/internal/errorpage (Compile/Lookup):
// code beats range, narrow range beats wide, site beats global.
func TestErrorPagesForPrecedence(t *testing.T) {
	global := []ErrorPageRule{
		{ID: "g-5xx", Category: ErrorOriginResponse, Ranges: [][2]int{{500, 599}}, MIMEType: "text/html", Asset: pageRef('a')},
		{ID: "g-50x", Category: ErrorOriginResponse, Ranges: [][2]int{{500, 504}}, MIMEType: "text/html", Asset: pageRef('b')},
		{ID: "g-503", Category: ErrorOriginResponse, Codes: []int{503}, MIMEType: "text/plain", Asset: pageRef('c')},
		{ID: "g-502", Category: ErrorEdgeConnect, Codes: []int{502}, MIMEType: "text/plain", Asset: pageRef('d')},
		{ID: "theme.edge_connect.504", Category: ErrorEdgeConnect, Codes: []int{504}, MIMEType: "text/html", StyleHash: testStyleHash, Asset: pageRef('e')},
	}
	site := []ErrorPageRule{
		{ID: testUUID, Category: ErrorOriginResponse, Codes: []int{404, 502}, MIMEType: "application/json", Asset: pageRef('f')},
		{ID: testUUID2, Category: ErrorEdgeConnect, Ranges: [][2]int{{502, 504}}, MIMEType: "text/plain", Asset: pageRef('1')},
	}
	pages, err := ErrorPagesFor(global, site)
	if err != nil {
		t.Fatal(err)
	}
	got := pagesByKey(pages)
	want := map[string]string{
		"origin_response|404": testUUID, "origin_response|502": testUUID, // site code
		"origin_response|500": "g-50x", "origin_response|501": "g-50x", "origin_response|503": "g-503", "origin_response|504": "g-50x",
		"origin_response|505": "g-5xx", "origin_response|599": "g-5xx",
		// site range replaces global code and theme page: scopes do not mix
		"edge_connect|502": testUUID2, "edge_connect|503": testUUID2, "edge_connect|504": testUUID2,
	}
	for key, rule := range want {
		if got[key] != rule {
			t.Errorf("%s: %q, want %q", key, got[key], rule)
		}
	}
	if len(pages) != 100+1+3 { // 500-599, 404, 502-504
		t.Errorf("%d pages", len(pages))
	}
	for index := 1; index < len(pages); index++ {
		previous, page := pages[index-1], pages[index]
		if previous.Category > page.Category || previous.Category == page.Category && previous.Status >= page.Status {
			t.Fatalf("not sorted at %d", index)
		}
	}
	if pages[0].Category != ErrorEdgeConnect || pages[0].StyleHash != "" {
		t.Errorf("first page %+v", pages[0])
	}
}

func TestErrorPagesForRejects(t *testing.T) {
	cases := map[string][]ErrorPageRule{
		"equal precedence": {
			{ID: "a", Category: ErrorOriginResponse, Codes: []int{404}, MIMEType: "text/html", Asset: pageRef('a')},
			{ID: "b", Category: ErrorOriginResponse, Codes: []int{404}, MIMEType: "text/html", Asset: pageRef('b')}},
		"rule twice": {
			{ID: "a", Category: ErrorOriginResponse, Codes: []int{404}, MIMEType: "text/html", Asset: pageRef('a')},
			{ID: "a", Category: ErrorOriginResponse, Codes: []int{405}, MIMEType: "text/html", Asset: pageRef('a')}},
		"connect 500":   {{ID: "a", Category: ErrorEdgeConnect, Codes: []int{500}, MIMEType: "text/html", Asset: pageRef('a')}},
		"node page":     {{ID: "a", Category: "unknown_site", Codes: []int{404}, MIMEType: "text/html", Asset: pageRef('a')}},
		"no status":     {{ID: "a", Category: ErrorOriginResponse, MIMEType: "text/html", Asset: pageRef('a')}},
		"range order":   {{ID: "a", Category: ErrorOriginResponse, Ranges: [][2]int{{510, 500}}, MIMEType: "text/html", Asset: pageRef('a')}},
		"bad mime":      {{ID: "a", Category: ErrorOriginResponse, Codes: []int{404}, MIMEType: "image/png", Asset: pageRef('a')}},
		"style on json": {{ID: "a", Category: ErrorOriginResponse, Codes: []int{404}, MIMEType: "application/json", StyleHash: testStyleHash, Asset: pageRef('a')}},
	}
	for name, rules := range cases {
		if _, err := ErrorPagesFor(nil, rules); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The widest legal policy: every status of every category.
	all := []ErrorPageRule{
		{ID: "o", Category: ErrorOriginResponse, Ranges: [][2]int{{400, 599}}, MIMEType: "text/html", Asset: pageRef('a')},
		{ID: "r", Category: ErrorEdgeRoute, Ranges: [][2]int{{400, 599}}, MIMEType: "text/html", Asset: pageRef('a')},
		{ID: "c", Category: ErrorEdgeConnect, Ranges: [][2]int{{502, 504}}, MIMEType: "text/html", Asset: pageRef('a')},
	}
	pages, err := ErrorPagesFor(all, nil)
	if err != nil || len(pages) != MaxErrorPages {
		t.Fatalf("%d pages, %v", len(pages), err)
	}
}

// errpage-ovr: edge_connect page variants (http_502/504 region / node
// overrides) round-trip and are refused outside their form.
func TestErrorPageVariants(t *testing.T) {
	node := "22222222-2222-4222-8222-222222222222"
	variant := func(status int, region, nodeID string) ErrorPageVariant {
		return ErrorPageVariant{Category: ErrorEdgeConnect, Status: status, Region: region, NodeID: nodeID,
			RuleID: "slot.http_" + itoa(status), MIMEType: "text/plain", Asset: pageRef('a')}
	}
	site := minimalSite()
	site.ErrorVariants = []ErrorPageVariant{variant(502, "cn-east", ""), variant(502, "", node), variant(504, "cn-east", "")}
	raw, err := Encode(site)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw)
	if err != nil || len(decoded.ErrorVariants) != 3 || decoded.ErrorVariants[1].NodeID != node {
		t.Fatalf("%+v %v", decoded.ErrorVariants, err)
	}
	if plain, _ := Encode(minimalSite()); strings.Contains(string(plain), "error_page_variants") {
		t.Fatal("a site without variants must not carry the field")
	}
	for name, bad := range map[string][]ErrorPageVariant{
		"category":   {{Category: ErrorEdgeRoute, Status: 502, Region: "a", RuleID: "r", MIMEType: "text/plain", Asset: pageRef('a')}},
		"status":     {variant(500, "a", "")},
		"no target":  {variant(502, "", "")},
		"both":       {variant(502, "a", node)},
		"region":     {variant(502, "CN", "")},
		"node":       {variant(502, "", "node-1")},
		"order":      {variant(504, "a", ""), variant(502, "a", "")},
		"node first": {variant(502, "", node), variant(502, "a", "")},
		"twice":      {variant(502, "a", ""), variant(502, "a", "")},
	} {
		site := minimalSite()
		site.ErrorVariants = bad
		if err := Validate(site); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
}
