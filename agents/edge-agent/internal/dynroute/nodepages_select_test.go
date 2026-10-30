package dynroute

import "testing"

// errpage-3 E3: per category a node takes its own page, else its region's,
// else the global one; other nodes' and regions' pages drop.
func TestSelectNodePagesPrefersNodeThenRegion(t *testing.T) {
	const self, other = "b0000000-0000-4000-8000-000000000001", "b0000000-0000-4000-8000-000000000002"
	pages := []NodePage{
		{Category: "blacklist", Body: []byte("global")},
		{Category: "blacklist", Region: "cn-east", Body: []byte("region")},
		{Category: "blacklist", NodeID: other, Body: []byte("other node")},
		{Category: "http_403", Region: "us-west", Body: []byte("other region")},
		{Category: "http_403", Body: []byte("global 403")},
		{Category: "connection_limit", NodeID: self, Body: []byte("mine")},
		{Category: "connection_limit", Region: "cn-east", Body: []byte("region 503")},
		{Category: "node_ip_access", NodeID: other, Body: []byte("not mine")},
	}
	got := map[string]string{}
	for _, page := range selectNodePages(pages, self, "cn-east") {
		got[page.Category] = string(page.Body)
	}
	want := map[string]string{"blacklist": "region", "http_403": "global 403", "connection_limit": "mine"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for category, body := range want {
		if got[category] != body {
			t.Fatalf("%s: %q, want %q (%v)", category, got[category], body, got)
		}
	}
	// No region configured: only global and own-node pages.
	got = map[string]string{}
	for _, page := range selectNodePages(pages, self, "") {
		got[page.Category] = string(page.Body)
	}
	if got["blacklist"] != "global" || got["connection_limit"] != "mine" || got["http_403"] != "global 403" {
		t.Fatalf("%v", got)
	}
}
