package httpapi

import (
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestOpenAPIRouteAudit verifies that every path in control.yaml has a
// matching route registered in the control-api HTTP mux. It parses route
// patterns from server.go (direct mux calls, mounted handler lists, and
// loop-registered patterns), adds routes known to be registered outside the
// mux (main.go middleware wrappers), and probes every control.yaml path
// against a test ServeMux. Paths that fall through to the "/" sentinel have
// no route and must be removed from the OpenAPI contract.
func TestOpenAPIRouteAudit(t *testing.T) {
	controlYAML, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatalf("read control.yaml: %v", err)
	}
	serverGo, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}

	yamlPathRe := regexp.MustCompile(`(?m)^  (/[^\s:]+):`)
	yamlMatches := yamlPathRe.FindAllSubmatch(controlYAML, -1)
	if len(yamlMatches) == 0 {
		t.Fatal("no paths found in control.yaml")
	}

	handlerStart := strings.Index(string(serverGo), "func (s *Server) Handler() http.Handler {")
	if handlerStart < 0 {
		t.Fatal("Handler() method not found in server.go")
	}
	depth := 0
	handlerEnd := handlerStart
	for i, c := range string(serverGo[handlerStart:]) {
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 {
				handlerEnd = handlerStart + i + 1
				break
			}
		}
	}
	handlerBody := string(serverGo[handlerStart:handlerEnd])

	// Handlers known to be nil in the community edition (their mounted
	// patterns are skipped). The commercial billing/package/reseller code is
	// deleted entirely from community; autoDefenseHandler is the only mounted
	// handler that remains in server.go but is nil.
	communityNilHandlers := map[string]bool{
		"autoDefenseHandler": true,
	}

	var patterns []string
	seen := map[string]bool{}
	addPattern := func(p string) {
		if p == "" || p == "/" || seen[p] {
			return
		}
		if !strings.Contains(p, "/") {
			return
		}
		seen[p] = true
		patterns = append(patterns, p)
	}

	// 1. Direct mux.Handle/HandleFunc("pattern", ...) calls.
	for _, m := range regexp.MustCompile(`mux\.Handle(?:Func)?\("([^"]+)"`).FindAllStringSubmatch(handlerBody, -1) {
		addPattern(m[1])
	}

	// 2. Mounted handler pattern lists (brace-balanced to handle {param}).
	mountedHeaderRe := regexp.MustCompile(
		`\{handler:\s*s\.(\w+),\s*(?:preserveRaw:\s*\w+,\s*)?patterns:\s*\[\]string\{`)
	for _, loc := range mountedHeaderRe.FindAllStringIndex(handlerBody, -1) {
		header := mountedHeaderRe.FindStringSubmatch(handlerBody[loc[0]:loc[1]])
		field := header[1]
		if communityNilHandlers[field] {
			continue
		}
		pos := loc[1]
		braceDepth := 1
		j := pos
		for j < len(handlerBody) && braceDepth > 0 {
			if handlerBody[j] == '{' {
				braceDepth++
			} else if handlerBody[j] == '}' {
				braceDepth--
			}
			j++
		}
		block := handlerBody[pos : j-1]
		for _, raw := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(block, -1) {
			addPattern(raw[1])
		}
	}

	// 3. Loop-registered patterns: for _, <var> := range []string{...}
	//    Variable names include "pattern", "base", "p", etc.
	loopHeaderRe := regexp.MustCompile(`for _, \w+ := range \[\]string\{`)
	for _, loc := range loopHeaderRe.FindAllStringIndex(handlerBody, -1) {
		pos := loc[1]
		braceDepth := 1
		j := pos
		for j < len(handlerBody) && braceDepth > 0 {
			if handlerBody[j] == '{' {
				braceDepth++
			} else if handlerBody[j] == '}' {
				braceDepth--
			}
			j++
		}
		block := handlerBody[pos : j-1]
		for _, raw := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(block, -1) {
			addPattern(raw[1])
		}
	}

	// 4. Go constant references in mounted patterns that the regex cannot
	//    extract (e.g. regioncataloghttp.Route). Add their known values.
	for _, p := range []string{
		"/v1/regions", "/v1/regions/",
		"/v1/admin/entitlement/refresh",
		// marketsubscribehttp constants (mountMarketSubscribe).
		"GET /v1/admin/market/plugin-library",
		"POST /v1/admin/market/plugin-downloads",
	} {
		addPattern(p)
	}

	// 5. Routes registered outside the httpapi mux, in main.go middleware
	//    wrappers. These are checked by separate handler tests.
	for _, p := range []string{
		"/v1/account-recovery/requests",
		"/v1/account-recovery/confirmations",
		"/v1/firewall/policy",
		"/v1/firewall/policy/recover",
		"/v1/firewall/hits",
		"/v1/openresty-security/configs/global",
		"/v1/openresty-security/overrides",
		"/v1/openresty-security/overrides/",
		"/v1/openresty-security/targets",
		"/v1/openresty-security/effective",
		"/v1/openresty-security/actions/download-cc-image",
		"/v1/cc-rule-groups",
		"/v1/cc-rule-groups/",
	} {
		addPattern(p)
	}

	// 6. Routes from "for _, base := range" loops that build patterns by
	//    concatenation (e.g. "GET " + base). These loops register the base
	//    paths and sub-paths with each method. Add the base as a prefix.
	//    Already handled by the generalized loop regex above, but the
	//    concatenated sub-paths (base+"/{list_id}") are not string literals
	//    in the loop body. The prefix route (base+"/") covers them via the
	//    ServeMux prefix match, but only if we register the trailing-slash
	//    version. Ensure we do:
	for _, p := range patterns {
		clean := p
		if i := strings.Index(clean, " "); i >= 0 {
			clean = clean[i+1:]
		}
		if !strings.HasSuffix(clean, "/") {
			addPattern(clean + "/")
		}
	}

	// Build the test ServeMux.
	stub := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	mux := http.NewServeMux()
	valid := 0
	for _, p := range patterns {
		parts := strings.SplitN(p, " ", 2)
		if len(parts) == 2 && !strings.HasPrefix(parts[1], "/") {
			continue
		}
		func() {
			defer func() { recover() }()
			mux.Handle(p, stub)
			valid++
		}()
	}
	func() {
		defer func() { recover() }()
		mux.Handle("/", http.NotFoundHandler())
	}()
	t.Logf("registered %d route patterns", valid)

	// 6. Paths that are covered by a prefix route (e.g. /v1/admin/themes/)
	//    but whose sub-handler code was deleted in the community edition.
	//    These must also be removed from control.yaml.
	deadDespitePrefix := map[string]bool{
		"/v1/admin/themes/tenant-policy":                                true,
		"/v1/admin/themes/tenants/{tenant_scope_id}":                    true,
		"/v1/admin/themes/tenants/{tenant_scope_id}/domains/{hostname}": true,
		"/v1/auth/bridge-sso":                                           true,
		"/v1/tenant-scopes/{tenant_scope_id}/theme":                     true,
	}

	paramRe := regexp.MustCompile(`\{[^}]+\}`)
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}

	var unrouted []string
	for _, m := range yamlMatches {
		path := string(m[1])
		examplePath := paramRe.ReplaceAllString(path, "00000000-0000-4000-8000-000000000000")

		routed := false
		for _, method := range methods {
			req, _ := http.NewRequest(method, examplePath, nil)
			_, pattern := mux.Handler(req)
			if pattern != "/" && pattern != "" {
				routed = true
				break
			}
		}
		if !routed || deadDespitePrefix[path] {
			unrouted = append(unrouted, path)
		}
	}

	sort.Strings(unrouted)
	if len(unrouted) > 0 {
		t.Errorf("control.yaml has %d paths with no matching route in the control-api mux (delete from control.yaml):\n%s",
			len(unrouted), strings.Join(unrouted, "\n"))
	}
	t.Logf("control.yaml: %d paths, %d routed, %d unrouted",
		len(yamlMatches), len(yamlMatches)-len(unrouted), len(unrouted))
}
