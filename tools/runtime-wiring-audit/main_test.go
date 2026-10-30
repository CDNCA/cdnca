package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdversarialFixtures(t *testing.T) {
	report := fixtureReport(t)

	assertStatus(t, report, "fakehandler", "http_handler", statusFail)
	assertStatus(t, report, "unmounted", "http_handler", statusPass)
	assertStatus(t, report, "unmounted", "runtime_dependency_wiring", statusFail)
	assertStatus(t, report, "unmounted", "router_mount", statusFail)
	assertStatus(t, report, "wrongmount", "runtime_dependency_wiring", statusPass)
	assertStatus(t, report, "wrongmount", "router_mount", statusFail)
	assertStatus(t, report, "testonly", "router_mount", statusFail)
	assertFinding(t, report, "testonly", "TEST_ONLY_MOUNT")

	assertStatus(t, report, "noopdep", "runtime_dependency_wiring", statusFail)
	assertFinding(t, report, "noopdep", "PLACEHOLDER_RUNTIME_DEFAULT")
	assertStatus(t, report, "nildep", "runtime_dependency_wiring", statusFail)
	assertFinding(t, report, "nildep", "NIL_RUNTIME_DEPENDENCY")
	assertStatus(t, report, "nilfactory", "runtime_dependency_wiring", statusFail)
	assertFinding(t, report, "nilfactory", "NIL_RUNTIME_DEPENDENCY")
	assertStatus(t, report, "generateddefault", "runtime_dependency_wiring", statusFail)
	assertFinding(t, report, "generateddefault", "PLACEHOLDER_RUNTIME_DEFAULT")
	assertStatus(t, report, "refonly", "runtime_dependency_wiring", statusFail)
	assertStatus(t, report, "loadedfactory", "runtime_dependency_wiring", statusPass)
	assertStatus(t, report, "fallibledep", "runtime_dependency_wiring", statusPass)
	assertStatus(t, report, "safedefault", "runtime_dependency_wiring", statusPass)
	assertStatus(t, report, "resetdefault", "runtime_dependency_wiring", statusFail)
	assertFinding(t, report, "resetdefault", "NIL_RUNTIME_DEPENDENCY")
	assertStatus(t, report, "nilescape", "runtime_dependency_wiring", statusFail)
	assertFinding(t, report, "nilescape", "NIL_RUNTIME_DEPENDENCY")

	assertStatus(t, report, "openapionly", "openapi_path", statusPass)
	assertStatus(t, report, "openapionly", "openapi_aggregation", statusFail)
	assertStatus(t, report, "openapionly", "frontend_api_consumer", statusFail)
	assertStatus(t, report, "openapionly", "http_handler", statusNotApplied)
	assertFinding(t, report, "openapionly", "OPENAPI_ONLY")
	assertStatus(t, report, "rbacstring", "rbac_permission", statusFail)
	assertFinding(t, report, "rbacstring", "RBAC_STRING_ONLY")
	assertStatus(t, report, "rbacdead", "rbac_permission", statusFail)
	assertStatus(t, report, "rbacdead", "rbac_transactional_recheck", statusFail)
	assertStatus(t, report, "neverstarted", "background_worker", statusFail)
	assertFinding(t, report, "neverstarted", "WORKER_NOT_STARTED")
	assertStatus(t, report, "syncworker", "runtime_dependency_wiring", statusPass)
	assertStatus(t, report, "syncworker", "background_worker", statusFail)
	assertStatus(t, report, "asyncworker", "background_worker", statusPass)
	assertStatus(t, report, "deadproof", "idempotency", statusFail)
	assertStatus(t, report, "deadproof", "audit", statusFail)
	assertStatus(t, report, "proofok", "rbac_permission", statusPass)
	assertStatus(t, report, "proofok", "rbac_transactional_recheck", statusPass)
	assertStatus(t, report, "proofok", "idempotency", statusPass)
	assertStatus(t, report, "proofok", "audit", statusPass)

	assertStatus(t, report, "commentsfake", "http_handler", statusNotApplied)
	assertStatus(t, report, "commentsfake", "background_worker", statusNotApplied)
	assertStatus(t, report, "samea", "runtime_dependency_wiring", statusPass)
	assertStatus(t, report, "samea", "router_mount", statusPass)
	assertStatus(t, report, "samea", "migration_runtime_head", statusPass)
	assertStatus(t, report, "samea", "openapi_aggregation", statusPass)
	assertStatus(t, report, "samea", "frontend_api_consumer", statusPass)
	assertStatus(t, report, "samea", "smoke_e2e", statusPass)
	assertStatus(t, report, "sameb", "runtime_dependency_wiring", statusFail)
	assertStatus(t, report, "shadowdefault", "runtime_dependency_wiring", statusFail)
	assertFinding(t, report, "shadowdefault", "NIL_RUNTIME_DEPENDENCY")
	assertStatus(t, report, "migrationowner", "migration_down", statusPass)
	assertEvidenceExcludes(t, report, "migrationowner", "migration_up", "#migration:002:")
	nested := findDomain(t, report, "nested")
	if !containsString(nested.Packages, "nested/sub") {
		t.Fatalf("nested packages=%v, want nested/sub", nested.Packages)
	}
	assertStatus(t, report, "nested", "core_package", statusPass)
}

func TestSameFileDispatchRoutesRemainFunctionScoped(t *testing.T) {
	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project")
	source, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range source.GoFiles {
		if file.Path != "services/control-api/internal/multidispatch/server.go" {
			continue
		}
		want := map[string]bool{
			"s.handleAlpha /v1/multi/alpha":      false,
			"s.handleAlpha /v1/multi/alpha/{id}": false,
			"s.handleBeta /v1/multi/beta":        false,
			"s.handleBeta /v1/multi/beta/{id}":   false,
		}
		for _, route := range file.Routes {
			key := route.Handler + " " + route.Path
			if _, expected := want[key]; expected {
				want[key] = true
			}
			if route.Handler == "s.handleAlpha" && strings.Contains(route.Path, "/beta") {
				t.Fatalf("alpha handler inherited beta route: %#v", route)
			}
			if route.Handler == "s.handleBeta" && strings.Contains(route.Path, "/alpha") {
				t.Fatalf("beta handler inherited alpha route: %#v", route)
			}
		}
		for registration, found := range want {
			if !found {
				t.Fatalf("missing real ServeMux registration %s: %#v", registration, file.Routes)
			}
		}
		return
	}
	t.Fatal("multidispatch fixture was not scanned")
}

func TestNestedCanonicalOpenAPIRootIsAuthoritative(t *testing.T) {
	report := fixtureReport(t)
	assertStatus(t, report, "samea", "openapi_aggregation", statusPass)
	assertStatus(t, report, "fragmentvisible", "openapi_aggregation", statusPass)
	assertStatus(t, report, "fragmenthidden", "openapi_aggregation", statusFail)
}

func TestNonLocalOpenAPIRefFailsClosed(t *testing.T) {
	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "openapi", "scheme-relative")
	if _, err := loadOpenAPI(root); err == nil || !strings.Contains(err.Error(), "non-local OpenAPI ref") {
		t.Fatalf("scheme-relative ref was not rejected as non-local: %v", err)
	}
}

func TestOpenAPINonLocalReferenceFixturesFailClosed(t *testing.T) {
	for _, fixture := range []string{"http-uri", "https-uri", "scheme-relative", "absolute-path", "query-ref"} {
		t.Run(fixture, func(t *testing.T) {
			root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "openapi", fixture)
			if _, err := loadOpenAPI(root); err == nil || !strings.Contains(err.Error(), "non-local OpenAPI ref") {
				t.Fatalf("non-local OpenAPI fixture %s was not rejected: %v", fixture, err)
			}
		})
	}
}

func TestOpenAPICycleTerminatesAtReachableRootInboundOperation(t *testing.T) {
	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "openapi", "cycle")
	documents, err := loadOpenAPI(root)
	if err != nil {
		t.Fatal(err)
	}
	if !referencedByAggregator(canonicalOpenAPIRoot, "/paths/~1v1~1root/get", documents) {
		t.Fatal("root inbound operation was not reachable through cyclic path-item refs")
	}
	if referencedByAggregator("api/openapi/fragments/a.yaml", "/paths/~1v1~1hidden/get", documents) {
		t.Fatal("unreferenced operation in cyclic document became canonical inbound")
	}
}

func TestOpenAPISymlinkCannotEscapeAPIRoot(t *testing.T) {
	root := t.TempDir()
	rootPath := filepath.Join(root, filepath.FromSlash(canonicalOpenAPIRoot))
	if err := os.MkdirAll(filepath.Dir(rootPath), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, []byte("openapi: 3.1.0\npaths: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, rootPath); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := loadOpenAPI(root); err == nil || !strings.Contains(err.Error(), "escapes real api root") {
		t.Fatalf("symlink escape was not rejected: %v", err)
	}
}

func TestOnlyProvenServeMuxRegistrationsBecomeRoutes(t *testing.T) {
	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project")
	source, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, file := range source.GoFiles {
		if file.Path != "services/control-api/internal/customregistry/registry.go" &&
			file.Path != "services/control-api/internal/slashdispatch/handler.go" {
			continue
		}
		found[file.Path] = true
		for _, route := range file.Routes {
			if route.Path == "/v1/not-registered" {
				t.Fatalf("unproven registration became route in %s: %#v", file.Path, route)
			}
		}
	}
	for _, file := range []string{
		"services/control-api/internal/customregistry/registry.go",
		"services/control-api/internal/slashdispatch/handler.go",
	} {
		if !found[file] {
			t.Fatalf("negative route fixture was not scanned: %s", file)
		}
	}
}

func TestFutureServeMuxAssignmentCannotProvePastRegistration(t *testing.T) {
	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project")
	source, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range source.GoFiles {
		if file.Path != "services/control-api/internal/futuremux/registry.go" {
			continue
		}
		for _, route := range file.Routes {
			if route.Path == "/v1/not-a-router" {
				t.Fatalf("future ServeMux assignment proved an earlier custom registration: %#v", route)
			}
		}
		return
	}
	t.Fatal("futuremux fixture was not scanned")
}

func TestRouteCFGAndClosureCaptureAreExecutionAware(t *testing.T) {
	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project")
	source, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"/cfg-direct":      false,
		"/capture-live":    false,
		"/capture-iife":    false,
		"/typed-parameter": false,
		"/typed-field":     false,
		"/defer-package":   false,
		"/go-package":      false,
	}
	reject := map[string]bool{
		"/goto-skipped":        true,
		"/dead-branch":         true,
		"/panic-dead":          true,
		"/switch-dead":         true,
		"/capture-rebound":     true,
		"/capture-dead":        true,
		"/capture-written":     true,
		"/address-alias":       true,
		"/address-alias-prior": true,
		"/typed-nil":           true,
		"/select-dead":         true,
		"/typed-interface":     true,
		"/defer-rebound":       true,
		"/defer-local-closure": true,
		"/go-rebound":          true,
	}
	for _, file := range source.GoFiles {
		if file.Path != "services/control-api/internal/controlflowroutes/router.go" {
			continue
		}
		for _, route := range file.Routes {
			if reject[route.Path] {
				t.Fatalf("unreachable or invalid registration became a route: %#v", route)
			}
			if _, ok := want[route.Path]; ok {
				want[route.Path] = true
			}
		}
		for route, found := range want {
			if !found {
				t.Fatalf("reachable ServeMux registration %s missing: %#v", route, file.Routes)
			}
		}
		return
	}
	t.Fatal("controlflowroutes fixture was not scanned")
}

func TestRouteAliasesUseObjectIdentity(t *testing.T) {
	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project")
	source, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"/alias-direct": false, "/alias-closure": false, "/method-value": false}
	var got []routeFact
	for _, file := range source.GoFiles {
		if file.Path != "services/control-api/internal/controlflowroutes/router.go" {
			continue
		}
		got = file.Routes
		for _, route := range file.Routes {
			if _, ok := want[route.Path]; ok {
				want[route.Path] = true
			}
		}
	}
	for route, found := range want {
		if !found {
			t.Fatalf("reachable route alias %s was not proven: %#v", route, got)
		}
	}
}

func TestScheduledRoutesPreserveProvableReceiverState(t *testing.T) {
	routes := fixtureRoutes(t, "services/control-api/internal/controlflowroutes/router.go")
	want := map[string]bool{
		"/defer-stable-local":       false,
		"/defer-stable-receiver":    false,
		"/defer-parameter-snapshot": false,
		"/go-waited-stable":         false,
	}
	for _, route := range routes {
		if _, ok := want[route.Path]; ok {
			want[route.Path] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Fatalf("provable scheduled route %s missing: %#v", path, routes)
		}
	}
}

func TestVarAliasesIgnoreUnreachableRebinds(t *testing.T) {
	routes := fixtureRoutes(t, "services/control-api/internal/controlflowroutes/router.go")
	want := map[string]bool{
		"/var-closure-dead-rebind":   false,
		"/var-method-dead-rebind":    false,
		"/var-closure-future-rebind": false,
		"/var-method-future-rebind":  false,
	}
	reject := map[string]bool{"/var-closure-live-rebind": true, "/var-method-live-rebind": true}
	for _, route := range routes {
		if reject[route.Path] {
			t.Fatalf("reachable alias rebind became a route: %#v", route)
		}
		if _, ok := want[route.Path]; ok {
			want[route.Path] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Fatalf("var alias with dead rebind %s missing: %#v", path, routes)
		}
	}
}

func TestVarCallbackAliasRemainsReachable(t *testing.T) {
	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project")
	source, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"aliasruntime.NewVarAlias":      false,
		"aliasruntime.NewTransactional": false,
		"aliasruntime.NewAsync":         false,
	}
	for _, file := range source.GoFiles {
		if file.Path != "services/control-api/cmd/control-api/var_alias_fixtures.go" {
			continue
		}
		for _, function := range file.Functions {
			if function.Name != "varAliasRuntimeReferences" {
				continue
			}
			for _, call := range function.Calls {
				if _, ok := want[call.Name]; ok {
					want[call.Name] = true
				}
			}
		}
	}
	for call, found := range want {
		if !found {
			t.Fatalf("var callback alias did not produce reachable call fact %s", call)
		}
	}
}

func TestRound8ScheduledClosureProofs(t *testing.T) {
	routes := fixtureRoutes(t, "services/control-api/internal/controlflowroutes/round8_scheduled.go")
	want := map[string]bool{
		"/round8-go-direct":    false,
		"/round8-defer-return": false,
		"/round8-dead-mutator": false,
	}
	reject := map[string]bool{
		"/round8-go-select-default": true,
		"/round8-go-competing":      true,
		"/round8-defer-select":      true,
		"/round8-defer-loop":        true,
	}
	for _, route := range routes {
		if reject[route.Path] {
			t.Fatalf("unproven scheduled route became pass: %#v", route)
		}
		if _, ok := want[route.Path]; ok {
			want[route.Path] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Fatalf("provable scheduled route %s missing: %#v", path, routes)
		}
	}
}

func TestRound8ParenthesizedBindingsUseOneUnwrapRule(t *testing.T) {
	routes := fixtureRoutes(t, "services/control-api/internal/controlflowroutes/round8_scheduled.go")
	wantRoutes := map[string]bool{
		"/round8-paren-closure": false,
		"/round8-paren-method":  false,
		"/round8-paren-iife":    false,
	}
	for _, route := range routes {
		if _, ok := wantRoutes[route.Path]; ok {
			wantRoutes[route.Path] = true
		}
	}
	for path, found := range wantRoutes {
		if !found {
			t.Fatalf("parenthesized route binding %s missing: %#v", path, routes)
		}
	}

	wantCalls := map[string]bool{
		"aliasruntime.NewParenDirect":        false,
		"aliasruntime.NewParenTransactional": false,
		"aliasruntime.NewParenAsync":         false,
		"aliasruntime.NewParenIIFE":          false,
	}
	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project")
	source, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range source.GoFiles {
		if file.Path != "services/control-api/cmd/control-api/round8_paren_alias.go" {
			continue
		}
		for _, function := range file.Functions {
			if function.Name != "round8ParenthesizedRuntimeReferences" {
				continue
			}
			for _, call := range function.Calls {
				if _, ok := wantCalls[call.Name]; ok {
					wantCalls[call.Name] = true
				}
			}
		}
	}
	for call, found := range wantCalls {
		if !found {
			t.Fatalf("parenthesized call binding %s missing", call)
		}
	}
}

func TestRound8ParenthesizedMuxBinding(t *testing.T) {
	routes := fixtureRoutes(t, "services/control-api/internal/controlflowroutes/round8_paren_mux.go")
	for _, route := range routes {
		if route.Path == "/round8-paren-mux" {
			return
		}
	}
	t.Fatalf("parenthesized ServeMux binding missing: %#v", routes)
}

func TestRound9GoroutineFactsRequireWorkBeforeCompletionSignal(t *testing.T) {
	const fixture = "services/control-api/internal/controlflowroutes/round9_scheduled.go"
	routes := fixtureRoutes(t, fixture)
	wantRoutes := map[string]bool{
		"/round9-go-work-before-close": false,
		"/round9-go-work-before-send":  false,
	}
	rejectRoutes := map[string]bool{
		"/round9-go-signal-before-work": true,
		"/round9-go-alternate-signal":   true,
		"/round9-go-conditional-work":   true,
	}
	for _, route := range routes {
		if rejectRoutes[route.Path] {
			t.Fatalf("goroutine work not proven before completion became route: %#v", route)
		}
		if _, ok := wantRoutes[route.Path]; ok {
			wantRoutes[route.Path] = true
		}
	}
	for path, found := range wantRoutes {
		if !found {
			t.Fatalf("goroutine work-before-signal route %s missing: %#v", path, routes)
		}
	}

	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project")
	source, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := map[string]bool{
		"aliasruntime.NewRound9BeforeClose": false,
		"aliasruntime.NewRound9BeforeSend":  false,
	}
	for _, file := range source.GoFiles {
		if file.Path != fixture {
			continue
		}
		for _, function := range file.Functions {
			for _, call := range function.Calls {
				if call.Name == "aliasruntime.NewRound9AfterSignal" {
					t.Fatalf("runtime call after completion signal was collected: %#v", call)
				}
				if _, ok := wantCalls[call.Name]; ok {
					wantCalls[call.Name] = true
				}
			}
		}
	}
	for call, found := range wantCalls {
		if !found {
			t.Fatalf("work-before-signal runtime call %s missing", call)
		}
	}
}

func TestRound9DeferredRoutesRejectEscapedMutatorsAndOSExit(t *testing.T) {
	routes := fixtureRoutes(t, "services/control-api/internal/controlflowroutes/round9_scheduled.go")
	reject := map[string]bool{
		"/round9-defer-global-escape":    true,
		"/round9-defer-selector-escape":  true,
		"/round9-defer-container-escape": true,
		"/round9-defer-helper-escape":    true,
		"/round9-defer-os-exit":          true,
	}
	for _, route := range routes {
		if reject[route.Path] {
			t.Fatalf("unproven deferred route became pass: %#v", route)
		}
	}
}

func TestRound10AllPossibleSignalsFollowAuditedWork(t *testing.T) {
	const fixture = "services/control-api/internal/controlflowroutes/round10_scheduled.go"
	routes := fixtureRoutes(t, fixture)
	want := map[string]bool{
		"/round10-work-before-multiple-signals": false,
	}
	reject := map[string]bool{
		"/round10-conditional-early-signal":    true,
		"/round10-exhaustive-signals-boundary": true,
		"/round10-channel-alias-boundary":      true,
	}
	for _, route := range routes {
		if reject[route.Path] {
			t.Fatalf("unproven goroutine signal set became route: %#v", route)
		}
		if _, ok := want[route.Path]; ok {
			want[route.Path] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Fatalf("work-before-all-signals route %s missing: %#v", path, routes)
		}
	}

	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project")
	source, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	foundPositive := false
	for _, file := range source.GoFiles {
		if file.Path != fixture {
			continue
		}
		for _, function := range file.Functions {
			for _, call := range function.Calls {
				if call.Name == "aliasruntime.NewRound10AfterPossibleSignal" {
					t.Fatalf("runtime fact after a possible early signal was collected: %#v", call)
				}
				foundPositive = foundPositive || call.Name == "aliasruntime.NewRound10BeforeSignals"
			}
		}
	}
	if !foundPositive {
		t.Fatal("runtime fact before all completion signals was not collected")
	}
}

func TestRound10DeferredStabilityTracksMutatorEscapeChains(t *testing.T) {
	routes := fixtureRoutes(t, "services/control-api/internal/controlflowroutes/round10_scheduled.go")
	want := map[string]bool{"/round10-defer-goexit": false}
	reject := map[string]bool{
		"/round10-defer-map-composite":     true,
		"/round10-defer-slice-composite":   true,
		"/round10-defer-iife-wrapper":      true,
		"/round10-defer-goroutine-wrapper": true,
		"/round10-defer-unknown-param":     true,
	}
	for _, route := range routes {
		if reject[route.Path] {
			t.Fatalf("unproven deferred receiver became route: %#v", route)
		}
		if _, ok := want[route.Path]; ok {
			want[route.Path] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Fatalf("proven deferred route %s missing: %#v", path, routes)
		}
	}
	for _, route := range fixtureRoutes(t, "services/control-api/internal/controlflowroutes/round8_scheduled.go") {
		if route.Path == "/round8-dead-mutator" {
			return
		}
	}
	t.Fatal("dead uncalled local mutator no longer preserves stable receiver")
}

func fixtureRoutes(t *testing.T, path string) []routeFact {
	t.Helper()
	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project")
	source, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range source.GoFiles {
		if file.Path == path {
			return file.Routes
		}
	}
	t.Fatalf("fixture %s was not scanned", path)
	return nil
}

func TestFunctionValueAliasesRemainReachableCallFacts(t *testing.T) {
	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project")
	source, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"aliasruntime.NewDirect":        false,
		"aliasruntime.NewTransactional": false,
		"aliasruntime.NewAsync":         false,
	}
	for _, file := range source.GoFiles {
		if file.Path != "services/control-api/cmd/control-api/alias_fixtures.go" {
			continue
		}
		for _, function := range file.Functions {
			if function.Name != "aliasRuntimeReferences" {
				continue
			}
			for _, call := range function.Calls {
				if _, ok := want[call.Name]; ok {
					want[call.Name] = true
				}
			}
		}
	}
	for call, found := range want {
		if !found {
			t.Fatalf("reachable callback alias call %s was not collected", call)
		}
	}
	assertStatus(t, fixtureReport(t), "aliasruntime", "runtime_dependency_wiring", statusPass)
}

func TestGeneralCallsRequireReachableCallSites(t *testing.T) {
	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project")
	source, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"deadBranchRuntimeReference":  false,
		"deadClosureRuntimeReference": false,
	}
	for _, file := range source.GoFiles {
		if file.Path != "services/control-api/cmd/control-api/main.go" {
			continue
		}
		for _, function := range file.Functions {
			if _, ok := want[function.Name]; !ok {
				continue
			}
			want[function.Name] = true
			for _, call := range function.Calls {
				if call.Name == "sameb.NewService" {
					t.Fatalf("%s retained unreachable constructor call %#v", function.Name, call)
				}
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("runtime call fixture %s was not scanned", name)
		}
	}
}

func TestDeadCentralRouterCallsDoNotActivateMount(t *testing.T) {
	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project")
	source, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	program := buildProgram(source)
	var runtime []goFileFact
	for _, file := range source.GoFiles {
		if !file.Test && isRuntimeRoot(file.Path) {
			runtime = append(runtime, file)
		}
	}
	if centralRouterLive(runtime, program) {
		t.Fatal("dead httpapi.New/Handler calls activated the central router")
	}
}

func TestNilDefaultUsesParameterObjectIdentity(t *testing.T) {
	path := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project",
		"services", "control-api", "internal", "shadowdefault", "client.go")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fact := parseGoFact("services/control-api/internal/shadowdefault/client.go", content)
	if fact.ParseError != "" {
		t.Fatal(fact.ParseError)
	}
	want := map[string]bool{"NewShortClient": false, "NewIfInitClient": false}
	for _, function := range fact.Functions {
		if _, ok := want[function.Name]; !ok {
			continue
		}
		want[function.Name] = true
		if containsString(function.NilDefaultParameters, "dependency") {
			t.Fatalf("%s treated a shadow assignment as the parameter default", function.Name)
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("nil shadow fixture %s was not scanned", name)
		}
	}
}

func TestParseGoFactHandlesBodylessAndNilDefaultFunctions(t *testing.T) {
	const source = `package fixture

type Client struct{}
type Service struct{ client *Client }

func external(dependency *Client) *Service

func NewService(dependency *Client) *Service {
	if dependency == nil {
		dependency = new(Client)
	}
	return &Service{client: dependency}
}
`
	fact := parseGoFact("services/control-api/internal/fixture/client.go", []byte(source))
	if fact.ParseError != "" {
		t.Fatal(fact.ParseError)
	}
	want := map[string]bool{"external": false, "NewService": false}
	for _, function := range fact.Functions {
		if _, ok := want[function.Name]; !ok {
			continue
		}
		want[function.Name] = true
		switch function.Name {
		case "external":
			if len(function.ParameterOrder) != 1 || function.ParameterOrder[0] != "dependency" || len(function.Results) != 1 {
				t.Fatalf("bodyless declaration facts were not retained: %#v", function)
			}
		case "NewService":
			if !containsString(function.NilDefaultParameters, "dependency") {
				t.Fatalf("valid nil default was not retained: %#v", function)
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("function %s was not scanned", name)
		}
	}
}

func TestCallbackRefsDoNotAggregateInboundOperations(t *testing.T) {
	report := fixtureReport(t)
	assertStatus(t, report, "callbackonly", "openapi_aggregation", statusFail)
}

func TestNilDefaultMustDominateAllDependencyReturns(t *testing.T) {
	report := fixtureReport(t)
	assertStatus(t, report, "earlyreturn", "runtime_dependency_wiring", statusFail)
	assertFinding(t, report, "earlyreturn", "NIL_RUNTIME_DEPENDENCY")
}

func TestNilDefaultRejectsClosureAndAddressEscapes(t *testing.T) {
	path := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project",
		"services", "control-api", "internal", "nilescape", "client.go")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fact := parseGoFact("services/control-api/internal/nilescape/client.go", content)
	if fact.ParseError != "" {
		t.Fatal(fact.ParseError)
	}
	want := map[string]bool{
		"NewImmediateClient": false,
		"NewClosureClient":   false,
		"NewAliasClient":     false,
		"NewHelperClient":    false,
	}
	for _, function := range fact.Functions {
		if _, ok := want[function.Name]; !ok {
			continue
		}
		want[function.Name] = true
		if containsString(function.NilDefaultParameters, "dependency") {
			t.Fatalf("%s treated an escaped nil default as safe", function.Name)
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("nil escape fixture function %s was not scanned", name)
		}
	}
}

func TestVendorExtensionRefDoesNotAggregateOperations(t *testing.T) {
	report := fixtureReport(t)
	assertStatus(t, report, "extensionref", "openapi_aggregation", statusFail)
}

func TestUnusedComponentPathItemDoesNotAggregateOperations(t *testing.T) {
	report := fixtureReport(t)
	assertStatus(t, report, "componentonly", "openapi_aggregation", statusFail)
}

func TestMigrationOwnershipIgnoresCommentsAndQuotedText(t *testing.T) {
	path := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project",
		"services", "control-api", "migrations", "100_lexical_real.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ownership := migrationOwnedObjects(content)
	if ownership.Unknown || len(ownership.Owned) != 1 || ownership.Owned[0] != "lexical_real_records" {
		t.Fatalf("migration ownership included comments or quoted SQL: %#v", ownership)
	}
}

func TestSQLTokenParserUsesQualifiedLeafIdentifiers(t *testing.T) {
	content := []byte(`
SELECT 1 AS "CREATE TABLE fake_records";
CREATE TABLE public.real_records (id bigint);
DROP VIEW audit.real_view, "Audit"."Quoted_View";
CREATE TABLE "Public"."Quoted_Table" (id bigint);
`)
	ownership := migrationOwnedObjects(content)
	want := []string{"quoted_table", "quoted_view", "real_records", "real_view"}
	if ownership.Unknown || strings.Join(ownership.Owned, ",") != strings.Join(want, ",") {
		t.Fatalf("qualified/quoted DDL ownership=%#v, want %v", ownership, want)
	}
}

func TestSQLWriteParserDoesNotConfuseSchemaOrDDL(t *testing.T) {
	values := []string{
		`INSERT INTO public.domain_records (id) VALUES ($1)`,
		`CREATE TABLE public.other_records (id bigint)`,
		`UPDATE "Tenant"."Domain_Records" SET id=$1`,
		`DELETE FROM audit.domain_deletions WHERE id=$1`,
	}
	want := []string{"domain_deletions", "domain_records"}
	if got := writtenTablesFromStrings(values); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("qualified write objects=%v, want %v", got, want)
	}
	if intersects(writtenTablesFromStrings(values[:1]), migrationOwnedObjects([]byte(values[1])).Owned) {
		t.Fatal("schema name or CREATE object caused false write/migration ownership intersection")
	}
}

func TestPostgresSQLLexingHandlesEscapesOnlyAndCreateModifiers(t *testing.T) {
	ddl := []byte(`
SELECT E'prefix \' CREATE TABLE fake_records';
CREATE OR REPLACE VIEW audit.real_view AS SELECT 1;
CREATE UNLOGGED TABLE public.real_records (id bigint);
`)
	ownership := migrationOwnedObjects(ddl)
	wantOwned := []string{"real_records", "real_view"}
	if ownership.Unknown || strings.Join(ownership.Owned, ",") != strings.Join(wantOwned, ",") {
		t.Fatalf("PostgreSQL DDL lexing=%#v, want %v", ownership, wantOwned)
	}
	writes := writtenTablesFromStrings([]string{
		"INSERT INTO ONLY public.domain_records (id) VALUES ($1)",
		"DELETE FROM ONLY audit.domain_deletions WHERE id=$1",
	})
	wantWrites := []string{"domain_deletions", "domain_records"}
	if strings.Join(writes, ",") != strings.Join(wantWrites, ",") {
		t.Fatalf("ONLY write objects=%v, want %v", writes, wantWrites)
	}
}

func TestSQLUncertaintyIsScopedToRelatedObjects(t *testing.T) {
	content := []byte(`
CREATE TABLE public.domain_records (id bigint PRIMARY KEY);
INSERT INTO public.domain_records (id) VALUES (1) ON CONFLICT DO NOTHING;
CREATE TRIGGER domain_records_guard BEFORE UPDATE ON public.domain_records
FOR EACH ROW EXECUTE FUNCTION protect_domain_records();
DO $$
BEGIN
  CREATE TABLE public.unrelated_dynamic_records (id bigint PRIMARY KEY);
END
$$;
`)
	ownership := migrationOwnedObjects(content)
	if strings.Join(ownership.Owned, ",") != "domain_records" {
		t.Fatalf("static ownership=%v, want domain_records", ownership.Owned)
	}
	if strings.Join(ownership.Uncertain, ",") != "unrelated_dynamic_records" {
		t.Fatalf("uncertain ownership=%v, want unrelated_dynamic_records", ownership.Uncertain)
	}

	domain := domainModel{
		Name: "domain",
		Prod: []goFileFact{{Functions: []functionFact{{Strings: []string{
			"INSERT INTO public.domain_records (id) VALUES ($1)",
		}}}}},
	}
	migrations := migrationIndex{
		Files: []migrationFact{
			{Path: "services/control-api/migrations/001_domain.up.sql", Version: "001", Direction: "up", Owned: ownership.Owned, Uncertain: ownership.Uncertain, Embedded: true},
			{Path: "services/control-api/migrations/001_domain.down.sql", Version: "001", Direction: "down", Owned: []string{"domain_records"}, Embedded: true},
		},
		RuntimeLoads: true,
		RuntimeProof: []string{"services/control-api/internal/database/migrate.go#Migrate->migrations.FS"},
	}
	up, down, head := migrationChecks(domain, migrations, checked(statusPass, []string{"repository.go#postgres-calls"}, "fixture"), "repository.go#package:domain")
	for name, result := range map[string]checkResult{"migration_up": up, "migration_down": down, "migration_runtime_head": head} {
		if result.Status != statusPass {
			t.Fatalf("%s status=%s evidence=%v reason=%s, want pass", name, result.Status, result.Evidence, result.Reason)
		}
	}
}

func TestRound8DoStringAndExecuteLiteralObjectsAreScoped(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{name: "do-e-string", content: "DO E'BEGIN\\nCREATE TABLE public.do_e_records (id bigint);\\nEND';", want: "do_e_records"},
		{name: "execute-literal", content: "DO $$ BEGIN EXECUTE 'INSERT INTO public.do_execute_records (id) VALUES (1)'; END $$;", want: "do_execute_records"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ownership := migrationOwnedObjects([]byte(test.content))
			if !ownership.Unknown || strings.Join(ownership.Uncertain, ",") != test.want {
				t.Fatalf("ownership=%#v, want object-level uncertainty %s", ownership, test.want)
			}
		})
	}
}

func TestRound8DynamicTriggerIsNotGlobalOwnershipUnknown(t *testing.T) {
	content := []byte(`
DO $$
BEGIN
  EXECUTE format(
    'CREATE TRIGGER %I_guard BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION protect_row()',
    table_name, table_name
  );
END
$$;
`)
	ownership := migrationOwnedObjects(content)
	if !ownership.Unknown || ownership.GlobalUnknown || len(ownership.Uncertain) != 0 {
		t.Fatalf("dynamic trigger contaminated table ownership: %#v", ownership)
	}
}

func TestRound9ExecuteExpressionMustBeOneStaticLiteral(t *testing.T) {
	literal := migrationOwnedObjects([]byte(`DO $$ BEGIN EXECUTE 'CREATE TABLE public.literal_records (id bigint)'; END $$;`))
	if literal.GlobalUnknown || strings.Join(literal.Uncertain, ",") != "literal_records" {
		t.Fatalf("single EXECUTE literal ownership=%#v", literal)
	}

	concatenated := migrationOwnedObjects([]byte(`DO $$ BEGIN EXECUTE 'CREATE TABLE public.' || quote_ident(target_name); END $$;`))
	if !concatenated.GlobalUnknown {
		t.Fatalf("dynamic EXECUTE concatenation was not global unknown: %#v", concatenated)
	}
}

func TestRound9DynamicConcatDoesNotHideUncoveredDomainWrite(t *testing.T) {
	report := fixtureReport(t)
	for _, check := range []string{"migration_up", "migration_down", "migration_runtime_head"} {
		assertStatus(t, report, "doconcat", check, statusUnknown)
		assertStatus(t, report, "doglobalcovered", check, statusPass)
	}
}

func TestRound10ExecuteFormatWholeCommandIsGlobalUnknown(t *testing.T) {
	for _, expression := range []string{
		"format('%s', dynamic_sql)",
		"format(E'%s', dynamic_sql)",
		"format($fmt$%s$fmt$, dynamic_sql)",
	} {
		content := []byte("DO $$ BEGIN EXECUTE " + expression + "; END $$;")
		ownership := migrationOwnedObjects(content)
		if !ownership.GlobalUnknown {
			t.Fatalf("dynamic whole-command format %q was not global unknown: %#v", expression, ownership)
		}
	}
}

func TestRound10DynamicFormatDoesNotHideUncoveredDomainWrite(t *testing.T) {
	report := fixtureReport(t)
	for _, check := range []string{"migration_up", "migration_down", "migration_runtime_head"} {
		assertStatus(t, report, "doformatcommand", check, statusUnknown)
		assertStatus(t, report, "doglobalcovered", check, statusPass)
	}
}

func TestRound8MigrationUnknownReasonDoesNotSpread(t *testing.T) {
	report := fixtureReport(t)
	wantDomains := map[string]bool{
		"doddl":            true,
		"doconcat":         true,
		"doe":              true,
		"doexecute":        true,
		"doformatcommand":  true,
		"doglobal":         true,
		"lexicaluncertain": true,
	}
	const reason = "DO/dynamic SQL 无法静态证明领域对象 ownership。"
	counts := map[string]int{}
	for _, domain := range report.Domains {
		for _, check := range []string{"migration_up", "migration_down", "migration_runtime_head"} {
			result := domain.Checks[check]
			if result.Status == statusUnknown && result.Reason == reason {
				counts[domain.Name]++
			}
		}
	}
	for domain := range wantDomains {
		if counts[domain] != 3 {
			t.Fatalf("reason-code migration unknown count for %s=%d, want 3; all=%v", domain, counts[domain], counts)
		}
		delete(counts, domain)
	}
	if len(counts) != 0 {
		t.Fatalf("migration ownership unknown spread to unrelated domains: %v", counts)
	}
	for _, check := range []string{"migration_up", "migration_down", "migration_runtime_head"} {
		assertStatus(t, report, "doglobalcovered", check, statusPass)
		assertStatus(t, report, "samea", check, statusPass)
	}
}

func TestLexicallyUncertainOwnershipCannotPassMigration(t *testing.T) {
	report := fixtureReport(t)
	for _, check := range []string{"migration_up", "migration_down", "migration_runtime_head"} {
		assertStatus(t, report, "lexicaluncertain", check, statusUnknown)
	}
}

func TestDoBlockMigrationOwnershipFailsClosed(t *testing.T) {
	report := fixtureReport(t)
	for _, check := range []string{"migration_up", "migration_down", "migration_runtime_head"} {
		assertStatus(t, report, "doddl", check, statusUnknown)
	}
}

func TestCanonicalOpenAPIRootParticipatesInSourceHash(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{
		"services/control-api/internal/valid", "services/control-api/cmd/control-api", "services/control-api/migrations",
		"api/openapi/v1", "api/openapi/fragments", "apps/web/src", "scripts", "tests",
	} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(directory)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "services/control-api/internal/valid/valid.go"), []byte("package valid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fragment := "api/openapi/fragments/valid.yaml"
	firstFragment := "openapi: 3.1.0\ninfo: {title: one, version: 1.0.0}\npaths:\n  /v1/valid: {}\n"
	if err := os.WriteFile(filepath.Join(root, fragment), []byte(firstFragment), 0o644); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(root, filepath.FromSlash(canonicalOpenAPIRoot))
	firstRoot := "openapi: 3.1.0\ninfo: {title: one, version: 1.0.0}\npaths:\n  /v1/valid:\n    $ref: '../fragments/valid.yaml#/paths/~1v1~1valid'\n"
	if err := os.WriteFile(rootPath, []byte(firstRoot), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	secondRoot := strings.Replace(firstRoot, "title: one", "title: two", 1)
	if err := os.WriteFile(rootPath, []byte(secondRoot), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	if first.SourceSHA256 == second.SourceSHA256 {
		t.Fatal("canonical OpenAPI root did not affect source hash")
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(fragment)), []byte(strings.Replace(firstFragment, "title: one", "title: changed", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	third, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	if second.SourceSHA256 == third.SourceSHA256 {
		t.Fatal("nested OpenAPI ref did not affect source hash")
	}
}

func TestSourceManifestVerificationFailsClosedOnDrift(t *testing.T) {
	tests := map[string]func(*testing.T, string, string){
		"modified": func(t *testing.T, root, _ string) {
			writeTestFile(t, root, "services/control-api/internal/valid/valid.go", "package valid\nconst changed = true\n")
		},
		"added": func(t *testing.T, root, _ string) {
			writeTestFile(t, root, "services/control-api/internal/added/added.go", "package added\n")
		},
		"deleted": func(t *testing.T, root, _ string) {
			if err := os.Remove(filepath.Join(root, "services/control-api/internal/valid/valid.go")); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, root, _ string) {
			path := filepath.Join(root, "services/control-api/internal/valid/valid.go")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, root, "services/control-api/internal/valid/valid.real", "package valid\n")
			if err := os.Symlink("valid.real", path); err != nil {
				t.Fatal(err)
			}
		},
		"openapi-symlink": func(t *testing.T, root, _ string) {
			path := filepath.Join(root, filepath.FromSlash(canonicalOpenAPIRoot))
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, root, "api/openapi/v1/control.real", "openapi: 3.1.0\npaths: {}\n")
			if err := os.Symlink("control.real", path); err != nil {
				t.Fatal(err)
			}
		},
		"non-canonical-path": func(t *testing.T, _, manifestPath string) {
			content, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var manifest fileManifest
			if err := json.Unmarshal(content, &manifest); err != nil {
				t.Fatal(err)
			}
			manifest.Entries[0].Path = "services/control-api/internal/../internal/valid/valid.go"
			content, err = encodeFileManifest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifestPath, content, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			root := newManifestFixture(t)
			source, err := buildSourceIndex(root)
			if err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(t.TempDir(), "source-manifest.json")
			content, err := encodeFileManifest(source.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifestPath, content, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := verifySourceManifest(root, manifestPath); err != nil {
				t.Fatalf("fresh source manifest failed verification: %v", err)
			}
			mutate(t, root, manifestPath)
			if err := verifySourceManifest(root, manifestPath); err == nil || !strings.Contains(err.Error(), "source manifest stale") {
				t.Fatalf("drift did not fail closed: %v", err)
			}
		})
	}
}

func TestSourceManifestIncludesInactiveFrontendAndCanonicalOpenAPI(t *testing.T) {
	root := newManifestFixture(t)
	source, err := buildSourceIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, entry := range source.Manifest.Entries {
		paths[entry.Path] = true
	}
	for _, path := range []string{canonicalOpenAPIRoot, "apps/web/src/inactive.ts"} {
		if !paths[path] {
			t.Fatalf("source manifest omitted audited input %s", path)
		}
	}
}

func newManifestFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{
		"services/control-api/internal/valid", "services/control-api/cmd/control-api", "services/control-api/migrations",
		"api/openapi/v1", "apps/web/src", "scripts", "tests",
	} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(directory)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, root, "services/control-api/internal/valid/valid.go", "package valid\n")
	writeTestFile(t, root, canonicalOpenAPIRoot, "openapi: 3.1.0\npaths: {}\n")
	writeTestFile(t, root, "apps/web/src/inactive.ts", "export const value = 1\n")
	return root
}

func writeTestFile(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationOwnershipExcludesSharedDependencies(t *testing.T) {
	report := fixtureReport(t)
	assertStatus(t, report, "migrationowner", "migration_down", statusPass)
	assertEvidenceExcludes(t, report, "migrationowner", "migration_up", "#migration:002:")
	assertStatus(t, report, "orders", "migration_down", statusPass)
	assertEvidenceExcludes(t, report, "orders", "migration_up", "#migration:099:")
}

func TestRouteMatchingIsExactOrSegmentTemplated(t *testing.T) {
	if !routeMatchesAny("/v1/items/${itemID}", []string{"/v1/items/{id}"}) {
		t.Fatal("equivalent template segments did not match")
	}
	for _, candidate := range []string{"/v1/items", "/v1", "/v1/items-extra", "/v1/items/id/extra"} {
		if routeMatchesAny(candidate, []string{"/v1/items/{id}"}) {
			t.Fatalf("broad prefix matched %q", candidate)
		}
	}
}

func TestConflictFiltersCoverActiveOwnerships(t *testing.T) {
	filters := currentConflictFilters()
	for _, name := range []string{"NODE", "CACHE", "SYSTEMCONFIG"} {
		found := false
		for _, filter := range filters {
			found = found || filter.Name == name
		}
		if !found {
			t.Fatalf("missing conflict filter %s", name)
		}
	}
	if !domainConflicted(domainResult{Packages: []string{"nodeidentity"}}, filters) ||
		!domainConflicted(domainResult{Packages: []string{"cachecontrol"}}, filters) ||
		!domainConflicted(domainResult{Packages: []string{"systemconfig"}}, filters) {
		t.Fatal("active NODE/CACHE/SYSTEMCONFIG package ownership was not filtered")
	}
}

func TestSourceWalkAndParseFailClosed(t *testing.T) {
	if _, err := buildSourceIndex(t.TempDir()); err == nil {
		t.Fatal("missing required source scopes did not fail")
	}
	root := t.TempDir()
	for _, directory := range []string{
		"services/control-api/internal/broken", "services/control-api/cmd/control-api", "services/control-api/migrations",
		"api/openapi/v1", "apps/web/src", "scripts", "tests",
	} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(directory)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "services/control-api/internal/broken/broken.go"), []byte("package broken\nfunc {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(canonicalOpenAPIRoot)), []byte("openapi: 3.1.0\npaths: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := buildSourceIndex(root); err == nil || !strings.Contains(err.Error(), "parse services/control-api/internal/broken/broken.go") {
		t.Fatalf("parse failure was not closed: %v", err)
	}

	openAPIRoot := t.TempDir()
	for _, directory := range []string{
		"services/control-api/internal/valid", "services/control-api/cmd/control-api", "services/control-api/migrations",
		"api/openapi/v1", "apps/web/src", "scripts", "tests",
	} {
		if err := os.MkdirAll(filepath.Join(openAPIRoot, filepath.FromSlash(directory)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(openAPIRoot, "services/control-api/internal/valid/valid.go"), []byte("package valid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(openAPIRoot, filepath.FromSlash(canonicalOpenAPIRoot)), []byte("paths: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := auditRepository(openAPIRoot); err == nil || !strings.Contains(err.Error(), "parse "+canonicalOpenAPIRoot) {
		t.Fatalf("OpenAPI parse failure was not closed: %v", err)
	}
}

func TestMigrationEvidenceRequiresTypedEmbedAndASTSelector(t *testing.T) {
	valid := parseGoFact("services/control-api/migrations/embed.go", []byte("package migrations\nimport \"embed\"\n//go:embed *.sql\nvar FS embed.FS\n"))
	if valid.ParseError != "" || len(valid.Embeds) != 1 || valid.Embeds[0].Variable != "FS" {
		t.Fatalf("valid embed was not parsed: %#v", valid.Embeds)
	}
	untyped := parseGoFact("services/control-api/migrations/embed.go", []byte("package migrations\nimport \"embed\"\nvar _ embed.FS\n//go:embed *.sql\nvar FS any\n"))
	if untyped.ParseError != "" || len(untyped.Embeds) != 0 {
		t.Fatalf("untyped embed counted as migration FS: %#v", untyped.Embeds)
	}
	commentOnly := parseGoFact("services/control-api/internal/database/migrate.go", []byte("package database\n// migrations.FS must not count.\nfunc Migrate() error { return nil }\n"))
	if commentOnly.ParseError != "" || len(commentOnly.Functions) != 1 || containsString(commentOnly.Functions[0].Selectors, "migrations.FS") {
		t.Fatalf("comment became selector evidence: %#v", commentOnly.Functions)
	}
}

func TestReportIsDeterministicAndBounded(t *testing.T) {
	first := fixtureReport(t)
	second := fixtureReport(t)
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("two fixture audits produced different JSON")
	}
	if len(first.NextTasks) > 8 {
		t.Fatalf("next_tasks=%d, want <=8", len(first.NextTasks))
	}
	allowed := map[status]bool{
		statusPass: true, statusFail: true, statusUnknown: true, statusNotApplied: true,
	}
	for _, domain := range first.Domains {
		for _, checkName := range checkOrder {
			check := domain.Checks[checkName]
			if !allowed[check.Status] {
				t.Fatalf("%s.%s status=%q", domain.Name, checkName, check.Status)
			}
			for _, evidence := range check.Evidence {
				if !strings.Contains(evidence, "#") || filepath.IsAbs(evidence) {
					t.Fatalf("non-relative or symbol-free evidence: %q", evidence)
				}
			}
		}
	}

	firstOut := t.TempDir()
	secondOut := t.TempDir()
	if err := writeReport(firstOut, first); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(secondOut, second); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.json", "report.md", "source-manifest.json", "tool-source-manifest.json", "SHA256SUMS"} {
		left, err := os.ReadFile(filepath.Join(firstOut, name))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(secondOut, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(left, right) {
			t.Fatalf("%s differs across deterministic writes", name)
		}
	}
}

func fixtureReport(t *testing.T) report {
	t.Helper()
	root := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "project")
	result, err := auditRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	result.ToolRoot, err = filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertStatus(t *testing.T, result report, domainName, checkName string, expected status) {
	t.Helper()
	domain := findDomain(t, result, domainName)
	if actual := domain.Checks[checkName].Status; actual != expected {
		t.Fatalf("%s.%s=%s, want %s (reason=%s evidence=%v)", domainName, checkName, actual, expected,
			domain.Checks[checkName].Reason, domain.Checks[checkName].Evidence)
	}
}

func assertEvidenceExcludes(t *testing.T, result report, domainName, checkName, excluded string) {
	t.Helper()
	for _, evidence := range findDomain(t, result, domainName).Checks[checkName].Evidence {
		if strings.Contains(evidence, excluded) {
			t.Fatalf("%s.%s evidence unexpectedly contains %q: %v", domainName, checkName, excluded,
				findDomain(t, result, domainName).Checks[checkName].Evidence)
		}
	}
}

func assertFinding(t *testing.T, result report, domainName, code string) {
	t.Helper()
	domain := findDomain(t, result, domainName)
	for _, item := range domain.Findings {
		if item.Code == code {
			return
		}
	}
	t.Fatalf("%s missing finding %s: %#v", domainName, code, domain.Findings)
}

func findDomain(t *testing.T, result report, name string) domainResult {
	t.Helper()
	for _, domain := range result.Domains {
		if domain.Name == name {
			return domain
		}
	}
	t.Fatalf("domain %q not found", name)
	return domainResult{}
}
