package jobhttp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestKindCatalogIsBoundToProductionJobCreationPaths(t *testing.T) {
	type producer struct {
		kindFile, createFile, kindExpression string
		directSQL                            bool
	}
	producers := map[string]producer{
		"analytics.log_export":    {"../analyticslog/export_postgres.go", "../analyticslog/export_postgres.go", "analytics.log_export", false},
		"cache.operation":         {"../cachecontrol/operation.go", "../cachecontrol/operation.go", "cache.operation", false},
		"dns.cleanup.v1":          {"../dnssettings/service.go", "../dnssettings/service.go", "kind", false},
		"dns.repair.v1":           {"../dnssettings/service.go", "../dnssettings/service.go", "kind", false},
		"dns.cname.allocation":    {"../cnameallocation/store.go", "../cnameallocation/store.go", "databaseJobKind", true},
		"dns.cname.intent":        {"../site/store.go", "../site/store.go", "dns.cname.intent", true},
		"dns.cname.stream_intent": {"../cnameallocation/stream.go", "../cnameallocation/stream.go", "StreamIntentJobKind", true},
		"dns_reconcile":           {"../dnsreconcile/model.go", "../dnsreconcile/postgres_store.go", "JobKind", true},
		"edge.publication":        {"../edgepublish/service.go", "../edgepublish/service.go", "edge.publication", false},
		"site.status_recovery":    {"../site/status_recovery.go", "../site/status_recovery.go", "statusRecoveryKind", false},
	}
	if len(producers) != len(integratedKinds) {
		t.Fatalf("producer count=%d catalog count=%d", len(producers), len(integratedKinds))
	}
	seen := map[string]bool{}
	for _, kind := range integratedKinds {
		t.Run(kind.Kind, func(t *testing.T) {
			producer, exists := producers[kind.Kind]
			if !exists || seen[kind.Kind] {
				t.Fatalf("unbound or duplicate catalog kind=%q", kind.Kind)
			}
			seen[kind.Kind] = true
			definition := parseProducerFile(t, producer.kindFile)
			if !astHasString(definition, kind.Kind) {
				t.Fatalf("kind %q is not a production literal in %s", kind.Kind, producer.kindFile)
			}
			creation := parseProducerFile(t, producer.createFile)
			found := false
			ast.Inspect(creation, func(node ast.Node) bool {
				if producer.directSQL {
					call, ok := node.(*ast.CallExpr)
					if !ok || !astHasString(call, "INSERT INTO background_jobs") {
						return true
					}
					for _, argument := range call.Args {
						if expressionText(argument) == producer.kindExpression || astHasString(argument, producer.kindExpression) {
							found = true
						}
					}
					return true
				}
				literal, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				selector, ok := literal.Type.(*ast.SelectorExpr)
				if !ok || expressionText(selector.X) != "jobstate" || selector.Sel.Name != "CreateInput" {
					return true
				}
				for _, element := range literal.Elts {
					pair, ok := element.(*ast.KeyValueExpr)
					if ok && expressionText(pair.Key) == "Kind" && expressionText(pair.Value) == producer.kindExpression {
						found = true
					}
				}
				return true
			})
			if !found {
				t.Fatalf("kind %q no longer enters the canonical job creation in %s", kind.Kind, producer.createFile)
			}
		})
	}
}

func TestTaskPriorityPoliciesReflectClaimOrProducerPaths(t *testing.T) {
	for _, test := range []struct {
		kind, file, call, kindExpression, policy string
	}{
		{"dns_reconcile", "../dnsreconcile/postgres_store.go", "Claim", "JobKind", "ready_fifo"},
		{"dns.cname.allocation", "../cnameallocation/worker.go", "Claim", "databaseJobKind", "ready_fifo"},
		{"dns.cname.intent", "../cnameallocation/worker.go", "Claim", "dns.cname.intent", "ready_fifo"},
		{"site.status_recovery", "../sitestatusrecovery/runtime.go", "Claim", "JobKind", "ready_fifo"},
		{"cache.operation", "../cachecontrol/lifecycle.go", "StartTx", "cache.operation", "producer_managed"},
		{"analytics.log_export", "../analyticslog/export_postgres.go", "StartTx", "analytics.log_export", "producer_managed"},
		{"edge.publication", "../edgepublish/service.go", "StartTx", "edge.publication", "producer_managed"},
	} {
		file := parseProducerFile(t, test.file)
		found := false
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != test.call {
				return true
			}
			ast.Inspect(call, func(child ast.Node) bool {
				pair, ok := child.(*ast.KeyValueExpr)
				if ok && expressionText(pair.Key) == "Kind" && expressionText(pair.Value) == test.kindExpression {
					found = true
				}
				return true
			})
			return true
		})
		if !found || derivedTaskMetadata(Job{Kind: test.kind}).Priority.Policy != test.policy {
			t.Errorf("kind %s policy %s is no longer backed by %s/%s", test.kind, test.policy, test.file, test.call)
		}
	}
	store := parseProducerFile(t, "../jobstate/store.go")
	if !astHasString(store, "ORDER BY claimable_at, created_at, id") {
		t.Fatal("ready_fifo policy no longer matches actual jobstate claim order")
	}
	for _, kind := range []string{"dns.repair.v1", "dns.cleanup.v1", "future.kind"} {
		if derivedTaskMetadata(Job{Kind: kind}).Priority.Policy != "unknown" {
			t.Fatalf("unverified policy for %s must remain unknown", kind)
		}
	}
}

func TestCompletionTaskIDIsCanonicalJobIDAndWorkerWaitsForCompletion(t *testing.T) {
	reader, err := os.ReadFile("../dnsreconcile/postgres_store.go")
	if err != nil {
		t.Fatal(err)
	}
	// l4-s6（迁移 507）：第三列是任务的锚（网站或转发），Task.ID 仍是 job_id。
	for _, source := range []string{"SELECT task.job_id,task.tenant_id,COALESCE(task.site_id,task.stream_id)", "&task.ID, &task.TenantID, &task.SiteID"} {
		if !strings.Contains(string(reader), source) {
			t.Fatalf("DNS Task.ID mapping changed; re-audit dependency identity: %s", source)
		}
	}
	worker, err := os.ReadFile("../cnameallocation/worker.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"target.ChildTaskID", "case task.Result.Status == dnscheck.TaskCommitted:", "worker.dependencies.Targets.Complete("} {
		if !strings.Contains(string(worker), source) {
			t.Fatalf("CNAME completion dependency path changed: %s", source)
		}
	}
}

func parseProducerFile(t *testing.T, path string) *ast.File {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, content, 0)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func expressionText(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.BasicLit:
		unquoted, _ := strconv.Unquote(value.Value)
		return unquoted
	}
	return ""
}

func astHasString(node ast.Node, value string) bool {
	found := false
	ast.Inspect(node, func(child ast.Node) bool {
		literal, ok := child.(*ast.BasicLit)
		if ok && literal.Kind == token.STRING && strings.Contains(expressionText(literal), value) {
			found = true
		}
		return true
	})
	return found
}
