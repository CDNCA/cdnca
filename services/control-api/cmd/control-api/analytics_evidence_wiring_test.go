package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestRunServerWiresAnalyticsEvidenceIsolationProvider(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	var runServer *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "runServer" {
			runServer = function
			break
		}
	}
	if runServer == nil || runServer.Body == nil {
		t.Fatal("runServer function not found")
	}

	constructorCount := 0
	ast.Inspect(runServer.Body, func(node ast.Node) bool {
		if statement, ok := node.(ast.Stmt); ok && constructsIsolationProvider(statement) {
			constructorCount++
		}
		return true
	})

	for index, statement := range runServer.Body.List {
		guard, ok := analyticsIngestEnabledGuard(statement)
		if !ok {
			continue
		}
		if constructorCount != 1 || len(guard.Body.List) != 5 ||
			!constructsIsolationProvider(guard.Body.List[0]) ||
			!clearsIsolationWrappingKey(guard.Body.List[1]) ||
			!nilsIsolationWrappingKey(guard.Body.List[2]) ||
			!guardsIsolationProviderError(guard.Body.List[3]) ||
			!assignsIsolationProvider(guard.Body.List[4]) {
			t.Fatal("enabled analytics ingest must exclusively construct, immediately clear, check, and assign the evidence provider")
		}
		if index+1 >= len(runServer.Body.List) || !opensAnalyticsIngestRuntime(runServer.Body.List[index+1]) {
			t.Fatal("analytics ingest runtime must open immediately after the evidence provider enabled guard")
		}
		return
	}
	t.Fatal("runServer is missing enabled analytics evidence constructor wiring")
}

func analyticsIngestEnabledGuard(statement ast.Stmt) (*ast.IfStmt, bool) {
	guard, ok := statement.(*ast.IfStmt)
	return guard, ok && guard.Init == nil && guard.Else == nil &&
		isSelectorPath(guard.Cond, "cfg", "AnalyticsIngest", "Enabled")
}

func constructsIsolationProvider(statement ast.Stmt) bool {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 {
		return false
	}
	provider, providerOK := assignment.Lhs[0].(*ast.Ident)
	errValue, errOK := assignment.Lhs[1].(*ast.Ident)
	call, callOK := assignment.Rhs[0].(*ast.CallExpr)
	return providerOK && provider.Name == "isolationKeyProvider" && errOK && errValue.Name == "err" && callOK &&
		isSelectorPath(call.Fun, "analytics", "NewAESGCMIsolationKeyProvider") && len(call.Args) == 2 &&
		isSelectorPath(call.Args[0], "cfg", "AnalyticsIngest", "IsolationWrappingKeyID") &&
		isSelectorPath(call.Args[1], "cfg", "AnalyticsIngest", "IsolationWrappingKey")
}

func clearsIsolationWrappingKey(statement ast.Stmt) bool {
	expression, ok := statement.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, callOK := expression.X.(*ast.CallExpr)
	if !callOK {
		return false
	}
	function, functionOK := call.Fun.(*ast.Ident)
	return functionOK && function.Name == "clear" && len(call.Args) == 1 &&
		isSelectorPath(call.Args[0], "cfg", "AnalyticsIngest", "IsolationWrappingKey")
}

func nilsIsolationWrappingKey(statement ast.Stmt) bool {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.ASSIGN || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 ||
		!isSelectorPath(assignment.Lhs[0], "cfg", "AnalyticsIngest", "IsolationWrappingKey") {
		return false
	}
	identifier, ok := assignment.Rhs[0].(*ast.Ident)
	return ok && identifier.Name == "nil"
}

func guardsIsolationProviderError(statement ast.Stmt) bool {
	guard, ok := statement.(*ast.IfStmt)
	if !ok || guard.Else != nil || len(guard.Body.List) != 1 {
		return false
	}
	condition, ok := guard.Cond.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	left, leftOK := condition.X.(*ast.Ident)
	right, rightOK := condition.Y.(*ast.Ident)
	_, returnOK := guard.Body.List[0].(*ast.ReturnStmt)
	return condition.Op == token.NEQ && leftOK && left.Name == "err" && rightOK && right.Name == "nil" && returnOK
}

func assignsIsolationProvider(statement ast.Stmt) bool {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.ASSIGN || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 ||
		!isSelectorPath(assignment.Lhs[0], "cfg", "AnalyticsIngest", "JetStream", "IsolationKeyProvider") {
		return false
	}
	identifier, ok := assignment.Rhs[0].(*ast.Ident)
	return ok && identifier.Name == "isolationKeyProvider"
}

func opensAnalyticsIngestRuntime(statement ast.Stmt) bool {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 {
		return false
	}
	call, ok := assignment.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	function, functionOK := call.Fun.(*ast.Ident)
	return functionOK && function.Name == "openAnalyticsIngestRuntime"
}

func isSelectorPath(expression ast.Expr, root string, selectors ...string) bool {
	for index := len(selectors) - 1; index >= 0; index-- {
		selector, ok := expression.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != selectors[index] {
			return false
		}
		expression = selector.X
	}
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == root
}
