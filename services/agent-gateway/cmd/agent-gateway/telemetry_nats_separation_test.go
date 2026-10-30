package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestRuntimeUsesDedicatedTelemetryNATSConnection(t *testing.T) {
	file := parseGoFile(t, "runtime.go")
	runtimeType := findStructType(t, file, "runtime")
	if !structHasField(runtimeType, "telemetryNATSConnection") {
		t.Fatal("runtime is missing a dedicated telemetry NATS connection")
	}

	build := findFunction(t, file, "buildRuntime", "")
	telemetryConnect := findCall(build.Body, func(call *ast.CallExpr) bool {
		return isSelector(call.Fun, "nats", "Connect") &&
			len(call.Args) > 0 && containsSelector(call.Args[0], "c", "telemetryNATSURL")
	})
	if telemetryConnect == nil {
		t.Fatal("buildRuntime does not establish a dedicated telemetry NATS connection")
	}
	if !callAssignedTo(build.Body, telemetryConnect, "r", "telemetryNATSConnection") {
		t.Fatal("telemetry NATS connection is not retained by runtime for readiness and shutdown")
	}
	telemetryOptions := findFunction(t, file, "telemetryConnectionOptions", "")
	if !containsSelector(telemetryOptions.Body, "c", "telemetryNATSUser") ||
		!containsSelector(telemetryOptions.Body, "c", "telemetryNATSPassword") {
		t.Fatal("buildRuntime does not apply the dedicated telemetry NATS credential pair")
	}

	publisher := findCall(build.Body, func(call *ast.CallExpr) bool {
		return isSelector(call.Fun, "gateway", "NewNATSTelemetryPublisher")
	})
	if publisher == nil || len(publisher.Args) == 0 {
		t.Fatal("buildRuntime does not construct the telemetry publisher")
	}
	if !containsSelector(publisher.Args[0], "r", "telemetryNATSConnection") {
		t.Fatal("telemetry publisher is not constructed from the dedicated connection")
	}
	if containsSelector(publisher.Args[0], "r", "natsConnection") {
		t.Fatal("telemetry publisher still uses the command-bus NATS connection")
	}

	readiness := findCall(build.Body, func(call *ast.CallExpr) bool {
		return isIdentifier(call.Fun, "newRuntimeReadiness")
	})
	if readiness == nil || (!containsSelector(readiness, "telemetryPublisher", "Check") &&
		!containsSelector(readiness, "r", "telemetryNATSConnection")) {
		t.Fatal("runtime readiness does not check the dedicated telemetry connection")
	}
	healthComposition := findCall(build.Body, func(call *ast.CallExpr) bool {
		return isIdentifier(call.Fun, "newHealthComposition")
	})
	if healthComposition == nil || !containsSelector(healthComposition, "telemetryPublisher", "Check") {
		t.Fatal("telemetry health Check is not wired to the dedicated publisher")
	}

	closeMethod := findFunction(t, file, "close", "runtime")
	if !containsSelector(closeMethod.Body, "r", "telemetryNATSConnection") ||
		findCall(closeMethod.Body, func(call *ast.CallExpr) bool {
			if isIdentifier(call.Fun, "drainNATS") && len(call.Args) == 1 {
				return containsSelector(call.Args[0], "r", "telemetryNATSConnection")
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			return ok && selector.Sel.Name == "Drain" &&
				containsSelector(selector.X, "r", "telemetryNATSConnection")
		}) == nil {
		t.Fatal("runtime close does not drain the dedicated telemetry NATS connection")
	}
}

func parseGoFile(t *testing.T, path string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return file
}

func findStructType(t *testing.T, file *ast.File, name string) *ast.StructType {
	t.Helper()
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, specification := range general.Specs {
			typeSpec, ok := specification.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != name {
				continue
			}
			structure, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("%s is not a struct", name)
			}
			return structure
		}
	}
	t.Fatalf("struct %s not found", name)
	return nil
}

func structHasField(structure *ast.StructType, name string) bool {
	for _, field := range structure.Fields.List {
		for _, candidate := range field.Names {
			if candidate.Name == name {
				return true
			}
		}
	}
	return false
}

func findFunction(t *testing.T, file *ast.File, name, receiver string) *ast.FuncDecl {
	t.Helper()
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != name {
			continue
		}
		if receiver == "" && function.Recv == nil {
			return function
		}
		if receiver != "" && function.Recv != nil && len(function.Recv.List) == 1 {
			if star, ok := function.Recv.List[0].Type.(*ast.StarExpr); ok {
				if identifier, ok := star.X.(*ast.Ident); ok && identifier.Name == receiver {
					return function
				}
			}
		}
	}
	t.Fatalf("function %s not found", name)
	return nil
}

func findCall(node ast.Node, matches func(*ast.CallExpr) bool) *ast.CallExpr {
	var match *ast.CallExpr
	ast.Inspect(node, func(candidate ast.Node) bool {
		if match != nil {
			return false
		}
		call, ok := candidate.(*ast.CallExpr)
		if ok && matches(call) {
			match = call
			return false
		}
		return true
	})
	return match
}

func callAssignedTo(node ast.Node, target *ast.CallExpr, receiver, field string) bool {
	found := false
	ast.Inspect(node, func(candidate ast.Node) bool {
		assignment, ok := candidate.(*ast.AssignStmt)
		if !ok {
			return true
		}
		containsTarget := false
		for _, expression := range assignment.Rhs {
			ast.Inspect(expression, func(n ast.Node) bool {
				if n == target {
					containsTarget = true
					return false
				}
				return true
			})
		}
		if !containsTarget {
			return true
		}
		for _, expression := range assignment.Lhs {
			if containsSelector(expression, receiver, field) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func containsSelector(node ast.Node, receiver, field string) bool {
	found := false
	ast.Inspect(node, func(candidate ast.Node) bool {
		selector, ok := candidate.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != field {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if ok && identifier.Name == receiver {
			found = true
			return false
		}
		return true
	})
	return found
}

func isSelector(expression ast.Expr, receiver, field string) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != field {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	return ok && identifier.Name == receiver
}

func isIdentifier(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name
}
