package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"testing"
)

func TestAPIKeyUsageProductionRuntimeWiring(t *testing.T) {
	source, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}

	var runServer *ast.FuncDecl
	for _, declaration := range source.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "runServer" {
			runServer = function
			break
		}
	}
	if runServer == nil {
		t.Fatal("runServer declaration is missing")
	}
	body := raw[int(runServer.Body.Pos())-1 : int(runServer.Body.End())-1]

	poolClose := bytes.Index(body, []byte("defer closePoolAfterStop(stop, pool)"))
	runtimeOpen := bytes.Index(body, []byte("apiKeyUsageRuntime, err := newAPIKeyUsageRuntime(pool)"))
	runtimeClose := bytes.Index(body, []byte("defer apiKeyUsageRuntime.Close()"))
	recorder := regexp.MustCompile(`APIKeyUsageRecorder:\s+apiKeyUsageRuntime,`).FindIndex(body)
	for name, position := range map[string]int{
		"database close":      poolClose,
		"usage runtime open":  runtimeOpen,
		"usage runtime close": runtimeClose,
	} {
		if position < 0 {
			t.Errorf("runServer is missing %s wiring", name)
		}
	}
	if !bytes.Contains(body, []byte(`runtimeStageError{stage: "initialize API key usage runtime", err: err}`)) {
		t.Error("runServer is missing the stable API key usage startup stage")
	}
	if recorder == nil {
		t.Error("runServer does not inject the API key usage recorder")
	}
	if poolClose >= 0 && runtimeOpen >= 0 && runtimeClose >= 0 && recorder != nil &&
		!(poolClose < runtimeOpen && runtimeOpen < runtimeClose && runtimeClose < recorder[0]) {
		t.Error("API key usage lifecycle is not ordered before the caller-owned database closes")
	}
}
