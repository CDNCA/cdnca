package main

import (
	"os"
	"strings"
	"testing"
)

func TestProductionRuntimeMountsCNAMEAllocationWorker(t *testing.T) {
	runtimeSource, err := os.ReadFile("dns_reconcile_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	mainSource, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"cnameallocation.NewStore", "cnameallocation.NewWorker", "cnameWorker"} {
		if !strings.Contains(string(runtimeSource), required) {
			t.Errorf("dns_reconcile_runtime.go missing %q", required)
		}
	}
	if !strings.Contains(string(mainSource), "cnameWorker.Run") {
		t.Fatal("main.go does not run CNAME allocation worker")
	}
}
