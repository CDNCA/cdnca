package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// buildSharedObject builds a shared object that exports (or not) the patch
// 27 symbol with the host C compiler: the probe reads the dynamic symbol
// table of a real ELF file (on a non-ELF host the test skips).
func buildSharedObject(t *testing.T, exported bool) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "probe.c")
	body := "int other(void) { return 0; }\n"
	if exported {
		body += "int ngx_http_cdnca_ssl_set_http2(void *ssl, int enable) { return ssl ? enable : -1; }\n"
	}
	if err := os.WriteFile(source, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, "probe.so")
	command := exec.Command(cc, "-shared", "-fPIC", "-o", output, source)
	if result, err := command.CombinedOutput(); err != nil {
		t.Skipf("cc -shared: %v %s", err, result)
	}
	return output
}

func TestOpenRestySetsSiteTLSOptionsOnlyWithPatch27(t *testing.T) {
	if openRestySetsSiteTLSOptions("") || openRestySetsSiteTLSOptions(filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("missing binary reported SITE_TLS_OPTIONS")
	}
	script := filepath.Join(t.TempDir(), "openresty")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if openRestySetsSiteTLSOptions(script) {
		t.Fatal("non-ELF binary reported SITE_TLS_OPTIONS")
	}
	with := buildSharedObject(t, true)
	if !isELF(with) {
		t.Skip("host toolchain does not produce ELF (e.g. macOS); covered on Linux")
	}
	if !openRestySetsSiteTLSOptions(with) {
		t.Fatal("binary exporting the patch 27 symbol not detected")
	}
	if openRestySetsSiteTLSOptions(buildSharedObject(t, false)) {
		t.Fatal("binary without the patch 27 symbol reported SITE_TLS_OPTIONS")
	}
}

func isELF(path string) bool {
	content, err := os.ReadFile(path)
	return err == nil && len(content) > 4 && string(content[:4]) == "\x7fELF"
}

func TestAddSiteTLSOptionsCapability(t *testing.T) {
	capabilities := &agentv1.AgentCapabilities{}
	addSiteTLSOptionsCapability(capabilities, false)
	if len(capabilities.Features) != 0 {
		t.Fatal("declared without patch 27")
	}
	addSiteTLSOptionsCapability(capabilities, true)
	if len(capabilities.Features) != 1 || capabilities.Features[0].Name != agentv1.CapabilityName_CAPABILITY_NAME_SITE_TLS_OPTIONS ||
		capabilities.Features[0].ApiVersion != 1 {
		t.Fatalf("features %+v", capabilities.Features)
	}
}
