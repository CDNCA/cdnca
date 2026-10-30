package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// fix-originnoverify: ORIGIN_TLS_NO_VERIFY v1 is declared only for a binary
// exporting native patch 29's function.
func TestOpenRestySkipsOriginHostCheckOnlyWithPatch29(t *testing.T) {
	if openRestySkipsOriginHostCheck("") || openRestySkipsOriginHostCheck(filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("missing binary reported ORIGIN_TLS_NO_VERIFY")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	build := func(body string) string {
		directory := t.TempDir()
		source := filepath.Join(directory, "probe.c")
		if err := os.WriteFile(source, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(directory, "probe.so")
		if result, err := exec.Command(cc, "-shared", "-fPIC", "-o", output, source).CombinedOutput(); err != nil {
			t.Skipf("cc -shared: %v %s", err, result)
		}
		return output
	}
	with := build("int ngx_http_cdnca_upstream_set_ssl_host_check(void *r, int enable) { return r ? enable : -1; }\n")
	if !isELF(with) {
		t.Skip("host toolchain does not produce ELF (e.g. macOS); covered on Linux")
	}
	if !openRestySkipsOriginHostCheck(with) {
		t.Fatal("binary exporting the patch 29 symbol not detected")
	}
	// patch 27 alone is not patch 29
	if openRestySkipsOriginHostCheck(build("int ngx_http_cdnca_ssl_set_http2(void *s, int e) { return e; }\n")) {
		t.Fatal("binary without the patch 29 symbol reported ORIGIN_TLS_NO_VERIFY")
	}
}

func TestAddOriginTLSNoVerifyCapability(t *testing.T) {
	capabilities := &agentv1.AgentCapabilities{}
	addOriginTLSNoVerifyCapability(capabilities, false)
	if len(capabilities.Features) != 0 {
		t.Fatal("declared without patch 29")
	}
	addOriginTLSNoVerifyCapability(capabilities, true)
	if len(capabilities.Features) != 1 || capabilities.Features[0].Name != agentv1.CapabilityName_CAPABILITY_NAME_ORIGIN_TLS_NO_VERIFY ||
		capabilities.Features[0].ApiVersion != 1 {
		t.Fatalf("features %+v", capabilities.Features)
	}
}
