package acmeruntime

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// CERT-RENEW-QUEUED-INTENT-01: a queued renewal the user turned off before it
// started is skipped for good (terminal), and is not reported as a failure.
func TestRenewalSkippedIsTerminalAndNotNotified(t *testing.T) {
	if !terminalFailure(codeRenewalSkipped) || !validateErrorCode(codeRenewalSkipped) {
		t.Fatalf("%s must be a valid terminal code", codeRenewalSkipped)
	}
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(strings.TrimSuffix(file, "renewal_skipped_test.go") + "dispatcher.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	build := source[strings.Index(source, "func (d *Dispatcher) buildRequest("):]
	fence := strings.Index(build, "certificate_asset_auto_renew_537(parent.scope_id,parent.issued_asset_id)")
	keys := strings.Index(build, "d.keys.ensureKey(")
	if fence < 0 || keys < 0 || fence > keys {
		t.Fatal("the latest asset auto-renew check must run before any key or CA side effect")
	}
	if !strings.Contains(source, "if code == codeRenewalSkipped {\n\t\t\treturn nil") {
		t.Fatal("a skipped renewal must not enqueue the renewal failure notice")
	}
}
