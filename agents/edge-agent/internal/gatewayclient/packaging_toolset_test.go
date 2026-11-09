package gatewayclient

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// With the packaging toolset probe the hello declares
// PACKAGING_TOOLSET_REPORT v1 and every runtime status carries the report.
func TestPackagingToolsetReportDeclaredAndCarried(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	report := &agentv1.PackagingToolsetStatus{RefreshStatus: "none"}
	for _, probe := range []func() *agentv1.PackagingToolsetStatus{nil, func() *agentv1.PackagingToolsetStatus { return report }} {
		root := secureTempDir(t)
		if err := os.Mkdir(filepath.Join(root, "state"), 0o700); err != nil {
			t.Fatal(err)
		}
		client, err := New(testClientConfig(filepath.Join(root, "journal")), &failingDialer{}, noOpManager{}, trust,
			WithRuntimeStatusProbe(RuntimeStatusProbe{PackagingToolset: probe,
				OpenResty: func(context.Context, string) error { return nil }}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		hello, err := client.agentHello()
		if err != nil {
			t.Fatal(err)
		}
		declared := 0
		for _, capability := range hello.Capabilities.Features {
			if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_PACKAGING_TOOLSET_REPORT && capability.ApiVersion == 1 {
				declared++
			}
		}
		carried := client.runtimeStatus(context.Background(), nil).PackagingToolset
		if probe == nil && (declared != 0 || carried != nil) {
			t.Fatalf("without the probe: declared %d, carried %v", declared, carried)
		}
		if probe != nil && (declared != 1 || carried != report) {
			t.Fatalf("with the probe: declared %d, carried %v", declared, carried)
		}
	}
}
