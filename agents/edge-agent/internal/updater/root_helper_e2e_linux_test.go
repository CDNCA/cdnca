//go:build linux && roothelpere2e

package updater_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/updater"
)

// Run only by agents/edge-agent/packaging/tests/root_helper_e2e.sh inside a
// disposable systemd container: a root Agent drives the real production
// helper, socket and packaging scripts from v1 to v2, then proves a release
// that never becomes healthy is rolled back with the service still running.

type bundleFacts struct {
	Version         string `json:"version"`
	ReleaseSequence uint64 `json:"release_sequence"`
	BundleFile      string `json:"bundle_file"`
	SHA256          string `json:"sha256"`
	Size            int64  `json:"size"`
}

func TestRootAgentUpgradesThroughProductionHelper(t *testing.T) {
	work := os.Getenv("CDNCA_ROOT_HELPER_E2E_DIR")
	if work == "" {
		t.Skip("root helper end-to-end environment is not provisioned")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Fatal("the native Agent identity is root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	trust, err := gatewayclient.LoadTrustStore("/etc/cdnca-edge-agent/trust/installer-receipt.json")
	if err != nil {
		t.Fatalf("installer receipt trust written by install-node.sh: %v", err)
	}
	keys, err := trust.Ed25519Keys()
	if err != nil {
		t.Fatal(err)
	}
	installer, err := updater.NewPackagingInstaller()
	if err != nil {
		t.Fatalf("production helper client: %v", err)
	}
	current, err := installer.Current(ctx)
	if err != nil {
		t.Fatalf("root peer current: %v", err)
	}
	verifyReceipt(t, current, keys)
	if current.CurrentVersion != "1.0.24" || current.Status != updater.ReceiptStatusActive {
		t.Fatalf("baseline receipt = %+v", current)
	}

	// Production control issues v3 executions (ExecutionSequence > 0), which
	// select helper protocol v3/v4. The helper requires each to exceed the
	// current receipt's sequence (the bootstrap receipt carries release 1).
	upgraded := activate(t, ctx, installer, current, filepath.Join(work, "prep-1.0.25"), "txn-root-e2e-v2", 10)
	verifyReceipt(t, upgraded, keys)
	if upgraded.CurrentVersion != "1.0.25" || upgraded.PreviousVersion != "1.0.24" || upgraded.Status != updater.ReceiptStatusActive {
		t.Fatalf("upgrade receipt = %+v", upgraded)
	}
	assertCurrentRelease(t, "1.0.25")
	assertServiceExecutable(t, "1.0.25")
	after, err := installer.Current(ctx)
	if err != nil || after.CurrentVersion != "1.0.25" {
		t.Fatalf("current after upgrade = %+v, %v", after, err)
	}

	// A release that never stays up is rolled back by packaging; the helper
	// answers with a signed rolled_back receipt and the previous release keeps
	// serving (PROTOCOL.md: rollback result).
	facts := readFacts(t, filepath.Join(work, "prep-1.0.26"))
	artifact := openBundle(t, filepath.Join(work, "prep-1.0.26"), facts)
	request := installRequest(facts, after, artifact, "txn-root-e2e-crash", 11)
	prepared, err := installer.Prepare(ctx, request)
	if err != nil {
		t.Fatalf("prepare crashing release: %v", err)
	}
	if _, err := installer.MarkInstalling(ctx, prepared); err != nil {
		t.Fatalf("mark crashing release: %v", err)
	}
	rolledBack, err := installer.Activate(ctx, prepared)
	if err != nil {
		t.Fatalf("activate never-healthy release: %v", err)
	}
	verifyReceipt(t, rolledBack, keys)
	if rolledBack.Status != updater.ReceiptStatusRolledBack || rolledBack.CurrentVersion != "1.0.25" ||
		rolledBack.PreviousVersion != "1.0.26" {
		t.Fatalf("never-healthy release receipt = %+v, want rolled_back to 1.0.25", rolledBack)
	}
	assertCurrentRelease(t, "1.0.25")
	assertServiceExecutable(t, "1.0.25")
	restored, err := installer.Current(ctx)
	if err != nil || restored.CurrentVersion != "1.0.25" {
		t.Fatalf("current after failed upgrade = %+v, %v", restored, err)
	}
}

func activate(t *testing.T, ctx context.Context, installer *updater.PackagingInstaller, current updater.ActivationReceipt,
	prepared, transaction string, executionSequence uint64) updater.ActivationReceipt {
	t.Helper()
	facts := readFacts(t, prepared)
	artifact := openBundle(t, prepared, facts)
	ack, err := installer.Prepare(ctx, installRequest(facts, current, artifact, transaction, executionSequence))
	if err != nil {
		t.Fatalf("prepare %s: %v", facts.Version, err)
	}
	status, err := installer.MarkInstalling(ctx, ack)
	if err != nil || status.Phase != updater.InstallerTransactionInstalling {
		t.Fatalf("mark installing %s: %+v, %v", facts.Version, status, err)
	}
	receipt, err := installer.Activate(ctx, ack)
	if err != nil {
		t.Fatalf("activate %s: %v", facts.Version, err)
	}
	return receipt
}

func installRequest(facts bundleFacts, current updater.ActivationReceipt, artifact *os.File, transaction string,
	executionSequence uint64) updater.InstallRequest {
	return updater.InstallRequest{
		InstallerTransactionID: transaction, ExecutionSequence: executionSequence, Action: updater.ActionUpgrade,
		ReleaseSequence: facts.ReleaseSequence,
		CurrentVersion:  current.CurrentVersion, TargetVersion: facts.Version,
		Platform: "linux", Architecture: archFromBundle(facts.BundleFile),
		ArtifactSHA256: facts.SHA256, ArtifactSize: facts.Size,
		StagedPath: artifact.Name(), Artifact: artifact, CurrentReceipt: current,
	}
}

func archFromBundle(name string) string {
	return strings.TrimSuffix(name[strings.LastIndex(name, "-")+1:], ".bundle")
}

func readFacts(t *testing.T, prepared string) bundleFacts {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(prepared, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var facts bundleFacts
	if err := json.Unmarshal(data, &facts); err != nil {
		t.Fatal(err)
	}
	return facts
}

func openBundle(t *testing.T, prepared string, facts bundleFacts) *os.File {
	t.Helper()
	file, err := os.Open(filepath.Join(prepared, facts.BundleFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func verifyReceipt(t *testing.T, receipt updater.ActivationReceipt, keys map[string]ed25519.PublicKey) {
	t.Helper()
	key, ok := keys[receipt.Signature.KeyID]
	if !ok {
		t.Fatalf("receipt key %q is not in the converted trust", receipt.Signature.KeyID)
	}
	payload, err := updater.ReceiptSigningBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawStdEncoding.DecodeString(receipt.Signature.Value)
	if err != nil || !ed25519.Verify(key, payload, signature) {
		t.Fatalf("receipt signature does not verify: %v", err)
	}
}

func assertCurrentRelease(t *testing.T, version string) {
	t.Helper()
	target, err := os.Readlink("/usr/lib/cdnca-edge-agent/current")
	if err != nil || target != "versions/"+version {
		t.Fatalf("current = %q, %v; want versions/%s", target, err, version)
	}
}

func assertServiceExecutable(t *testing.T, version string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		output, err := exec.Command("systemctl", "show", "cdnca-edge-agent.service", "--property=MainPID", "--value").Output()
		pid := strings.TrimSpace(string(output))
		if err == nil && pid != "" && pid != "0" {
			executable, linkErr := os.Readlink("/proc/" + pid + "/exe")
			status, statusErr := os.ReadFile("/proc/" + pid + "/status")
			if linkErr == nil && statusErr == nil && executable == "/usr/lib/cdnca-edge-agent/versions/"+version+"/edge-agent" &&
				strings.Contains(string(status), "\nUid:\t0\t0\t0\t0\n") {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("service is not running %s as root (pid %q): %v", version, pid, errors.Join(err))
		}
		time.Sleep(time.Second)
	}
}
