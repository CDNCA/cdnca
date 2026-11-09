//go:build linux && roothelpere2e

package updater_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/updater"
)

// Run only by agents/edge-agent/packaging/tests/root_helper_refresh_e2e.sh:
// a root node installed exactly as the previous release (86c4d871) installs
// it, with its packaging scripts and its own helper binary, upgrades through
// the production helper with full v1 bundles (no native section, as the
// release build makes them) whose signed SBOM carries the scripts and the
// helper. The hook asserts helper file, running helper, record, report,
// service, state and links between the steps.
func TestRootHelperRefreshesThroughProductionHelper(t *testing.T) {
	work := os.Getenv("CDNCA_ROOT_HELPER_E2E_DIR")
	hook := os.Getenv("CDNCA_REFRESH_HOOK")
	if work == "" || hook == "" {
		t.Skip("helper refresh environment is not provisioned")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	trust, err := gatewayclient.LoadTrustStore("/etc/cdnca-edge-agent/trust/installer-receipt.json")
	if err != nil {
		t.Fatalf("installer receipt trust: %v", err)
	}
	keys, err := trust.Ed25519Keys()
	if err != nil {
		t.Fatal(err)
	}
	installer, err := updater.NewPackagingInstaller()
	if err != nil {
		t.Fatalf("production helper client: %v", err)
	}
	runHook := func(phase string) {
		t.Helper()
		output, err := exec.CommandContext(ctx, hook, phase).CombinedOutput()
		t.Logf("hook %s:\n%s", phase, output)
		if err != nil {
			t.Fatalf("hook %s: %v", phase, err)
		}
	}
	current := func(version string) updater.ActivationReceipt {
		t.Helper()
		receipt, err := installer.Current(ctx)
		if err != nil || receipt.CurrentVersion != version {
			t.Fatalf("current = %+v, %v; want %s", receipt, err, version)
		}
		verifyReceipt(t, receipt, keys)
		return receipt
	}
	runHook("baseline")
	baseline := current("1.0.24")

	// The previous release's own scripts run this upgrade: they refresh the scripts, not the helper.
	first := activate(t, ctx, installer, baseline, filepath.Join(work, "prep-1.0.25"), "txn-refresh-first", 10)
	verifyReceipt(t, first, keys)
	runHook("after-first")

	// The refreshed scripts replace the helper file through a transient unit;
	// the previous helper keeps running (it never exits on its own).
	second := activate(t, ctx, installer, current("1.0.25"), filepath.Join(work, "prep-1.0.26"), "txn-refresh-second", 11)
	verifyReceipt(t, second, keys)
	runHook("after-second")

	// Next start (a reboot): the new helper takes over the previous helper's journal and receipt key.
	runHook("restart-helper")
	taken := current("1.0.26")
	if taken.InstallerTransactionID != second.InstallerTransactionID || taken.Signature != second.Signature {
		t.Fatalf("new helper's current = %+v, want the receipt the previous helper signed %+v", taken, second)
	}
	runHook("after-takeover")
	facts := readFacts(t, filepath.Join(work, "prep-1.0.26"))
	back, err := installer.Rollback(ctx, updater.RollbackRequest{
		InstallerTransactionID: "txn-refresh-second", ReleaseSequence: facts.ReleaseSequence,
		ArtifactSHA256: facts.SHA256, ExpectedCurrentVersion: "1.0.26", RollbackVersion: "1.0.25",
		ActiveReceipt: second, PreviousReceipt: first,
	})
	if err != nil || back.CurrentVersion != "1.0.25" {
		t.Fatalf("rollback of the previous helper's transaction by the new helper = %+v, %v", back, err)
	}
	verifyReceipt(t, back, keys)
	runHook("after-rollback")

	// Upgrade again: the new helper replaces itself and exits after the exchange.
	again := activate(t, ctx, installer, current("1.0.25"), filepath.Join(work, "prep-1.0.27"), "txn-refresh-again", 12)
	verifyReceipt(t, again, keys)
	runHook("after-again")
	current("1.0.27")
	runHook("after-self-exit")

	// Operator one-time refresh (install.sh --refresh-toolset) on a node still
	// running its first-install helper: replaced and restarted, then serves.
	runHook("operator-refresh")
	current("1.0.27")
}
