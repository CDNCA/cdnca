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

// Run only by agents/edge-agent/packaging/tests/root_helper_transition_e2e.sh:
// a node installed with an older packaging toolset whose Agent state holds the
// version pointer links is upgraded through the production helper. The first
// attempt is refused by the old toolset, the one-time toolset refresh lets the
// same helper path upgrade, roll back and upgrade again. The hook asserts the
// on-disk facts (current, links, service) between the steps.
func TestRootAgentToolsetTransitionThroughProductionHelper(t *testing.T) {
	work := os.Getenv("CDNCA_ROOT_HELPER_E2E_DIR")
	hook := os.Getenv("CDNCA_TRANSITION_HOOK")
	if work == "" || hook == "" {
		t.Skip("toolset transition environment is not provisioned")
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
	baseline, err := installer.Current(ctx)
	if err != nil || baseline.CurrentVersion != "1.0.24" {
		t.Fatalf("baseline receipt = %+v, %v", baseline, err)
	}

	// The old toolset refuses the state links; the node must keep serving.
	refused, err := tryActivate(t, ctx, installer, baseline, filepath.Join(work, "prep-1.0.25"), "txn-transition-refused", 10)
	t.Logf("old toolset result: receipt %+v, error %v", refused, err)
	if err == nil && (refused.CurrentVersion != "1.0.24" || refused.Status != updater.ReceiptStatusRolledBack) {
		t.Fatalf("old toolset with version pointer links: receipt %+v, want refused or rolled_back to 1.0.24", refused)
	}
	runHook("after-refused")
	runHook("refresh")

	baseline, err = installer.Current(ctx)
	if err != nil || baseline.CurrentVersion != "1.0.24" {
		t.Fatalf("receipt after refresh = %+v, %v", baseline, err)
	}
	upgraded := activate(t, ctx, installer, baseline, filepath.Join(work, "prep-1.0.25"), "txn-transition-upgrade", 11)
	verifyReceipt(t, upgraded, keys)
	if upgraded.CurrentVersion != "1.0.25" || upgraded.Status != updater.ReceiptStatusActive {
		t.Fatalf("upgrade receipt = %+v", upgraded)
	}
	runHook("after-upgrade")

	facts := readFacts(t, filepath.Join(work, "prep-1.0.25"))
	rolledBack, err := installer.Rollback(ctx, updater.RollbackRequest{
		InstallerTransactionID: "txn-transition-upgrade", ReleaseSequence: facts.ReleaseSequence,
		ArtifactSHA256: facts.SHA256, ExpectedCurrentVersion: "1.0.25", RollbackVersion: "1.0.24",
		ActiveReceipt: upgraded, PreviousReceipt: baseline,
	})
	if err != nil || rolledBack.CurrentVersion != "1.0.24" {
		t.Fatalf("rollback receipt = %+v, %v", rolledBack, err)
	}
	verifyReceipt(t, rolledBack, keys)
	runHook("after-rollback")

	current, err := installer.Current(ctx)
	if err != nil || current.CurrentVersion != "1.0.24" {
		t.Fatalf("receipt after rollback = %+v, %v", current, err)
	}
	again := activate(t, ctx, installer, current, filepath.Join(work, "prep-1.0.26"), "txn-transition-again", 12)
	verifyReceipt(t, again, keys)
	if again.CurrentVersion != "1.0.26" || again.Status != updater.ReceiptStatusActive {
		t.Fatalf("second upgrade receipt = %+v", again)
	}
	runHook("after-again")

	// From here the installed toolset refreshes itself after each upgrade from
	// the scripts the new release signs; a rollback keeps it.
	before := again
	auto := activate(t, ctx, installer, before, filepath.Join(work, "prep-1.0.27"), "txn-transition-auto", 13)
	verifyReceipt(t, auto, keys)
	if auto.CurrentVersion != "1.0.27" || auto.Status != updater.ReceiptStatusActive {
		t.Fatalf("auto refresh upgrade receipt = %+v", auto)
	}
	runHook("after-auto")
	autoFacts := readFacts(t, filepath.Join(work, "prep-1.0.27"))
	autoBack, err := installer.Rollback(ctx, updater.RollbackRequest{
		InstallerTransactionID: "txn-transition-auto", ReleaseSequence: autoFacts.ReleaseSequence,
		ArtifactSHA256: autoFacts.SHA256, ExpectedCurrentVersion: "1.0.27", RollbackVersion: "1.0.26",
		ActiveReceipt: auto, PreviousReceipt: before,
	})
	if err != nil || autoBack.CurrentVersion != "1.0.26" {
		t.Fatalf("auto refresh rollback receipt = %+v, %v", autoBack, err)
	}
	runHook("after-auto-rollback")
	current, err = installer.Current(ctx)
	if err != nil || current.CurrentVersion != "1.0.26" {
		t.Fatalf("receipt after auto rollback = %+v, %v", current, err)
	}
	autoAgain := activate(t, ctx, installer, current, filepath.Join(work, "prep-1.0.28"), "txn-transition-auto-again", 14)
	if autoAgain.CurrentVersion != "1.0.28" || autoAgain.Status != updater.ReceiptStatusActive {
		t.Fatalf("auto refresh second upgrade receipt = %+v", autoAgain)
	}
	runHook("after-auto-again")

	// A toolset whose carried bytes do not match the digests the SBOM signs is
	// not installed, and the upgrade still succeeds.
	tampered := activate(t, ctx, installer, autoAgain, filepath.Join(work, "prep-1.0.29"), "txn-transition-tampered", 15)
	if tampered.CurrentVersion != "1.0.29" || tampered.Status != updater.ReceiptStatusActive {
		t.Fatalf("tampered toolset upgrade receipt = %+v", tampered)
	}
	runHook("after-tampered")
}

func tryActivate(t *testing.T, ctx context.Context, installer *updater.PackagingInstaller, current updater.ActivationReceipt,
	prepared, transaction string, executionSequence uint64) (updater.ActivationReceipt, error) {
	t.Helper()
	facts := readFacts(t, prepared)
	ack, err := installer.Prepare(ctx, installRequest(facts, current, openBundle(t, prepared, facts), transaction, executionSequence))
	if err != nil {
		return updater.ActivationReceipt{}, err
	}
	if _, err := installer.MarkInstalling(ctx, ack); err != nil {
		return updater.ActivationReceipt{}, err
	}
	return installer.Activate(ctx, ack)
}
