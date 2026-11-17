package helper

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

// rereleaseRunner behaves like install.sh --upgrade for a same-version
// re-release: the installed build moves to .previous-<version> and the new
// one takes versions/<version>; RestorePreviousBuild is rollback.sh
// --restore-previous-build.
type rereleaseRunner struct {
	*serviceRunner
	restoreCalls int
}

func (runner *rereleaseRunner) Upgrade(ctx context.Context, staged StagedBundle) error {
	manifest, err := os.ReadFile(staged.ManifestPath)
	if err != nil {
		return err
	}
	parsed, err := parseReleaseManifest(manifest)
	if err != nil {
		return err
	}
	directory := filepath.Join(runner.paths.ReleaseRoot, "versions", parsed.Version)
	installed, err := os.ReadFile(filepath.Join(directory, "manifest"))
	if err != nil || bytes.Equal(installed, manifest) {
		return runner.serviceRunner.Upgrade(ctx, staged)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.upgradeCalls++
	previous := filepath.Join(runner.paths.ReleaseRoot, "versions", ".previous-"+parsed.Version)
	_ = os.RemoveAll(previous)
	if err := os.Rename(directory, previous); err != nil {
		return err
	}
	return runner.installStaged(staged, parsed.Version)
}

func (runner *rereleaseRunner) RestorePreviousBuild(_ context.Context, version string) error {
	runner.restoreCalls++
	directory := filepath.Join(runner.paths.ReleaseRoot, "versions", version)
	previous := filepath.Join(runner.paths.ReleaseRoot, "versions", ".previous-"+version)
	if _, err := os.Stat(previous); err != nil {
		return ErrPackagingCommand
	}
	if err := os.RemoveAll(directory); err != nil {
		return err
	}
	return os.Rename(previous, directory)
}

func newRereleaseFixture(t *testing.T) (*serviceFixture, *rereleaseRunner) {
	t.Helper()
	fixture := newServiceFixture(t)
	runner := &rereleaseRunner{serviceRunner: fixture.runner}
	service, err := NewService(ServiceConfig{
		Paths: fixture.paths, OwnerUID: fixture.uid, OwnerGID: fixture.gid,
		ReceiptKey:        KeyMaterial{KeyID: fixture.receiptKeyID, PrivateKey: fixture.receiptPrivate},
		ReceiptPublicKeys: fixture.receiptPublicKeys,
		ReleasePublicKey:  fixture.packagePublic, Runner: runner,
		Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = service
	return fixture, runner
}

func (fixture *serviceFixture) prepareV3(transactionID string, executionSequence uint64, action protocol.Action,
	release serviceRelease, previous protocol.Receipt) protocol.Response {
	fixture.t.Helper()
	request := fixture.prepareRequest(transactionID, release, previous)
	request.ProtocolVersion = protocol.JournalV3Version
	request.ExecutionSequence = executionSequence
	request.Action = action
	return fixture.handle(request, fixture.artifact(release))
}

func installedSequence(t *testing.T, fixture *serviceFixture, version string) uint64 {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(fixture.paths.ReleaseRoot, "versions", version, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseReleaseManifest(content)
	if err != nil {
		t.Fatal(err)
	}
	return manifest.ReleaseSequence
}

func TestServiceSameVersionRereleaseHigherSequenceActivates(t *testing.T) {
	fixture, _ := newRereleaseFixture(t)
	baseline := fixture.current()
	rerelease := fixture.release(5, "1.0.0")
	active := fixture.activateV3("txn-samever-up", 20, protocol.ActionUpgrade, rerelease, baseline)
	if active.CurrentVersion != "1.0.0" || active.PreviousVersion != "1.0.0" || active.ReleaseSequence != 5 {
		t.Fatalf("same-version active receipt = %#v", active)
	}
	if got := installedSequence(t, fixture, "1.0.0"); got != 5 {
		t.Fatalf("installed release sequence = %d, want 5", got)
	}
	if current := fixture.current(); !sameReceipt(current, active) {
		t.Fatalf("current after re-release = %#v, want %#v", current, active)
	}
}

func TestServiceSameVersionRereleaseRejectsEqualOrLowerSequence(t *testing.T) {
	fixture, runner := newRereleaseFixture(t)
	baseline := fixture.current()
	active := fixture.activateV3("txn-samever-first", 20, protocol.ActionUpgrade, fixture.release(5, "1.0.0"), baseline)
	calls := runner.upgradeCalls
	for _, test := range []struct {
		name     string
		sequence uint64
	}{{"equal", 5}, {"lower", 4}} {
		response := fixture.prepareV3("txn-samever-"+test.name, 30, protocol.ActionUpgrade, fixture.release(test.sequence, "1.0.0"), active)
		if response.OK || response.ErrorCode != protocol.ErrorTransactionConflict {
			t.Fatalf("%s sequence prepare = %#v, want transaction conflict", test.name, response)
		}
	}
	if runner.upgradeCalls != calls || installedSequence(t, fixture, "1.0.0") != 5 {
		t.Fatalf("refused re-release touched the installation: calls %d->%d", calls, runner.upgradeCalls)
	}
}

func TestServiceSameVersionRequiresV3Upgrade(t *testing.T) {
	fixture, runner := newRereleaseFixture(t)
	baseline := fixture.current()
	rerelease := fixture.release(5, "1.0.0")
	v2 := fixture.handle(fixture.prepareRequest("txn-samever-v2", rerelease, baseline), fixture.artifact(rerelease))
	if v2.OK || v2.ErrorCode != protocol.ErrorTransactionConflict {
		t.Fatalf("v2 same-version prepare = %#v", v2)
	}
	rollback := fixture.prepareV3("txn-samever-rollback-action", 20, protocol.ActionRollback, rerelease, baseline)
	if rollback.OK || rollback.ErrorCode != protocol.ErrorTransactionConflict {
		t.Fatalf("same-version rollback action prepare = %#v", rollback)
	}
	if runner.upgradeCalls != 0 || installedSequence(t, fixture, "1.0.0") != 1 {
		t.Fatal("refused same-version request touched the installation")
	}
}

func TestServiceSameVersionRollbackRestoresKeptBuild(t *testing.T) {
	fixture, runner := newRereleaseFixture(t)
	baseline := fixture.current()
	rerelease := fixture.release(5, "1.0.0")
	active := fixture.activateV3("txn-samever-back", 20, protocol.ActionUpgrade, rerelease, baseline)
	response := fixture.handle(fixture.rollbackRequest("txn-samever-back", rerelease, active, baseline), nil)
	if !response.OK || response.Receipt == nil || response.Receipt.Status != "rolled_back" ||
		response.Receipt.CurrentVersion != "1.0.0" || runner.restoreCalls != 1 || runner.rollbackCalls != 0 {
		t.Fatalf("same-version rollback = %#v restore=%d rollback=%d", response, runner.restoreCalls, runner.rollbackCalls)
	}
	if got := installedSequence(t, fixture, "1.0.0"); got != 1 {
		t.Fatalf("restored release sequence = %d, want 1", got)
	}
}

func TestServiceSameVersionRollbackWithoutRestorerFails(t *testing.T) {
	fixture := newServiceFixture(t)
	baseline := fixture.current()
	rerelease := fixture.release(5, "1.0.0")
	runner := &rereleaseRunner{serviceRunner: fixture.runner}
	// Activate with a runner that can swap, then roll back with one that cannot restore.
	fixture.service.config.Runner = runner
	active := fixture.activateV3("txn-samever-norestore", 20, protocol.ActionUpgrade, rerelease, baseline)
	fixture.service.config.Runner = fixture.runner
	response := fixture.handle(fixture.rollbackRequest("txn-samever-norestore", rerelease, active, baseline), nil)
	if response.OK || response.ErrorCode != protocol.ErrorRollbackFailed {
		t.Fatalf("rollback without restorer = %#v", response)
	}
}

func TestJournalSameVersionOnlyForV3UpgradeAboveInstalled(t *testing.T) {
	base := JournalRecord{SchemaVersion: journalSchemaVersionV3, Action: protocol.ActionUpgrade,
		PreviousVersion: "1.0.35", TargetVersion: "1.0.35", ReleaseSequence: 9, PreviousPhysicalReleaseSequence: 7}
	if !sameVersionRerelease(base) {
		t.Fatal("v3 upgrade above installed sequence must be a re-release")
	}
	for name, mutate := range map[string]func(*JournalRecord){
		"v2":        func(record *JournalRecord) { record.SchemaVersion = journalSchemaVersion },
		"rollback":  func(record *JournalRecord) { record.Action = protocol.ActionRollback },
		"equal":     func(record *JournalRecord) { record.ReleaseSequence = 7 },
		"lower":     func(record *JournalRecord) { record.ReleaseSequence = 6 },
		"unknown":   func(record *JournalRecord) { record.PreviousPhysicalReleaseSequence = 0 },
		"different": func(record *JournalRecord) { record.TargetVersion = "1.0.36" },
	} {
		record := base
		mutate(&record)
		if sameVersionRerelease(record) {
			t.Fatalf("%s: accepted as a same-version re-release", name)
		}
	}
	if !errors.Is(validateJournalRecord(JournalRecord{PreviousVersion: "1.0.35", TargetVersion: "1.0.35"}), ErrJournalCorrupt) {
		t.Fatal("same-version legacy record must be corrupt")
	}
}

// A node installed by the legacy protocol at release 124, so its current receipt
// is schema 1 and its sequence is the release sequence. The helper keeps one ratchet
// across protocols: the first v3 execution_sequence must exceed that legacy sequence.
// The license service numbered the node's first v3 attempts from 1 (exec 3), and the helper
// refused the same-version re-release 124 -> 136 without staging anything.
func TestServiceFirstV3PrepareMustExceedLegacyReceiptSequence(t *testing.T) {
	fixture, runner := newRereleaseFixture(t)
	fixture.installRelease(fixture.release(124, "1.0.35"), true)
	baseline := fixture.current()
	if baseline.SchemaVersion != 1 || baseline.ReleaseSequence != 124 {
		t.Fatalf("legacy baseline = %#v", baseline)
	}
	rerelease := fixture.release(136, "1.0.35")
	refused := fixture.prepareV3("txn-node-exec-3", 3, protocol.ActionUpgrade, rerelease, baseline)
	if refused.OK || refused.ErrorCode != protocol.ErrorTransactionConflict {
		t.Fatalf("exec 3 over legacy 124 = %#v, want transaction conflict", refused)
	}
	entries, err := os.ReadDir(filepath.Join(fixture.paths.StateDirectory, "transactions"))
	if err != nil || len(entries) != 0 || runner.upgradeCalls != 0 {
		t.Fatalf("refused prepare left state: entries=%v err=%v upgrades=%d", entries, err, runner.upgradeCalls)
	}
	if inspect := fixture.handle(func() protocol.Request {
		request := fixture.inspectRequest("txn-node-exec-3")
		request.ProtocolVersion = protocol.JournalV3Version
		return request
	}(), nil); !inspect.OK || inspect.TransactionStatus == nil || inspect.TransactionStatus.Phase != "unknown" {
		t.Fatalf("inspect after refusal = %#v, want phase unknown", inspect)
	}
	active := fixture.activateV3("txn-node-exec-125", 125, protocol.ActionUpgrade, rerelease, baseline)
	if active.ReleaseSequence != 136 || active.CurrentVersion != "1.0.35" {
		t.Fatalf("exec 125 re-release = %#v", active)
	}
}
