package helper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

// installOutOfBand replaces the installed release the way node-rerelease-upgrade.sh
// (upgrade.sh --native) does: the helper is not involved, its current.json and
// journals are left as they were.
func (fixture *serviceFixture) installOutOfBand(release serviceRelease) {
	fixture.t.Helper()
	if err := os.RemoveAll(filepath.Join(fixture.paths.ReleaseRoot, "versions", release.version)); err != nil {
		fixture.t.Fatal(err)
	}
	fixture.installRelease(release, true)
}

// A v3 prepare was left prepared when the agent state was set aside, then the node was
// upgraded out of band to a newer release. Current
// answered STATE_UNCERTAIN forever, so every console upgrade failed before it started.
func TestServiceCurrentAbandonsPreparedTransactionAfterOutOfBandUpgrade(t *testing.T) {
	fixture, _ := newRereleaseFixture(t)
	baseline := fixture.current()
	stale := fixture.prepareV3("txn-stale-prepared", 2, protocol.ActionUpgrade, fixture.release(3, "1.0.0"), baseline)
	if !stale.OK || stale.PreparedAck == nil {
		t.Fatalf("stale prepare = %#v", stale)
	}
	fixture.installOutOfBand(fixture.release(4, "1.0.0"))

	current := fixture.current()
	if current.SchemaVersion != 1 || current.ReleaseSequence != 4 || current.CurrentVersion != "1.0.0" || current.Status != "active" {
		t.Fatalf("current after out-of-band upgrade = %#v", current)
	}
	if again := fixture.current(); !sameReceipt(again, current) {
		t.Fatalf("current is not stable: %#v then %#v", current, again)
	}
	record, err := fixture.service.journals.Load("txn-stale-prepared")
	if err != nil || record.Phase != JournalAborted {
		t.Fatalf("stale prepared journal = (%+v, %v), want aborted", record, err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.paths.StateDirectory, "transactions", "txn-stale-prepared")); !os.IsNotExist(err) {
		t.Fatalf("stale transaction directory still present: %v", err)
	}
	// The aborted execution stays a floor: it cannot be replayed.
	if replay := fixture.prepareV3("txn-replay", 2, protocol.ActionUpgrade, fixture.release(5, "1.0.0"), current); replay.OK ||
		replay.ErrorCode != protocol.ErrorTransactionConflict {
		t.Fatalf("replayed execution prepare = %#v", replay)
	}
	active := fixture.activateV3("txn-after-out-of-band", 5, protocol.ActionUpgrade, fixture.release(6, "1.0.0"), current)
	if active.ExecutionSequence != 5 || active.ReleaseSequence != 6 || installedSequence(t, fixture, "1.0.0") != 6 {
		t.Fatalf("console upgrade after out-of-band upgrade = %#v", active)
	}
}

// A prepared transaction whose previous release is still installed may belong to an
// agent between Prepare and MarkInstalling; Current keeps refusing to guess.
func TestServiceCurrentKeepsPreparedTransactionWhilePreviousIsInstalled(t *testing.T) {
	fixture, _ := newRereleaseFixture(t)
	baseline := fixture.current()
	prepared := fixture.prepareV3("txn-live-prepared", 2, protocol.ActionUpgrade, fixture.release(3, "1.0.0"), baseline)
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	response := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent}, nil)
	if response.OK || response.ErrorCode != protocol.ErrorStateUncertain {
		t.Fatalf("current with a live prepared transaction = %#v", response)
	}
	record, err := fixture.service.journals.Load("txn-live-prepared")
	if err != nil || record.Phase != JournalPrepared {
		t.Fatalf("live prepared journal = (%+v, %v)", record, err)
	}
}
