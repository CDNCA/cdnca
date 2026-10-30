package helper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

type serviceRelease struct {
	sequence   uint64
	version    string
	manifest   []byte
	signature  []byte
	sbom       []byte
	executable []byte
	bundle     []byte
}

type serviceRunner struct {
	mu              sync.Mutex
	paths           RuntimePaths
	upgradeCalls    int
	rollbackCalls   int
	autoRollback    bool
	upgradeErr      error
	rollbackErr     error
	upgradeEntered  chan struct{}
	releaseUpgrade  chan struct{}
	rollbackEntered chan struct{}
	releaseRollback chan struct{}
}

func (runner *serviceRunner) Upgrade(_ context.Context, staged StagedBundle) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.upgradeCalls++
	if runner.upgradeEntered != nil {
		select {
		case <-runner.upgradeEntered:
		default:
			close(runner.upgradeEntered)
		}
		<-runner.releaseUpgrade
	}
	if runner.upgradeErr != nil && !runner.autoRollback {
		return runner.upgradeErr
	}
	manifest, err := os.ReadFile(staged.ManifestPath)
	if err != nil {
		return err
	}
	parsed, err := parseReleaseManifest(manifest)
	if err != nil {
		return err
	}
	current, err := os.Readlink(filepath.Join(runner.paths.ReleaseRoot, "current"))
	if err == nil && current == filepath.Join("versions", parsed.Version) {
		return runner.upgradeErr
	}
	accepted, acceptedErr := os.ReadFile(runner.paths.AcceptedManifest)
	previousVersion := "1.0.0"
	if err == nil {
		previousVersion = strings.TrimPrefix(current, "versions/")
	}
	if err := runner.installStaged(staged, parsed.Version); err != nil {
		return err
	}
	if runner.autoRollback {
		if err := runner.switchCurrent(previousVersion); err != nil {
			return err
		}
		// Like packaging install.sh: the accepted manifest is published only
		// after the health gate, so a failed upgrade restores the old one.
		if acceptedErr == nil {
			if err := os.WriteFile(runner.paths.AcceptedManifest, accepted, 0o600); err != nil {
				return err
			}
		}
		if runner.upgradeErr != nil {
			return runner.upgradeErr
		}
		return ErrPackagingCommand
	}
	return runner.upgradeErr
}

func (runner *serviceRunner) Rollback(_ context.Context, version string) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.rollbackCalls++
	if runner.rollbackEntered != nil {
		select {
		case <-runner.rollbackEntered:
		default:
			close(runner.rollbackEntered)
		}
		<-runner.releaseRollback
	}
	if runner.rollbackErr != nil {
		return runner.rollbackErr
	}
	return runner.switchCurrent(version)
}

func (runner *serviceRunner) installStaged(staged StagedBundle, version string) error {
	directory := filepath.Join(runner.paths.ReleaseRoot, "versions", version)
	created := true
	if err := os.Mkdir(directory, 0o755); errors.Is(err, os.ErrExist) {
		created = false
	} else if err != nil {
		return err
	}
	files := []struct {
		source string
		name   string
		mode   os.FileMode
	}{
		{staged.ManifestPath, "manifest", 0o444},
		{staged.SignaturePath, "manifest.sig", 0o444},
		{staged.SBOMPath, "edge-agent.spdx.json", 0o444},
		{staged.ExecutablePath, "edge-agent", 0o555},
	}
	for _, file := range files {
		content, err := os.ReadFile(file.source)
		if err != nil {
			return err
		}
		path := filepath.Join(directory, file.name)
		if !created {
			existing, err := os.ReadFile(path)
			info, statErr := os.Lstat(path)
			if err != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != file.mode ||
				!bytes.Equal(existing, content) {
				return ErrPackagingCommand
			}
			continue
		}
		if err := os.WriteFile(path, content, file.mode); err != nil {
			return err
		}
		if err := os.Chmod(path, file.mode); err != nil {
			return err
		}
	}
	accepted, err := os.ReadFile(staged.ManifestPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(runner.paths.AcceptedManifest, accepted, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(runner.paths.AcceptedManifest, 0o600); err != nil {
		return err
	}
	return runner.switchCurrent(version)
}

func (runner *serviceRunner) switchCurrent(version string) error {
	current := filepath.Join(runner.paths.ReleaseRoot, "current")
	temporary := filepath.Join(runner.paths.ReleaseRoot, ".current-test")
	_ = os.Remove(temporary)
	if err := os.Symlink(filepath.Join("versions", version), temporary); err != nil {
		return err
	}
	return os.Rename(temporary, current)
}

type serviceFixture struct {
	t                 *testing.T
	paths             RuntimePaths
	packagePrivate    ed25519.PrivateKey
	packagePublic     ed25519.PublicKey
	receiptPrivate    ed25519.PrivateKey
	receiptPublic     ed25519.PublicKey
	receiptKeyID      string
	receiptPublicKeys map[string]ed25519.PublicKey
	runner            *serviceRunner
	service           *Service
	now               time.Time
	uid               uint32
	gid               uint32
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	root := t.TempDir()
	paths := RuntimePaths{
		StateDirectory:   filepath.Join(root, "helper-state"),
		ReleaseRoot:      filepath.Join(root, "usr", "lib", "cdnca-edge-agent"),
		AcceptedManifest: filepath.Join(root, "var", "lib", "cdnca-edge-agent-packaging", "accepted-manifest"),
	}
	for _, directory := range []string{
		paths.ReleaseRoot,
		filepath.Join(paths.ReleaseRoot, "versions"),
		filepath.Dir(paths.AcceptedManifest),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	packagePublic, packagePrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	receiptPublic, receiptPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &serviceFixture{
		t: t, paths: paths, packagePrivate: packagePrivate, packagePublic: packagePublic,
		receiptPrivate: receiptPrivate, receiptPublic: receiptPublic, receiptKeyID: "helper-test-old",
		receiptPublicKeys: map[string]ed25519.PublicKey{"helper-test-old": append(ed25519.PublicKey(nil), receiptPublic...)},
		now:               time.Date(2026, 7, 28, 4, 0, 0, 0, time.UTC),
		uid:               uint32(os.Geteuid()), gid: uint32(os.Getegid()),
	}
	fixture.runner = &serviceRunner{paths: paths}
	fixture.installRelease(fixture.release(1, "1.0.0"), true)
	fixture.service = fixture.newService()
	return fixture
}

func (fixture *serviceFixture) newService() *Service {
	fixture.t.Helper()
	service, err := NewService(ServiceConfig{
		Paths: fixture.paths, OwnerUID: fixture.uid, OwnerGID: fixture.gid,
		ReceiptKey:        KeyMaterial{KeyID: fixture.receiptKeyID, PrivateKey: fixture.receiptPrivate},
		ReceiptPublicKeys: fixture.receiptPublicKeys,
		ReleasePublicKey:  fixture.packagePublic, Runner: fixture.runner,
		Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		fixture.t.Fatal(err)
	}
	return service
}

func (fixture *serviceFixture) release(sequence uint64, version string) serviceRelease {
	fixture.t.Helper()
	executable := []byte("\x7fELF-cdnca-edge-agent-" + version)
	sbom := []byte(`{"spdxVersion":"SPDX-2.3","name":"edge-agent-` + version + `"}`)
	executableDigest := sha256.Sum256(executable)
	sbomDigest := sha256.Sum256(sbom)
	architecture := runtime.GOARCH
	if architecture != "amd64" && architecture != "arm64" {
		architecture = "amd64"
	}
	manifest := []byte(strings.Join([]string{
		"manifest_version=2",
		fmt.Sprintf("release_sequence=%d", sequence),
		"version=" + version,
		"artifact_path=edge-agent",
		"artifact_sha256=" + hex.EncodeToString(executableDigest[:]),
		fmt.Sprintf("artifact_size=%d", len(executable)),
		"sbom_path=edge-agent.spdx.json",
		"sbom_sha256=" + hex.EncodeToString(sbomDigest[:]),
		fmt.Sprintf("sbom_size=%d", len(sbom)),
		"os=linux",
		"arch=" + architecture,
		"source_repository=https://example.invalid/cdnca",
		"source_commit=" + strings.Repeat("a", 40),
		"build_time=2026-07-28T00:00:00Z",
		"minimum_control_protocol=1.0",
		"minimum_agent_protocol=1.0",
	}, "\n") + "\n")
	signature := ed25519.Sign(fixture.packagePrivate, manifest)
	return serviceRelease{
		sequence: sequence, version: version, manifest: manifest, signature: signature,
		sbom: sbom, executable: executable, bundle: testBundle(manifest, signature, sbom, executable),
	}
}

func (fixture *serviceFixture) installRelease(release serviceRelease, accepted bool) {
	fixture.t.Helper()
	directory := filepath.Join(fixture.paths.ReleaseRoot, "versions", release.version)
	if err := os.Mkdir(directory, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		fixture.t.Fatal(err)
	}
	for _, file := range []struct {
		name    string
		content []byte
		mode    os.FileMode
	}{
		{"manifest", release.manifest, 0o444},
		{"manifest.sig", release.signature, 0o444},
		{"edge-agent.spdx.json", release.sbom, 0o444},
		{"edge-agent", release.executable, 0o555},
	} {
		path := filepath.Join(directory, file.name)
		if err := os.WriteFile(path, file.content, file.mode); err != nil {
			fixture.t.Fatal(err)
		}
		if err := os.Chmod(path, file.mode); err != nil {
			fixture.t.Fatal(err)
		}
	}
	if err := fixture.runner.switchCurrent(release.version); err != nil {
		fixture.t.Fatal(err)
	}
	if accepted {
		if err := os.WriteFile(fixture.paths.AcceptedManifest, release.manifest, 0o600); err != nil {
			fixture.t.Fatal(err)
		}
		if err := os.Chmod(fixture.paths.AcceptedManifest, 0o600); err != nil {
			fixture.t.Fatal(err)
		}
	}
}

func (fixture *serviceFixture) current() protocol.Receipt {
	fixture.t.Helper()
	request := protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent}
	response := fixture.handle(request, nil)
	if !response.OK || response.Receipt == nil {
		fixture.t.Fatalf("current response = %#v", response)
	}
	fixture.verifyReceipt(*response.Receipt)
	return *response.Receipt
}

func (fixture *serviceFixture) installRequest(transactionID string, release serviceRelease, current protocol.Receipt) protocol.Request {
	fixture.t.Helper()
	architecture := runtime.GOARCH
	if architecture != "amd64" && architecture != "arm64" {
		architecture = "amd64"
	}
	return protocol.Request{
		ProtocolVersion: protocol.Version, Operation: protocol.OperationInstall,
		TransactionID: transactionID, ReleaseSequence: release.sequence,
		CurrentVersion: current.CurrentVersion, TargetVersion: release.version,
		Platform: "linux", Architecture: architecture,
		ArtifactSHA256: digestOf(release.bundle), ArtifactSize: int64(len(release.bundle)),
		AuditBasename: "artifact", CurrentReceipt: &current,
	}
}

func (fixture *serviceFixture) rollbackRequest(transactionID string, release serviceRelease, active, previous protocol.Receipt) protocol.Request {
	fixture.t.Helper()
	return protocol.Request{
		ProtocolVersion: protocol.Version, Operation: protocol.OperationRollback,
		TransactionID: transactionID, ReleaseSequence: release.sequence,
		ArtifactSHA256: digestOf(release.bundle), ExpectedCurrentVersion: release.version,
		RollbackVersion: previous.CurrentVersion, ActiveReceipt: &active, PreviousReceipt: &previous,
	}
}

func (fixture *serviceFixture) prepareRequest(transactionID string, release serviceRelease, current protocol.Receipt) protocol.Request {
	request := fixture.installRequest(transactionID, release, current)
	request.ProtocolVersion = protocol.JournalVersion
	request.Operation = protocol.OperationPrepareInstall
	return request
}

func (fixture *serviceFixture) activateRequest(ack protocol.PreparedAck) protocol.Request {
	return protocol.Request{
		ProtocolVersion: protocol.JournalVersion, Operation: protocol.OperationActivateInstall,
		TransactionID: ack.TransactionID, InstallPayloadSHA256: ack.InstallPayloadSHA256, PreparedAck: &ack,
	}
}

func (fixture *serviceFixture) markInstallingRequest(ack protocol.PreparedAck) protocol.Request {
	return protocol.Request{
		ProtocolVersion: protocol.JournalV4Version, Operation: protocol.OperationMarkInstalling,
		TransactionID: ack.TransactionID, InstallPayloadSHA256: ack.InstallPayloadSHA256, PreparedAck: &ack,
	}
}

func (fixture *serviceFixture) activateV3(transactionID string, executionSequence uint64,
	action protocol.Action, release serviceRelease, previous protocol.Receipt) protocol.Receipt {
	fixture.t.Helper()
	request := fixture.prepareRequest(transactionID, release, previous)
	request.ProtocolVersion = protocol.JournalV3Version
	request.ExecutionSequence = executionSequence
	request.Action = action
	prepared := fixture.handle(request, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		fixture.t.Fatalf("v3 prepare = %#v", prepared)
	}
	activate := fixture.activateRequest(*prepared.PreparedAck)
	activate.ProtocolVersion = protocol.JournalV3Version
	activated := fixture.handle(activate, nil)
	if !activated.OK || activated.Receipt == nil || activated.Receipt.SchemaVersion != 2 ||
		activated.Receipt.ExecutionSequence != executionSequence ||
		activated.Receipt.ReleaseSequence != release.sequence || activated.Receipt.CurrentVersion != release.version {
		fixture.t.Fatalf("v3 activate = %#v", activated)
	}
	return *activated.Receipt
}

func (fixture *serviceFixture) abortPreparedRequest(ack protocol.PreparedAck) protocol.Request {
	return protocol.Request{
		ProtocolVersion: protocol.JournalVersion, Operation: protocol.OperationAbortPrepared,
		TransactionID: ack.TransactionID, InstallPayloadSHA256: ack.InstallPayloadSHA256, PreparedAck: &ack,
	}
}

func (fixture *serviceFixture) inspectRequest(transactionID string) protocol.Request {
	return protocol.Request{ProtocolVersion: protocol.JournalVersion, Operation: protocol.OperationInspectTransaction, TransactionID: transactionID}
}

func (fixture *serviceFixture) handle(request protocol.Request, artifact *os.File) protocol.Response {
	fixture.t.Helper()
	packet, err := protocol.MarshalRequest(request)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return fixture.service.Handle(context.Background(), packet, request, artifact)
}

func (fixture *serviceFixture) artifact(release serviceRelease) *os.File {
	fixture.t.Helper()
	return openTestArtifact(fixture.t, release.bundle, os.O_RDONLY)
}

func (fixture *serviceFixture) verifyReceipt(receipt protocol.Receipt) {
	fixture.t.Helper()
	payload, err := ReceiptSigningBytes(receipt)
	if err != nil {
		fixture.t.Fatal(err)
	}
	signature, err := decodeReceiptSignature(receipt.Signature.Value)
	if err != nil || !ed25519.Verify(fixture.receiptPublic, payload, signature) {
		fixture.t.Fatalf("receipt signature invalid: %v", err)
	}
}

func TestServiceCurrentInstallQueryRollbackAndReplay(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	if previous.CurrentVersion != "1.0.0" || previous.ReleaseSequence != 1 || previous.Status != "active" || previous.ArtifactSHA256 != digestOf(fixture.release(1, "1.0.0").bundle) {
		t.Fatalf("baseline current = %+v", previous)
	}
	unknown := fixture.handle(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: "missing"}, nil)
	if unknown.OK || unknown.ErrorCode != protocol.ErrorTransactionUnknown {
		t.Fatalf("unknown query = %#v", unknown)
	}

	release := fixture.release(2, "2.0.0")
	install := fixture.installRequest("txn-main", release, previous)
	installed := fixture.handle(install, fixture.artifact(release))
	if !installed.OK || installed.Receipt == nil || installed.Receipt.Status != "active" || installed.Receipt.ArtifactSHA256 != install.ArtifactSHA256 {
		t.Fatalf("install = %#v", installed)
	}
	fixture.verifyReceipt(*installed.Receipt)
	if fixture.runner.upgradeCalls != 1 {
		t.Fatalf("upgrade calls = %d", fixture.runner.upgradeCalls)
	}

	query := fixture.handle(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
	if !query.OK || query.Receipt == nil || !sameReceipt(*query.Receipt, *installed.Receipt) || fixture.runner.upgradeCalls != 1 {
		t.Fatalf("active query = %#v calls=%d", query, fixture.runner.upgradeCalls)
	}
	replayed := fixture.handle(install, fixture.artifact(release))
	if !replayed.OK || replayed.Receipt == nil || !sameReceipt(*replayed.Receipt, *installed.Receipt) || fixture.runner.upgradeCalls != 1 {
		t.Fatalf("install replay = %#v calls=%d", replayed, fixture.runner.upgradeCalls)
	}
	conflict := install
	conflict.AuditBasename = "different"
	conflicted := fixture.handle(conflict, fixture.artifact(release))
	if conflicted.OK || conflicted.ErrorCode != protocol.ErrorTransactionConflict {
		t.Fatalf("install conflict = %#v", conflicted)
	}

	rollback := fixture.rollbackRequest(install.TransactionID, release, *installed.Receipt, previous)
	rolledBack := fixture.handle(rollback, nil)
	if !rolledBack.OK || rolledBack.Receipt == nil || rolledBack.Receipt.Status != "rolled_back" || rolledBack.Receipt.CurrentVersion != "1.0.0" {
		t.Fatalf("rollback = %#v", rolledBack)
	}
	fixture.verifyReceipt(*rolledBack.Receipt)
	if fixture.runner.rollbackCalls != 1 {
		t.Fatalf("rollback calls = %d", fixture.runner.rollbackCalls)
	}
	replayedRollback := fixture.handle(rollback, nil)
	if !replayedRollback.OK || replayedRollback.Receipt == nil || !sameReceipt(*replayedRollback.Receipt, *rolledBack.Receipt) || fixture.runner.rollbackCalls != 1 {
		t.Fatalf("rollback replay = %#v calls=%d", replayedRollback, fixture.runner.rollbackCalls)
	}
	rollbackConflict := rollback
	rollbackConflict.ExpectedCurrentVersion = "2.0.1"
	conflicted = fixture.handle(rollbackConflict, nil)
	if conflicted.OK || conflicted.ErrorCode != protocol.ErrorTransactionConflict {
		t.Fatalf("rollback conflict = %#v", conflicted)
	}
	query = fixture.handle(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
	if !query.OK || query.Receipt == nil || query.Receipt.Status != "rolled_back" || fixture.runner.rollbackCalls != 1 {
		t.Fatalf("rolled-back query = %#v calls=%d", query, fixture.runner.rollbackCalls)
	}
	current := fixture.current()
	if current.CurrentVersion != "1.0.0" || current.ReleaseSequence != 2 {
		t.Fatalf("restored current = %+v", current)
	}
}

func TestServiceMarkInstallingPersistsJournalBeforeActivation(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepared := fixture.handle(fixture.prepareRequest("txn-mark-installing", release, previous), fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	mark := fixture.handle(fixture.markInstallingRequest(*prepared.PreparedAck), nil)
	if !mark.OK || mark.TransactionStatus == nil || mark.TransactionStatus.Phase != protocol.TransactionInstalling {
		t.Fatalf("mark installing = %#v", mark)
	}
	record, err := fixture.service.journals.Load("txn-mark-installing")
	if err != nil || record.Phase != JournalInstalling || record.InstallPayloadSHA256 != prepared.PreparedAck.InstallPayloadSHA256 {
		t.Fatalf("journal after mark = (%+v, %v)", record, err)
	}
	second := fixture.handle(fixture.markInstallingRequest(*prepared.PreparedAck), nil)
	if !second.OK || second.TransactionStatus == nil || second.TransactionStatus.Phase != protocol.TransactionInstalling {
		t.Fatalf("idempotent mark installing = %#v", second)
	}
}

func TestServiceMarkInstallingReplayRequiresDurableDirectorySync(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepared := fixture.handle(fixture.prepareRequest("txn-mark-installing-sync", release, previous), fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	record, err := fixture.service.journals.Load(prepared.PreparedAck.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	record.Phase = JournalInstalling
	if err := fixture.service.journals.Save(record); err != nil {
		t.Fatal(err)
	}

	syncErr := errors.New("injected journal directory sync failure")
	syncCalls := 0
	fixture.service.syncJournalDirectory = func() error {
		syncCalls++
		return syncErr
	}
	request := fixture.markInstallingRequest(*prepared.PreparedAck)
	failed := fixture.handle(request, nil)
	if failed.OK || failed.ErrorCode != protocol.ErrorStateUncertain || failed.TransactionStatus != nil || syncCalls != 1 {
		t.Fatalf("mark installing before durable directory sync = %#v sync_calls=%d", failed, syncCalls)
	}
	if fixture.runner.upgradeCalls != 0 || fixture.runner.rollbackCalls != 0 {
		t.Fatalf("runner calls before durable directory sync: upgrade=%d rollback=%d", fixture.runner.upgradeCalls, fixture.runner.rollbackCalls)
	}
	current, _, err := fixture.service.current.Load()
	if err != nil || !sameReceipt(current, previous) {
		t.Fatalf("current changed before durable directory sync: got %+v want %+v err=%v", current, previous, err)
	}

	fixture.service.syncJournalDirectory = func() error {
		syncCalls++
		return syncHelperDirectory(fixture.paths.StateDirectory)
	}
	replayed := fixture.handle(request, nil)
	if !replayed.OK || replayed.TransactionStatus == nil || replayed.TransactionStatus.Phase != protocol.TransactionInstalling || syncCalls != 2 {
		t.Fatalf("mark installing after durable directory sync = %#v sync_calls=%d", replayed, syncCalls)
	}
	if fixture.runner.upgradeCalls != 0 || fixture.runner.rollbackCalls != 0 {
		t.Fatalf("runner calls after durable directory sync: upgrade=%d rollback=%d", fixture.runner.upgradeCalls, fixture.runner.rollbackCalls)
	}
	current, _, err = fixture.service.current.Load()
	if err != nil || !sameReceipt(current, previous) {
		t.Fatalf("current changed after durable directory sync: got %+v want %+v err=%v", current, previous, err)
	}
}

func TestServiceMarkInstallingRequiresDurableDirectorySyncOnTransition(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepared := fixture.handle(fixture.prepareRequest("txn-mark-installing-transition-sync", release, previous), fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}

	syncErr := errors.New("injected transition journal directory sync failure")
	syncCalls := 0
	fixture.service.syncJournalDirectory = func() error {
		syncCalls++
		return syncErr
	}
	request := fixture.markInstallingRequest(*prepared.PreparedAck)
	failed := fixture.handle(request, nil)
	if failed.OK || failed.ErrorCode != protocol.ErrorStateUncertain || failed.TransactionStatus != nil || syncCalls != 1 {
		t.Fatalf("mark installing before durable transition sync = %#v sync_calls=%d", failed, syncCalls)
	}
	if fixture.runner.upgradeCalls != 0 || fixture.runner.rollbackCalls != 0 {
		t.Fatalf("runner calls before durable transition sync: upgrade=%d rollback=%d", fixture.runner.upgradeCalls, fixture.runner.rollbackCalls)
	}
	current, _, err := fixture.service.current.Load()
	if err != nil || !sameReceipt(current, previous) {
		t.Fatalf("current changed before durable transition sync: got %+v want %+v err=%v", current, previous, err)
	}

	fixture.service.syncJournalDirectory = func() error {
		syncCalls++
		return syncHelperDirectory(fixture.paths.StateDirectory)
	}
	replayed := fixture.handle(request, nil)
	if !replayed.OK || replayed.TransactionStatus == nil || replayed.TransactionStatus.Phase != protocol.TransactionInstalling || syncCalls != 2 {
		t.Fatalf("mark installing after durable transition sync = %#v sync_calls=%d", replayed, syncCalls)
	}
	if fixture.runner.upgradeCalls != 0 || fixture.runner.rollbackCalls != 0 {
		t.Fatalf("runner calls after durable transition sync: upgrade=%d rollback=%d", fixture.runner.upgradeCalls, fixture.runner.rollbackCalls)
	}
}

func TestServiceCurrentAndNextPrepareAfterRollbackToHistoricalActive(t *testing.T) {
	fixture := newServiceFixture(t)
	baseline := fixture.current()
	release2 := fixture.release(2, "2.0.0")
	install2 := fixture.installRequest("txn-historical-active-2", release2, baseline)
	installed2 := fixture.handle(install2, fixture.artifact(release2))
	if !installed2.OK || installed2.Receipt == nil {
		t.Fatalf("install2 = %#v", installed2)
	}
	release3 := fixture.release(3, "3.0.0")
	install3 := fixture.installRequest("txn-historical-active-3", release3, *installed2.Receipt)
	installed3 := fixture.handle(install3, fixture.artifact(release3))
	if !installed3.OK || installed3.Receipt == nil {
		t.Fatalf("install3 = %#v", installed3)
	}
	rolledBack := fixture.handle(fixture.rollbackRequest(install3.TransactionID, release3, *installed3.Receipt, *installed2.Receipt), nil)
	if !rolledBack.OK || rolledBack.Receipt == nil || rolledBack.Receipt.Status != "rolled_back" {
		t.Fatalf("rollback3-to2 = %#v", rolledBack)
	}

	currentResponse := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent}, nil)
	if !currentResponse.OK || currentResponse.Receipt == nil || currentResponse.Receipt.CurrentVersion != release2.version || currentResponse.Receipt.ReleaseSequence != release3.sequence {
		t.Fatalf("current after rollback3-to2 = %#v", currentResponse)
	}
	release4 := fixture.release(4, "4.0.0")
	prepare4 := fixture.prepareRequest("txn-after-historical-active", release4, *currentResponse.Receipt)
	prepared4 := fixture.handle(prepare4, fixture.artifact(release4))
	if !prepared4.OK || prepared4.PreparedAck == nil || fixture.runner.upgradeCalls != 2 {
		t.Fatalf("prepare4 after rollback = %#v upgrade_calls=%d", prepared4, fixture.runner.upgradeCalls)
	}
	highWater, err := fixture.service.journals.HighWaterMark()
	facts, factsErr := InspectInstalled(fixture.paths, fixture.packagePublic, fixture.uid, fixture.gid)
	if err != nil || highWater != release3.sequence || factsErr != nil || facts.ReleaseSequence != release2.sequence {
		t.Fatalf("logical/physical previous before activate4 = high_water=%d high_water_err=%v facts=(%+v, %v)", highWater, err, facts, factsErr)
	}
	activated4 := fixture.handle(fixture.activateRequest(*prepared4.PreparedAck), nil)
	if !activated4.OK || activated4.Receipt == nil || activated4.Receipt.Status != "active" ||
		activated4.Receipt.ReleaseSequence != release4.sequence || activated4.Receipt.CurrentVersion != release4.version || fixture.runner.upgradeCalls != 3 {
		t.Fatalf("activate4 after rollback = %#v upgrade_calls=%d", activated4, fixture.runner.upgradeCalls)
	}
	requireJournalV2PreviousBinding(t, fixture, prepare4.TransactionID, release2.sequence, digestBytes(release2.manifest))
	record2, err := fixture.service.journals.Load(install2.TransactionID)
	if err != nil || record2.Phase != JournalActive {
		t.Fatalf("historical active journal2 = (%+v, %v)", record2, err)
	}
	record3, err := fixture.service.journals.Load(install3.TransactionID)
	if err != nil || record3.Phase != JournalRolledBack {
		t.Fatalf("rolled-back journal3 = (%+v, %v)", record3, err)
	}
}

func TestServiceCurrentRejectsHighestUnresolvedInstallAndActivationRecovers(t *testing.T) {
	for _, test := range []struct {
		name            string
		afterRunner     bool
		wantRunnerCalls int
	}{
		{name: "prepared-before-runner", wantRunnerCalls: 1},
		{name: "installing-after-runner", afterRunner: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			previous := fixture.current()
			release := fixture.release(2, "2.0.0")
			prepare := fixture.prepareRequest("txn-current-unresolved-"+test.name, release, previous)
			prepared := fixture.handle(prepare, fixture.artifact(release))
			if !prepared.OK || prepared.PreparedAck == nil {
				t.Fatalf("prepare = %#v", prepared)
			}
			if test.afterRunner {
				record, err := fixture.service.journals.Load(prepare.TransactionID)
				if err != nil {
					t.Fatal(err)
				}
				record.Phase = JournalInstalling
				if err := fixture.service.journals.Save(record); err != nil {
					t.Fatal(err)
				}
				fixture.installRelease(release, true)
			}
			currentPath := filepath.Join(fixture.paths.StateDirectory, "current.json")
			before, err := os.ReadFile(currentPath)
			if err != nil {
				t.Fatal(err)
			}
			current := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent}, nil)
			if current.OK || current.ErrorCode != protocol.ErrorStateUncertain || current.Receipt != nil {
				t.Fatalf("current with unresolved %s = %#v", test.name, current)
			}
			after, err := os.ReadFile(currentPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("current mutated by unresolved %s: %v", test.name, err)
			}
			activated := fixture.handle(fixture.activateRequest(*prepared.PreparedAck), nil)
			if !activated.OK || activated.Receipt == nil || activated.Receipt.Status != "active" ||
				activated.Receipt.ReleaseSequence != release.sequence || fixture.runner.upgradeCalls != test.wantRunnerCalls {
				t.Fatalf("activation recovery for %s = %#v calls=%d", test.name, activated, fixture.runner.upgradeCalls)
			}
			current = fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent}, nil)
			if !current.OK || current.Receipt == nil || current.Receipt.ReleaseSequence != release.sequence || current.Receipt.CurrentVersion != release.version {
				t.Fatalf("current after %s recovery = %#v", test.name, current)
			}
		})
	}
}

func TestServiceV2PrepareInspectActivateResponseLossAndReplay(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-v2-main", release, previous)
	preparePacket, err := protocol.MarshalRequest(prepare)
	if err != nil {
		t.Fatal(err)
	}
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil || prepared.Receipt != nil || prepared.TransactionStatus != nil || fixture.runner.upgradeCalls != 0 {
		t.Fatalf("prepare = %#v calls=%d", prepared, fixture.runner.upgradeCalls)
	}
	ack := *prepared.PreparedAck
	record, err := fixture.service.journals.Load(prepare.TransactionID)
	if err != nil || record.Phase != JournalPrepared || record.InstallPayloadSHA256 != HashCanonicalPayload(preparePacket) || ack.InstallPayloadSHA256 != record.InstallPayloadSHA256 {
		t.Fatalf("durable prepared state = (%+v, %v), ack=%+v", record, err, ack)
	}

	journalPath := filepath.Join(fixture.paths.StateDirectory, "journal-"+prepare.TransactionID+".json")
	journalBefore, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	currentBefore, err := os.ReadFile(filepath.Join(fixture.paths.StateDirectory, "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	linkBefore, err := os.Readlink(filepath.Join(fixture.paths.ReleaseRoot, "current"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = fixture.newService()
	inspected := fixture.handle(fixture.inspectRequest(prepare.TransactionID), nil)
	if !inspected.OK || inspected.TransactionStatus == nil || inspected.TransactionStatus.Phase != protocol.TransactionPrepared ||
		inspected.TransactionStatus.PreparedAck == nil || *inspected.TransactionStatus.PreparedAck != ack || fixture.runner.upgradeCalls != 0 {
		t.Fatalf("prepared inspect = %#v calls=%d", inspected, fixture.runner.upgradeCalls)
	}
	journalAfter, _ := os.ReadFile(journalPath)
	currentAfter, _ := os.ReadFile(filepath.Join(fixture.paths.StateDirectory, "current.json"))
	linkAfter, _ := os.Readlink(filepath.Join(fixture.paths.ReleaseRoot, "current"))
	if !bytes.Equal(journalBefore, journalAfter) || !bytes.Equal(currentBefore, currentAfter) || linkBefore != linkAfter {
		t.Fatal("inspect mutated journal, current receipt, or installed release")
	}
	unknown := fixture.handle(fixture.inspectRequest("txn-v2-missing"), nil)
	if !unknown.OK || unknown.TransactionStatus == nil || unknown.TransactionStatus.Phase != protocol.TransactionUnknown ||
		unknown.TransactionStatus.PreparedAck != nil || unknown.TransactionStatus.Receipt != nil || fixture.runner.upgradeCalls != 0 {
		t.Fatalf("unknown inspect = %#v calls=%d", unknown, fixture.runner.upgradeCalls)
	}

	badDigest := fixture.activateRequest(ack)
	badDigestAck := ack
	badDigestAck.InstallPayloadSHA256 = digestOf([]byte("different-prepare-packet"))
	badDigest.InstallPayloadSHA256 = badDigestAck.InstallPayloadSHA256
	badDigest.PreparedAck = &badDigestAck
	conflicted := fixture.handle(badDigest, nil)
	if conflicted.OK || conflicted.ErrorCode != protocol.ErrorTransactionConflict || fixture.runner.upgradeCalls != 0 {
		t.Fatalf("payload conflict = %#v calls=%d", conflicted, fixture.runner.upgradeCalls)
	}
	badAck := ack
	badAck.TargetVersion = "2.0.1"
	conflicted = fixture.handle(fixture.activateRequest(badAck), nil)
	if conflicted.OK || conflicted.ErrorCode != protocol.ErrorTransactionConflict || fixture.runner.upgradeCalls != 0 {
		t.Fatalf("ack conflict = %#v calls=%d", conflicted, fixture.runner.upgradeCalls)
	}

	activate := fixture.activateRequest(ack)
	activated := fixture.handle(activate, nil)
	if !activated.OK || activated.Receipt == nil || activated.Receipt.Status != "active" || activated.PreparedAck != nil ||
		activated.TransactionStatus != nil || fixture.runner.upgradeCalls != 1 {
		t.Fatalf("activate = %#v calls=%d", activated, fixture.runner.upgradeCalls)
	}
	fixture.verifyReceipt(*activated.Receipt)
	activeInspect := fixture.handle(fixture.inspectRequest(prepare.TransactionID), nil)
	if !activeInspect.OK || activeInspect.TransactionStatus == nil || activeInspect.TransactionStatus.Phase != protocol.TransactionActive ||
		activeInspect.TransactionStatus.Receipt == nil || !sameReceipt(*activeInspect.TransactionStatus.Receipt, *activated.Receipt) || fixture.runner.upgradeCalls != 1 {
		t.Fatalf("active inspect = %#v calls=%d", activeInspect, fixture.runner.upgradeCalls)
	}

	fixture.service = fixture.newService()
	replayed := fixture.handle(activate, nil)
	if !replayed.OK || replayed.Receipt == nil || !sameReceipt(*replayed.Receipt, *activated.Receipt) || fixture.runner.upgradeCalls != 1 {
		t.Fatalf("response-loss activate replay = %#v calls=%d", replayed, fixture.runner.upgradeCalls)
	}
	preparedReplay := fixture.handle(prepare, fixture.artifact(release))
	if !preparedReplay.OK || preparedReplay.PreparedAck == nil || *preparedReplay.PreparedAck != ack || fixture.runner.upgradeCalls != 1 {
		t.Fatalf("terminal prepare replay = %#v calls=%d", preparedReplay, fixture.runner.upgradeCalls)
	}

	rollback := fixture.rollbackRequest(prepare.TransactionID, release, *activated.Receipt, previous)
	rolledBack := fixture.handle(rollback, nil)
	if !rolledBack.OK || rolledBack.Receipt == nil || rolledBack.Receipt.Status != "rolled_back" {
		t.Fatalf("v2 transaction rollback = %#v", rolledBack)
	}
	rollbackCalls := fixture.runner.rollbackCalls
	rolledBackInspect := fixture.handle(fixture.inspectRequest(prepare.TransactionID), nil)
	if !rolledBackInspect.OK || rolledBackInspect.TransactionStatus == nil || rolledBackInspect.TransactionStatus.Phase != protocol.TransactionRolledBack ||
		rolledBackInspect.TransactionStatus.Receipt == nil || !sameReceipt(*rolledBackInspect.TransactionStatus.Receipt, *rolledBack.Receipt) || fixture.runner.rollbackCalls != rollbackCalls {
		t.Fatalf("rolled-back inspect = %#v rollback_calls=%d", rolledBackInspect, fixture.runner.rollbackCalls)
	}
}

func TestServiceV3RollbackAndReuseUseExecutionHighWater(t *testing.T) {
	fixture := newServiceFixture(t)
	current := fixture.current()
	prepareAndActivate := func(transactionID string, executionSequence uint64,
		action protocol.Action, release serviceRelease, previous protocol.Receipt) protocol.Receipt {
		request := fixture.prepareRequest(transactionID, release, previous)
		request.ProtocolVersion = protocol.JournalV3Version
		request.ExecutionSequence = executionSequence
		request.Action = action
		prepared := fixture.handle(request, fixture.artifact(release))
		if !prepared.OK || prepared.PreparedAck == nil || prepared.PreparedAck.ExecutionSequence != executionSequence ||
			prepared.PreparedAck.ReleaseSequence != release.sequence {
			t.Fatalf("v3 prepare = %#v", prepared)
		}
		activate := fixture.activateRequest(*prepared.PreparedAck)
		activate.ProtocolVersion = protocol.JournalV3Version
		activated := fixture.handle(activate, nil)
		if !activated.OK || activated.Receipt == nil || activated.Receipt.ExecutionSequence != executionSequence ||
			activated.Receipt.ReleaseSequence != release.sequence || activated.Receipt.CurrentVersion != release.version {
			t.Fatalf("v3 activate = %#v receipt=%+v want execution=%d release=%d version=%s",
				activated, activated.Receipt, executionSequence, release.sequence, release.version)
		}
		replayed := fixture.handle(activate, nil)
		if !reflect.DeepEqual(replayed.Receipt, activated.Receipt) {
			t.Fatalf("activation replay = %#v, want %#v", replayed, activated)
		}
		return *activated.Receipt
	}

	forward := fixture.release(12, "2.0.0")
	forwardReceipt := prepareAndActivate("txn-v3-forward", 20, protocol.ActionUpgrade, forward, current)
	for _, request := range []protocol.Request{
		{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent},
		{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: "txn-v3-forward"},
	} {
		response := fixture.handle(request, nil)
		if !response.OK || response.Receipt == nil || !sameReceipt(*response.Receipt, forwardReceipt) {
			t.Fatalf("v3 %s through current protocol = %#v", request.Operation, response)
		}
		// PROTOCOL.md: a client rejects a response whose protocol_version
		// differs from its request, so a v1 request must get a v1 response.
		if response.ProtocolVersion != request.ProtocolVersion {
			t.Fatalf("v3 receipt through %s answered protocol %d, want %d", request.Operation, response.ProtocolVersion, request.ProtocolVersion)
		}
		packet, err := protocol.MarshalResponse(response)
		if err != nil {
			t.Fatalf("marshal v3 %s response: %v", request.Operation, err)
		}
		if _, err := protocol.ParseResponse(packet); err != nil {
			t.Fatalf("parse v3 %s response: %v", request.Operation, err)
		}
	}
	stored, _, err := fixture.service.current.Load()
	if err != nil || !sameReceipt(stored, forwardReceipt) {
		t.Fatalf("stored v3 current = (%#v, %v), want %#v", stored, err, forwardReceipt)
	}
	rollback := fixture.release(4, "1.5.0")
	rollbackReceipt := prepareAndActivate("txn-v3-rollback", 21, protocol.ActionRollback, rollback, forwardReceipt)
	fixture.service = fixture.newService()
	reused := prepareAndActivate("txn-v3-reuse-forward", 22, protocol.ActionUpgrade, forward, rollbackReceipt)

	conflictingRelease := fixture.release(13, "3.0.0")
	conflict := fixture.prepareRequest("txn-v3-conflict", conflictingRelease, reused)
	conflict.ProtocolVersion = protocol.JournalV3Version
	conflict.ExecutionSequence = 22
	conflict.Action = protocol.ActionUpgrade
	response := fixture.handle(conflict, fixture.artifact(conflictingRelease))
	if response.OK || response.ErrorCode != protocol.ErrorTransactionConflict {
		t.Fatalf("same execution conflict = %#v", response)
	}
	lower := conflict
	lower.TransactionID = "txn-v3-lower"
	lower.ExecutionSequence = 21
	response = fixture.handle(lower, fixture.artifact(conflictingRelease))
	if response.OK || response.ErrorCode != protocol.ErrorTransactionConflict {
		t.Fatalf("lower execution conflict = %#v", response)
	}
	v2 := fixture.prepareRequest("txn-v2-after-v3", conflictingRelease, reused)
	response = fixture.handle(v2, fixture.artifact(conflictingRelease))
	if response.OK || response.ErrorCode != protocol.ErrorProtocol {
		t.Fatalf("v2 downgrade after v3 = %#v", response)
	}
}

func TestServiceV3AutomaticRollbackAfterReuseUsesExecutionFence(t *testing.T) {
	fixture := newServiceFixture(t)
	baseline := fixture.current()
	forward := fixture.release(12, "2.0.0")
	forwardReceipt := fixture.activateV3("txn-v3-auto-forward", 20, protocol.ActionUpgrade, forward, baseline)
	rollback := fixture.release(4, "1.5.0")
	rollbackReceipt := fixture.activateV3("txn-v3-auto-older", 21, protocol.ActionRollback, rollback, forwardReceipt)
	reused := fixture.activateV3("txn-v3-auto-reuse", 22, protocol.ActionUpgrade, forward, rollbackReceipt)

	automatic := fixture.rollbackRequest("txn-v3-auto-reuse", forward, reused, rollbackReceipt)
	response := fixture.handle(automatic, nil)
	if !response.OK || response.Receipt == nil || response.Receipt.Status != "rolled_back" ||
		response.Receipt.SchemaVersion != 2 || response.Receipt.ExecutionSequence != 22 ||
		response.Receipt.ReleaseSequence != forward.sequence || response.Receipt.CurrentVersion != rollback.version {
		t.Fatalf("v3 automatic rollback after reuse = %#v", response)
	}
}

func TestServiceV3RollbackRestoredCurrentPreservesExecutionBinding(t *testing.T) {
	fixture := newServiceFixture(t)
	baseline := fixture.current()
	forward := fixture.release(12, "2.0.0")
	active := fixture.activateV3("txn-v3-restored-current", 20, protocol.ActionUpgrade, forward, baseline)
	response := fixture.handle(fixture.rollbackRequest("txn-v3-restored-current", forward, active, baseline), nil)
	if !response.OK || response.Receipt == nil || response.Receipt.Status != "rolled_back" {
		t.Fatalf("v3 rollback = %#v", response)
	}
	fixture.service = fixture.newService()
	current := fixture.current()
	if current.SchemaVersion != 2 || current.ExecutionSequence != 20 ||
		current.ReleaseSequence != forward.sequence || current.CurrentVersion != baseline.CurrentVersion ||
		current.PreviousVersion != forward.version {
		t.Fatalf("restored v3 current = %#v", current)
	}
}

func TestServiceV2InspectInstallingIsPure(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-v2-inspecting", release, previous)
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	record, err := fixture.service.journals.Load(prepare.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	record.Phase = JournalInstalling
	if err := fixture.service.journals.Save(record); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(fixture.paths.StateDirectory, "journal-"+prepare.TransactionID+".json")
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	response := fixture.handle(fixture.inspectRequest(prepare.TransactionID), nil)
	after, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.TransactionStatus == nil || response.TransactionStatus.Phase != protocol.TransactionInstalling ||
		response.TransactionStatus.PreparedAck == nil || *response.TransactionStatus.PreparedAck != *prepared.PreparedAck ||
		fixture.runner.upgradeCalls != 0 || fixture.runner.rollbackCalls != 0 || !bytes.Equal(before, after) {
		t.Fatalf("installing inspect = %#v upgrade=%d rollback=%d mutated=%t", response, fixture.runner.upgradeCalls, fixture.runner.rollbackCalls, !bytes.Equal(before, after))
	}
}

func TestServiceV2AbortPreparedPersistsTombstoneAndReplays(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-v2-abort", release, previous)
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	ack := *prepared.PreparedAck

	mismatchedAck := ack
	mismatchedAck.TargetVersion = "2.0.1"
	conflicted := fixture.handle(fixture.abortPreparedRequest(mismatchedAck), nil)
	if conflicted.OK || conflicted.ErrorCode != protocol.ErrorTransactionConflict || fixture.runner.upgradeCalls != 0 {
		t.Fatalf("mismatched abort = %#v calls=%d", conflicted, fixture.runner.upgradeCalls)
	}

	abort := fixture.abortPreparedRequest(ack)
	aborted := fixture.handle(abort, nil)
	if !aborted.OK || aborted.TransactionStatus == nil || aborted.TransactionStatus.Phase != protocol.TransactionAborted ||
		aborted.TransactionStatus.PreparedAck == nil || *aborted.TransactionStatus.PreparedAck != ack ||
		aborted.Receipt != nil || aborted.PreparedAck != nil || fixture.runner.upgradeCalls != 0 || fixture.runner.rollbackCalls != 0 {
		t.Fatalf("abort = %#v upgrade=%d rollback=%d", aborted, fixture.runner.upgradeCalls, fixture.runner.rollbackCalls)
	}
	record, err := fixture.service.journals.Load(prepare.TransactionID)
	if err != nil || record.Phase != JournalAborted {
		t.Fatalf("durable aborted tombstone = (%+v, %v)", record, err)
	}
	journalPath := filepath.Join(fixture.paths.StateDirectory, "journal-"+prepare.TransactionID+".json")
	beforeRestart, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}

	fixture.service = fixture.newService()
	inspected := fixture.handle(fixture.inspectRequest(prepare.TransactionID), nil)
	if !inspected.OK || inspected.TransactionStatus == nil || inspected.TransactionStatus.Phase != protocol.TransactionAborted ||
		inspected.TransactionStatus.PreparedAck == nil || *inspected.TransactionStatus.PreparedAck != ack {
		t.Fatalf("aborted inspect after restart = %#v", inspected)
	}
	replayed := fixture.handle(abort, nil)
	if !replayed.OK || replayed.TransactionStatus == nil || replayed.TransactionStatus.TransactionID != aborted.TransactionStatus.TransactionID ||
		replayed.TransactionStatus.Phase != aborted.TransactionStatus.Phase || replayed.TransactionStatus.PreparedAck == nil ||
		*replayed.TransactionStatus.PreparedAck != *aborted.TransactionStatus.PreparedAck {
		t.Fatalf("abort response-loss replay = %#v", replayed)
	}
	afterReplay, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(beforeRestart, afterReplay) {
		t.Fatalf("abort replay mutated tombstone: %v", err)
	}
	activated := fixture.handle(fixture.activateRequest(ack), nil)
	if activated.OK || activated.ErrorCode != protocol.ErrorTransactionConflict || fixture.runner.upgradeCalls != 0 {
		t.Fatalf("activate aborted transaction = %#v calls=%d", activated, fixture.runner.upgradeCalls)
	}
	current := fixture.current()
	if current.CurrentVersion != previous.CurrentVersion || current.ReleaseSequence != previous.ReleaseSequence {
		t.Fatalf("abort changed current = %+v, previous=%+v", current, previous)
	}
}

func TestServicePrepareAbortedTransactionRejectsSamePayloadReplay(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-aborted-prepare-replay", release, previous)
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	aborted := fixture.handle(fixture.abortPreparedRequest(*prepared.PreparedAck), nil)
	if !aborted.OK || aborted.TransactionStatus == nil || aborted.TransactionStatus.Phase != protocol.TransactionAborted {
		t.Fatalf("abort = %#v", aborted)
	}
	replayed := fixture.handle(prepare, fixture.artifact(release))
	if replayed.OK || replayed.ErrorCode != protocol.ErrorTransactionConflict || replayed.PreparedAck != nil || fixture.runner.upgradeCalls != 0 {
		t.Fatalf("aborted prepare replay = %#v calls=%d", replayed, fixture.runner.upgradeCalls)
	}
}

func TestServiceAbortPreparedCleansStagingAfterDurableTombstone(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-abort-cleanup", release, previous)
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	directory := filepath.Join(fixture.paths.StateDirectory, "transactions", prepare.TransactionID)
	if _, err := os.Stat(directory); err != nil {
		t.Fatalf("staging before abort = %v", err)
	}
	aborted := fixture.handle(fixture.abortPreparedRequest(*prepared.PreparedAck), nil)
	if !aborted.OK || aborted.TransactionStatus == nil || aborted.TransactionStatus.Phase != protocol.TransactionAborted {
		t.Fatalf("abort = %#v", aborted)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging after abort = %v", err)
	}
	record, err := fixture.service.journals.Load(prepare.TransactionID)
	if err != nil || record.Phase != JournalAborted || record.InstallPayloadSHA256 != prepared.PreparedAck.InstallPayloadSHA256 {
		t.Fatalf("aborted tombstone = (%+v, %v)", record, err)
	}
}

func TestServiceAbortPreparedCleanupFailureKeepsTombstoneAndRetries(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-abort-cleanup-retry", release, previous)
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	directory := filepath.Join(fixture.paths.StateDirectory, "transactions", prepare.TransactionID)
	if err := os.WriteFile(filepath.Join(directory, "unexpected"), []byte("keep"), 0o400); err != nil {
		t.Fatal(err)
	}
	aborted := fixture.handle(fixture.abortPreparedRequest(*prepared.PreparedAck), nil)
	if aborted.OK || aborted.ErrorCode != protocol.ErrorStateUncertain {
		t.Fatalf("abort with cleanup failure = %#v", aborted)
	}
	record, err := fixture.service.journals.Load(prepare.TransactionID)
	if err != nil || record.Phase != JournalAborted {
		t.Fatalf("tombstone after cleanup failure = (%+v, %v)", record, err)
	}
	if err := os.Remove(filepath.Join(directory, "unexpected")); err != nil {
		t.Fatal(err)
	}
	retried := fixture.handle(fixture.abortPreparedRequest(*prepared.PreparedAck), nil)
	if !retried.OK || retried.TransactionStatus == nil || retried.TransactionStatus.Phase != protocol.TransactionAborted {
		t.Fatalf("abort retry = %#v", retried)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging after cleanup retry = %v", err)
	}
}

func TestServiceAbortPreparedInspectWaitsForCleanupAfterTombstone(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-abort-cleanup-crash", release, previous)
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	record, err := fixture.service.journals.Load(prepare.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	record.Phase = JournalAborted
	if err := fixture.service.journals.Save(record); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(fixture.paths.StateDirectory, "transactions", prepare.TransactionID)
	if _, err := os.Stat(directory); err != nil {
		t.Fatalf("staging after tombstone crash = %v", err)
	}

	fixture.service = fixture.newService()
	inspected := fixture.handle(fixture.inspectRequest(prepare.TransactionID), nil)
	if inspected.OK || inspected.ErrorCode != protocol.ErrorStateUncertain || inspected.TransactionStatus != nil {
		t.Fatalf("inspect before abort cleanup = %#v", inspected)
	}
	replayed := fixture.handle(fixture.abortPreparedRequest(*prepared.PreparedAck), nil)
	if !replayed.OK || replayed.TransactionStatus == nil || replayed.TransactionStatus.Phase != protocol.TransactionAborted {
		t.Fatalf("abort cleanup replay = %#v", replayed)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging after abort cleanup replay = %v", err)
	}
	inspected = fixture.handle(fixture.inspectRequest(prepare.TransactionID), nil)
	if !inspected.OK || inspected.TransactionStatus == nil || inspected.TransactionStatus.Phase != protocol.TransactionAborted {
		t.Fatalf("inspect after abort cleanup = %#v", inspected)
	}
	if fixture.runner.upgradeCalls != 0 || fixture.runner.rollbackCalls != 0 {
		t.Fatalf("abort cleanup runner calls: upgrade=%d rollback=%d", fixture.runner.upgradeCalls, fixture.runner.rollbackCalls)
	}
}

func TestServiceAbortPreparedRequiresParentSyncAfterDirectoryAlreadyMissing(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-abort-cleanup-parent-sync", release, previous)
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	record, err := fixture.service.journals.Load(prepare.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	record.Phase = JournalAborted
	if err := fixture.service.journals.Save(record); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(fixture.paths.StateDirectory, "transactions", prepare.TransactionID)
	if err := os.RemoveAll(directory); err != nil {
		t.Fatal(err)
	}

	fixture.service = fixture.newService()
	syncErr := errors.New("injected transactions directory sync failure")
	syncCalls := 0
	fixture.service.syncTransactions = func() error {
		syncCalls++
		return syncErr
	}
	inspected := fixture.handle(fixture.inspectRequest(prepare.TransactionID), nil)
	if inspected.OK || inspected.ErrorCode != protocol.ErrorStateUncertain || inspected.TransactionStatus != nil || syncCalls != 1 {
		t.Fatalf("inspect before parent sync = %#v sync_calls=%d", inspected, syncCalls)
	}
	replayed := fixture.handle(fixture.abortPreparedRequest(*prepared.PreparedAck), nil)
	if replayed.OK || replayed.ErrorCode != protocol.ErrorStateUncertain || replayed.TransactionStatus != nil || syncCalls != 2 {
		t.Fatalf("abort replay before parent sync = %#v sync_calls=%d", replayed, syncCalls)
	}

	fixture.service.syncTransactions = func() error {
		syncCalls++
		return syncHelperDirectory(filepath.Join(fixture.paths.StateDirectory, "transactions"))
	}
	replayed = fixture.handle(fixture.abortPreparedRequest(*prepared.PreparedAck), nil)
	if !replayed.OK || replayed.TransactionStatus == nil || replayed.TransactionStatus.Phase != protocol.TransactionAborted || syncCalls != 3 {
		t.Fatalf("abort replay after parent sync = %#v sync_calls=%d", replayed, syncCalls)
	}
	inspected = fixture.handle(fixture.inspectRequest(prepare.TransactionID), nil)
	if !inspected.OK || inspected.TransactionStatus == nil || inspected.TransactionStatus.Phase != protocol.TransactionAborted || syncCalls != 4 {
		t.Fatalf("inspect after parent sync = %#v sync_calls=%d", inspected, syncCalls)
	}
}

func TestServiceAbortPreparedCannotRaceActivationAcrossInstances(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepareRequest := fixture.prepareRequest("txn-cross-instance-abort", release, previous)
	prepared := fixture.handle(prepareRequest, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	secondService := fixture.newService()
	entered := make(chan struct{})
	releaseSave := make(chan struct{})
	fixture.service.journals.beforeWrite = func(_, next JournalRecord) {
		if next.Phase != JournalInstalling {
			return
		}
		close(entered)
		<-releaseSave
	}
	activateDone := make(chan protocol.Response, 1)
	go func() {
		activateDone <- fixture.service.Handle(context.Background(), nil,
			fixture.activateRequest(*prepared.PreparedAck), nil)
	}()
	<-entered
	abortDone := make(chan protocol.Response, 1)
	go func() {
		abortDone <- secondService.Handle(context.Background(), nil,
			fixture.abortPreparedRequest(*prepared.PreparedAck), nil)
	}()
	select {
	case response := <-abortDone:
		t.Fatalf("abort completed while activation held the directory lock: %#v", response)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseSave)
	activated := <-activateDone
	aborted := <-abortDone
	if !activated.OK || activated.Receipt == nil || activated.Receipt.Status != "active" {
		t.Fatalf("activation = %#v", activated)
	}
	if aborted.OK || aborted.ErrorCode != protocol.ErrorTransactionConflict {
		t.Fatalf("cross-instance abort = %#v, want transition rejection", aborted)
	}
	if fixture.runner.upgradeCalls != 1 {
		t.Fatalf("runner upgrade calls = %d, want 1", fixture.runner.upgradeCalls)
	}
}

func TestServiceActivateClaimsRunnerAcrossInstances(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-cross-instance-activate", release, previous)
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	ack := *prepared.PreparedAck
	restarted := fixture.newService()
	fixture.runner.upgradeEntered = make(chan struct{})
	fixture.runner.releaseUpgrade = make(chan struct{})
	responses := make(chan protocol.Response, 2)
	go func() {
		responses <- fixture.service.Handle(context.Background(), nil, fixture.activateRequest(ack), nil)
	}()
	select {
	case <-fixture.runner.upgradeEntered:
	case <-time.After(time.Second):
		t.Fatal("first activation did not enter runner")
	}
	go func() { responses <- restarted.Handle(context.Background(), nil, fixture.activateRequest(ack), nil) }()
	select {
	case response := <-responses:
		t.Fatalf("second activation completed while first runner was held: %#v", response)
	case <-time.After(100 * time.Millisecond):
	}
	close(fixture.runner.releaseUpgrade)
	first := <-responses
	second := <-responses
	if !first.OK || first.Receipt == nil || first.Receipt.Status != "active" || !second.OK || second.Receipt == nil || second.Receipt.Status != "active" {
		t.Fatalf("activations = %#v, %#v", first, second)
	}
	if fixture.runner.upgradeCalls != 1 {
		t.Fatalf("runner upgrade calls = %d, want 1", fixture.runner.upgradeCalls)
	}
}

func TestServiceActivateRejectsStalePreparedCurrentAcrossInstances(t *testing.T) {
	for _, test := range []struct {
		name         string
		firstRelease serviceRelease
		staleRelease serviceRelease
	}{
		{name: "higher-high-water", firstRelease: serviceRelease{sequence: 3, version: "3.0.0"}, staleRelease: serviceRelease{sequence: 2, version: "2.0.0"}},
		{name: "stale-previous-higher-sequence", firstRelease: serviceRelease{sequence: 2, version: "2.0.0"}, staleRelease: serviceRelease{sequence: 3, version: "3.0.0"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			previous := fixture.current()
			firstRelease := fixture.release(test.firstRelease.sequence, test.firstRelease.version)
			staleRelease := fixture.release(test.staleRelease.sequence, test.staleRelease.version)
			firstRequest := fixture.prepareRequest("txn-stale-first-"+test.name, firstRelease, previous)
			staleRequest := fixture.prepareRequest("txn-stale-second-"+test.name, staleRelease, previous)
			firstPrepared := fixture.handle(firstRequest, fixture.artifact(firstRelease))
			if !firstPrepared.OK || firstPrepared.PreparedAck == nil {
				t.Fatalf("first prepare = %#v", firstPrepared)
			}
			secondService := fixture.newService()
			stalePrepared := secondService.Handle(context.Background(), mustPacket(t, staleRequest), staleRequest, fixture.artifact(staleRelease))
			if !stalePrepared.OK || stalePrepared.PreparedAck == nil {
				t.Fatalf("stale prepare = %#v", stalePrepared)
			}

			firstService := fixture.service
			staleService := secondService
			firstActivated := firstService.Handle(context.Background(), mustPacket(t, fixture.activateRequest(*firstPrepared.PreparedAck)), fixture.activateRequest(*firstPrepared.PreparedAck), nil)
			if !firstActivated.OK || firstActivated.Receipt == nil {
				t.Fatalf("first activation = %#v", firstActivated)
			}
			calls := fixture.runner.upgradeCalls
			staleActivateRequest := fixture.activateRequest(*stalePrepared.PreparedAck)
			staleActivated := staleService.Handle(context.Background(), mustPacket(t, staleActivateRequest), staleActivateRequest, nil)
			if staleActivated.OK || staleActivated.ErrorCode != protocol.ErrorTransactionConflict || fixture.runner.upgradeCalls != calls {
				t.Fatalf("stale activation = %#v calls=%d want=%d", staleActivated, fixture.runner.upgradeCalls, calls)
			}
			facts, err := InspectInstalled(fixture.paths, fixture.packagePublic, fixture.uid, fixture.gid)
			if err != nil || facts.Version != test.firstRelease.version || facts.ReleaseSequence != test.firstRelease.sequence {
				t.Fatalf("installed after stale activation = (%+v, %v)", facts, err)
			}
		})
	}
}

func TestServiceActivateRejectsAcceptedManifestHighWater(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-accepted-high-water", release, previous)
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	higherAccepted := fixture.release(3, "3.0.0")
	if err := os.WriteFile(fixture.paths.AcceptedManifest, higherAccepted.manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.paths.AcceptedManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	activated := fixture.handle(fixture.activateRequest(*prepared.PreparedAck), nil)
	if activated.OK || activated.ErrorCode != protocol.ErrorTransactionConflict || fixture.runner.upgradeCalls != 0 {
		t.Fatalf("accepted high-water activation = %#v calls=%d", activated, fixture.runner.upgradeCalls)
	}
	if facts, err := InspectInstalled(fixture.paths, fixture.packagePublic, fixture.uid, fixture.gid); err != nil || facts.Version != previous.CurrentVersion {
		t.Fatalf("installed after accepted high-water = (%+v, %v)", facts, err)
	}
}

func TestServiceActivateRejectsTargetWithStaleAcceptedManifest(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-stale-accepted-target", release, previous)
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	record, err := fixture.service.journals.Load(prepare.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	record.Phase = JournalInstalling
	if err := fixture.service.journals.Save(record); err != nil {
		t.Fatal(err)
	}
	fixture.installRelease(release, false)

	response := fixture.handle(fixture.activateRequest(*prepared.PreparedAck), nil)
	if response.OK || response.ErrorCode != protocol.ErrorStateUncertain || response.Receipt != nil || fixture.runner.upgradeCalls != 0 {
		t.Fatalf("target with stale accepted manifest = %#v calls=%d", response, fixture.runner.upgradeCalls)
	}
	persisted, err := fixture.service.journals.Load(prepare.TransactionID)
	if err != nil || persisted.Phase != JournalInstalling || persisted.ActiveReceipt != nil {
		t.Fatalf("journal after stale accepted target = (%+v, %v)", persisted, err)
	}
}

func TestServiceActivateRejectsHigherInstallingHighWater(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	lower := fixture.release(2, "2.0.0")
	lowerPrepare := fixture.prepareRequest("txn-lower-installing-fence", lower, previous)
	lowerPrepared := fixture.handle(lowerPrepare, fixture.artifact(lower))
	if !lowerPrepared.OK || lowerPrepared.PreparedAck == nil {
		t.Fatalf("lower prepare = %#v", lowerPrepared)
	}
	higher := fixture.release(3, "3.0.0")
	higherPrepare := fixture.prepareRequest("txn-installing-high-water", higher, previous)
	higherPrepared := fixture.handle(higherPrepare, fixture.artifact(higher))
	if !higherPrepared.OK || higherPrepared.PreparedAck == nil {
		t.Fatalf("higher prepare = %#v", higherPrepared)
	}
	higherRecord, err := fixture.service.journals.Load(higherPrepare.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	higherRecord.Phase = JournalInstalling
	if err := fixture.service.journals.Save(higherRecord); err != nil {
		t.Fatal(err)
	}
	activated := fixture.handle(fixture.activateRequest(*lowerPrepared.PreparedAck), nil)
	if activated.OK || activated.ErrorCode != protocol.ErrorTransactionConflict || fixture.runner.upgradeCalls != 0 {
		t.Fatalf("installing high-water activation = %#v calls=%d", activated, fixture.runner.upgradeCalls)
	}
}

func TestServiceCurrentRepairsMissingCurrentFromActiveJournal(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	install := fixture.installRequest("txn-current-active-journal-missing", release, previous)
	installed := fixture.handle(install, fixture.artifact(release))
	if !installed.OK || installed.Receipt == nil {
		t.Fatalf("install = %#v", installed)
	}
	if err := os.Remove(filepath.Join(fixture.paths.StateDirectory, "current.json")); err != nil {
		t.Fatal(err)
	}
	current := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent}, nil)
	if !current.OK || current.Receipt == nil || !receiptFactsMatch(*current.Receipt, *installed.Receipt) {
		t.Fatalf("current after missing active current = %#v", current)
	}
	stored, _, err := fixture.service.current.Load()
	if err != nil || !receiptFactsMatch(stored, *installed.Receipt) {
		t.Fatalf("stored current after repair = (%+v, %v)", stored, err)
	}
	fixture.verifyReceipt(stored)
}

func TestServiceActiveCurrentRepairRejectsValidForeignReceipts(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(active, previous protocol.Receipt) protocol.Receipt
	}{
		{
			name: "higher-sequence",
			mutate: func(active, _ protocol.Receipt) protocol.Receipt {
				active.InstallerTransactionID = "txn-valid-higher-current"
				active.ReleaseSequence++
				return active
			},
		},
		{
			name: "equal-sequence-mismatch",
			mutate: func(active, _ protocol.Receipt) protocol.Receipt {
				active.PreviousVersion = "9.0.0"
				return active
			},
		},
		{
			name: "lower-sequence-foreign",
			mutate: func(_, previous protocol.Receipt) protocol.Receipt {
				previous.InstallerTransactionID = "txn-valid-lower-foreign"
				return previous
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			previous := fixture.current()
			release := fixture.release(2, "2.0.0")
			install := fixture.installRequest("txn-active-current-"+test.name, release, previous)
			installed := fixture.handle(install, fixture.artifact(release))
			if !installed.OK || installed.Receipt == nil {
				t.Fatalf("install = %#v", installed)
			}
			facts, err := InspectInstalled(fixture.paths, fixture.packagePublic, fixture.uid, fixture.gid)
			if err != nil {
				t.Fatal(err)
			}
			foreign := test.mutate(*installed.Receipt, previous)
			if err := SignReceipt(&foreign, KeyMaterial{KeyID: fixture.receiptKeyID, PrivateKey: fixture.receiptPrivate}); err != nil {
				t.Fatal(err)
			}
			if err := fixture.service.current.Save(foreign, facts.ManifestSHA256); err != nil {
				t.Fatal(err)
			}

			response := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
			if response.OK || response.ErrorCode != protocol.ErrorStateUncertain || response.Receipt != nil {
				t.Fatalf("query with %s current = %#v", test.name, response)
			}
			stored, _, err := fixture.service.current.Load()
			if err != nil || !sameReceipt(stored, foreign) {
				t.Fatalf("foreign current overwritten = (%+v, %v), want %+v", stored, err, foreign)
			}
		})
	}
}

func TestServiceQueryClaimsRunnerAcrossInstances(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-cross-instance-query", release, previous)
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	record, err := fixture.service.journals.Load(prepare.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	record.Phase = JournalInstalling
	if err := fixture.service.journals.Save(record); err != nil {
		t.Fatal(err)
	}
	restarted := fixture.newService()
	fixture.runner.upgradeEntered = make(chan struct{})
	fixture.runner.releaseUpgrade = make(chan struct{})
	queries := make(chan protocol.Response, 2)
	query := protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: prepare.TransactionID}
	go func() { queries <- fixture.service.Handle(context.Background(), nil, query, nil) }()
	select {
	case <-fixture.runner.upgradeEntered:
	case <-time.After(time.Second):
		t.Fatal("first query did not enter runner")
	}
	go func() { queries <- restarted.Handle(context.Background(), nil, query, nil) }()
	select {
	case response := <-queries:
		t.Fatalf("second query completed while first runner was held: %#v", response)
	case <-time.After(100 * time.Millisecond):
	}
	close(fixture.runner.releaseUpgrade)
	first := <-queries
	second := <-queries
	if !first.OK || first.Receipt == nil || first.Receipt.Status != "active" || !second.OK || second.Receipt == nil || second.Receipt.Status != "active" {
		t.Fatalf("queries = %#v, %#v", first, second)
	}
	if fixture.runner.upgradeCalls != 1 {
		t.Fatalf("runner upgrade calls = %d, want 1", fixture.runner.upgradeCalls)
	}
}

func TestServiceRollbackClaimsRunnerAcrossInstances(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	install := fixture.installRequest("txn-cross-instance-rollback", release, previous)
	installed := fixture.handle(install, fixture.artifact(release))
	if !installed.OK || installed.Receipt == nil {
		t.Fatalf("install = %#v", installed)
	}
	rollback := fixture.rollbackRequest(install.TransactionID, release, *installed.Receipt, previous)
	fixture.runner.rollbackEntered = make(chan struct{})
	fixture.runner.releaseRollback = make(chan struct{})
	secondService := fixture.newService()
	responses := make(chan protocol.Response, 2)
	go func() { responses <- fixture.service.Handle(context.Background(), nil, rollback, nil) }()
	select {
	case <-fixture.runner.rollbackEntered:
	case <-time.After(time.Second):
		t.Fatal("first rollback did not enter runner")
	}
	query := protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}
	go func() { responses <- secondService.Handle(context.Background(), nil, query, nil) }()
	select {
	case response := <-responses:
		t.Fatalf("second rollback recovery completed while first runner was held: %#v", response)
	case <-time.After(100 * time.Millisecond):
	}
	close(fixture.runner.releaseRollback)
	first := <-responses
	second := <-responses
	if !first.OK || first.Receipt == nil || first.Receipt.Status != "rolled_back" || !second.OK || second.Receipt == nil || second.Receipt.Status != "rolled_back" {
		t.Fatalf("rollback responses = %#v, %#v", first, second)
	}
	if fixture.runner.rollbackCalls != 1 {
		t.Fatalf("runner rollback calls = %d, want 1", fixture.runner.rollbackCalls)
	}
}

func TestServiceInspectWaitsForActivationCommitAcrossInstances(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-cross-instance-inspect", release, previous)
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	fixture.runner.upgradeEntered = make(chan struct{})
	fixture.runner.releaseUpgrade = make(chan struct{})
	secondService := fixture.newService()
	activateDone := make(chan protocol.Response, 1)
	go func() {
		activateDone <- fixture.service.Handle(context.Background(), nil, fixture.activateRequest(*prepared.PreparedAck), nil)
	}()
	select {
	case <-fixture.runner.upgradeEntered:
	case <-time.After(time.Second):
		t.Fatal("activation did not enter runner")
	}
	inspectDone := make(chan protocol.Response, 1)
	go func() {
		inspectDone <- secondService.Handle(context.Background(), nil, fixture.inspectRequest(prepare.TransactionID), nil)
	}()
	select {
	case response := <-inspectDone:
		t.Fatalf("inspect completed before activation commit: %#v", response)
	case <-time.After(100 * time.Millisecond):
	}
	close(fixture.runner.releaseUpgrade)
	activated := <-activateDone
	inspected := <-inspectDone
	if !activated.OK || activated.Receipt == nil || !inspected.OK || inspected.TransactionStatus == nil || inspected.TransactionStatus.Phase != protocol.TransactionActive {
		t.Fatalf("activation/inspect = %#v, %#v", activated, inspected)
	}
	if fixture.runner.upgradeCalls != 1 {
		t.Fatalf("runner upgrade calls = %d, want 1", fixture.runner.upgradeCalls)
	}
}

func TestServiceCurrentWaitsForActivationCommitAcrossInstances(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-cross-instance-current", release, previous)
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	fixture.runner.upgradeEntered = make(chan struct{})
	fixture.runner.releaseUpgrade = make(chan struct{})
	secondService := fixture.newService()
	activateDone := make(chan protocol.Response, 1)
	go func() {
		activateDone <- fixture.service.Handle(context.Background(), nil, fixture.activateRequest(*prepared.PreparedAck), nil)
	}()
	select {
	case <-fixture.runner.upgradeEntered:
	case <-time.After(time.Second):
		t.Fatal("activation did not enter runner")
	}
	currentDone := make(chan protocol.Response, 1)
	go func() {
		currentDone <- secondService.Handle(context.Background(), nil, protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent}, nil)
	}()
	select {
	case response := <-currentDone:
		t.Fatalf("current completed before activation commit: %#v", response)
	case <-time.After(100 * time.Millisecond):
	}
	close(fixture.runner.releaseUpgrade)
	activated := <-activateDone
	current := <-currentDone
	if !activated.OK || activated.Receipt == nil || !current.OK || current.Receipt == nil || current.Receipt.CurrentVersion != release.version {
		t.Fatalf("activation/current = %#v, %#v", activated, current)
	}
	if fixture.runner.upgradeCalls != 1 {
		t.Fatalf("runner upgrade calls = %d, want 1", fixture.runner.upgradeCalls)
	}
}

func TestServiceTerminalQueriesRejectPhysicalDrift(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	install := fixture.installRequest("txn-terminal-physical-drift", release, previous)
	installed := fixture.handle(install, fixture.artifact(release))
	if !installed.OK || installed.Receipt == nil {
		t.Fatalf("install = %#v", installed)
	}
	if err := fixture.runner.switchCurrent(previous.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	secondService := fixture.newService()
	for _, request := range []protocol.Request{
		{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: install.TransactionID},
		fixture.inspectRequest(install.TransactionID),
	} {
		response := secondService.Handle(context.Background(), mustPacket(t, request), request, nil)
		if response.OK || response.ErrorCode != protocol.ErrorStateUncertain {
			t.Fatalf("physical drift request %s = %#v", request.Operation, response)
		}
	}
	rollback := fixture.rollbackRequest(install.TransactionID, release, *installed.Receipt, previous)
	response := secondService.Handle(context.Background(), mustPacket(t, rollback), rollback, nil)
	if response.OK || response.ErrorCode != protocol.ErrorStateUncertain || fixture.runner.rollbackCalls != 0 {
		t.Fatalf("rollback after physical drift = %#v calls=%d", response, fixture.runner.rollbackCalls)
	}
}

func TestServiceTerminalPersistenceFailureDoesNotReportSuccess(t *testing.T) {
	for _, operation := range []string{"query", "inspect", "rollback"} {
		t.Run(operation, func(t *testing.T) {
			fixture := newServiceFixture(t)
			previous := fixture.current()
			release := fixture.release(2, "2.0.0")
			prepare := fixture.prepareRequest("txn-terminal-current-save-failure-"+operation, release, previous)
			prepared := fixture.handle(prepare, fixture.artifact(release))
			if !prepared.OK || prepared.PreparedAck == nil {
				t.Fatalf("prepare = %#v", prepared)
			}
			originalPath := fixture.service.current.path
			badPath := filepath.Join(fixture.paths.StateDirectory, "current-save-directory")
			if err := os.Mkdir(badPath, 0o700); err != nil {
				t.Fatal(err)
			}
			fixture.service.journals.beforeWrite = func(_, next JournalRecord) {
				if next.Phase == JournalActive {
					fixture.service.current.path = badPath
				}
			}
			failed := fixture.handle(fixture.activateRequest(*prepared.PreparedAck), nil)
			fixture.service.current.path = originalPath
			if failed.OK || failed.ErrorCode != protocol.ErrorStateUncertain || failed.Receipt != nil {
				t.Fatalf("activation after current save failure = %#v", failed)
			}
			record, err := fixture.service.journals.Load(prepare.TransactionID)
			if err != nil || record.Phase != JournalActive || record.ActiveReceipt == nil {
				t.Fatalf("terminal journal after current save failure = (%+v, %v)", record, err)
			}
			oldReceipt := *record.ActiveReceipt
			newPublic, newPrivate, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			fixture.receiptPublic = newPublic
			fixture.receiptPrivate = newPrivate
			fixture.receiptKeyID = "helper-test-recovery-new"
			fixture.receiptPublicKeys[fixture.receiptKeyID] = append(ed25519.PublicKey(nil), newPublic...)
			fixture.service = fixture.newService()

			switch operation {
			case "query":
				response := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: prepare.TransactionID}, nil)
				if !response.OK || response.Receipt == nil || !sameReceipt(*response.Receipt, oldReceipt) {
					t.Fatalf("query recovery = %#v", response)
				}
			case "inspect":
				response := fixture.handle(fixture.inspectRequest(prepare.TransactionID), nil)
				if !response.OK || response.TransactionStatus == nil || response.TransactionStatus.Phase != protocol.TransactionActive ||
					response.TransactionStatus.Receipt == nil || !sameReceipt(*response.TransactionStatus.Receipt, oldReceipt) {
					t.Fatalf("inspect recovery = %#v", response)
				}
			case "rollback":
				response := fixture.handle(fixture.rollbackRequest(prepare.TransactionID, release, oldReceipt, previous), nil)
				if !response.OK || response.Receipt == nil || response.Receipt.Status != "rolled_back" || fixture.runner.rollbackCalls != 1 {
					t.Fatalf("rollback recovery = %#v calls=%d", response, fixture.runner.rollbackCalls)
				}
			}
			if fixture.runner.upgradeCalls != 1 {
				t.Fatalf("recovery repeated upgrade runner: %d", fixture.runner.upgradeCalls)
			}
			record, err = fixture.service.journals.Load(prepare.TransactionID)
			if err != nil || record.ActiveReceipt == nil || !sameReceipt(*record.ActiveReceipt, oldReceipt) {
				t.Fatalf("journal historical receipt after recovery = (%+v, %v)", record, err)
			}
			if operation != "rollback" {
				current, _, err := fixture.service.current.Load()
				if err != nil || current.Signature.KeyID != fixture.receiptKeyID || !receiptFactsMatch(current, oldReceipt) {
					t.Fatalf("repaired current = (%+v, %v), journal=%+v", current, err, oldReceipt)
				}
			}
		})
	}
}

func TestServiceRolledBackCurrentRecoveryAfterPersistenceFailure(t *testing.T) {
	for _, operation := range []string{"query", "current-missing", "inspect", "rollback"} {
		t.Run(operation, func(t *testing.T) {
			fixture := newServiceFixture(t)
			previous := fixture.current()
			release := fixture.release(2, "2.0.0")
			install := fixture.installRequest("txn-rollback-current-recovery-"+operation, release, previous)
			installed := fixture.handle(install, fixture.artifact(release))
			if !installed.OK || installed.Receipt == nil {
				t.Fatalf("install = %#v", installed)
			}
			rollback := fixture.rollbackRequest(install.TransactionID, release, *installed.Receipt, previous)
			originalPath := fixture.service.current.path
			badPath := filepath.Join(fixture.paths.StateDirectory, "rollback-current-save-directory-"+operation)
			if err := os.Mkdir(badPath, 0o700); err != nil {
				t.Fatal(err)
			}
			fixture.service.journals.beforeWrite = func(_, next JournalRecord) {
				if next.Phase == JournalRolledBack {
					fixture.service.current.path = badPath
				}
			}
			failed := fixture.handle(rollback, nil)
			fixture.service.current.path = originalPath
			fixture.service.journals.beforeWrite = nil
			if failed.OK || failed.ErrorCode != protocol.ErrorStateUncertain || failed.Receipt != nil {
				t.Fatalf("rollback after current save failure = %#v", failed)
			}
			record, err := fixture.service.journals.Load(install.TransactionID)
			if err != nil || record.Phase != JournalRolledBack || record.RollbackReceipt == nil {
				t.Fatalf("rollback terminal journal after current save failure = (%+v, %v)", record, err)
			}
			historicalRollback := *record.RollbackReceipt
			if operation == "current-missing" {
				if err := os.Remove(originalPath); err != nil {
					t.Fatal(err)
				}
			}
			newPublic, newPrivate, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			fixture.receiptPublic = newPublic
			fixture.receiptPrivate = newPrivate
			fixture.receiptKeyID = "helper-test-rollback-recovery-new"
			fixture.receiptPublicKeys[fixture.receiptKeyID] = append(ed25519.PublicKey(nil), newPublic...)
			fixture.service = fixture.newService()

			switch operation {
			case "query":
				response := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
				if !response.OK || response.Receipt == nil || !sameReceipt(*response.Receipt, historicalRollback) {
					t.Fatalf("query recovery = %#v", response)
				}
			case "current-missing":
				response := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent}, nil)
				if !response.OK || response.Receipt == nil || response.Receipt.Status != "active" {
					t.Fatalf("current recovery = %#v", response)
				}
			case "inspect":
				response := fixture.handle(fixture.inspectRequest(install.TransactionID), nil)
				if !response.OK || response.TransactionStatus == nil || response.TransactionStatus.Phase != protocol.TransactionRolledBack ||
					response.TransactionStatus.Receipt == nil || !sameReceipt(*response.TransactionStatus.Receipt, historicalRollback) {
					t.Fatalf("inspect recovery = %#v", response)
				}
			case "rollback":
				response := fixture.handle(rollback, nil)
				if !response.OK || response.Receipt == nil || !sameReceipt(*response.Receipt, historicalRollback) {
					t.Fatalf("rollback replay recovery = %#v", response)
				}
			}
			restored, manifestDigest, err := fixture.service.current.Load()
			if err != nil || restored.Signature.KeyID != fixture.receiptKeyID || restored.ReleaseSequence != release.sequence ||
				restored.CurrentVersion != previous.CurrentVersion || restored.PreviousVersion != release.version ||
				restored.ArtifactSHA256 != previous.ArtifactSHA256 || manifestDigest != digestBytes(fixture.release(1, "1.0.0").manifest) {
				t.Fatalf("restored current after %s = (%+v, %s, %v)", operation, restored, manifestDigest, err)
			}
			record, err = fixture.service.journals.Load(install.TransactionID)
			if err != nil || record.RollbackReceipt == nil || !sameReceipt(*record.RollbackReceipt, historicalRollback) {
				t.Fatalf("historical rollback receipt after recovery = (%+v, %v)", record, err)
			}

			next := fixture.release(3, "3.0.0")
			prepare := fixture.prepareRequest("txn-after-rollback-current-recovery-"+operation, next, restored)
			prepared := fixture.handle(prepare, fixture.artifact(next))
			if !prepared.OK || prepared.PreparedAck == nil {
				t.Fatalf("next prepare after %s recovery = %#v", operation, prepared)
			}
			activated := fixture.handle(fixture.activateRequest(*prepared.PreparedAck), nil)
			if !activated.OK || activated.Receipt == nil || activated.Receipt.CurrentVersion != next.version || activated.Receipt.ReleaseSequence != next.sequence {
				t.Fatalf("next activate after %s recovery = %#v", operation, activated)
			}
		})
	}
}

func TestServiceRolledBackCurrentRecoveryRejectsForeignAndAmbiguousState(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(protocol.Receipt) protocol.Receipt
	}{
		{
			name: "equal-sequence-foreign-current",
			mutate: func(receipt protocol.Receipt) protocol.Receipt {
				receipt.InstallerTransactionID = "current-valid-equal-foreign"
				return receipt
			},
		},
		{
			name: "higher-sequence-foreign-current",
			mutate: func(receipt protocol.Receipt) protocol.Receipt {
				receipt.InstallerTransactionID = "current-valid-higher-foreign"
				receipt.ReleaseSequence++
				return receipt
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			previous := fixture.current()
			release := fixture.release(2, "2.0.0")
			install := fixture.installRequest("txn-rollback-reject-"+test.name, release, previous)
			installed := fixture.handle(install, fixture.artifact(release))
			if !installed.OK || installed.Receipt == nil {
				t.Fatalf("install = %#v", installed)
			}
			rolledBack := fixture.handle(fixture.rollbackRequest(install.TransactionID, release, *installed.Receipt, previous), nil)
			if !rolledBack.OK || rolledBack.Receipt == nil {
				t.Fatalf("rollback = %#v", rolledBack)
			}
			facts, err := InspectInstalled(fixture.paths, fixture.packagePublic, fixture.uid, fixture.gid)
			if err != nil {
				t.Fatal(err)
			}
			current, _, err := fixture.service.current.Load()
			if err != nil {
				t.Fatal(err)
			}
			foreign := test.mutate(current)
			if err := SignReceipt(&foreign, KeyMaterial{KeyID: fixture.receiptKeyID, PrivateKey: fixture.receiptPrivate}); err != nil {
				t.Fatal(err)
			}
			if err := fixture.service.current.Save(foreign, facts.ManifestSHA256); err != nil {
				t.Fatal(err)
			}
			response := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
			if response.OK || response.ErrorCode != protocol.ErrorStateUncertain || response.Receipt != nil {
				t.Fatalf("query with %s = %#v", test.name, response)
			}
			stored, _, err := fixture.service.current.Load()
			if err != nil || !sameReceipt(stored, foreign) {
				t.Fatalf("foreign current overwritten = (%+v, %v), want %+v", stored, err, foreign)
			}
		})
	}

	t.Run("duplicate-highest-rolled-back-journal", func(t *testing.T) {
		fixture := newServiceFixture(t)
		previous := fixture.current()
		release := fixture.release(2, "2.0.0")
		install := fixture.installRequest("txn-rollback-ambiguous-original", release, previous)
		installed := fixture.handle(install, fixture.artifact(release))
		if !installed.OK || installed.Receipt == nil {
			t.Fatalf("install = %#v", installed)
		}
		rolledBack := fixture.handle(fixture.rollbackRequest(install.TransactionID, release, *installed.Receipt, previous), nil)
		if !rolledBack.OK || rolledBack.Receipt == nil {
			t.Fatalf("rollback = %#v", rolledBack)
		}
		record, err := fixture.service.journals.Load(install.TransactionID)
		if err != nil || record.ActiveReceipt == nil || record.RollbackReceipt == nil {
			t.Fatalf("rolled-back journal = (%+v, %v)", record, err)
		}
		duplicate := record
		duplicate.TransactionID = "txn-rollback-ambiguous-duplicate"
		active := *record.ActiveReceipt
		active.InstallerTransactionID = duplicate.TransactionID
		if err := SignReceipt(&active, KeyMaterial{KeyID: fixture.receiptKeyID, PrivateKey: fixture.receiptPrivate}); err != nil {
			t.Fatal(err)
		}
		rollbackReceipt := *record.RollbackReceipt
		rollbackReceipt.InstallerTransactionID = duplicate.TransactionID
		if err := SignReceipt(&rollbackReceipt, KeyMaterial{KeyID: fixture.receiptKeyID, PrivateKey: fixture.receiptPrivate}); err != nil {
			t.Fatal(err)
		}
		duplicate.ActiveReceipt = &active
		duplicate.RollbackReceipt = &rollbackReceipt
		if err := fixture.service.journals.Save(duplicate); err != nil {
			t.Fatal(err)
		}
		before, _, err := fixture.service.current.Load()
		if err != nil {
			t.Fatal(err)
		}
		response := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
		if response.OK || response.ErrorCode != protocol.ErrorStateUncertain || response.Receipt != nil {
			t.Fatalf("query with duplicate highest rolled-back journal = %#v", response)
		}
		after, _, err := fixture.service.current.Load()
		if err != nil || !sameReceipt(after, before) {
			t.Fatalf("current mutated by ambiguous recovery = (%+v, %v), want %+v", after, err, before)
		}
	})
}

func TestServiceLegacyJournalCompatibilityAndMigration(t *testing.T) {
	t.Run("terminal-history-does-not-poison-new-v2-prepare", func(t *testing.T) {
		fixture := newServiceFixture(t)
		previous := fixture.current()
		release2 := fixture.release(2, "2.0.0")
		install2 := fixture.installRequest("txn-legacy-history-active", release2, previous)
		installed2 := fixture.handle(install2, fixture.artifact(release2))
		if !installed2.OK || installed2.Receipt == nil {
			t.Fatalf("install2 = %#v", installed2)
		}
		rewriteJournalAsLegacyV1(t, fixture, install2.TransactionID)
		fixture.service = fixture.newService()
		query := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: install2.TransactionID}, nil)
		if !query.OK || query.Receipt == nil || !sameReceipt(*query.Receipt, *installed2.Receipt) {
			t.Fatalf("legacy active query = %#v", query)
		}
		current := fixture.current()
		release3 := fixture.release(3, "3.0.0")
		prepare3 := fixture.prepareRequest("txn-after-legacy-history", release3, current)
		prepared3 := fixture.handle(prepare3, fixture.artifact(release3))
		if !prepared3.OK || prepared3.PreparedAck == nil {
			t.Fatalf("new prepare after legacy history = %#v", prepared3)
		}
		requireJournalV2PreviousBinding(t, fixture, prepare3.TransactionID, release2.sequence, digestBytes(release2.manifest))
	})

	t.Run("exact-v1-in-flight-migrates-before-runner", func(t *testing.T) {
		fixture := newServiceFixture(t)
		previous := fixture.current()
		release := fixture.release(2, "2.0.0")
		prepare := fixture.prepareRequest("txn-legacy-in-flight-exact", release, previous)
		prepared := fixture.handle(prepare, fixture.artifact(release))
		if !prepared.OK || prepared.PreparedAck == nil {
			t.Fatalf("prepare = %#v", prepared)
		}
		rewriteJournalAsLegacyV1(t, fixture, prepare.TransactionID)
		fixture.service = fixture.newService()
		activated := fixture.handle(fixture.activateRequest(*prepared.PreparedAck), nil)
		if !activated.OK || activated.Receipt == nil || activated.Receipt.Status != "active" || fixture.runner.upgradeCalls != 1 {
			t.Fatalf("legacy activation recovery = %#v calls=%d", activated, fixture.runner.upgradeCalls)
		}
		requireJournalV2PreviousBinding(t, fixture, prepare.TransactionID, previous.ReleaseSequence, digestBytes(fixture.release(1, "1.0.0").manifest))
	})

	t.Run("exact-v1-installing-migrates-before-runner", func(t *testing.T) {
		fixture := newServiceFixture(t)
		previous := fixture.current()
		release := fixture.release(2, "2.0.0")
		prepare := fixture.prepareRequest("txn-legacy-installing-exact", release, previous)
		prepared := fixture.handle(prepare, fixture.artifact(release))
		if !prepared.OK || prepared.PreparedAck == nil {
			t.Fatalf("prepare = %#v", prepared)
		}
		record, err := fixture.service.journals.Load(prepare.TransactionID)
		if err != nil {
			t.Fatal(err)
		}
		record.Phase = JournalInstalling
		if err := fixture.service.journals.Save(record); err != nil {
			t.Fatal(err)
		}
		rewriteJournalAsLegacyV1(t, fixture, prepare.TransactionID)
		fixture.service = fixture.newService()
		activated := fixture.handle(fixture.activateRequest(*prepared.PreparedAck), nil)
		if !activated.OK || activated.Receipt == nil || activated.Receipt.Status != "active" || fixture.runner.upgradeCalls != 1 {
			t.Fatalf("legacy installing activation recovery = %#v calls=%d", activated, fixture.runner.upgradeCalls)
		}
		requireJournalV2PreviousBinding(t, fixture, prepare.TransactionID, previous.ReleaseSequence, digestBytes(fixture.release(1, "1.0.0").manifest))
	})

	for _, test := range []struct {
		name     string
		sequence uint64
		version  string
	}{
		{name: "equal-high-water", sequence: 2, version: "2.1.0"},
		{name: "higher-high-water", sequence: 3, version: "3.0.0"},
	} {
		t.Run(test.name+"-rejects-without-mutation", func(t *testing.T) {
			fixture := newServiceFixture(t)
			previous := fixture.current()
			releaseA := fixture.release(2, "2.0.0")
			prepareA := fixture.prepareRequest("txn-legacy-high-water-a-"+test.name, releaseA, previous)
			preparedA := fixture.handle(prepareA, fixture.artifact(releaseA))
			if !preparedA.OK || preparedA.PreparedAck == nil {
				t.Fatalf("prepare A = %#v", preparedA)
			}
			rewriteJournalAsLegacyV1(t, fixture, prepareA.TransactionID)

			releaseB := fixture.release(test.sequence, test.version)
			prepareB := fixture.prepareRequest("txn-high-water-b-"+test.name, releaseB, previous)
			preparedB := fixture.handle(prepareB, fixture.artifact(releaseB))
			if !preparedB.OK || preparedB.PreparedAck == nil {
				t.Fatalf("prepare B = %#v", preparedB)
			}
			recordB, err := fixture.service.journals.Load(prepareB.TransactionID)
			if err != nil {
				t.Fatal(err)
			}
			recordB.Phase = JournalInstalling
			if err := fixture.service.journals.Save(recordB); err != nil {
				t.Fatal(err)
			}

			journalPath := filepath.Join(fixture.paths.StateDirectory, "journal-"+prepareA.TransactionID+".json")
			journalBefore, err := os.ReadFile(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			currentPath := filepath.Join(fixture.paths.StateDirectory, "current.json")
			currentBefore, err := os.ReadFile(currentPath)
			if err != nil {
				t.Fatal(err)
			}

			fixture.service = fixture.newService()
			activated := fixture.handle(fixture.activateRequest(*preparedA.PreparedAck), nil)
			if activated.OK || activated.ErrorCode != protocol.ErrorTransactionConflict || activated.Receipt != nil || fixture.runner.upgradeCalls != 0 {
				t.Fatalf("activation with %s = %#v calls=%d", test.name, activated, fixture.runner.upgradeCalls)
			}
			journalAfter, err := os.ReadFile(journalPath)
			if err != nil || !bytes.Equal(journalBefore, journalAfter) {
				t.Fatalf("A journal mutated by %s rejection: %v", test.name, err)
			}
			currentAfter, err := os.ReadFile(currentPath)
			if err != nil || !bytes.Equal(currentBefore, currentAfter) {
				t.Fatalf("current mutated by %s rejection: %v", test.name, err)
			}
		})
	}

	t.Run("ambiguous-v1-in-flight-fails-locally-without-mutation", func(t *testing.T) {
		fixture := newServiceFixture(t)
		previous := fixture.current()
		release := fixture.release(2, "2.0.0")
		prepare := fixture.prepareRequest("txn-legacy-in-flight-ambiguous", release, previous)
		prepared := fixture.handle(prepare, fixture.artifact(release))
		if !prepared.OK || prepared.PreparedAck == nil {
			t.Fatalf("prepare = %#v", prepared)
		}
		rewriteJournalAsLegacyV1(t, fixture, prepare.TransactionID)
		journalPath := filepath.Join(fixture.paths.StateDirectory, "journal-"+prepare.TransactionID+".json")
		journalBefore, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.service.current.Save(previous, digestOf([]byte("foreign-current-manifest"))); err != nil {
			t.Fatal(err)
		}
		currentPath := filepath.Join(fixture.paths.StateDirectory, "current.json")
		currentBefore, err := os.ReadFile(currentPath)
		if err != nil {
			t.Fatal(err)
		}
		fixture.service = fixture.newService()
		current := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent}, nil)
		if current.OK || current.ErrorCode != protocol.ErrorStateUncertain || current.Receipt != nil {
			t.Fatalf("current with ambiguous legacy in-flight = %#v", current)
		}
		currentAfter, err := os.ReadFile(currentPath)
		if err != nil || !bytes.Equal(currentBefore, currentAfter) {
			t.Fatalf("current mutated by ambiguous legacy in-flight: %v", err)
		}
		activated := fixture.handle(fixture.activateRequest(*prepared.PreparedAck), nil)
		if activated.OK || activated.ErrorCode != protocol.ErrorStateUncertain || activated.Receipt != nil || fixture.runner.upgradeCalls != 0 {
			t.Fatalf("ambiguous legacy activation = %#v calls=%d", activated, fixture.runner.upgradeCalls)
		}
		journalAfter, err := os.ReadFile(journalPath)
		if err != nil || !bytes.Equal(journalBefore, journalAfter) {
			t.Fatalf("ambiguous legacy journal mutated: %v", err)
		}
	})
}

func TestServicePrepareAndCurrentSerializeAcrossInstances(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-prepare-current-race", release, previous)
	entered := make(chan struct{})
	releaseSave := make(chan struct{})
	fixture.service.journals.beforeWrite = func(_, next JournalRecord) {
		if next.Phase == JournalPrepared {
			close(entered)
			<-releaseSave
		}
	}
	preparedDone := make(chan protocol.Response, 1)
	go func() {
		preparedDone <- fixture.service.Handle(context.Background(), nil, prepare, fixture.artifact(release))
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("prepare did not reach durable journal write")
	}
	secondService := fixture.newService()
	currentDone := make(chan protocol.Response, 1)
	go func() {
		currentDone <- secondService.Handle(context.Background(), nil, protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent}, nil)
	}()
	select {
	case response := <-currentDone:
		t.Fatalf("current completed while prepare was committing: %#v", response)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseSave)
	prepared := <-preparedDone
	current := <-currentDone
	if !prepared.OK || prepared.PreparedAck == nil || current.OK || current.ErrorCode != protocol.ErrorStateUncertain || current.Receipt != nil {
		t.Fatalf("prepare/current = %#v, %#v", prepared, current)
	}
}

func TestServiceAbortWinsBeforeActivationAcrossInstances(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	prepare := fixture.prepareRequest("txn-abort-wins", release, previous)
	prepared := fixture.handle(prepare, fixture.artifact(release))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("prepare = %#v", prepared)
	}
	ack := *prepared.PreparedAck
	aborter := fixture.newService()
	entered := make(chan struct{})
	releaseSave := make(chan struct{})
	aborter.journals.beforeWrite = func(_, next JournalRecord) {
		if next.Phase == JournalAborted {
			close(entered)
			<-releaseSave
		}
	}
	abortDone := make(chan protocol.Response, 1)
	go func() { abortDone <- aborter.Handle(context.Background(), nil, fixture.abortPreparedRequest(ack), nil) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("abort did not reach durable journal write")
	}
	activateDone := make(chan protocol.Response, 1)
	go func() {
		activateDone <- fixture.service.Handle(context.Background(), nil, fixture.activateRequest(ack), nil)
	}()
	select {
	case response := <-activateDone:
		t.Fatalf("activation completed before abort commit: %#v", response)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseSave)
	aborted := <-abortDone
	activated := <-activateDone
	if !aborted.OK || aborted.TransactionStatus == nil || aborted.TransactionStatus.Phase != protocol.TransactionAborted {
		t.Fatalf("abort = %#v", aborted)
	}
	if activated.OK || activated.ErrorCode != protocol.ErrorTransactionConflict || fixture.runner.upgradeCalls != 0 {
		t.Fatalf("activation after abort = %#v calls=%d", activated, fixture.runner.upgradeCalls)
	}
}

func TestServicePrepareDoesNotOverwriteConcurrentTransactionStaging(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	releaseA := fixture.release(2, "2.0.0")
	releaseB := fixture.release(3, "3.0.0")
	requestA := fixture.prepareRequest("txn-staging-race", releaseA, previous)
	requestB := fixture.prepareRequest("txn-staging-race", releaseB, previous)
	entered := make(chan struct{})
	releaseSave := make(chan struct{})
	fixture.service.journals.beforeWrite = func(_, next JournalRecord) {
		if next.Phase == JournalPrepared {
			close(entered)
			<-releaseSave
		}
	}
	responseA := make(chan protocol.Response, 1)
	go func() {
		responseA <- fixture.service.Handle(context.Background(), mustPacket(t, requestA), requestA, fixture.artifact(releaseA))
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first prepare did not reach durable journal write")
	}
	secondService := fixture.newService()
	responseB := make(chan protocol.Response, 1)
	go func() {
		responseB <- secondService.Handle(context.Background(), mustPacket(t, requestB), requestB, fixture.artifact(releaseB))
	}()
	select {
	case response := <-responseB:
		t.Fatalf("conflicting prepare completed while first prepare was held: %#v", response)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseSave)
	preparedA := <-responseA
	preparedB := <-responseB
	if !preparedA.OK || preparedA.PreparedAck == nil || preparedB.OK || preparedB.ErrorCode != protocol.ErrorTransactionConflict {
		t.Fatalf("prepare responses = %#v, %#v", preparedA, preparedB)
	}
	record, err := fixture.service.journals.Load(requestA.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(fixture.paths.StateDirectory, "transactions", requestA.TransactionID)
	staged, err := stagedBundleForTest(t, directory)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := VerifyReleaseManifest(staged, fixture.packagePublic, ManifestExpectation{
		ReleaseSequence: releaseA.sequence, TargetVersion: releaseA.version, Platform: requestA.Platform, Architecture: requestA.Architecture,
	})
	if err != nil || manifest.ManifestSHA256 != record.ManifestSHA256 || staged.OuterSHA256 != record.OuterArtifactSHA256 {
		t.Fatalf("staged contents mismatch: manifest=%+v err=%v record=%+v staged=%+v", manifest, err, record, staged)
	}
}

func TestServicePrepareRejectsMismatchedOrphanWithoutOverwrite(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	releaseA := fixture.release(2, "2.0.0")
	releaseB := fixture.release(3, "3.0.0")
	request := fixture.prepareRequest("txn-mismatched-orphan", releaseA, previous)
	directory := filepath.Join(fixture.paths.StateDirectory, "transactions", request.TransactionID)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := StageReleaseBundle(fixture.artifact(releaseB), directory, int64(len(releaseB.bundle)), digestOf(releaseB.bundle)); err != nil {
		t.Fatal(err)
	}
	response := fixture.handle(request, fixture.artifact(releaseA))
	if response.OK || response.ErrorCode != protocol.ErrorStateUncertain || fixture.runner.upgradeCalls != 0 {
		t.Fatalf("mismatched orphan = %#v calls=%d", response, fixture.runner.upgradeCalls)
	}
	staged, err := stagedBundleForTest(t, directory)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := VerifyReleaseManifest(staged, fixture.packagePublic, ManifestExpectation{
		ReleaseSequence: releaseB.sequence, TargetVersion: releaseB.version, Platform: request.Platform, Architecture: request.Architecture,
	})
	if err != nil || manifest.Version != releaseB.version {
		t.Fatalf("mismatched orphan was overwritten: manifest=%+v err=%v", manifest, err)
	}
}

func TestServiceV2AbortPreparedRejectsInstallingAndActive(t *testing.T) {
	t.Run("installing", func(t *testing.T) {
		fixture := newServiceFixture(t)
		previous := fixture.current()
		release := fixture.release(2, "2.0.0")
		prepare := fixture.prepareRequest("txn-v2-abort-installing", release, previous)
		prepared := fixture.handle(prepare, fixture.artifact(release))
		if !prepared.OK || prepared.PreparedAck == nil {
			t.Fatalf("prepare = %#v", prepared)
		}
		record, err := fixture.service.journals.Load(prepare.TransactionID)
		if err != nil {
			t.Fatal(err)
		}
		record.Phase = JournalInstalling
		if err := fixture.service.journals.Save(record); err != nil {
			t.Fatal(err)
		}
		response := fixture.handle(fixture.abortPreparedRequest(*prepared.PreparedAck), nil)
		if response.OK || response.ErrorCode != protocol.ErrorTransactionConflict || fixture.runner.upgradeCalls != 0 || fixture.runner.rollbackCalls != 0 {
			t.Fatalf("installing abort = %#v upgrade=%d rollback=%d", response, fixture.runner.upgradeCalls, fixture.runner.rollbackCalls)
		}
	})

	t.Run("active", func(t *testing.T) {
		fixture := newServiceFixture(t)
		previous := fixture.current()
		release := fixture.release(2, "2.0.0")
		prepare := fixture.prepareRequest("txn-v2-abort-active", release, previous)
		prepared := fixture.handle(prepare, fixture.artifact(release))
		if !prepared.OK || prepared.PreparedAck == nil {
			t.Fatalf("prepare = %#v", prepared)
		}
		activated := fixture.handle(fixture.activateRequest(*prepared.PreparedAck), nil)
		if !activated.OK || activated.Receipt == nil {
			t.Fatalf("activate = %#v", activated)
		}
		upgradeCalls := fixture.runner.upgradeCalls
		response := fixture.handle(fixture.abortPreparedRequest(*prepared.PreparedAck), nil)
		if response.OK || response.ErrorCode != protocol.ErrorTransactionConflict || fixture.runner.upgradeCalls != upgradeCalls {
			t.Fatalf("active abort = %#v calls=%d", response, fixture.runner.upgradeCalls)
		}
	})
}

func TestServiceV2SIGKILLWindowsFailClosedAndDoNotRepeatRunner(t *testing.T) {
	t.Run("installing before activation resumes once", func(t *testing.T) {
		fixture := newServiceFixture(t)
		previous := fixture.current()
		release := fixture.release(2, "2.0.0")
		prepare := fixture.prepareRequest("txn-v2-before-activation", release, previous)
		prepared := fixture.handle(prepare, fixture.artifact(release))
		if !prepared.OK || prepared.PreparedAck == nil {
			t.Fatalf("prepare = %#v", prepared)
		}
		record, err := fixture.service.journals.Load(prepare.TransactionID)
		if err != nil {
			t.Fatal(err)
		}
		record.Phase = JournalInstalling
		if err := fixture.service.journals.Save(record); err != nil {
			t.Fatal(err)
		}
		fixture.service = fixture.newService()
		response := fixture.handle(fixture.activateRequest(*prepared.PreparedAck), nil)
		if !response.OK || response.Receipt == nil || response.Receipt.Status != "active" || fixture.runner.upgradeCalls != 1 {
			t.Fatalf("pre-activation recovery = %#v calls=%d", response, fixture.runner.upgradeCalls)
		}
	})

	t.Run("installing after activation persists receipt without runner", func(t *testing.T) {
		fixture := newServiceFixture(t)
		previous := fixture.current()
		release := fixture.release(2, "2.0.0")
		prepare := fixture.prepareRequest("txn-v2-after-activation", release, previous)
		prepared := fixture.handle(prepare, fixture.artifact(release))
		if !prepared.OK || prepared.PreparedAck == nil {
			t.Fatalf("prepare = %#v", prepared)
		}
		record, err := fixture.service.journals.Load(prepare.TransactionID)
		if err != nil {
			t.Fatal(err)
		}
		record.Phase = JournalInstalling
		if err := fixture.service.journals.Save(record); err != nil {
			t.Fatal(err)
		}
		fixture.installRelease(release, true)
		fixture.service = fixture.newService()
		response := fixture.handle(fixture.activateRequest(*prepared.PreparedAck), nil)
		if !response.OK || response.Receipt == nil || response.Receipt.Status != "active" || fixture.runner.upgradeCalls != 0 {
			t.Fatalf("post-activation recovery = %#v calls=%d", response, fixture.runner.upgradeCalls)
		}
	})

	t.Run("installing with third state is uncertain without runner", func(t *testing.T) {
		fixture := newServiceFixture(t)
		previous := fixture.current()
		release := fixture.release(2, "2.0.0")
		prepare := fixture.prepareRequest("txn-v2-third-state", release, previous)
		prepared := fixture.handle(prepare, fixture.artifact(release))
		if !prepared.OK || prepared.PreparedAck == nil {
			t.Fatalf("prepare = %#v", prepared)
		}
		record, err := fixture.service.journals.Load(prepare.TransactionID)
		if err != nil {
			t.Fatal(err)
		}
		record.Phase = JournalInstalling
		if err := fixture.service.journals.Save(record); err != nil {
			t.Fatal(err)
		}
		fixture.installRelease(fixture.release(3, "3.0.0"), true)
		fixture.service = fixture.newService()
		response := fixture.handle(fixture.activateRequest(*prepared.PreparedAck), nil)
		if response.OK || response.ErrorCode != protocol.ErrorStateUncertain || fixture.runner.upgradeCalls != 0 || fixture.runner.rollbackCalls != 0 {
			t.Fatalf("third-state recovery = %#v upgrade=%d rollback=%d", response, fixture.runner.upgradeCalls, fixture.runner.rollbackCalls)
		}
	})
}

func TestServiceAutomaticRollbackAndRollbackFailureRecovery(t *testing.T) {
	t.Run("automatic rollback", func(t *testing.T) {
		fixture := newServiceFixture(t)
		fixture.runner.autoRollback = true
		fixture.runner.upgradeErr = ErrPackagingCommand
		previous := fixture.current()
		release := fixture.release(2, "2.0.0")
		request := fixture.installRequest("txn-auto", release, previous)
		response := fixture.handle(request, fixture.artifact(release))
		if !response.OK || response.Receipt == nil || response.Receipt.Status != "rolled_back" || response.Receipt.CurrentVersion != previous.CurrentVersion {
			t.Fatalf("automatic rollback = %#v", response)
		}
		record, err := fixture.service.journals.Load(request.TransactionID)
		if err != nil || record.Phase != JournalRolledBack || record.ActiveReceipt != nil || record.RollbackPayloadSHA256 != "" {
			t.Fatalf("automatic rollback journal = (%+v, %v)", record, err)
		}
		// Packaging never publishes the failed release's manifest, so the
		// accepted sequence stays below the record's; current must still
		// report the restored release (the Agent probes it right after).
		for _, service := range []*Service{fixture.service, fixture.newService()} {
			fixture.service = service
			current := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent}, nil)
			if !current.OK || current.Receipt == nil || current.Receipt.CurrentVersion != previous.CurrentVersion ||
				current.Receipt.Status != "active" {
				t.Fatalf("current after automatic rollback = %#v", current)
			}
		}
	})

	t.Run("v3 automatic rollback then current", func(t *testing.T) {
		fixture := newServiceFixture(t)
		baseline := fixture.current()
		forward := fixture.release(12, "2.0.0")
		active := fixture.activateV3("txn-v3-auto-current-forward", 20, protocol.ActionUpgrade, forward, baseline)
		fixture.runner.autoRollback = true
		fixture.runner.upgradeErr = ErrPackagingCommand
		failing := fixture.release(13, "3.0.0")
		request := fixture.prepareRequest("txn-v3-auto-current-failing", failing, active)
		request.ProtocolVersion = protocol.JournalV3Version
		request.ExecutionSequence = 21
		request.Action = protocol.ActionUpgrade
		prepared := fixture.handle(request, fixture.artifact(failing))
		if !prepared.OK || prepared.PreparedAck == nil {
			t.Fatalf("v3 prepare = %#v", prepared)
		}
		activate := fixture.activateRequest(*prepared.PreparedAck)
		activate.ProtocolVersion = protocol.JournalV3Version
		rolledBack := fixture.handle(activate, nil)
		if !rolledBack.OK || rolledBack.Receipt == nil || rolledBack.Receipt.Status != "rolled_back" {
			t.Fatalf("v3 automatic rollback = %#v", rolledBack)
		}
		for _, service := range []*Service{fixture.service, fixture.newService()} {
			fixture.service = service
			current := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent}, nil)
			if !current.OK || current.Receipt == nil || current.ProtocolVersion != protocol.Version ||
				current.Receipt.Status != "active" || current.Receipt.CurrentVersion != rolledBack.Receipt.CurrentVersion {
				t.Fatalf("current after v3 automatic rollback = %#v", current)
			}
		}
	})

	t.Run("rollback failure then restart", func(t *testing.T) {
		fixture := newServiceFixture(t)
		previous := fixture.current()
		release := fixture.release(2, "2.0.0")
		install := fixture.installRequest("txn-rollback-fail", release, previous)
		installed := fixture.handle(install, fixture.artifact(release))
		if !installed.OK || installed.Receipt == nil {
			t.Fatalf("install = %#v", installed)
		}
		fixture.runner.rollbackErr = ErrPackagingCommand
		rollback := fixture.rollbackRequest(install.TransactionID, release, *installed.Receipt, previous)
		failed := fixture.handle(rollback, nil)
		if failed.OK || failed.ErrorCode != protocol.ErrorRollbackFailed {
			t.Fatalf("rollback failure = %#v", failed)
		}
		record, err := fixture.service.journals.Load(install.TransactionID)
		if err != nil || record.Phase != JournalRollbacking {
			t.Fatalf("rollback journal = (%+v, %v)", record, err)
		}
		fixture.runner.rollbackErr = nil
		fixture.service = fixture.newService()
		recovered := fixture.handle(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
		if !recovered.OK || recovered.Receipt == nil || recovered.Receipt.Status != "rolled_back" || fixture.runner.rollbackCalls != 2 {
			t.Fatalf("rollback recovery = %#v calls=%d", recovered, fixture.runner.rollbackCalls)
		}
	})
}

func TestServiceResponseLossAndHelperRestart(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	install := fixture.installRequest("txn-response-lost", release, previous)
	response := fixture.handle(install, fixture.artifact(release))
	if !response.OK || response.Receipt == nil {
		t.Fatalf("install = %#v", response)
	}
	fixture.service = fixture.newService()
	query := fixture.handle(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
	if !query.OK || query.Receipt == nil || !sameReceipt(*query.Receipt, *response.Receipt) || fixture.runner.upgradeCalls != 1 {
		t.Fatalf("response-loss query = %#v calls=%d", query, fixture.runner.upgradeCalls)
	}
	fixture.service = fixture.newService()
	current := fixture.current()
	if current.CurrentVersion != release.version || current.ArtifactSHA256 != install.ArtifactSHA256 {
		t.Fatalf("agent/helper restart current = %+v", current)
	}
}

func TestServiceRollbackRecoveryAfterPackagingAlreadySwitched(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	install := fixture.installRequest("txn-rollback-switched", release, previous)
	installed := fixture.handle(install, fixture.artifact(release))
	if !installed.OK || installed.Receipt == nil {
		t.Fatalf("install = %#v", installed)
	}
	fixture.runner.rollbackErr = ErrPackagingCommand
	rollback := fixture.rollbackRequest(install.TransactionID, release, *installed.Receipt, previous)
	failed := fixture.handle(rollback, nil)
	if failed.OK || failed.ErrorCode != protocol.ErrorRollbackFailed {
		t.Fatalf("initial rollback = %#v", failed)
	}
	if err := fixture.runner.switchCurrent(previous.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	fixture.service = fixture.newService()
	recovered := fixture.handle(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
	if !recovered.OK || recovered.Receipt == nil || recovered.Receipt.Status != "rolled_back" || fixture.runner.rollbackCalls != 1 {
		t.Fatalf("already-switched recovery = %#v calls=%d", recovered, fixture.runner.rollbackCalls)
	}
}

func TestServiceRollbackingRecoveryRejectsThirdStateAndCurrentDrift(t *testing.T) {
	t.Run("third-state", func(t *testing.T) {
		fixture := newServiceFixture(t)
		previous := fixture.current()
		release := fixture.release(2, "2.0.0")
		install := fixture.installRequest("txn-rollback-third-state", release, previous)
		installed := fixture.handle(install, fixture.artifact(release))
		if !installed.OK || installed.Receipt == nil {
			t.Fatalf("install = %#v", installed)
		}
		fixture.runner.rollbackErr = ErrPackagingCommand
		rollback := fixture.rollbackRequest(install.TransactionID, release, *installed.Receipt, previous)
		failed := fixture.handle(rollback, nil)
		if failed.OK || failed.ErrorCode != protocol.ErrorRollbackFailed {
			t.Fatalf("initial rollback = %#v", failed)
		}
		third := fixture.release(3, "3.0.0")
		fixture.installRelease(third, true)
		fixture.runner.rollbackErr = nil
		query := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
		if query.OK || query.ErrorCode != protocol.ErrorTransactionConflict || fixture.runner.rollbackCalls != 1 {
			t.Fatalf("third-state recovery = %#v calls=%d", query, fixture.runner.rollbackCalls)
		}
	})

	t.Run("current-drift", func(t *testing.T) {
		fixture := newServiceFixture(t)
		previous := fixture.current()
		release := fixture.release(2, "2.0.0")
		install := fixture.installRequest("txn-rollback-current-drift", release, previous)
		installed := fixture.handle(install, fixture.artifact(release))
		if !installed.OK || installed.Receipt == nil {
			t.Fatalf("install = %#v", installed)
		}
		record, err := fixture.service.journals.Load(install.TransactionID)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := protocol.MarshalRequest(fixture.rollbackRequest(install.TransactionID, release, *installed.Receipt, previous))
		if err != nil {
			t.Fatal(err)
		}
		record.Phase = JournalRollbacking
		record.RollbackPayloadSHA256 = HashCanonicalPayload(packet)
		if err := fixture.service.journals.Save(record); err != nil {
			t.Fatal(err)
		}
		facts, err := InspectInstalled(fixture.paths, fixture.packagePublic, fixture.uid, fixture.gid)
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.service.current.Save(previous, facts.ManifestSHA256); err != nil {
			t.Fatal(err)
		}
		query := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
		if query.OK || query.ErrorCode != protocol.ErrorStateUncertain || fixture.runner.rollbackCalls != 0 {
			t.Fatalf("current-drift recovery = %#v calls=%d", query, fixture.runner.rollbackCalls)
		}
	})
}

func TestServiceRollbackRejectsHigherInFlightAndAcceptedHighWater(t *testing.T) {
	t.Run("higher installing blocks older rollback runner", func(t *testing.T) {
		fixture := newServiceFixture(t)
		previous := fixture.current()
		activeRelease := fixture.release(2, "2.0.0")
		install := fixture.installRequest("txn-rollback-fenced-active", activeRelease, previous)
		installed := fixture.handle(install, fixture.artifact(activeRelease))
		if !installed.OK || installed.Receipt == nil {
			t.Fatalf("install = %#v", installed)
		}
		higherRelease := fixture.release(3, "3.0.0")
		higherPrepare := fixture.prepareRequest("txn-rollback-fenced-installing", higherRelease, *installed.Receipt)
		higherPrepared := fixture.handle(higherPrepare, fixture.artifact(higherRelease))
		if !higherPrepared.OK || higherPrepared.PreparedAck == nil {
			t.Fatalf("higher prepare = %#v", higherPrepared)
		}
		higherRecord, err := fixture.service.journals.Load(higherPrepare.TransactionID)
		if err != nil {
			t.Fatal(err)
		}
		higherRecord.Phase = JournalInstalling
		if err := fixture.service.journals.Save(higherRecord); err != nil {
			t.Fatal(err)
		}

		response := fixture.handle(fixture.rollbackRequest(install.TransactionID, activeRelease, *installed.Receipt, previous), nil)
		if response.OK || response.ErrorCode != protocol.ErrorTransactionConflict || response.Receipt != nil || fixture.runner.rollbackCalls != 0 {
			t.Fatalf("older rollback with higher installing = %#v calls=%d", response, fixture.runner.rollbackCalls)
		}
		facts, err := InspectInstalled(fixture.paths, fixture.packagePublic, fixture.uid, fixture.gid)
		if err != nil || facts.Version != activeRelease.version || facts.ReleaseSequence != activeRelease.sequence || facts.AcceptedSequence != activeRelease.sequence {
			t.Fatalf("physical facts after fenced rollback = (%+v, %v)", facts, err)
		}
	})

	for _, test := range []struct {
		name           string
		addHigherWater func(t *testing.T, fixture *serviceFixture, current protocol.Receipt)
	}{
		{
			name: "stale rollbacking with higher installing journal",
			addHigherWater: func(t *testing.T, fixture *serviceFixture, current protocol.Receipt) {
				higherRelease := fixture.release(3, "3.0.0")
				prepare := fixture.prepareRequest("txn-stale-rollbacking-higher-installing", higherRelease, current)
				prepared := fixture.handle(prepare, fixture.artifact(higherRelease))
				if !prepared.OK || prepared.PreparedAck == nil {
					t.Fatalf("higher prepare = %#v", prepared)
				}
				record, err := fixture.service.journals.Load(prepare.TransactionID)
				if err != nil {
					t.Fatal(err)
				}
				record.Phase = JournalInstalling
				if err := fixture.service.journals.Save(record); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "stale rollbacking with higher rollbacking journal",
			addHigherWater: func(t *testing.T, fixture *serviceFixture, current protocol.Receipt) {
				higherRelease := fixture.release(3, "3.0.0")
				prepare := fixture.prepareRequest("txn-stale-rollbacking-higher-rollbacking", higherRelease, current)
				prepared := fixture.handle(prepare, fixture.artifact(higherRelease))
				if !prepared.OK || prepared.PreparedAck == nil {
					t.Fatalf("higher prepare = %#v", prepared)
				}
				record, err := fixture.service.journals.Load(prepare.TransactionID)
				if err != nil {
					t.Fatal(err)
				}
				record.Phase = JournalInstalling
				if err := fixture.service.journals.Save(record); err != nil {
					t.Fatal(err)
				}
				active := fixture.service.newReceipt(record.TransactionID, record.ReleaseSequence, record.OuterArtifactSHA256, record.TargetVersion, record.PreviousVersion, "active")
				if err := SignReceipt(&active, KeyMaterial{KeyID: fixture.receiptKeyID, PrivateKey: fixture.receiptPrivate}); err != nil {
					t.Fatal(err)
				}
				record.Phase = JournalActive
				record.ActiveReceipt = &active
				if err := fixture.service.journals.Save(record); err != nil {
					t.Fatal(err)
				}
				rollback := fixture.rollbackRequest(record.TransactionID, higherRelease, active, current)
				record.Phase = JournalRollbacking
				record.RollbackPayloadSHA256 = HashCanonicalPayload(mustPacket(t, rollback))
				if err := fixture.service.journals.Save(record); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "stale rollbacking with higher accepted manifest",
			addHigherWater: func(t *testing.T, fixture *serviceFixture, _ protocol.Receipt) {
				higherRelease := fixture.release(3, "3.0.0")
				if err := os.WriteFile(fixture.paths.AcceptedManifest, higherRelease.manifest, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(fixture.paths.AcceptedManifest, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			previous := fixture.current()
			activeRelease := fixture.release(2, "2.0.0")
			install := fixture.installRequest("txn-stale-rollbacking", activeRelease, previous)
			installed := fixture.handle(install, fixture.artifact(activeRelease))
			if !installed.OK || installed.Receipt == nil {
				t.Fatalf("install = %#v", installed)
			}
			record, err := fixture.service.journals.Load(install.TransactionID)
			if err != nil {
				t.Fatal(err)
			}
			rollback := fixture.rollbackRequest(install.TransactionID, activeRelease, *installed.Receipt, previous)
			record.Phase = JournalRollbacking
			record.RollbackPayloadSHA256 = HashCanonicalPayload(mustPacket(t, rollback))
			if err := fixture.service.journals.Save(record); err != nil {
				t.Fatal(err)
			}
			test.addHigherWater(t, fixture, *installed.Receipt)
			if err := fixture.runner.switchCurrent(previous.CurrentVersion); err != nil {
				t.Fatal(err)
			}

			response := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
			if response.OK || response.ErrorCode != protocol.ErrorTransactionConflict || response.Receipt != nil || fixture.runner.rollbackCalls != 0 {
				t.Fatalf("stale rollbacking recovery = %#v calls=%d", response, fixture.runner.rollbackCalls)
			}
			persisted, err := fixture.service.journals.Load(install.TransactionID)
			if err != nil || persisted.Phase != JournalRollbacking || persisted.RollbackReceipt != nil {
				t.Fatalf("stale rollbacking journal = (%+v, %v)", persisted, err)
			}
			current, _, err := fixture.service.current.Load()
			if err != nil || !sameReceipt(current, *installed.Receipt) {
				t.Fatalf("current downgraded by stale rollback = (%+v, %v), want %+v", current, err, *installed.Receipt)
			}
		})
	}
}

func TestServiceRollbackUsesCapturedPreviousPhysicalReleaseSequence(t *testing.T) {
	fixture := newServiceFixture(t)
	baseline := fixture.current()
	release2 := fixture.release(2, "2.0.0")
	install2 := fixture.installRequest("txn-rollback-previous-sequence-2", release2, baseline)
	installed2 := fixture.handle(install2, fixture.artifact(release2))
	if !installed2.OK || installed2.Receipt == nil {
		t.Fatalf("install2 = %#v", installed2)
	}
	rolledBack2 := fixture.handle(fixture.rollbackRequest(install2.TransactionID, release2, *installed2.Receipt, baseline), nil)
	if !rolledBack2.OK || rolledBack2.Receipt == nil || rolledBack2.Receipt.Status != "rolled_back" {
		t.Fatalf("rollback2-to1 = %#v", rolledBack2)
	}
	restored := fixture.current()
	if restored.CurrentVersion != baseline.CurrentVersion || restored.ReleaseSequence != release2.sequence {
		t.Fatalf("restored logical current = %+v", restored)
	}

	release3 := fixture.release(3, "3.0.0")
	install3 := fixture.prepareRequest("txn-rollback-previous-sequence-3", release3, restored)
	prepared3 := fixture.handle(install3, fixture.artifact(release3))
	if !prepared3.OK || prepared3.PreparedAck == nil {
		t.Fatalf("prepare3 = %#v", prepared3)
	}
	record3, err := fixture.service.journals.Load(install3.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	record3.Phase = JournalInstalling
	if err := fixture.service.journals.Save(record3); err != nil {
		t.Fatal(err)
	}
	fixture.installRelease(release3, true)
	installed3 := fixture.handle(fixture.activateRequest(*prepared3.PreparedAck), nil)
	if !installed3.OK || installed3.Receipt == nil {
		t.Fatalf("recover active3 after target switch = %#v", installed3)
	}
	rolledBack3 := fixture.handle(fixture.rollbackRequest(install3.TransactionID, release3, *installed3.Receipt, restored), nil)
	if !rolledBack3.OK || rolledBack3.Receipt == nil || rolledBack3.Receipt.Status != "rolled_back" || fixture.runner.rollbackCalls != 2 {
		t.Fatalf("rollback3 to captured physical sequence = %#v calls=%d", rolledBack3, fixture.runner.rollbackCalls)
	}
	facts, err := InspectInstalled(fixture.paths, fixture.packagePublic, fixture.uid, fixture.gid)
	if err != nil || facts.Version != baseline.CurrentVersion || facts.ReleaseSequence != baseline.ReleaseSequence ||
		facts.ReleaseSequence == restored.ReleaseSequence {
		t.Fatalf("physical previous facts = (%+v, %v), restored=%+v", facts, err, restored)
	}
	record3, err = fixture.service.journals.Load(install3.TransactionID)
	if err != nil || record3.Phase != JournalRolledBack || record3.RollbackReceipt == nil ||
		record3.PreviousPhysicalReleaseSequence != baseline.ReleaseSequence || record3.PreviousManifestSHA256 != facts.ManifestSHA256 {
		t.Fatalf("rollback3 journal with captured physical sequence = (%+v, %v)", record3, err)
	}
	current, _, err := fixture.service.current.Load()
	if err != nil || current.CurrentVersion != baseline.CurrentVersion || current.ReleaseSequence != release3.sequence {
		t.Fatalf("current after captured physical rollback = (%+v, %v)", current, err)
	}
}

func TestServiceRollbackRejectsPreviousArtifactDigestMismatch(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	install := fixture.installRequest("txn-rollback-previous-digest-mismatch", release, previous)
	installed := fixture.handle(install, fixture.artifact(release))
	if !installed.OK || installed.Receipt == nil {
		t.Fatalf("install = %#v", installed)
	}

	previousDirectory := filepath.Join(fixture.paths.ReleaseRoot, "versions", previous.CurrentVersion)
	if err := os.RemoveAll(previousDirectory); err != nil {
		t.Fatal(err)
	}
	mismatchedPrevious := fixture.release(9, previous.CurrentVersion)
	fixture.installRelease(mismatchedPrevious, false)
	if err := fixture.runner.switchCurrent(release.version); err != nil {
		t.Fatal(err)
	}

	rollback := fixture.rollbackRequest(install.TransactionID, release, *installed.Receipt, previous)
	failed := fixture.handle(rollback, nil)
	if failed.OK || failed.ErrorCode != protocol.ErrorTransactionConflict || failed.Receipt != nil {
		t.Fatalf("rollback with mismatched previous artifact = %#v", failed)
	}
	facts, err := InspectInstalled(fixture.paths, fixture.packagePublic, fixture.uid, fixture.gid)
	if err != nil || facts.Version != previous.CurrentVersion ||
		facts.OuterArtifactSHA256 == previous.ArtifactSHA256 {
		t.Fatalf("mismatched installed previous facts = (%+v, %v), previous=%+v", facts, err, previous)
	}
	record, err := fixture.service.journals.Load(install.TransactionID)
	if err != nil || record.Phase != JournalRollbacking || record.RollbackReceipt != nil {
		t.Fatalf("rollback journal after mismatch = (%+v, %v)", record, err)
	}
	current, _, err := fixture.service.current.Load()
	if err != nil || !sameReceipt(current, *installed.Receipt) {
		t.Fatalf("current after mismatch = (%+v, %v), want installed %+v", current, err, *installed.Receipt)
	}

	fixture.service = fixture.newService()
	recovered := fixture.handle(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
	if recovered.OK || recovered.ErrorCode != protocol.ErrorTransactionConflict || recovered.Receipt != nil ||
		fixture.runner.rollbackCalls != 1 {
		t.Fatalf("rollback recovery with mismatched previous artifact = %#v calls=%d", recovered, fixture.runner.rollbackCalls)
	}
	record, err = fixture.service.journals.Load(install.TransactionID)
	if err != nil || record.Phase != JournalRollbacking || record.RollbackReceipt != nil {
		t.Fatalf("rollback recovery journal after mismatch = (%+v, %v)", record, err)
	}
}

func TestServiceRestagesOrphanTransactionWithoutGuessingConflict(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	request := fixture.installRequest("txn-orphan", release, previous)
	directory := filepath.Join(fixture.paths.StateDirectory, "transactions", request.TransactionID)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := StageReleaseBundle(fixture.artifact(release), directory, request.ArtifactSize, request.ArtifactSHA256); err != nil {
		t.Fatal(err)
	}
	response := fixture.handle(request, fixture.artifact(release))
	if !response.OK || response.Receipt == nil || response.Receipt.Status != "active" || fixture.runner.upgradeCalls != 1 {
		t.Fatalf("orphan retry = %#v calls=%d", response, fixture.runner.upgradeCalls)
	}
}

func TestServiceRejectsInvalidPersistedReceiptSignature(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	install := fixture.installRequest("txn-bad-persisted-receipt", release, previous)
	response := fixture.handle(install, fixture.artifact(release))
	if !response.OK || response.Receipt == nil {
		t.Fatalf("install = %#v", response)
	}
	record, err := fixture.service.journals.Load(install.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	record.ActiveReceipt.Signature.Value = base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	content, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fixture.paths.StateDirectory, "journal-"+install.TransactionID+".json")
	writeTestProtectedFile(t, path, journalMode, content)
	fixture.service = fixture.newService()
	query := fixture.handle(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
	if query.OK || query.ErrorCode != protocol.ErrorStateUncertain {
		t.Fatalf("invalid persisted signature query = %#v", query)
	}
}

func TestServiceRejectsForgedTrustedAndUnknownReceiptKeys(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	install := fixture.installRequest("txn-forged-receipt-key", release, previous)
	response := fixture.handle(install, fixture.artifact(release))
	if !response.OK || response.Receipt == nil {
		t.Fatalf("install = %#v", response)
	}
	record, err := fixture.service.journals.Load(install.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fixture.paths.StateDirectory, "journal-"+install.TransactionID+".json")
	trustedOtherPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.receiptPublicKeys["helper-test-trusted-other"] = trustedOtherPublic
	for _, keyID := range []string{"helper-test-trusted-other", "helper-test-unknown"} {
		forged := record
		active := *record.ActiveReceipt
		active.Signature.KeyID = keyID
		forged.ActiveReceipt = &active
		content, err := json.Marshal(forged)
		if err != nil {
			t.Fatal(err)
		}
		writeTestProtectedFile(t, path, journalMode, content)
		fixture.service = fixture.newService()
		query := fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
		if query.OK || query.ErrorCode != protocol.ErrorStateUncertain || query.Receipt != nil {
			t.Fatalf("forged %s receipt query = %#v", keyID, query)
		}
	}
}

func TestServiceReturnsOldKeyReceiptAcrossKeyRotation(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	install := fixture.installRequest("txn-key-rotation", release, previous)
	response := fixture.handle(install, fixture.artifact(release))
	if !response.OK || response.Receipt == nil {
		t.Fatalf("install = %#v", response)
	}
	oldReceipt := *response.Receipt
	newPublic, newPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.receiptPublic = newPublic
	fixture.receiptPrivate = newPrivate
	fixture.receiptKeyID = "helper-test-new"
	fixture.receiptPublicKeys[fixture.receiptKeyID] = append(ed25519.PublicKey(nil), newPublic...)
	fixture.service = fixture.newService()
	query := fixture.handle(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
	if !query.OK || query.Receipt == nil || !sameReceipt(*query.Receipt, oldReceipt) {
		t.Fatalf("old-key query = %#v", query)
	}
	current := fixture.current()
	if current.Signature.KeyID != "helper-test-new" || current.Signature.Value == oldReceipt.Signature.Value {
		t.Fatalf("rotated current = %+v", current)
	}
	query = fixture.handle(protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: install.TransactionID}, nil)
	if !query.OK || query.Receipt == nil || !sameReceipt(*query.Receipt, oldReceipt) {
		t.Fatalf("old-key query after current rotation = %#v", query)
	}
	inspect := fixture.handle(fixture.inspectRequest(install.TransactionID), nil)
	if !inspect.OK || inspect.TransactionStatus == nil || inspect.TransactionStatus.Phase != protocol.TransactionActive ||
		inspect.TransactionStatus.Receipt == nil || !sameReceipt(*inspect.TransactionStatus.Receipt, oldReceipt) {
		t.Fatalf("old-key inspect after current rotation = %#v", inspect)
	}
	rollback := fixture.rollbackRequest(install.TransactionID, release, oldReceipt, previous)
	rolledBack := fixture.handle(rollback, nil)
	if !rolledBack.OK || rolledBack.Receipt == nil || rolledBack.Receipt.Status != "rolled_back" || fixture.runner.rollbackCalls != 1 {
		t.Fatalf("old-key rollback after current rotation = %#v calls=%d", rolledBack, fixture.runner.rollbackCalls)
	}
}

func TestServiceRejectsUnsafeOrphanTransactionDirectory(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	request := fixture.installRequest("txn-unsafe-orphan", release, previous)
	directory := filepath.Join(fixture.paths.StateDirectory, "transactions", request.TransactionID)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "caller-path"), []byte("unsafe"), 0o400); err != nil {
		t.Fatal(err)
	}
	response := fixture.handle(request, fixture.artifact(release))
	if response.OK || response.ErrorCode != protocol.ErrorStateUncertain || fixture.runner.upgradeCalls != 0 {
		t.Fatalf("unsafe orphan = %#v calls=%d", response, fixture.runner.upgradeCalls)
	}
}

func TestServiceRecoversPreparedAndInstallingTransactions(t *testing.T) {
	for _, test := range []struct {
		name             string
		phase            JournalPhase
		alreadyActivated bool
	}{
		{name: "prepared", phase: JournalPrepared},
		{name: "installing", phase: JournalInstalling},
		{name: "installing-after-activation", phase: JournalInstalling, alreadyActivated: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			previous := fixture.current()
			release := fixture.release(2, "2.0.0")
			request := fixture.installRequest("txn-"+test.name, release, previous)
			packet, err := protocol.MarshalRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(fixture.paths.StateDirectory, "transactions", request.TransactionID)
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			staged, err := StageReleaseBundle(fixture.artifact(release), directory, request.ArtifactSize, request.ArtifactSHA256)
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := VerifyReleaseManifest(staged, fixture.packagePublic, ManifestExpectation{
				ReleaseSequence: release.sequence, TargetVersion: release.version,
				Platform: request.Platform, Architecture: request.Architecture,
			})
			if err != nil {
				t.Fatal(err)
			}
			record := JournalRecord{
				SchemaVersion: journalSchemaVersion, TransactionID: request.TransactionID, Phase: test.phase,
				InstallPayloadSHA256: HashCanonicalPayload(packet), ReleaseSequence: release.sequence,
				OuterArtifactSHA256: request.ArtifactSHA256, ManifestSHA256: manifest.ManifestSHA256,
				ExecutableSHA256: manifest.ArtifactSHA256, SBOMSHA256: manifest.SBOMSHA256,
				PreviousVersion: previous.CurrentVersion, TargetVersion: release.version,
				PreviousPhysicalReleaseSequence: previous.ReleaseSequence,
				PreviousManifestSHA256:          digestBytes(fixture.release(1, "1.0.0").manifest), PreviousReceipt: &previous,
			}
			if err := fixture.service.journals.Save(record); err != nil {
				t.Fatal(err)
			}
			if test.alreadyActivated {
				fixture.installRelease(release, true)
			}
			fixture.service = fixture.newService()
			recovered := fixture.handle(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: request.TransactionID}, nil)
			wantCalls := 1
			if test.alreadyActivated {
				wantCalls = 0
			}
			if !recovered.OK || recovered.Receipt == nil || recovered.Receipt.Status != "active" || fixture.runner.upgradeCalls != wantCalls {
				t.Fatalf("%s recovery = %#v calls=%d", test.name, recovered, fixture.runner.upgradeCalls)
			}
		})
	}
}

func TestServiceQueryRecoveryDoesNotGuessRollback(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	request := fixture.installRequest("txn-query-recovery-error", release, previous)
	packet, err := protocol.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(fixture.paths.StateDirectory, "transactions", request.TransactionID)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	staged, err := StageReleaseBundle(fixture.artifact(release), directory, request.ArtifactSize, request.ArtifactSHA256)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := VerifyReleaseManifest(staged, fixture.packagePublic, ManifestExpectation{
		ReleaseSequence: release.sequence, TargetVersion: release.version,
		Platform: request.Platform, Architecture: request.Architecture,
	})
	if err != nil {
		t.Fatal(err)
	}
	record := JournalRecord{
		SchemaVersion: journalSchemaVersion, TransactionID: request.TransactionID, Phase: JournalInstalling,
		InstallPayloadSHA256: HashCanonicalPayload(packet), ReleaseSequence: release.sequence,
		OuterArtifactSHA256: request.ArtifactSHA256, ManifestSHA256: manifest.ManifestSHA256,
		ExecutableSHA256: manifest.ArtifactSHA256, SBOMSHA256: manifest.SBOMSHA256,
		PreviousVersion: previous.CurrentVersion, TargetVersion: release.version,
		PreviousPhysicalReleaseSequence: previous.ReleaseSequence,
		PreviousManifestSHA256:          digestBytes(fixture.release(1, "1.0.0").manifest), PreviousReceipt: &previous,
	}
	if err := fixture.service.journals.Save(record); err != nil {
		t.Fatal(err)
	}
	fixture.runner.upgradeErr = ErrPackagingCommand
	fixture.runner.rollbackErr = ErrPackagingCommand

	failed := fixture.handle(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: request.TransactionID}, nil)
	if failed.OK || failed.ErrorCode != protocol.ErrorRollbackFailed || failed.Receipt != nil ||
		fixture.runner.upgradeCalls != 1 || fixture.runner.rollbackCalls != 1 {
		t.Fatalf("failed recovery = %#v upgrade_calls=%d rollback_calls=%d", failed, fixture.runner.upgradeCalls, fixture.runner.rollbackCalls)
	}
	persisted, err := fixture.service.journals.Load(request.TransactionID)
	if err != nil || persisted.Phase != JournalInstalling || persisted.ActiveReceipt != nil || persisted.RollbackReceipt != nil {
		t.Fatalf("journal after failed recovery = (%+v, %v)", persisted, err)
	}
	current, _, err := fixture.service.current.Load()
	if err != nil || !sameReceipt(current, previous) {
		t.Fatalf("current after failed recovery = (%+v, %v), want previous %+v", current, err, previous)
	}

	fixture.runner.upgradeErr = nil
	fixture.runner.rollbackErr = nil
	recovered := fixture.handle(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: request.TransactionID}, nil)
	if !recovered.OK || recovered.Receipt == nil || recovered.Receipt.Status != "active" ||
		recovered.Receipt.ArtifactSHA256 != request.ArtifactSHA256 || fixture.runner.upgradeCalls != 2 || fixture.runner.rollbackCalls != 1 {
		t.Fatalf("recovered query = %#v upgrade_calls=%d rollback_calls=%d", recovered, fixture.runner.upgradeCalls, fixture.runner.rollbackCalls)
	}
}

func TestServiceRecoveryRejectsInstalledOuterDigestMismatch(t *testing.T) {
	fixture := newServiceFixture(t)
	previous := fixture.current()
	release := fixture.release(2, "2.0.0")
	request := fixture.installRequest("txn-outer-digest-mismatch", release, previous)
	actualOuterDigest := request.ArtifactSHA256
	directory := filepath.Join(fixture.paths.StateDirectory, "transactions", request.TransactionID)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	staged, err := StageReleaseBundle(fixture.artifact(release), directory, request.ArtifactSize, request.ArtifactSHA256)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := VerifyReleaseManifest(staged, fixture.packagePublic, ManifestExpectation{
		ReleaseSequence: release.sequence, TargetVersion: release.version,
		Platform: request.Platform, Architecture: request.Architecture,
	})
	if err != nil {
		t.Fatal(err)
	}
	request.ArtifactSHA256 = digestOf([]byte("different-canonical-bundle"))
	packet, err := protocol.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	record := JournalRecord{
		SchemaVersion: journalSchemaVersion, TransactionID: request.TransactionID, Phase: JournalInstalling,
		InstallPayloadSHA256: HashCanonicalPayload(packet), ReleaseSequence: release.sequence,
		OuterArtifactSHA256: request.ArtifactSHA256, ManifestSHA256: manifest.ManifestSHA256,
		ExecutableSHA256: manifest.ArtifactSHA256, SBOMSHA256: manifest.SBOMSHA256,
		PreviousVersion: previous.CurrentVersion, TargetVersion: release.version,
		PreviousPhysicalReleaseSequence: previous.ReleaseSequence,
		PreviousManifestSHA256:          digestBytes(fixture.release(1, "1.0.0").manifest), PreviousReceipt: &previous,
	}
	if err := fixture.service.journals.Save(record); err != nil {
		t.Fatal(err)
	}

	response := fixture.handle(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: request.TransactionID}, nil)
	if response.OK || response.ErrorCode != protocol.ErrorStateUncertain || response.Receipt != nil {
		t.Fatalf("outer digest mismatch recovery = %#v", response)
	}
	installed, err := InspectInstalled(fixture.paths, fixture.packagePublic, fixture.uid, fixture.gid)
	if err != nil {
		t.Fatal(err)
	}
	if installed.Version != release.version || installed.OuterArtifactSHA256 != actualOuterDigest || installed.OuterArtifactSHA256 == record.OuterArtifactSHA256 {
		t.Fatalf("installed facts = %+v journal_outer=%s", installed, record.OuterArtifactSHA256)
	}
	persisted, err := fixture.service.journals.Load(request.TransactionID)
	if err != nil || persisted.Phase != JournalInstalling || persisted.ActiveReceipt != nil {
		t.Fatalf("journal after mismatch = (%+v, %v)", persisted, err)
	}
	current, _, err := fixture.service.current.Load()
	if err != nil || !sameReceipt(current, previous) {
		t.Fatalf("current after mismatch = (%+v, %v), want previous %+v", current, err, previous)
	}
}

func decodeReceiptSignature(value string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(value)
}

func journalFields(t *testing.T, fixture *serviceFixture, transactionID string) map[string]any {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(fixture.paths.StateDirectory, "journal-"+transactionID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(content, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func rewriteJournalAsLegacyV1(t *testing.T, fixture *serviceFixture, transactionID string) {
	t.Helper()
	record, err := fixture.service.journals.Load(transactionID)
	if err != nil {
		t.Fatal(err)
	}
	record.SchemaVersion = legacyJournalSchemaVersion
	record.PreviousPhysicalReleaseSequence = 0
	record.PreviousManifestSHA256 = ""
	content, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeTestProtectedFile(t, filepath.Join(fixture.paths.StateDirectory, "journal-"+transactionID+".json"), journalMode, content)
}

func requireJournalV2PreviousBinding(t *testing.T, fixture *serviceFixture, transactionID string, sequence uint64, manifestDigest string) {
	t.Helper()
	fields := journalFields(t, fixture, transactionID)
	if fields["schema_version"] != float64(2) || fields["previous_physical_release_sequence"] != float64(sequence) ||
		fields["previous_manifest_sha256"] != manifestDigest {
		t.Fatalf("journal physical previous binding = %#v, want schema=2 sequence=%d manifest=%s", fields, sequence, manifestDigest)
	}
}

func mustPacket(t *testing.T, request protocol.Request) []byte {
	t.Helper()
	packet, err := protocol.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func stagedBundleForTest(t *testing.T, directory string) (StagedBundle, error) {
	t.Helper()
	read := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(directory, name)) }
	manifest, err := read("manifest")
	if err != nil {
		return StagedBundle{}, err
	}
	signature, err := read("manifest.sig")
	if err != nil {
		return StagedBundle{}, err
	}
	sbom, err := read("edge-agent.spdx.json")
	if err != nil {
		return StagedBundle{}, err
	}
	executable, err := read("edge-agent")
	if err != nil {
		return StagedBundle{}, err
	}
	bundle := testBundle(manifest, signature, sbom, executable)
	return StagedBundle{
		Directory: directory, ManifestPath: filepath.Join(directory, "manifest"), SignaturePath: filepath.Join(directory, "manifest.sig"),
		SBOMPath: filepath.Join(directory, "edge-agent.spdx.json"), ExecutablePath: filepath.Join(directory, "edge-agent"),
		OuterSHA256: digestOf(bundle), OuterSize: int64(len(bundle)), ManifestSHA256: digestOf(manifest), ManifestSize: int64(len(manifest)),
		SignatureSHA256: digestOf(signature), SBOMSHA256: digestOf(sbom), SBOMSize: int64(len(sbom)),
		ExecutableSHA256: digestOf(executable), ExecutableSize: int64(len(executable)),
	}, nil
}
