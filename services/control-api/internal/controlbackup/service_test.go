package controlbackup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestBackupOrchestratorFreezesCapturesAllComponentsAndReleases(t *testing.T) {
	t.Parallel()

	events := []string{}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x12}, ed25519.SeedSize))
	manifest := testManifest()
	store := &recordingManifestStore{events: &events}
	orchestrator := BackupOrchestrator{
		Freeze: &recordingFreeze{events: &events},
		Capturers: []ComponentCapturer{
			staticCapturer{events: &events, checkpoint: manifest.Checkpoints[0]},
			staticCapturer{events: &events, checkpoint: manifest.Checkpoints[1]},
			staticCapturer{events: &events, checkpoint: manifest.Checkpoints[2]},
		},
		Store:        store,
		SigningKeyID: "recovery-signing-2026-08",
		PrivateKey:   privateKey,
		Now:          func() time.Time { return manifest.CreatedAt },
	}

	result, err := orchestrator.Run(context.Background(), BackupRequest{
		BackupID:           manifest.BackupID,
		SourceClusterID:    manifest.SourceClusterID,
		AppVersion:         manifest.AppVersion,
		SchemaVersion:      manifest.SchemaVersion,
		CoreManifestSHA256: manifest.CoreManifestSHA256,
		EnvelopeKey:        manifest.EnvelopeKey,
		TargetRPO:          15 * time.Minute,
		TargetRTO:          30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	wantEvents := []string{"freeze", "capture:postgresql:freeze-ops12", "capture:clickhouse:freeze-ops12", "capture:jetstream:freeze-ops12", "manifest", "release"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
	if result.Manifest.WriteFreezeID != "freeze-ops12" || result.Manifest.Objectives.ObservedRPOSeconds != 8 {
		t.Fatalf("result manifest = %#v", result.Manifest)
	}
	if store.signed.PayloadSHA256 == "" || store.signed.Signature == "" {
		t.Fatalf("stored signed manifest = %#v", store.signed)
	}
}

func TestBackupOrchestratorReleasesFreezeOnCaptureFailure(t *testing.T) {
	t.Parallel()

	events := []string{}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x13}, ed25519.SeedSize))
	manifest := testManifest()
	orchestrator := BackupOrchestrator{
		Freeze: &recordingFreeze{events: &events},
		Capturers: []ComponentCapturer{
			staticCapturer{events: &events, checkpoint: manifest.Checkpoints[0]},
			staticCapturer{events: &events, checkpoint: manifest.Checkpoints[1], err: errors.New("clickhouse unavailable")},
			staticCapturer{events: &events, checkpoint: manifest.Checkpoints[2]},
		},
		Store:        &recordingManifestStore{events: &events},
		SigningKeyID: "recovery-signing-2026-08",
		PrivateKey:   privateKey,
		Now:          func() time.Time { return manifest.CreatedAt },
	}

	_, err := orchestrator.Run(context.Background(), backupRequestFromManifest(manifest))
	if err == nil {
		t.Fatal("Run() unexpectedly succeeded")
	}
	want := []string{"freeze", "capture:postgresql:freeze-ops12", "capture:clickhouse:freeze-ops12", "release"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %#v, want %#v", events, want)
	}
}

func TestRestoreOrchestratorPreflightsRestoresProbesAndReplaysReceipt(t *testing.T) {
	t.Parallel()

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize))
	signed, err := SignManifest(testManifest(), "recovery-signing-2026-08", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	events := []string{}
	receipts := &recordingReceiptStore{MemoryReceiptStore: NewMemoryReceiptStore(), events: &events}
	orchestrator := RestoreOrchestrator{
		Target:    &recordingTarget{events: &events},
		Restorers: restoreComponents(&events, ""),
		Probes: []RecoveryProbe{
			recordingProbe{events: &events, name: ProbeDNS},
			recordingProbe{events: &events, name: ProbeAgentReconnect},
		},
		Receipts: receipts,
		PublicKeys: map[string]ed25519.PublicKey{
			"recovery-signing-2026-08": privateKey.Public().(ed25519.PublicKey),
		},
		Now: func() time.Time { return testManifest().CreatedAt.Add(2 * time.Minute) },
	}
	request := RestoreRequest{
		OperationID:      "restore-ops12-1",
		TargetID:         "recovery-control-b",
		SignedManifest:   signed,
		MaxSchemaVersion: 143,
	}

	receipt, err := orchestrator.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	want := []string{"preflight", "restore:postgresql", "restore:clickhouse", "restore:jetstream", "probe:dns", "probe:agent_reconnect", "receipt:succeeded"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %#v, want %#v", events, want)
	}
	if receipt.State != RestoreSucceeded || receipt.ObservedRTOSeconds != 0 || receipt.ObservedRPOSeconds != 128 {
		t.Fatalf("receipt = %#v", receipt)
	}

	events = nil
	replayed, err := orchestrator.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("replay Run() error = %v", err)
	}
	if !replayed.Replayed || replayed.OperationID != receipt.OperationID {
		t.Fatalf("replayed receipt = %#v", replayed)
	}
	if len(events) != 0 {
		t.Fatalf("replay mutated target: events = %#v", events)
	}

	request.TargetID = "different-target"
	if _, err := orchestrator.Run(context.Background(), request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting replay error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestRestoreOrchestratorCompensatesReverseOrderWhenPostRestoreProbeFails(t *testing.T) {
	t.Parallel()

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	signed, err := SignManifest(testManifest(), "recovery-signing-2026-08", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	events := []string{}
	orchestrator := RestoreOrchestrator{
		Target:    &recordingTarget{events: &events},
		Restorers: restoreComponents(&events, ""),
		Probes: []RecoveryProbe{
			recordingProbe{events: &events, name: ProbeDNS},
			recordingProbe{events: &events, name: ProbeAgentReconnect, err: errors.New("agents did not reconnect")},
		},
		Receipts: &recordingReceiptStore{MemoryReceiptStore: NewMemoryReceiptStore(), events: &events},
		PublicKeys: map[string]ed25519.PublicKey{
			"recovery-signing-2026-08": privateKey.Public().(ed25519.PublicKey),
		},
		Now: func() time.Time { return testManifest().CreatedAt.Add(time.Minute) },
	}

	receipt, err := orchestrator.Run(context.Background(), RestoreRequest{
		OperationID: "restore-ops12-failed", TargetID: "recovery-control-b",
		SignedManifest: signed, MaxSchemaVersion: 143,
	})
	if err == nil {
		t.Fatal("Run() unexpectedly succeeded")
	}
	want := []string{"preflight", "restore:postgresql", "restore:clickhouse", "restore:jetstream", "probe:dns", "probe:agent_reconnect", "compensate:jetstream", "compensate:clickhouse", "compensate:postgresql", "receipt:failed"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %#v, want %#v", events, want)
	}
	if receipt.State != RestoreFailed || !receipt.Compensated || receipt.FailureCode != FailureProbe {
		t.Fatalf("receipt = %#v", receipt)
	}
}

func TestRestoreOrchestratorPersistsStableDriverFailureCode(t *testing.T) {
	t.Parallel()

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x23}, ed25519.SeedSize))
	signed, err := SignManifest(testManifest(), "recovery-signing-2026-08", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	events := []string{}
	orchestrator := RestoreOrchestrator{
		Target:    &recordingTarget{events: &events},
		Restorers: restoreComponents(&events, ""),
		Probes: []RecoveryProbe{
			recordingProbe{events: &events, name: ProbeDNS, err: DriverError{Code: "dns_cutover_timeout"}},
			recordingProbe{events: &events, name: ProbeAgentReconnect},
		},
		Receipts: &recordingReceiptStore{MemoryReceiptStore: NewMemoryReceiptStore(), events: &events},
		PublicKeys: map[string]ed25519.PublicKey{
			"recovery-signing-2026-08": privateKey.Public().(ed25519.PublicKey),
		},
		Now: func() time.Time { return testManifest().CreatedAt.Add(time.Minute) },
	}
	receipt, err := orchestrator.Run(context.Background(), RestoreRequest{
		OperationID: "restore-ops12-coded", TargetID: "recovery-control-b",
		SignedManifest: signed, MaxSchemaVersion: 143,
	})
	if err == nil || receipt.FailureCode != "dns_cutover_timeout" {
		t.Fatalf("receipt/error = (%#v, %v), want stable driver code", receipt, err)
	}
}

type recordingFreeze struct{ events *[]string }

func (freeze *recordingFreeze) Acquire(context.Context, string) (WriteFreezeLease, error) {
	*freeze.events = append(*freeze.events, "freeze")
	return &recordingLease{events: freeze.events}, nil
}

type recordingLease struct{ events *[]string }

func (lease *recordingLease) ID() string { return "freeze-ops12" }
func (lease *recordingLease) Release(context.Context) error {
	*lease.events = append(*lease.events, "release")
	return nil
}

type staticCapturer struct {
	events     *[]string
	checkpoint ComponentCheckpoint
	err        error
}

func (capturer staticCapturer) Name() Component { return capturer.checkpoint.Component }
func (capturer staticCapturer) Capture(_ context.Context, request CaptureRequest) (ComponentCheckpoint, error) {
	*capturer.events = append(*capturer.events, "capture:"+string(capturer.checkpoint.Component)+":"+request.WriteFreezeID)
	return capturer.checkpoint, capturer.err
}

type recordingManifestStore struct {
	events *[]string
	signed SignedManifest
}

func (store *recordingManifestStore) Put(_ context.Context, signed SignedManifest) error {
	*store.events = append(*store.events, "manifest")
	store.signed = signed
	return nil
}

type recordingTarget struct {
	events *[]string
	err    error
}

type recordingReceiptStore struct {
	*MemoryReceiptStore
	events *[]string
}

func (store *recordingReceiptStore) Put(ctx context.Context, receipt RestoreReceipt) error {
	*store.events = append(*store.events, "receipt:"+string(receipt.State))
	return store.MemoryReceiptStore.Put(ctx, receipt)
}

func (target *recordingTarget) Preflight(context.Context, Manifest, string) error {
	*target.events = append(*target.events, "preflight")
	return target.err
}

type recordingRestorer struct {
	events *[]string
	name   Component
	err    error
}

func (restorer recordingRestorer) Name() Component { return restorer.name }
func (restorer recordingRestorer) Restore(context.Context, ComponentCheckpoint, string) error {
	*restorer.events = append(*restorer.events, "restore:"+string(restorer.name))
	return restorer.err
}
func (restorer recordingRestorer) Compensate(context.Context, string, string) error {
	*restorer.events = append(*restorer.events, "compensate:"+string(restorer.name))
	return nil
}

func restoreComponents(events *[]string, failing Component) []ComponentRestorer {
	return []ComponentRestorer{
		recordingRestorer{events: events, name: ComponentPostgreSQL, err: componentError(failing, ComponentPostgreSQL)},
		recordingRestorer{events: events, name: ComponentClickHouse, err: componentError(failing, ComponentClickHouse)},
		recordingRestorer{events: events, name: ComponentJetStream, err: componentError(failing, ComponentJetStream)},
	}
}

func componentError(failing, current Component) error {
	if failing == current {
		return errors.New("restore failed")
	}
	return nil
}

type recordingProbe struct {
	events *[]string
	name   ProbeName
	err    error
}

func (probe recordingProbe) Name() ProbeName { return probe.name }
func (probe recordingProbe) Check(context.Context, Manifest, string) error {
	*probe.events = append(*probe.events, "probe:"+string(probe.name))
	return probe.err
}

func backupRequestFromManifest(manifest Manifest) BackupRequest {
	return BackupRequest{
		BackupID: manifest.BackupID, SourceClusterID: manifest.SourceClusterID,
		AppVersion: manifest.AppVersion, SchemaVersion: manifest.SchemaVersion,
		CoreManifestSHA256: manifest.CoreManifestSHA256, EnvelopeKey: manifest.EnvelopeKey,
		TargetRPO: 15 * time.Minute, TargetRTO: 30 * time.Minute,
	}
}
