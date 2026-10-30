package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackup"
)

func TestVerifyRestorePlanBindsExactSignedEncryptedRecoveryPoint(t *testing.T) {
	t.Parallel()

	plan, signed, publicKey := validRestoreFixture(t)
	manifest, err := verifyRestorePlan(plan, signed, publicKey)
	if err != nil || manifest.BackupID != plan.ExpectedBackupID || manifest.EnvelopeKey != plan.ExpectedEnvelopeKey {
		t.Fatalf("verifyRestorePlan() = (%+v, %v)", manifest, err)
	}

	tests := []struct {
		name   string
		mutate func(*restorePlan)
	}{
		{name: "backup id", mutate: func(value *restorePlan) { value.ExpectedBackupID = "another-backup" }},
		{name: "source cluster", mutate: func(value *restorePlan) { value.ExpectedSourceClusterID = "another-control" }},
		{name: "app version", mutate: func(value *restorePlan) { value.ExpectedAppVersion = "1.9.0" }},
		{name: "signed payload digest", mutate: func(value *restorePlan) { value.ExpectedManifestSHA256 = strings.Repeat("b", 64) }},
		{name: "core manifest digest", mutate: func(value *restorePlan) { value.ExpectedCoreManifestSHA256 = strings.Repeat("c", 64) }},
		{name: "envelope provider", mutate: func(value *restorePlan) { value.ExpectedEnvelopeKey.Provider = "other-kms" }},
		{name: "envelope name", mutate: func(value *restorePlan) { value.ExpectedEnvelopeKey.Name = "control-backup/other" }},
		{name: "envelope version", mutate: func(value *restorePlan) { value.ExpectedEnvelopeKey.Version = "43" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			changed := plan
			test.mutate(&changed)
			if _, err := verifyRestorePlan(changed, signed, publicKey); !errors.Is(err, errRestorePlanMismatch) {
				t.Fatalf("verifyRestorePlan() error = %v, want errRestorePlanMismatch", err)
			}
		})
	}
}

func TestPutRestoreIntentIsImmutableAndExposesUncertainOutcome(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	intent := restoreIntent{
		Schema: restoreIntentSchema, OperationID: "restore-ops12-20260809", TargetID: "recovery-control-b",
		BackupID: "backup-ops12-20260809", ManifestSHA256: strings.Repeat("a", 64),
		State: restoreIntentStarted, StartedAt: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
	}
	created, err := putRestoreIntent(directory, intent)
	if err != nil || !created {
		t.Fatalf("first putRestoreIntent() = (%v, %v)", created, err)
	}
	created, err = putRestoreIntent(directory, intent)
	if err != nil || created {
		t.Fatalf("replay putRestoreIntent() = (%v, %v)", created, err)
	}

	changed := intent
	changed.TargetID = "different-target"
	if _, err := putRestoreIntent(directory, changed); !errors.Is(err, errRestoreIntentConflict) {
		t.Fatalf("conflicting putRestoreIntent() error = %v", err)
	}
	path := filepath.Join(directory, intent.OperationID+".intent.json")
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(encoded, []byte("\n")) {
		t.Fatal("restore intent is not a complete line-delimited audit fact")
	}
	var stored restoreIntent
	if err := json.Unmarshal(encoded, &stored); err != nil || stored != intent {
		t.Fatalf("stored restore intent = (%+v, %v)", stored, err)
	}
}

func validRestoreFixture(t *testing.T) (restorePlan, controlbackup.SignedManifest, ed25519.PublicKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	manifest := controlbackup.Manifest{
		Schema: controlbackup.ManifestSchema, BackupID: "backup-ops12-20260809", SourceClusterID: "customer-control-a",
		AppVersion: "1.8.0", SchemaVersion: 176,
		CreatedAt:       time.Date(2026, 8, 9, 11, 59, 59, 0, time.UTC),
		RecoveryPointAt: time.Date(2026, 8, 9, 11, 59, 50, 0, time.UTC),
		WriteFreezeID:   "freeze-ops12-20260809", CoreManifestSHA256: strings.Repeat("d", 64),
		EnvelopeKey: controlbackup.SecretReference{Provider: "kms", Name: "control-backup/customer-a", Version: "42"},
		Checkpoints: []controlbackup.ComponentCheckpoint{
			{Component: controlbackup.ComponentPostgreSQL, BackupID: "backup-ops12-20260809", WriteFreezeID: "freeze-ops12-20260809", SnapshotID: "pg-snapshot", Revision: 176, CapturedAt: time.Date(2026, 8, 9, 11, 59, 50, 0, time.UTC), SHA256: strings.Repeat("1", 64), SizeBytes: 1024},
			{Component: controlbackup.ComponentClickHouse, BackupID: "backup-ops12-20260809", WriteFreezeID: "freeze-ops12-20260809", SnapshotID: "ch-snapshot", Revision: 81, CapturedAt: time.Date(2026, 8, 9, 11, 59, 52, 0, time.UTC), SHA256: strings.Repeat("2", 64), SizeBytes: 2048},
			{Component: controlbackup.ComponentJetStream, BackupID: "backup-ops12-20260809", WriteFreezeID: "freeze-ops12-20260809", SnapshotID: "js-snapshot", Revision: 19, CapturedAt: time.Date(2026, 8, 9, 11, 59, 54, 0, time.UTC), SHA256: strings.Repeat("3", 64), SizeBytes: 4096, JetStreamTopology: controlbackup.RequiredJetStreamTopology()},
		},
		Objectives: controlbackup.RecoveryObjectives{ObservedRPOSeconds: 9, TargetRPOSeconds: 300, TargetRTOSeconds: 1800},
	}
	signed, err := controlbackup.SignManifest(manifest, "backup-signing-2026-08", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return restorePlan{
		Schema: restorePlanSchema, OperationID: "restore-ops12-20260809", TargetID: "recovery-control-b",
		MaxSchemaVersion: 176, ExpectedBackupID: manifest.BackupID,
		ExpectedSourceClusterID: manifest.SourceClusterID, ExpectedAppVersion: manifest.AppVersion,
		ExpectedManifestSHA256: signed.PayloadSHA256, ExpectedCoreManifestSHA256: manifest.CoreManifestSHA256,
		ExpectedEnvelopeKey: manifest.EnvelopeKey, SigningKeyID: signed.SigningKeyID,
	}, signed, privateKey.Public().(ed25519.PublicKey)
}
