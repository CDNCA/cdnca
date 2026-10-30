package controlbackup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestSignedManifestIsCanonicalBoundAndSecretSafe(t *testing.T) {
	t.Parallel()

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	manifest := testManifest()
	signed, err := SignManifest(manifest, "recovery-signing-2026-08", privateKey)
	if err != nil {
		t.Fatalf("SignManifest() error = %v", err)
	}

	encoded, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, secret := range [][]byte{[]byte("private-key-material"), []byte("envelope-key-material")} {
		if bytes.Contains(encoded, secret) {
			t.Fatalf("signed manifest leaked secret %q", secret)
		}
	}

	verified, err := VerifyManifest(signed, map[string]ed25519.PublicKey{
		"recovery-signing-2026-08": privateKey.Public().(ed25519.PublicKey),
	}, ManifestExpectation{
		BackupID:         manifest.BackupID,
		SourceClusterID:  manifest.SourceClusterID,
		AppVersion:       manifest.AppVersion,
		MaxSchemaVersion: manifest.SchemaVersion,
	})
	if err != nil {
		t.Fatalf("VerifyManifest() error = %v", err)
	}
	if verified.BackupID != manifest.BackupID || len(verified.Checkpoints) != 3 {
		t.Fatalf("verified manifest = %#v", verified)
	}

	tampered := signed
	tampered.Payload = append([]byte(nil), signed.Payload...)
	tampered.Payload[len(tampered.Payload)-2] ^= 1
	if _, err := VerifyManifest(tampered, map[string]ed25519.PublicKey{
		"recovery-signing-2026-08": privateKey.Public().(ed25519.PublicKey),
	}, ManifestExpectation{}); !errors.Is(err, ErrManifestIntegrity) {
		t.Fatalf("tampered VerifyManifest() error = %v, want ErrManifestIntegrity", err)
	}

	newerSchema := ManifestExpectation{MaxSchemaVersion: manifest.SchemaVersion - 1}
	if _, err := VerifyManifest(signed, map[string]ed25519.PublicKey{
		"recovery-signing-2026-08": privateKey.Public().(ed25519.PublicKey),
	}, newerSchema); !errors.Is(err, ErrSchemaIncompatible) {
		t.Fatalf("newer schema VerifyManifest() error = %v, want ErrSchemaIncompatible", err)
	}
}

func TestManifestRejectsMissingExternalCheckpointsAndRawSecretReferences(t *testing.T) {
	t.Parallel()

	manifest := testManifest()
	manifest.Checkpoints = manifest.Checkpoints[:2]
	if err := manifest.Validate(); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("missing JetStream checkpoint error = %v, want ErrInvalidManifest", err)
	}

	manifest = testManifest()
	manifest.EnvelopeKey.Name = "literal:envelope-key-material"
	if err := manifest.Validate(); !errors.Is(err, ErrInvalidSecretReference) {
		t.Fatalf("literal secret reference error = %v, want ErrInvalidSecretReference", err)
	}
}

func TestManifestBindsEveryCheckpointToBackupFreezeAndExactJetStreamTopology(t *testing.T) {
	t.Parallel()

	manifest := testManifest()
	if err := manifest.Validate(); err != nil {
		t.Fatalf("valid bound manifest rejected: %v", err)
	}

	for index := range manifest.Checkpoints {
		mutated := manifest
		mutated.Checkpoints = append([]ComponentCheckpoint(nil), manifest.Checkpoints...)
		mutated.Checkpoints[index].WriteFreezeID = "different-freeze"
		if err := mutated.Validate(); !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("checkpoint %d freeze mismatch error = %v", index, err)
		}
	}

	mutated := manifest
	mutated.Checkpoints = append([]ComponentCheckpoint(nil), manifest.Checkpoints...)
	mutated.Checkpoints[2].JetStreamTopology.Consumers = mutated.Checkpoints[2].JetStreamTopology.Consumers[:3]
	if err := mutated.Validate(); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("missing JetStream consumer error = %v", err)
	}

	mutated = manifest
	mutated.Checkpoints = append([]ComponentCheckpoint(nil), manifest.Checkpoints...)
	mutated.Checkpoints[2].JetStreamTopology.Streams[0] = "WRONG_STREAM"
	if err := mutated.Validate(); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("wrong JetStream stream error = %v", err)
	}
}

func testManifest() Manifest {
	recoveryPoint := time.Date(2026, 8, 8, 3, 4, 5, 0, time.UTC)
	return Manifest{
		Schema:             ManifestSchema,
		BackupID:           "00000000-0000-4000-8000-000000000012",
		SourceClusterID:    "customer-control-a",
		AppVersion:         "0.1.0",
		SchemaVersion:      143,
		CreatedAt:          recoveryPoint.Add(8 * time.Second),
		RecoveryPointAt:    recoveryPoint,
		WriteFreezeID:      "freeze-ops12",
		CoreManifestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		EnvelopeKey: SecretReference{
			Provider: "kubernetes-secret",
			Name:     "control-backup-envelope-key",
			Version:  "resource-version-42",
		},
		Checkpoints: []ComponentCheckpoint{
			{Component: ComponentPostgreSQL, BackupID: "00000000-0000-4000-8000-000000000012", WriteFreezeID: "freeze-ops12", SnapshotID: "pg-exported-snapshot-1", Revision: 143, CapturedAt: recoveryPoint, SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", SizeBytes: 4096},
			{Component: ComponentClickHouse, BackupID: "00000000-0000-4000-8000-000000000012", WriteFreezeID: "freeze-ops12", SnapshotID: "ch-checkpoint-1", Revision: 74, CapturedAt: recoveryPoint.Add(time.Second), SHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", SizeBytes: 2048},
			{Component: ComponentJetStream, BackupID: "00000000-0000-4000-8000-000000000012", WriteFreezeID: "freeze-ops12", SnapshotID: "js-checkpoint-1", Revision: 91, CapturedAt: recoveryPoint.Add(2 * time.Second), SHA256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", SizeBytes: 1024, JetStreamTopology: RequiredJetStreamTopology()},
		},
		Objectives: RecoveryObjectives{
			ObservedRPOSeconds: 8,
			TargetRPOSeconds:   900,
			TargetRTOSeconds:   1800,
		},
	}
}
