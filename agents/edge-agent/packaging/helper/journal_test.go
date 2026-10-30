package helper

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

func TestJournalPersistsCanonicalTransactionAcrossRestarts(t *testing.T) {
	store, config := testJournalStore(t)
	installPacket := []byte(`{"protocol_version":1,"operation":"install"}`)
	record := testPreparedRecord(2, HashCanonicalPayload(installPacket))
	previous := testReceipt(t, JournalRecord{
		TransactionID: "bootstrap-1", ReleaseSequence: 1, OuterArtifactSHA256: journalDigest("previous"),
		PreviousVersion: "0.9.0", TargetVersion: record.PreviousVersion,
	}, "active")
	previous.CurrentVersion = record.PreviousVersion
	previous.PreviousVersion = ""
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	if err := SignReceipt(&previous, KeyMaterial{KeyID: "helper-2026-01", PrivateKey: privateKey}); err != nil {
		t.Fatal(err)
	}
	record.PreviousReceipt = &previous
	if err := store.Save(record); err != nil {
		t.Fatalf("save prepared: %v", err)
	}
	if highWater, err := store.HighWaterMark(); err != nil || highWater != 0 {
		t.Fatalf("prepared high water = (%d, %v)", highWater, err)
	}
	if err := record.MatchInstallPayload(installPacket); err != nil {
		t.Fatalf("match install: %v", err)
	}
	if err := record.MatchInstallPayload([]byte("different")); !errors.Is(err, ErrTransactionConflict) {
		t.Fatalf("different install error = %v", err)
	}
	path := filepath.Join(config.Directory, "journal-"+record.TransactionID+".json")
	assertFileMode(t, path, journalMode)

	restarted, err := NewJournalStore(config)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := restarted.Load(record.TransactionID)
	if err != nil || loaded.InstallPayloadSHA256 != record.InstallPayloadSHA256 || loaded.Phase != JournalPrepared {
		t.Fatalf("restart load = (%+v, %v)", loaded, err)
	}
	if err := restarted.Save(loaded); err != nil {
		t.Fatalf("idempotent save: %v", err)
	}

	loaded.Phase = JournalInstalling
	if err := restarted.Save(loaded); err != nil {
		t.Fatalf("save installing: %v", err)
	}
	active := testReceipt(t, loaded, "active")
	loaded.Phase = JournalActive
	loaded.ActiveReceipt = &active
	if err := restarted.Save(loaded); err != nil {
		t.Fatalf("save active: %v", err)
	}
	if highWater, err := restarted.HighWaterMark(); err != nil || highWater != record.ReleaseSequence {
		t.Fatalf("active high water = (%d, %v)", highWater, err)
	}

	rollbackPacket := []byte(`{"protocol_version":1,"operation":"rollback"}`)
	loaded.Phase = JournalRollbacking
	loaded.RollbackPayloadSHA256 = HashCanonicalPayload(rollbackPacket)
	if err := restarted.Save(loaded); err != nil {
		t.Fatalf("save rollbacking: %v", err)
	}
	if err := loaded.MatchRollbackPayload(rollbackPacket); err != nil {
		t.Fatalf("match rollback: %v", err)
	}
	rollback := testReceipt(t, loaded, "rolled_back")
	loaded.Phase = JournalRolledBack
	loaded.RollbackReceipt = &rollback
	if err := restarted.Save(loaded); err != nil {
		t.Fatalf("save rolled back: %v", err)
	}

	finalStore, err := NewJournalStore(config)
	if err != nil {
		t.Fatal(err)
	}
	final, err := finalStore.Load(record.TransactionID)
	if err != nil || final.Phase != JournalRolledBack || final.RollbackReceipt == nil {
		t.Fatalf("final restart = (%+v, %v)", final, err)
	}
	highWater, err := finalStore.HighWaterMark()
	if err != nil || highWater != record.ReleaseSequence {
		t.Fatalf("high water = (%d, %v)", highWater, err)
	}
}

func TestJournalV3HighWaterUsesExecutionSequenceAndPersistsPhysicalRelease(t *testing.T) {
	store, _ := testJournalStore(t)
	record := testPreparedRecord(7, journalDigest("v3-install"))
	record.SchemaVersion = journalSchemaVersionV3
	record.ExecutionSequence = 20
	record.Action = protocol.ActionUpgrade
	previous := testReceipt(t, JournalRecord{TransactionID: "bootstrap-v3", ReleaseSequence: 3,
		ExecutionSequence: 19, OuterArtifactSHA256: journalDigest("previous-v3"),
		PreviousVersion: "0.9.0", TargetVersion: record.PreviousVersion}, "active")
	previous.SchemaVersion = 2
	previous.ExecutionSequence = 19
	record.PreviousReceipt = &previous
	if err := store.Save(record); err != nil {
		t.Fatalf("save v3 prepared: %v", err)
	}
	record.Phase = JournalInstalling
	if err := store.Save(record); err != nil {
		t.Fatalf("save v3 installing: %v", err)
	}
	active := testReceipt(t, record, "active")
	active.SchemaVersion = 2
	active.ExecutionSequence = record.ExecutionSequence
	record.Phase = JournalActive
	record.ActiveReceipt = &active
	if err := store.Save(record); err != nil {
		t.Fatalf("save v3 active: %v", err)
	}
	if highWater, err := store.HighWaterMark(); err != nil || highWater != record.ExecutionSequence {
		t.Fatalf("v3 high water = (%d, %v), want %d", highWater, err, record.ExecutionSequence)
	}
	loaded, err := store.Load(record.TransactionID)
	if err != nil || loaded.ExecutionSequence != 20 || loaded.ReleaseSequence != 7 || loaded.Action != protocol.ActionUpgrade {
		t.Fatalf("loaded v3 journal = (%#v, %v)", loaded, err)
	}
}

func TestJournalRejectsConflictsAndInvalidTransitions(t *testing.T) {
	store, _ := testJournalStore(t)
	record := testPreparedRecord(2, HashCanonicalPayload([]byte("install")))
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	conflict := record
	conflict.OuterArtifactSHA256 = journalDigest("different-outer")
	if err := store.Save(conflict); !errors.Is(err, ErrTransactionConflict) {
		t.Fatalf("same transaction different facts error = %v", err)
	}
	conflict = record
	conflict.InstallPayloadSHA256 = journalDigest("different-request")
	if err := store.Save(conflict); !errors.Is(err, ErrTransactionConflict) {
		t.Fatalf("same transaction different packet error = %v", err)
	}
	invalid := record
	invalid.Phase = JournalActive
	active := testReceipt(t, invalid, "active")
	invalid.ActiveReceipt = &active
	if err := store.Save(invalid); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("skipped transition error = %v", err)
	}
	if _, err := store.Load("unknown"); !errors.Is(err, ErrJournalNotFound) {
		t.Fatalf("unknown transaction error = %v", err)
	}
}

func TestJournalGenericSaveRejectsLegacySchemaUpgrade(t *testing.T) {
	for _, phase := range []JournalPhase{
		JournalPrepared, JournalInstalling, JournalAborted, JournalActive, JournalRollbacking, JournalRolledBack,
	} {
		t.Run(string(phase), func(t *testing.T) {
			store, _ := testJournalStore(t)
			record := testPreparedRecord(2, journalDigest("legacy-schema-upgrade-"+string(phase)))
			record.SchemaVersion = legacyJournalSchemaVersion
			record.PreviousPhysicalReleaseSequence = 0
			record.PreviousManifestSHA256 = ""
			previous := testReceipt(t, JournalRecord{
				TransactionID: "bootstrap-1", ReleaseSequence: 1, OuterArtifactSHA256: journalDigest("previous"),
				PreviousVersion: "0.9.0", TargetVersion: record.PreviousVersion,
			}, "active")
			record.PreviousReceipt = &previous
			if err := store.Save(record); err != nil {
				t.Fatal(err)
			}

			if phase != JournalPrepared && phase != JournalAborted {
				record.Phase = JournalInstalling
				if err := store.Save(record); err != nil {
					t.Fatal(err)
				}
			}
			if phase == JournalAborted {
				record.Phase = JournalAborted
				if err := store.Save(record); err != nil {
					t.Fatal(err)
				}
			}
			if phase == JournalActive || phase == JournalRollbacking || phase == JournalRolledBack {
				active := testReceipt(t, record, "active")
				record.Phase = JournalActive
				record.ActiveReceipt = &active
				if err := store.Save(record); err != nil {
					t.Fatal(err)
				}
			}
			if phase == JournalRollbacking || phase == JournalRolledBack {
				record.Phase = JournalRollbacking
				record.RollbackPayloadSHA256 = journalDigest("rollback-" + string(phase))
				if err := store.Save(record); err != nil {
					t.Fatal(err)
				}
			}
			if phase == JournalRolledBack {
				rolledBack := testReceipt(t, record, "rolled_back")
				record.Phase = JournalRolledBack
				record.RollbackReceipt = &rolledBack
				if err := store.Save(record); err != nil {
					t.Fatal(err)
				}
			}

			migrated := record
			migrated.SchemaVersion = journalSchemaVersion
			migrated.PreviousPhysicalReleaseSequence = 1
			migrated.PreviousManifestSHA256 = journalDigest("captured-previous-manifest")
			if err := store.Save(migrated); !errors.Is(err, ErrTransactionConflict) {
				t.Fatalf("generic %s schema migration error = %v, want %v", phase, err, ErrTransactionConflict)
			}
		})
	}
}

func TestJournalPreparedAbortIsDurableTerminal(t *testing.T) {
	store, config := testJournalStore(t)
	record := testPreparedRecord(2, journalDigest("install"))
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	record.Phase = JournalAborted
	if err := store.Save(record); err != nil {
		t.Fatalf("save aborted tombstone: %v", err)
	}

	restarted, err := NewJournalStore(config)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := restarted.Load(record.TransactionID)
	if err != nil || loaded.Phase != JournalAborted || loaded != record {
		t.Fatalf("restart load aborted = (%+v, %v), want %+v", loaded, err, record)
	}
	if err := restarted.Save(loaded); err != nil {
		t.Fatalf("idempotent aborted replay: %v", err)
	}
	if highWater, err := restarted.HighWaterMark(); err != nil || highWater != 0 {
		t.Fatalf("aborted high water = (%d, %v)", highWater, err)
	}
	for _, phase := range []JournalPhase{JournalPrepared, JournalInstalling, JournalActive, JournalRolledBack} {
		next := loaded
		next.Phase = phase
		if err := restarted.Save(next); !errors.Is(err, ErrJournalCorrupt) {
			t.Fatalf("aborted -> %s error = %v", phase, err)
		}
	}
	invalid := testPreparedRecord(3, journalDigest("other-install"))
	invalid.TransactionID = "txn-aborted-invalid"
	invalid.Phase = JournalAborted
	active := testReceipt(t, invalid, "active")
	invalid.ActiveReceipt = &active
	if err := restarted.Save(invalid); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("aborted record with receipt error = %v", err)
	}
}

func TestJournalRejectsBareAbortAndEqualVersions(t *testing.T) {
	store, _ := testJournalStore(t)
	bared := testPreparedRecord(2, journalDigest("bare-abort"))
	bared.Phase = JournalAborted
	if err := store.Save(bared); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("bare aborted record error = %v, want %v", err, ErrJournalCorrupt)
	}

	equal := testPreparedRecord(3, journalDigest("equal-versions"))
	equal.TargetVersion = equal.PreviousVersion
	if err := store.Save(equal); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("equal-version record error = %v, want %v", err, ErrJournalCorrupt)
	}
}

func TestJournalTerminalPhasesRequirePreviousReceiptChain(t *testing.T) {
	store, _ := testJournalStore(t)
	record := testPreparedRecord(2, journalDigest("terminal-previous-chain"))
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	record.Phase = JournalInstalling
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	active := testReceipt(t, record, "active")
	record.Phase = JournalActive
	record.ActiveReceipt = &active
	if err := store.Save(record); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("active without previous receipt error = %v", err)
	}
	record.PreviousReceipt = &active
	if err := store.Save(record); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("active with mismatched previous receipt error = %v", err)
	}
}

func TestJournalStoreSerializesStaleTransitionsAcrossInstances(t *testing.T) {
	storeA, config := testJournalStore(t)
	storeB, err := NewJournalStore(config)
	if err != nil {
		t.Fatal(err)
	}
	record := testPreparedRecord(2, journalDigest("stale-transition"))
	if err := storeA.Save(record); err != nil {
		t.Fatal(err)
	}
	preparedA, err := storeA.Load(record.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	preparedB, err := storeB.Load(record.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	storeA.beforeWrite = func(_, next JournalRecord) {
		if next.Phase != JournalInstalling {
			return
		}
		close(started)
		<-release
	}
	installDone := make(chan error, 1)
	go func() {
		preparedA.Phase = JournalInstalling
		installDone <- storeA.Save(preparedA)
	}()
	<-started
	abortDone := make(chan error, 1)
	go func() {
		preparedB.Phase = JournalAborted
		abortDone <- storeB.Save(preparedB)
	}()
	select {
	case err := <-abortDone:
		t.Fatalf("stale abort completed while install held the directory lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-installDone; err != nil {
		t.Fatalf("install transition: %v", err)
	}
	if err := <-abortDone; !errors.Is(err, ErrJournalCorrupt) && !errors.Is(err, ErrTransactionConflict) {
		t.Fatalf("stale abort error = %v, want transition rejection", err)
	}
	final, err := storeA.Load(record.TransactionID)
	if err != nil || final.Phase != JournalInstalling {
		t.Fatalf("final stale transition = (%+v, %v), want installing", final, err)
	}
}

func TestJournalSaveFailurePreservesPreviousRecord(t *testing.T) {
	store, config := testJournalStore(t)
	record := testPreparedRecord(2, journalDigest("directory-failure"))
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	next := record
	next.Phase = JournalInstalling
	if err := os.Chmod(config.Directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(next); !errors.Is(err, ErrJournalPolicy) {
		t.Fatalf("directory failure error = %v, want %v", err, ErrJournalPolicy)
	}
	if err := os.Chmod(config.Directory, stateDirMode); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(record.TransactionID)
	if err != nil || loaded.Phase != JournalPrepared {
		t.Fatalf("record after failed save = (%+v, %v), want prepared", loaded, err)
	}
}

func TestJournalPersistsAutomaticPackagingRollback(t *testing.T) {
	store, _ := testJournalStore(t)
	record := testPreparedRecord(2, journalDigest("install"))
	previous := testReceipt(t, JournalRecord{
		TransactionID: "bootstrap-1", ReleaseSequence: 1, OuterArtifactSHA256: journalDigest("previous"),
		PreviousVersion: "0.9.0", TargetVersion: record.PreviousVersion,
	}, "active")
	previous.CurrentVersion = record.PreviousVersion
	previous.PreviousVersion = ""
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	if err := SignReceipt(&previous, KeyMaterial{KeyID: "helper-2026-01", PrivateKey: privateKey}); err != nil {
		t.Fatal(err)
	}
	record.PreviousReceipt = &previous
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	record.Phase = JournalInstalling
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	rolledBack := testReceipt(t, record, "rolled_back")
	record.Phase = JournalRolledBack
	record.RollbackReceipt = &rolledBack
	if err := store.Save(record); err != nil {
		t.Fatalf("persist automatic rollback: %v", err)
	}
	loaded, err := store.Load(record.TransactionID)
	if err != nil || loaded.Phase != JournalRolledBack || loaded.RollbackPayloadSHA256 != "" {
		t.Fatalf("automatic rollback = (%+v, %v)", loaded, err)
	}
}

func TestJournalFilesFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, path string)
		want   error
	}{
		{
			name: "wide-mode",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: ErrJournalPolicy,
		},
		{
			name: "symlink",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				target := path + ".target"
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
			want: ErrJournalPolicy,
		},
		{
			name: "hardlink",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			},
			want: ErrJournalPolicy,
		},
		{
			name: "unknown-field",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				content, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				content[len(content)-1] = ','
				content = append(content, []byte(`"unknown":true}`)...)
				writeTestProtectedFile(t, path, journalMode, content)
			},
			want: ErrJournalCorrupt,
		},
		{
			name: "trailing-byte",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				content, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				writeTestProtectedFile(t, path, journalMode, append(content, '\n'))
			},
			want: ErrJournalCorrupt,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, config := testJournalStore(t)
			record := testPreparedRecord(2, journalDigest("install"))
			if err := store.Save(record); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(config.Directory, "journal-"+record.TransactionID+".json")
			test.mutate(t, path)
			if _, err := store.Load(record.TransactionID); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestJournalHighWaterRejectsUnsafeJournalName(t *testing.T) {
	store, config := testJournalStore(t)
	path := filepath.Join(config.Directory, "journal-..json")
	if err := os.WriteFile(path, []byte("{}"), journalMode); err != nil {
		t.Fatal(err)
	}
	if _, err := store.HighWaterMark(); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("unsafe journal name error = %v", err)
	}
}

func TestJournalDirectoryPolicyFailsClosed(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "state")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	config := JournalConfig{Directory: directory, OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid())}
	if _, err := NewJournalStore(config); !errors.Is(err, ErrJournalPolicy) {
		t.Fatalf("wide directory error = %v", err)
	}
	if err := os.Chmod(directory, stateDirMode); err != nil {
		t.Fatal(err)
	}
	config.OwnerUID++
	if _, err := NewJournalStore(config); !errors.Is(err, ErrJournalPolicy) {
		t.Fatalf("wrong owner error = %v", err)
	}
}

func TestProductionJournalConfigRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("process is root")
	}
	if _, err := ProductionJournalConfig(); !errors.Is(err, ErrJournalPolicy) {
		t.Fatalf("ProductionJournalConfig error = %v", err)
	}
}

func testJournalStore(t *testing.T) (*JournalStore, JournalConfig) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	config := JournalConfig{
		Directory: filepath.Join(t.TempDir(), "state"), OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid()),
		TrustedReceiptKeys: map[string]ed25519.PublicKey{"helper-2026-01": append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)},
	}
	store, err := NewJournalStore(config)
	if err != nil {
		t.Fatal(err)
	}
	return store, config
}

func testPreparedRecord(sequence uint64, installHash string) JournalRecord {
	return JournalRecord{
		SchemaVersion: journalSchemaVersion, TransactionID: "txn-123", Phase: JournalPrepared,
		InstallPayloadSHA256: installHash, ReleaseSequence: sequence,
		OuterArtifactSHA256: journalDigest("outer"), ManifestSHA256: journalDigest("manifest"),
		ExecutableSHA256: journalDigest("executable"), SBOMSHA256: journalDigest("sbom"),
		PreviousVersion: "1.0.0", TargetVersion: "1.1.0",
		PreviousPhysicalReleaseSequence: sequence - 1, PreviousManifestSHA256: journalDigest("previous-manifest"),
	}
}

func testReceipt(t *testing.T, record JournalRecord, status string) protocol.Receipt {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	receipt := protocol.Receipt{
		SchemaVersion: 1, InstallerTransactionID: record.TransactionID, ReleaseSequence: record.ReleaseSequence,
		ArtifactSHA256: record.OuterArtifactSHA256, IssuedAt: time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC), Status: status,
	}
	if record.SchemaVersion == journalSchemaVersionV3 || record.ExecutionSequence != 0 {
		receipt.SchemaVersion = 2
		receipt.ExecutionSequence = record.ExecutionSequence
	}
	if status == "active" {
		receipt.CurrentVersion = record.TargetVersion
		receipt.PreviousVersion = record.PreviousVersion
	} else {
		receipt.CurrentVersion = record.PreviousVersion
		receipt.PreviousVersion = record.TargetVersion
	}
	if err := SignReceipt(&receipt, KeyMaterial{KeyID: "helper-2026-01", PrivateKey: privateKey}); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func journalDigest(value string) string {
	return HashCanonicalPayload([]byte(value))
}
