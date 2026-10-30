package controlplaneupgrade

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestOPS06PostgresSecretRepositoryCASBindsSnapshot(t *testing.T) {
	installationID := uuid.NewString()
	database := &postgresRepositoryDatabase{}
	repository, err := newPostgresSecretRepository(database, installationID, SystemdControlUpgradeOperation)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := repository.Read(t.Context())
	if err != nil || empty.ResourceVersion != "0" || empty.Data == nil {
		t.Fatalf("empty Read() = (%#v, %v)", empty, err)
	}
	document := postgresRepositoryDocument(installationID)
	document.ResourceVersion = "0"
	stored, err := repository.CompareAndSwap(t.Context(), "0", document)
	if err != nil || stored.ResourceVersion != "1" || database.revision != 1 {
		t.Fatalf("CompareAndSwap() = (%#v, %v), database revision=%d", stored, err, database.revision)
	}
	if database.installationID != installationID || database.operation != SystemdControlUpgradeOperation ||
		database.planID != document.Publication.PlanID || database.publicationRevision != 1 ||
		fmt.Sprintf("%x", database.bundleDigest) != document.Publication.BundleSHA256 {
		t.Fatalf("stored bindings installation=%q operation=%q plan=%q publication=%d digest=%x",
			database.installationID, database.operation, database.planID, database.publicationRevision, database.bundleDigest)
	}
	loaded, err := repository.Read(t.Context())
	if err != nil || loaded.ResourceVersion != "1" || string(loaded.Bundle) != string(document.Bundle) ||
		loaded.Publication == nil || loaded.Publication.PlanID != document.Publication.PlanID || string(loaded.Data["future-key"]) != "preserved" {
		t.Fatalf("Read() = (%#v, %v)", loaded, err)
	}
	if _, err := repository.CompareAndSwap(t.Context(), "0", document); !errors.Is(err, ErrSecretConflict) {
		t.Fatalf("stale CAS error = %v", err)
	}
	database.snapshot[0] ^= 0xff
	if _, err := repository.Read(t.Context()); !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("tampered snapshot error = %v", err)
	}
}

func TestOPS06PostgresSecretRepositoryRejectsCrossBindingAndUnsafeHA(t *testing.T) {
	installationID := uuid.NewString()
	if _, err := newPostgresSecretRepository(&postgresRepositoryDatabase{}, installationID, "rollback"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("operation error = %v", err)
	}
	repository, err := newPostgresSecretRepository(&postgresRepositoryDatabase{}, installationID, SystemdControlUpgradeOperation)
	if err != nil {
		t.Fatal(err)
	}
	missing := postgresRepositoryDocument(installationID)
	missing.ResourceVersion = "2"
	if _, err := repository.CompareAndSwap(t.Context(), "2", missing); !errors.Is(err, ErrSecretConflict) {
		t.Fatalf("non-initial missing-row CAS error = %v", err)
	}
	document := postgresRepositoryDocument(uuid.NewString())
	document.ResourceVersion = "0"
	if _, err := repository.CompareAndSwap(t.Context(), "0", document); !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("cross-installation error = %v", err)
	}
	for _, pair := range [][2]int{{1, 1}, {2, 1}, {3, 1}, {4, 2}, {3, 4}} {
		if err := ValidateSystemdHAConfig(pair[0], pair[1]); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("ValidateSystemdHAConfig(%d,%d) = %v", pair[0], pair[1], err)
		}
	}
	for _, pair := range [][2]int{{2, 2}, {3, 2}, {5, 3}} {
		if err := ValidateSystemdHAConfig(pair[0], pair[1]); err != nil {
			t.Errorf("ValidateSystemdHAConfig(%d,%d) = %v", pair[0], pair[1], err)
		}
	}
}

func postgresRepositoryDocument(installationID string) SecretDocument {
	bundle := []byte(`{"signed":"control-upgrade-plan"}`)
	digest := sha256.Sum256(bundle)
	return SecretDocument{Bundle: bundle, Publication: &PublicationReceipt{
		Schema: publicationSchema, ReceiptID: "receipt:1", PlanID: uuid.NewString(), BundleSHA256: fmt.Sprintf("%x", digest),
		PublicationRevision: 1, ChannelRevision: 5, ReleaseSequence: 8, InstallationID: installationID,
		Component: "control-api", CurrentVersion: "1.4.0", CurrentDigest: strings.Repeat("11", 32),
		TargetVersion: "1.5.0", TargetDigest: strings.Repeat("22", 32), RollbackVersion: "1.4.0",
		RollbackDigest: strings.Repeat("11", 32), ProtocolVersion: 2, IdempotencySHA256: strings.Repeat("33", 32),
		RequestID: "request-1", ActorUserID: uuid.New(), ActorScopeID: uuid.New(), PublishedAt: 1,
	}, Data: map[string][]byte{"future-key": []byte("preserved")}}
}

type postgresRepositoryDatabase struct {
	revision            int64
	installationID      string
	operation           string
	planID              string
	publicationRevision int64
	bundle              []byte
	bundleDigest        []byte
	snapshot            []byte
	snapshotDigest      []byte
}

func (database *postgresRepositoryDatabase) QueryRow(_ context.Context, query string, arguments ...any) pgx.Row {
	if strings.Contains(query, "INSERT INTO control_upgrade_systemd_repository_154") {
		expected := arguments[2].(int64)
		if expected != database.revision {
			return postgresRepositoryRow{err: pgx.ErrNoRows}
		}
		database.installationID = arguments[0].(string)
		database.operation = arguments[1].(string)
		database.revision = arguments[3].(int64)
		database.planID = arguments[4].(string)
		database.publicationRevision = arguments[5].(int64)
		database.bundle = append([]byte(nil), arguments[6].([]byte)...)
		database.bundleDigest = append([]byte(nil), arguments[7].([]byte)...)
		database.snapshot = append([]byte(nil), arguments[8].([]byte)...)
		database.snapshotDigest = append([]byte(nil), arguments[9].([]byte)...)
		return postgresRepositoryRow{values: []any{database.revision}}
	}
	if database.revision == 0 {
		return postgresRepositoryRow{err: pgx.ErrNoRows}
	}
	return postgresRepositoryRow{values: []any{database.revision, database.planID, database.publicationRevision,
		append([]byte(nil), database.bundle...), append([]byte(nil), database.bundleDigest...),
		append([]byte(nil), database.snapshot...), append([]byte(nil), database.snapshotDigest...)}}
}

type postgresRepositoryRow struct {
	values []any
	err    error
}

func (row postgresRepositoryRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != len(row.values) {
		return errors.New("unexpected scan shape")
	}
	for index, value := range row.values {
		switch destination := destinations[index].(type) {
		case *int64:
			*destination = value.(int64)
		case *string:
			*destination = value.(string)
		case *[]byte:
			*destination = append([]byte(nil), value.([]byte)...)
		default:
			return errors.New("unexpected scan destination")
		}
	}
	return nil
}
