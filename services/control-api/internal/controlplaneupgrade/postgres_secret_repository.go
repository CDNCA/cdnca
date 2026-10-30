package controlplaneupgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	SystemdControlUpgradeOperation = "control-upgrade"
	postgresSecretSnapshotSchema   = "cdnca.control-plane-upgrade-systemd-repository/v1"
)

type postgresSecretRowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type PostgresSecretRepository struct {
	database       postgresSecretRowQuerier
	installationID string
	operation      string
}

type postgresSecretSnapshot struct {
	Schema         string              `json:"schema"`
	InstallationID string              `json:"installation_id"`
	Operation      string              `json:"operation"`
	Publication    *PublicationReceipt `json:"publication"`
	Control        *ControlState       `json:"control,omitempty"`
	Data           map[string][]byte   `json:"data"`
}

func NewPostgresSecretRepository(database postgresSecretRowQuerier, installationID,
	operation string) (*PostgresSecretRepository, error) {
	return newPostgresSecretRepository(database, installationID, operation)
}

func newPostgresSecretRepository(database postgresSecretRowQuerier, installationID,
	operation string) (*PostgresSecretRepository, error) {
	parsed, err := uuid.Parse(installationID)
	if database == nil || err != nil || parsed == uuid.Nil || parsed.String() != installationID ||
		operation != SystemdControlUpgradeOperation {
		return nil, ErrInvalidConfig
	}
	return &PostgresSecretRepository{database: database, installationID: installationID, operation: operation}, nil
}

func ValidateSystemdHAConfig(expectedReplicas, quorum int) error {
	if expectedReplicas < 2 || quorum < 1 || quorum > expectedReplicas || quorum <= expectedReplicas/2 {
		return ErrInvalidConfig
	}
	return nil
}

func (repository *PostgresSecretRepository) Read(ctx context.Context) (SecretDocument, error) {
	var revision, publicationRevision int64
	var planID string
	var bundle, bundleSHA256, snapshot, snapshotSHA256 []byte
	err := repository.database.QueryRow(ctx, `
SELECT revision,plan_id,publication_revision,bundle_bytes,bundle_sha256,snapshot_bytes,snapshot_sha256
FROM control_upgrade_systemd_repository_154
WHERE installation_id=$1 AND operation=$2`, repository.installationID, repository.operation).Scan(
		&revision, &planID, &publicationRevision, &bundle, &bundleSHA256, &snapshot, &snapshotSHA256)
	if errors.Is(err, pgx.ErrNoRows) {
		return SecretDocument{ResourceVersion: "0", Data: make(map[string][]byte)}, nil
	}
	if err != nil || revision < 1 || publicationRevision < 1 || len(bundle) == 0 || len(bundleSHA256) != sha256.Size ||
		len(snapshot) == 0 || len(snapshotSHA256) != sha256.Size {
		return SecretDocument{}, ErrSecretUnavailable
	}
	actualBundleDigest := sha256.Sum256(bundle)
	actualSnapshotDigest := sha256.Sum256(snapshot)
	if !bytes.Equal(actualBundleDigest[:], bundleSHA256) || !bytes.Equal(actualSnapshotDigest[:], snapshotSHA256) {
		return SecretDocument{}, ErrSecretUnavailable
	}
	document, err := decodePostgresSecretSnapshot(snapshot, repository.installationID, repository.operation)
	if err != nil || document.Publication == nil || document.Publication.PlanID != planID ||
		document.Publication.PublicationRevision != uint64(publicationRevision) ||
		document.Publication.BundleSHA256 != digestBytes(bundle) {
		return SecretDocument{}, ErrSecretUnavailable
	}
	document.ResourceVersion = strconv.FormatInt(revision, 10)
	document.Bundle = append([]byte(nil), bundle...)
	return document, nil
}

func (repository *PostgresSecretRepository) CompareAndSwap(ctx context.Context, expected string,
	document SecretDocument) (SecretDocument, error) {
	expectedRevision, err := strconv.ParseInt(expected, 10, 64)
	if err != nil || expectedRevision < 0 || expectedRevision == math.MaxInt64 || document.ResourceVersion != expected {
		return SecretDocument{}, ErrSecretConflict
	}
	snapshot, err := encodePostgresSecretSnapshot(document, repository.installationID, repository.operation)
	if err != nil {
		return SecretDocument{}, err
	}
	if document.Publication == nil || document.Publication.PublicationRevision > math.MaxInt64 {
		return SecretDocument{}, ErrSecretUnavailable
	}
	bundleDigest := sha256.Sum256(document.Bundle)
	snapshotDigest := sha256.Sum256(snapshot)
	newRevision := expectedRevision + 1
	var storedRevision int64
	err = repository.database.QueryRow(ctx, `
WITH updated AS (
    UPDATE control_upgrade_systemd_repository_154 SET
        revision=$4,plan_id=$5,publication_revision=$6,bundle_bytes=$7,bundle_sha256=$8,
        snapshot_bytes=$9,snapshot_sha256=$10,updated_at=transaction_timestamp()
    WHERE installation_id=$1 AND operation=$2 AND revision=$3
    RETURNING revision
), inserted AS (
    INSERT INTO control_upgrade_systemd_repository_154
        (installation_id,operation,revision,plan_id,publication_revision,bundle_bytes,bundle_sha256,snapshot_bytes,snapshot_sha256)
    SELECT $1,$2,$4,$5,$6,$7,$8,$9,$10 WHERE $3=0
    ON CONFLICT (installation_id,operation) DO NOTHING
    RETURNING revision
)
SELECT revision FROM updated UNION ALL SELECT revision FROM inserted`, repository.installationID, repository.operation, expectedRevision, newRevision,
		document.Publication.PlanID, int64(document.Publication.PublicationRevision), append([]byte(nil), document.Bundle...),
		bundleDigest[:], snapshot, snapshotDigest[:]).Scan(&storedRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return SecretDocument{}, ErrSecretConflict
	}
	if err != nil || storedRevision != newRevision {
		return SecretDocument{}, ErrSecretUnavailable
	}
	stored := cloneSecretDocument(document)
	stored.ResourceVersion = strconv.FormatInt(storedRevision, 10)
	return stored, nil
}

func encodePostgresSecretSnapshot(document SecretDocument, installationID, operation string) ([]byte, error) {
	if document.Publication == nil || !validPublication(*document.Publication) || len(document.Bundle) == 0 ||
		len(document.Bundle) > 1<<20 || document.Publication.InstallationID != installationID ||
		document.Publication.BundleSHA256 != digestBytes(document.Bundle) {
		return nil, ErrSecretUnavailable
	}
	if document.Control != nil && !validControlState(*document.Control) {
		return nil, ErrSecretUnavailable
	}
	data := document.Data
	if data == nil {
		data = make(map[string][]byte)
	}
	snapshot := postgresSecretSnapshot{Schema: postgresSecretSnapshotSchema, InstallationID: installationID,
		Operation: operation, Publication: document.Publication, Control: document.Control, Data: data}
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) > 2<<20 {
		return nil, ErrSecretUnavailable
	}
	return encoded, nil
}

func decodePostgresSecretSnapshot(encoded []byte, installationID, operation string) (SecretDocument, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var snapshot postgresSecretSnapshot
	if decoder.Decode(&snapshot) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		snapshot.Schema != postgresSecretSnapshotSchema || snapshot.InstallationID != installationID ||
		snapshot.Operation != operation || snapshot.Publication == nil || !validPublication(*snapshot.Publication) ||
		snapshot.Publication.InstallationID != installationID || snapshot.Data == nil {
		return SecretDocument{}, ErrSecretUnavailable
	}
	if snapshot.Control != nil && !validControlState(*snapshot.Control) {
		return SecretDocument{}, ErrSecretUnavailable
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return SecretDocument{}, ErrSecretUnavailable
	}
	document := SecretDocument{Publication: snapshot.Publication, Control: snapshot.Control, Data: snapshot.Data}
	return cloneSecretDocument(document), nil
}
