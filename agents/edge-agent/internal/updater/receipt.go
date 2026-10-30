package updater

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const (
	receiptSchemaVersion   = 1
	receiptSchemaVersionV2 = 2
)

type signableReceipt struct {
	SchemaVersion          int           `json:"schema_version"`
	InstallerTransactionID string        `json:"installer_transaction_id"`
	ExecutionSequence      uint64        `json:"execution_sequence,omitempty"`
	ReleaseSequence        uint64        `json:"release_sequence"`
	ArtifactSHA256         string        `json:"artifact_sha256"`
	CurrentVersion         string        `json:"current_version"`
	PreviousVersion        string        `json:"previous_version,omitempty"`
	Status                 ReceiptStatus `json:"status"`
	IssuedAt               time.Time     `json:"issued_at"`
	KeyID                  string        `json:"key_id"`
}

func ReceiptSigningBytes(receipt ActivationReceipt) ([]byte, error) {
	return json.Marshal(signableReceipt{
		SchemaVersion: receipt.SchemaVersion, InstallerTransactionID: receipt.InstallerTransactionID,
		ExecutionSequence: receipt.ExecutionSequence, ReleaseSequence: receipt.ReleaseSequence,
		ArtifactSHA256: receipt.ArtifactSHA256,
		CurrentVersion: receipt.CurrentVersion, PreviousVersion: receipt.PreviousVersion,
		Status: receipt.Status, IssuedAt: receipt.IssuedAt, KeyID: receipt.Signature.KeyID,
	})
}

func SignReceipt(receipt *ActivationReceipt, keyID string, privateKey ed25519.PrivateKey) error {
	if receipt == nil || len(privateKey) != ed25519.PrivateKeySize || !safeIDPattern.MatchString(keyID) {
		return fmt.Errorf("%w: signing input", ErrInvalidReceipt)
	}
	receipt.Signature = Signature{KeyID: keyID}
	payload, err := ReceiptSigningBytes(*receipt)
	if err != nil {
		return ErrInvalidReceipt
	}
	receipt.Signature.Value = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return nil
}

func validateReceipt(receipt ActivationReceipt, keys map[string]ed25519.PublicKey, now time.Time) error {
	if (receipt.SchemaVersion != receiptSchemaVersion && receipt.SchemaVersion != receiptSchemaVersionV2) ||
		!safeIDPattern.MatchString(receipt.InstallerTransactionID) ||
		receipt.ReleaseSequence == 0 || !validDigest(receipt.ArtifactSHA256) ||
		(receipt.Status != ReceiptStatusActive && receipt.Status != ReceiptStatusRolledBack) ||
		receipt.IssuedAt.IsZero() || !receipt.IssuedAt.Equal(receipt.IssuedAt.UTC()) || receipt.IssuedAt.After(now.Add(5*time.Minute)) ||
		!safeIDPattern.MatchString(receipt.Signature.KeyID) {
		return ErrInvalidReceipt
	}
	if receipt.SchemaVersion == receiptSchemaVersion && receipt.ExecutionSequence != 0 ||
		receipt.SchemaVersion == receiptSchemaVersionV2 && receipt.ExecutionSequence == 0 {
		return ErrInvalidReceipt
	}
	if _, err := parseVersion(receipt.CurrentVersion); err != nil {
		return ErrInvalidReceipt
	}
	if receipt.PreviousVersion != "" {
		if _, err := parseVersion(receipt.PreviousVersion); err != nil {
			return ErrInvalidReceipt
		}
	}
	key, exists := keys[receipt.Signature.KeyID]
	if !exists {
		return ErrInvalidReceipt
	}
	signature, err := base64.RawStdEncoding.DecodeString(receipt.Signature.Value)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidReceipt
	}
	payload, err := ReceiptSigningBytes(receipt)
	if err != nil || !ed25519.Verify(key, payload, signature) {
		return ErrInvalidReceipt
	}
	return nil
}

func validateActiveReceipt(receipt ActivationReceipt, value *transaction, keys map[string]ed25519.PublicKey, now time.Time) error {
	if err := validateReceipt(receipt, keys, now); err != nil || receipt.Status != ReceiptStatusActive ||
		receipt.InstallerTransactionID != value.InstallerTransactionID ||
		receipt.ReleaseSequence != value.Plan.ReleaseSequence || receipt.ArtifactSHA256 != value.Plan.Artifact.SHA256 ||
		receipt.SchemaVersion == receiptSchemaVersionV2 && receipt.ExecutionSequence != value.Plan.ExecutionSequence ||
		receipt.CurrentVersion != value.Plan.TargetVersion || receipt.PreviousVersion != value.Plan.CurrentVersion {
		return ErrInvalidReceipt
	}
	return nil
}

func validateRollbackReceipt(receipt ActivationReceipt, value *transaction, keys map[string]ed25519.PublicKey, now time.Time) error {
	if err := validateReceipt(receipt, keys, now); err != nil || receipt.Status != ReceiptStatusRolledBack ||
		receipt.InstallerTransactionID != value.InstallerTransactionID ||
		receipt.ReleaseSequence != value.Plan.ReleaseSequence || receipt.ArtifactSHA256 != value.Plan.Artifact.SHA256 ||
		receipt.SchemaVersion == receiptSchemaVersionV2 && receipt.ExecutionSequence != value.Plan.ExecutionSequence ||
		receipt.CurrentVersion != value.Before.CurrentVersion || receipt.PreviousVersion != value.Plan.TargetVersion {
		return ErrInvalidReceipt
	}
	return nil
}

func sameInstalledRelease(left, right ActivationReceipt) bool {
	return left.Status == right.Status && left.InstallerTransactionID == right.InstallerTransactionID &&
		left.ExecutionSequence == right.ExecutionSequence && left.ReleaseSequence == right.ReleaseSequence &&
		left.ArtifactSHA256 == right.ArtifactSHA256 &&
		left.CurrentVersion == right.CurrentVersion && left.PreviousVersion == right.PreviousVersion
}
