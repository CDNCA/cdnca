package helper

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

var (
	ErrReceiptInput       = errors.New("invalid activation receipt input")
	helperIdentifierRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type signableReceipt struct {
	SchemaVersion          int       `json:"schema_version"`
	InstallerTransactionID string    `json:"installer_transaction_id"`
	ExecutionSequence      uint64    `json:"execution_sequence,omitempty"`
	ReleaseSequence        uint64    `json:"release_sequence"`
	ArtifactSHA256         string    `json:"artifact_sha256"`
	CurrentVersion         string    `json:"current_version"`
	PreviousVersion        string    `json:"previous_version,omitempty"`
	Status                 string    `json:"status"`
	IssuedAt               time.Time `json:"issued_at"`
	KeyID                  string    `json:"key_id"`
}

func ReceiptSigningBytes(receipt protocol.Receipt) ([]byte, error) {
	return json.Marshal(signableReceipt{
		SchemaVersion: receipt.SchemaVersion, InstallerTransactionID: receipt.InstallerTransactionID,
		ExecutionSequence: receipt.ExecutionSequence,
		ReleaseSequence:   receipt.ReleaseSequence, ArtifactSHA256: receipt.ArtifactSHA256,
		CurrentVersion: receipt.CurrentVersion, PreviousVersion: receipt.PreviousVersion,
		Status: receipt.Status, IssuedAt: receipt.IssuedAt, KeyID: receipt.Signature.KeyID,
	})
}

func SignReceipt(receipt *protocol.Receipt, key KeyMaterial) error {
	if receipt == nil || (receipt.SchemaVersion != 1 && receipt.SchemaVersion != 2) ||
		(receipt.SchemaVersion == 1 && receipt.ExecutionSequence != 0) ||
		(receipt.SchemaVersion == 2 && receipt.ExecutionSequence == 0) ||
		!validHelperIdentifier(receipt.InstallerTransactionID) ||
		receipt.ReleaseSequence == 0 || !validHelperDigest(receipt.ArtifactSHA256) ||
		!validHelperVersion(receipt.CurrentVersion) || (receipt.PreviousVersion != "" && !validHelperVersion(receipt.PreviousVersion)) ||
		(receipt.Status != "active" && receipt.Status != "rolled_back") ||
		receipt.IssuedAt.IsZero() || receipt.IssuedAt.Location() != time.UTC ||
		!validHelperIdentifier(key.KeyID) || len(key.PrivateKey) != ed25519.PrivateKeySize {
		return ErrReceiptInput
	}
	receipt.Signature = protocol.Signature{KeyID: key.KeyID}
	payload, err := ReceiptSigningBytes(*receipt)
	if err != nil {
		return ErrReceiptInput
	}
	receipt.Signature.Value = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key.PrivateKey, payload))
	return nil
}

func validHelperIdentifier(value string) bool {
	return helperIdentifierRegex.MatchString(value)
}

func validHelperDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}

func validHelperVersion(value string) bool {
	if !validHelperIdentifier(value) || strings.Contains(value, "+") {
		return false
	}
	core, prerelease, found := strings.Cut(value, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 || (found && !validHelperPrerelease(prerelease)) {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 64); err != nil {
			return false
		}
	}
	return true
}

func validHelperPrerelease(value string) bool {
	if value == "" {
		return false
	}
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for _, character := range identifier {
			if character < '0' || character > '9' {
				numeric = false
			}
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
		if numeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}
