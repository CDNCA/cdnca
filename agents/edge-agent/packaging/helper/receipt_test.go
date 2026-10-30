package helper_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/updater"
	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper"
	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

func TestSignReceiptMatchesUpdaterSigningContract(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	receipt := protocol.Receipt{
		SchemaVersion: 1, InstallerTransactionID: "txn-123", ReleaseSequence: 2,
		ArtifactSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CurrentVersion: "1.1.0", PreviousVersion: "1.0.0", Status: "active",
		IssuedAt: time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC),
	}
	if err := helper.SignReceipt(&receipt, helper.KeyMaterial{KeyID: "helper-2026-01", PrivateKey: privateKey}); err != nil {
		t.Fatalf("SignReceipt: %v", err)
	}
	signingBytes, err := helper.ReceiptSigningBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":1,"installer_transaction_id":"txn-123","release_sequence":2,"artifact_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","current_version":"1.1.0","previous_version":"1.0.0","status":"active","issued_at":"2026-07-28T00:00:00Z","key_id":"helper-2026-01"}`
	if string(signingBytes) != want {
		t.Fatalf("signing bytes = %s", signingBytes)
	}
	updaterBytes, err := updater.ReceiptSigningBytes(updater.ActivationReceipt{
		SchemaVersion: receipt.SchemaVersion, InstallerTransactionID: receipt.InstallerTransactionID,
		ReleaseSequence: receipt.ReleaseSequence, ArtifactSHA256: receipt.ArtifactSHA256,
		CurrentVersion: receipt.CurrentVersion, PreviousVersion: receipt.PreviousVersion,
		Status: updater.ReceiptStatus(receipt.Status), IssuedAt: receipt.IssuedAt,
		Signature: updater.Signature{KeyID: receipt.Signature.KeyID, Value: receipt.Signature.Value},
	})
	if err != nil || string(updaterBytes) != string(signingBytes) {
		t.Fatalf("updater signing bytes differ: %s, %v", updaterBytes, err)
	}
	signature, err := base64.RawStdEncoding.DecodeString(receipt.Signature.Value)
	if err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatalf("signature = (%x, %v)", signature, err)
	}
	if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), signingBytes, signature) {
		t.Fatal("updater signing bytes do not verify")
	}
	if receipt.Signature.KeyID != "helper-2026-01" || receipt.Signature.Value[len(receipt.Signature.Value)-1] == '=' {
		t.Fatalf("signature = %+v", receipt.Signature)
	}
}

func TestSignReceiptRejectsInvalidFacts(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	valid := protocol.Receipt{
		SchemaVersion: 1, InstallerTransactionID: "txn-123", ReleaseSequence: 2,
		ArtifactSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CurrentVersion: "1.1.0", PreviousVersion: "1.0.0", Status: "active",
		IssuedAt: time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC),
	}
	tests := map[string]func(*protocol.Receipt){
		"schema":       func(value *protocol.Receipt) { value.SchemaVersion = 2 },
		"transaction":  func(value *protocol.Receipt) { value.InstallerTransactionID = "../txn" },
		"sequence":     func(value *protocol.Receipt) { value.ReleaseSequence = 0 },
		"digest":       func(value *protocol.Receipt) { value.ArtifactSHA256 = "A" + value.ArtifactSHA256[1:] },
		"version":      func(value *protocol.Receipt) { value.CurrentVersion = "01.1.0" },
		"status":       func(value *protocol.Receipt) { value.Status = "unknown" },
		"issued-at":    func(value *protocol.Receipt) { value.IssuedAt = time.Time{} },
		"non-utc":      func(value *protocol.Receipt) { value.IssuedAt = value.IssuedAt.In(time.FixedZone("x", 3600)) },
		"bad-previous": func(value *protocol.Receipt) { value.PreviousVersion = "latest" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			receipt := valid
			mutate(&receipt)
			if err := helper.SignReceipt(&receipt, helper.KeyMaterial{KeyID: "helper-2026-01", PrivateKey: privateKey}); !errors.Is(err, helper.ErrReceiptInput) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if err := helper.SignReceipt(nil, helper.KeyMaterial{KeyID: "helper-2026-01", PrivateKey: privateKey}); !errors.Is(err, helper.ErrReceiptInput) {
		t.Fatalf("nil receipt error = %v", err)
	}
}
