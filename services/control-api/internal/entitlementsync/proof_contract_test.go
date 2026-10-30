package entitlementsync

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/uuid"
)

type proofContract struct {
	Version             string `json:"version"`
	Seed                string `json:"seed"`
	PublicKey           string `json:"public_key"`
	InstallationID      string `json:"installation_id"`
	Name                string `json:"name"`
	ActivationCode      string `json:"activation_code"`
	ActivationRequestID string `json:"activation_request_id"`
	ActivationMessage   string `json:"activation_message"`
	ActivationSignature string `json:"activation_signature"`
	RenewalRequestID    string `json:"renewal_request_id"`
	RenewalMessage      string `json:"renewal_message"`
	RenewalSignature    string `json:"renewal_signature"`
}

func TestEntitlementProofContract(t *testing.T) {
	contract := loadProofContract(t)
	seed := decodeProofContractValue(t, contract.Seed)
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if expected := decodeProofContractValue(t, contract.PublicKey); !bytes.Equal(publicKey, expected) {
		t.Fatal("fixture public key does not match its seed")
	}
	installationID := uuid.MustParse(contract.InstallationID)
	activation := activationRequest{
		InstallationID: installationID,
		Name:           contract.Name,
		ActivationCode: contract.ActivationCode,
		PublicKey:      publicKey,
		RequestID:      contract.ActivationRequestID,
	}
	assertProofContract(t, publicKey, activationProofMessage(activation), contract.ActivationMessage, contract.ActivationSignature)
	assertProofContract(t, publicKey, renewalProofMessage(installationID, contract.RenewalRequestID), contract.RenewalMessage, contract.RenewalSignature)
}

func loadProofContract(t *testing.T) proofContract {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate proof contract test")
	}
	encoded, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "../../../../tests/contracts/entitlement-proof-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract proofContract
	if err := json.Unmarshal(encoded, &contract); err != nil {
		t.Fatal(err)
	}
	if contract.Version != "cdnca-entitlement-proof-contract/v1" {
		t.Fatalf("proof contract version = %q", contract.Version)
	}
	return contract
}

func decodeProofContractValue(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func assertProofContract(t *testing.T, publicKey ed25519.PublicKey, message []byte, encodedMessage, encodedSignature string) {
	t.Helper()
	expectedMessage := decodeProofContractValue(t, encodedMessage)
	if !bytes.Equal(message, expectedMessage) {
		t.Fatalf("proof message = %s, want %s", base64.RawURLEncoding.EncodeToString(message), encodedMessage)
	}
	signature := decodeProofContractValue(t, encodedSignature)
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("fixture signature does not verify")
	}
}
