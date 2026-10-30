package entitlementsync

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestInstallationEncryptionKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "encryption.key")
	public, err := GenerateEncryptionKey(path)
	if err != nil || len(public) != 32 {
		t.Fatalf("generate = %d bytes, %v", len(public), err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, %v", info.Mode(), err)
	}
	if _, err := GenerateEncryptionKey(path); err == nil {
		t.Fatal("an existing key file was overwritten")
	}
	private, err := LoadEncryptionKey(path)
	if err != nil || len(private) != 32 {
		t.Fatalf("load = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEncryptionKey(path); err == nil {
		t.Fatal("a world-readable key file was accepted")
	}
}

// The encryption key is a trailing proof field only when present, so an
// activation without it proves exactly what it did before PA-14.
func TestActivationCarriesOptionalEncryptionKey(t *testing.T) {
	identity := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	code := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	id := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	plain, err := prepareActivation(id, "main", code, identity, nil)
	if err != nil {
		t.Fatal(err)
	}
	encryption := bytes.Repeat([]byte{9}, 32)
	withKey, err := prepareActivation(id, "main", code, identity, encryption)
	if err != nil {
		t.Fatal(err)
	}
	var plainBody, keyBody map[string]string
	if json.Unmarshal(plain.body, &plainBody) != nil || json.Unmarshal(withKey.body, &keyBody) != nil {
		t.Fatal("bodies do not decode")
	}
	if _, present := plainBody["encryption_public_key"]; present {
		t.Fatal("activation without a key sends the field")
	}
	if keyBody["encryption_public_key"] == "" || keyBody["proof"] == plainBody["proof"] {
		t.Fatal("the encryption key is not sent or not bound by the proof")
	}
	request := activationRequest{InstallationID: id, Name: "main", ActivationCode: code,
		PublicKey: identity.Public().(ed25519.PublicKey), RequestID: plain.requestID}
	before := activationProofMessage(request)
	request.EncryptionPublicKey = encryption
	if bytes.Equal(before, activationProofMessage(request)) {
		t.Fatal("proof message ignores the encryption key")
	}
}

// encryptionActivationVector is pinned identically in license-service
// (licensing.TestActivationProofEncryptionKeyVector): both sides must hash
// the optional field the same way.
const encryptionActivationVector = "44efc4a42b12890fc76b1c1e64f3ebe4032808885a8aa812982c7f33884c5c3a"

func TestActivationProofEncryptionKeyVector(t *testing.T) {
	identity := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	request := activationRequest{InstallationID: uuid.MustParse("00000000-0000-4000-8000-000000000001"), Name: "main",
		ActivationCode: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", PublicKey: identity.Public().(ed25519.PublicKey),
		RequestID: "control-activate-x", EncryptionPublicKey: bytes.Repeat([]byte{9}, 32)}
	if got := hex.EncodeToString(activationProofMessage(request)); got != encryptionActivationVector {
		t.Fatalf("activation proof message = %s", got)
	}
}
