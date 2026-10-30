package entitlementsync

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestSecretSourcesRequireRestrictedFilesOrStdin(t *testing.T) {
	directory := t.TempDir()
	credential := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	restricted := filepath.Join(directory, "credential")
	if err := os.WriteFile(restricted, []byte(credential+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadActivationCredential(restricted, nil)
	if err != nil || loaded != credential {
		t.Fatalf("ReadActivationCredential(file) = (%q, %v)", loaded, err)
	}
	loaded, err = ReadActivationCredential("-", bytes.NewBufferString(credential+"\n"))
	if err != nil || loaded != credential {
		t.Fatalf("ReadActivationCredential(stdin) = (%q, %v)", loaded, err)
	}
	open := filepath.Join(directory, "open-credential")
	if err := os.WriteFile(open, []byte(credential), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadActivationCredential(open, nil); err == nil {
		t.Fatal("world-readable activation credential unexpectedly accepted")
	}
}

func TestLoadPrivateKeyAcceptsRestrictedPKCS8Ed25519(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "installation-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey() error = %v", err)
	}
	if !bytes.Equal(loaded, privateKey) {
		t.Fatal("LoadPrivateKey() returned different key material")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(path); err == nil {
		t.Fatal("group-readable private key unexpectedly accepted")
	}
}
