// Command edge-enroll-pending-fixture is a smoke-test tool (fz-x13), not
// shipped in the node package: it turns a committed identity directory back
// into the pending state of an enrollment whose Gateway response was lost
// (<identity>.enrolling/pending.json, no identity.json), so
// tests/install-smoke/node-resume-identity.sh can exercise install --resume.
// Ed25519 signatures are deterministic, so the CSR rebuilt from the client key
// is byte-identical to the one the controller stored (csr_sha256 matches).
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

func main() {
	if len(os.Args) != 2 || !filepath.IsAbs(os.Args[1]) {
		fmt.Fprintln(os.Stderr, "usage: edge-enroll-pending-fixture <absolute identity dir>")
		os.Exit(2)
	}
	if err := run(filepath.Clean(os.Args[1])); err != nil {
		fmt.Fprintln(os.Stderr, "edge-enroll-pending-fixture:", err)
		os.Exit(1)
	}
}

func run(identityDir string) error {
	var identity struct {
		MachineFingerprintSHA256 string `json:"machine_fingerprint_sha256"`
	}
	raw, err := os.ReadFile(filepath.Join(identityDir, "identity.json"))
	if err != nil || json.Unmarshal(raw, &identity) != nil || identity.MachineFingerprintSHA256 == "" {
		return fmt.Errorf("read identity.json: %v", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(identityDir, "client-key.pem"))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("client-key.pem is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return fmt.Errorf("client key is not Ed25519")
	}
	csr, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{}, key)
	if err != nil {
		return err
	}
	artifact, err := os.ReadFile(filepath.Join(identityDir, "artifact-x25519-key.bin"))
	if err != nil {
		return err
	}
	pending, err := json.Marshal(map[string]any{
		"version": 1, "request_id": uuid.NewString(),
		"machine_fingerprint_sha256":      identity.MachineFingerprintSHA256,
		"certificate_signing_request_der": base64.RawStdEncoding.EncodeToString(csr),
		"client_private_key_pkcs8":        base64.RawStdEncoding.EncodeToString(block.Bytes),
		"artifact_x25519_private_key":     base64.RawStdEncoding.EncodeToString(artifact),
	})
	if err != nil {
		return err
	}
	pendingDir := identityDir + ".enrolling"
	if err := os.Rename(identityDir, pendingDir); err != nil {
		return err
	}
	for _, name := range []string{"identity.json", "client.pem", "client-key.pem", "artifact-x25519-key.bin"} {
		if err := os.Remove(filepath.Join(pendingDir, name)); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(pendingDir, "pending.json"), pending, 0o600)
}
