package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimecomposition"
	"github.com/google/uuid"
)

// The golden digests were computed with the license service's own
// licensing.CommunityRegisterProofMessage / CommunityRefreshProofMessage
// (fix-ceport 177746796) for the same inputs.
func TestCommunityProofMessagesMatchLicenseService(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	public := []byte(key.Public().(ed25519.PublicKey))
	installation := uuid.MustParse("3f6c2a1e-8b7d-4c5e-9a1f-2b3c4d5e6f70")
	register := communityDigest(communityRegisterDomain, "req-1", installation.String(), strings.TrimSpace(" ce-a "),
		base64.RawURLEncoding.EncodeToString(public), base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
		strings.ToLower(strings.TrimSpace(" Alice ")), strconv.FormatInt(1700000000, 10))
	if got := hex.EncodeToString(register); got != "117754eb344dd94954eea6aebb1a836c447810926e03ed1967371024e2f834db" {
		t.Fatalf("register digest %s", got)
	}
	refresh := communityDigest(communityRefreshDomain, "req-2", installation.String(), "1700000001")
	if got := hex.EncodeToString(refresh); got != "03e049909b283e1e6ca1966b322b2482bfd301b224652b12e718894f8f737ad0" {
		t.Fatalf("refresh digest %s", got)
	}
	proof := communityRegisterProof(key, "req-1", installation, " ce-a ", public, []byte{1, 2, 3}, " Alice ", 1700000000)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), register, proof) {
		t.Fatal("register proof does not verify over the license service digest")
	}
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), refresh, communityRefreshProof(key, "req-2", installation, 1700000001)) {
		t.Fatal("refresh proof does not verify")
	}
}

func TestCommunityIdentityPathDefault(t *testing.T) {
	t.Setenv(communityIdentityFileEnv, "")
	if got := communityIdentityPath(); got != "/etc/cdnca-control/community/identity.json" {
		t.Fatalf("default path %s", got)
	}
}

// installation_taken is explained (the encryption key is one of the unique
// keys the license service checks); other failures pass through.
func TestCommunityRegisterConflictIsExplained(t *testing.T) {
	taken := &communityServiceError{status: 409, code: "installation_taken"}
	if err := communityRegisterError(taken, true); !errors.Is(err, taken) || !strings.Contains(err.Error(), "encryption key") {
		t.Fatalf("with encryption key: %v", err)
	}
	if err := communityRegisterError(taken, false); strings.Contains(err.Error(), "encryption key") {
		t.Fatalf("without encryption key: %v", err)
	}
	other := &communityServiceError{status: 401, code: "invalid_credentials"}
	if err := communityRegisterError(other, true); err != other {
		t.Fatalf("other failure rewritten: %v", err)
	}
}

// A configured but missing encryption key file (an installation older than
// the key) registers without it; the key is registered after.
func TestCommunityInstallationWithoutEncryptionKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "installation.key")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t)}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTROL_INSTALLATION_ID", "3f6c2a1e-8b7d-4c5e-9a1f-2b3c4d5e6f70")
	t.Setenv("CONTROL_INSTALLATION_PRIVATE_KEY_FILE", keyFile)
	t.Setenv("CONTROL_INSTALLATION_ENCRYPTION_KEY_FILE", filepath.Join(dir, "installation-encryption.key"))
	local, err := loadCommunityInstallation()
	if err != nil || len(local.encryption) != 0 || local.encryptionFile == "" {
		t.Fatalf("missing key file: %+v %v", local.encryption, err)
	}
	if _, err := entitlementsync.GenerateEncryptionKey(local.encryptionFile); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(local.encryptionFile); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("encryption key mode %v %v", info, err)
	}
	if local, err = loadCommunityInstallation(); err != nil || len(local.encryption) != 32 {
		t.Fatalf("existing key file: %d %v", len(local.encryption), err)
	}
}

func mustPKCS8(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The market client certificate manager must accept the community settings.
func TestCommunityCertificateManagerConfiguration(t *testing.T) {
	dir := t.TempDir()
	paths := communityClientCertificatePaths(dir)
	_, err := pluginruntimecomposition.NewCertificateManager(pluginruntimecomposition.CertificateManagerConfig{
		BaseURL: "https://auth.example.test", InstallationID: uuid.New(), ActivationPrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32)),
		CertificateFile: paths.certificate, PrivateKeyFile: paths.privateKey, RuntimeCAFile: paths.runtimeCA,
		StateFile: paths.state, Now: time.Now, Timeout: communityCertificateTimeout, MaxBodyBytes: 64 << 10,
	})
	if err != nil {
		t.Fatalf("community certificate manager configuration rejected: %v", err)
	}
}

// The market runtime renews the community client certificate through a
// certificate manager once the installation registered; before that it has
// nothing to renew.
func TestCommunityCertificateManagerForMarket(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "installation.key")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t)}), 0o600); err != nil {
		t.Fatal(err)
	}
	installation := uuid.New()
	identity := filepath.Join(dir, "community", "identity.json")
	t.Setenv("CONTROL_INSTALLATION_ID", installation.String())
	t.Setenv("CONTROL_INSTALLATION_PRIVATE_KEY_FILE", keyFile)
	t.Setenv(communityIdentityFileEnv, identity)
	t.Setenv(communityServiceURLEnv, "https://auth.example.test")
	if manager, err := newCommunityCertificateManager(); err != nil || manager != nil {
		t.Fatalf("unregistered: manager %v, err %v", manager, err)
	}
	if err := os.MkdirAll(filepath.Dir(identity), 0o700); err != nil {
		t.Fatal(err)
	}
	stored := fmt.Sprintf(`{"installation_id":%q,"edition":"community","community_identity":"e30="}`, installation)
	if err := os.WriteFile(identity, []byte(stored), 0o600); err != nil {
		t.Fatal(err)
	}
	if manager, err := newCommunityCertificateManager(); err != nil || manager == nil {
		t.Fatalf("registered: manager %v, err %v", manager, err)
	}
}
