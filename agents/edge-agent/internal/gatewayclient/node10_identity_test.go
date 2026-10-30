package gatewayclient

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/google/uuid"
)

func TestOpenIdentityArtifactRequiresNodeTenantDeploymentAndCurrentRecipient(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("node-identity-secret")
	binding := IdentityArtifactBinding{
		Schema:          identityArtifactBindingSchema,
		NodeID:          uuid.MustParse("d318940f-bbe5-453c-b6a6-bd04bc31e5c7"),
		TenantID:        uuid.MustParse("706876a3-f788-4f15-ac9f-5be430f8431b"),
		ConfigVersionID: uuid.MustParse("f4c9cc4f-f2f4-4ed4-8482-2a4074eb7ccb"),
		DeploymentID:    uuid.MustParse("c973265d-081c-4b35-9600-f0d229b48afb"),
		ArtifactID:      uuid.MustParse("f2806dbe-0b69-4fa3-933d-bdcce3d8af54"),
		PlaintextSHA256: sha256.Sum256(plaintext), RecipientKeyRevision: 9,
		RecipientKeyID: identityArtifactRecipientKeyID(privateKey.PublicKey().Bytes()),
	}
	wire := sealIdentityArtifactFixture(t, privateKey.PublicKey().Bytes(), binding, plaintext)
	opened, err := OpenIdentityArtifact(privateKey.Bytes(), wire, binding)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("OpenIdentityArtifact() = (%q, %v)", opened, err)
	}
	wrong := binding
	wrong.NodeID = uuid.New()
	if _, err := OpenIdentityArtifact(privateKey.Bytes(), wire, wrong); err == nil {
		t.Fatal("cross-node artifact was accepted")
	}
}

func sealIdentityArtifactFixture(t *testing.T, publicKey []byte, binding IdentityArtifactBinding, plaintext []byte) []byte {
	t.Helper()
	bindingBytes, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	recipient, err := scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	info, aad := identityArtifactContext(bindingBytes)
	sender, err := identityArtifactSuite.NewSender(recipient, info)
	if err != nil {
		t.Fatal(err)
	}
	encapsulation, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := sealer.Seal(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	wire := append([]byte(identityArtifactWireMagic), make([]byte, 4)...)
	binary.BigEndian.PutUint32(wire[len(identityArtifactWireMagic):], uint32(len(bindingBytes)))
	wire = append(wire, bindingBytes...)
	wire = append(wire, encapsulation...)
	return append(wire, ciphertext...)
}

func TestIdentityTrustUpdatePersistsOverlappingRootsAndRejectsReplay(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	clock := now
	overlapUntil := now.Add(time.Hour)
	oldRoot := identityTrustRootPEM(t, 1, now)
	newRoot := identityTrustRootPEM(t, 2, now)
	body := AgentIdentityTrustUpdate{Schema: agentIdentityTrustSchema, InstallationID: "01HZXNODE10INSTALLATION", Revision: 1,
		CurrentEpoch: 2, IssuedAt: now, ExpiresAt: now.Add(2 * time.Hour), KeyID: "identity-trust-key",
		Epochs: []AgentIdentityTrustEpoch{{Epoch: 1, Status: "overlap", ChainPEM: []string{oldRoot}, OverlapUntil: &overlapUntil}, {Epoch: 2, Status: "active", ChainPEM: []string{newRoot}}}}
	wire := signedAgentIdentityTrustFixture(t, privateKey, body)
	path := filepath.Join(node10SecureTempDir(t), "identity", "trust-lkg.json")
	store, err := NewIdentityTrustLKG(path, body.InstallationID, map[string]ed25519.PublicKey{body.KeyID: publicKey}, func() time.Time { return clock }, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if revision, err := store.ApplyIdentityTrustUpdate(wire); err != nil || revision != 1 {
		t.Fatalf("ApplyIdentityTrustUpdate() = (%d, %v)", revision, err)
	}
	roots, revision, found := store.RootPEM()
	if !found || revision != 1 || !strings.Contains(string(roots), oldRoot) || !strings.Contains(string(roots), newRoot) {
		t.Fatalf("RootPEM() revision=%d found=%v roots=%q", revision, found, roots)
	}
	reloaded, err := NewIdentityTrustLKG(path, body.InstallationID, map[string]ed25519.PublicKey{body.KeyID: publicKey}, func() time.Time { return now }, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, revision, found := reloaded.RootPEM(); !found || revision != 1 {
		t.Fatalf("reloaded revision=%d found=%v", revision, found)
	}
	if _, err := store.ApplyIdentityTrustUpdate(wire); !errors.Is(err, ErrIdentityTrustReplay) {
		t.Fatalf("replay error = %v", err)
	}
	clock = body.ExpiresAt.Add(3 * time.Minute)
	if _, _, found := store.RootPEM(); found {
		t.Fatal("expired identity trust LKG remained usable")
	}
}

func node10SecureTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func identityTrustRootPEM(t *testing.T, serial int64, now time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "identity trust root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func signedAgentIdentityTrustFixture(t *testing.T, key ed25519.PrivateKey, body AgentIdentityTrustUpdate) []byte {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(key, append(append([]byte{}, agentIdentityTrustSignatureDomain...), bodyBytes...))
	wire, err := json.Marshal(signedAgentIdentityTrustUpdate{Body: bodyBytes, Signature: base64.RawStdEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
