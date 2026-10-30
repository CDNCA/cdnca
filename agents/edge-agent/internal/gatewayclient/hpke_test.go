package gatewayclient

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cloudflare/circl/hpke"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func TestArtifactHPKERoundTripAndBinding(t *testing.T) {
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	command, plaintext := signedTestCommand(t, signingKey)
	privateKey, keyID := newArtifactRecipient(t)
	wire := encryptTestArtifact(t, command, command.Artifacts[0], plaintext, privateKey, keyID, signingKey)
	decoded, err := decryptArtifactHPKE(command, command.Artifacts[0], wire, privateKey)
	if err != nil {
		t.Fatalf("decryptArtifactHPKE() error = %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatal("HPKE plaintext does not match")
	}

	mutations := []struct {
		name   string
		change func(*agentv1.DeploymentCommand)
	}{
		{name: "event replay", change: func(value *agentv1.DeploymentCommand) { value.Event.EventId = newUUID(t) }},
		{name: "deployment replay", change: func(value *agentv1.DeploymentCommand) { value.DeploymentId = newUUID(t) }},
		{name: "attempt replay", change: func(value *agentv1.DeploymentCommand) { value.Attempt++ }},
		{name: "configuration replay", change: func(value *agentv1.DeploymentCommand) { value.ConfigVersionId = "cfg-v2" }},
		{name: "artifact replay", change: func(value *agentv1.DeploymentCommand) { value.Artifacts[0].ArtifactId = newUUID(t) }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			mutated := proto.Clone(command).(*agentv1.DeploymentCommand)
			test.change(mutated)
			if _, err := decryptArtifactHPKE(mutated, mutated.Artifacts[0], wire, privateKey); !errors.Is(err, ErrArtifactIntegrity) {
				t.Fatalf("decryptArtifactHPKE() error = %v, want integrity failure", err)
			}
		})
	}
}

func TestArtifactHPKERejectsWrongKeyTruncationAndTampering(t *testing.T) {
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	command, plaintext := signedTestCommand(t, signingKey)
	privateKey, keyID := newArtifactRecipient(t)
	wire := encryptTestArtifact(t, command, command.Artifacts[0], plaintext, privateKey, keyID, signingKey)
	wrongKey, _ := newArtifactRecipient(t)
	tampered := bytes.Clone(wire)
	tampered[len(tampered)-1] ^= 0x80
	for _, test := range []struct {
		name string
		wire []byte
		key  []byte
	}{
		{name: "wrong key", wire: wire, key: wrongKey},
		{name: "truncated envelope", wire: wire[:47], key: privateKey},
		{name: "tampered ciphertext", wire: tampered, key: privateKey},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decryptArtifactHPKE(command, command.Artifacts[0], test.wire, test.key); !errors.Is(err, ErrArtifactIntegrity) {
				t.Fatalf("decryptArtifactHPKE() error = %v, want integrity failure", err)
			}
		})
	}
}

func TestEncryptedArtifactValidationFailsClosed(t *testing.T) {
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A configuration release's encrypted artifact is its site object key
	// envelope (Artifacts[1]), sealed to testClientConfig's recipient.
	command, _ := signedTestCommand(t, signingKey)
	config := testClientConfig(t.TempDir())
	if err := validateRoutedCommand(command, config, time.Now()); err != nil {
		t.Fatalf("validateCommand(encrypted) error = %v", err)
	}

	tests := []struct {
		name   string
		change func(*agentv1.DeploymentCommand, *Config)
	}{
		{name: "wrong recipient ID", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			other := "x25519:" + string(bytes.Repeat([]byte{'0'}, 64))
			value.Artifacts[1].RecipientKeyId = &other
		}},
		{name: "missing private key", change: func(_ *agentv1.DeploymentCommand, config *Config) { config.ArtifactDecryptionPrivateKey = nil }},
		{name: "truncated envelope", change: func(value *agentv1.DeploymentCommand, _ *Config) { value.Artifacts[1].SizeBytes = 47 }},
		{name: "encrypted artifact exceeds limit", change: func(value *agentv1.DeploymentCommand, config *Config) {
			config.MaxArtifactBytes = value.Artifacts[1].SizeBytes - 1
		}},
		{name: "unknown encryption", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.Artifacts[1].EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm(99)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := proto.Clone(command).(*agentv1.DeploymentCommand)
			local := config
			test.change(value, &local)
			if err := validateRoutedCommand(value, local, time.Now()); err == nil {
				t.Fatal("validateCommand() accepted invalid encrypted artifact")
			}
		})
	}

	plaintextCommand, _ := signedTestCommand(t, signingKey)
	if err := validateRoutedCommand(plaintextCommand, testClientConfig(t.TempDir()), time.Now()); err != nil {
		t.Fatalf("plaintext compatibility error = %v", err)
	}
	secret := proto.Clone(plaintextCommand).(*agentv1.DeploymentCommand)
	secret.Artifacts[0].Kind = agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE
	if err := validateRoutedCommand(secret, testClientConfig(t.TempDir()), time.Now()); err == nil {
		t.Fatal("unencrypted node secret bundle was accepted")
	}
}

func newArtifactRecipient(t *testing.T) ([]byte, string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(key.PublicKey().Bytes())
	return key.Bytes(), "x25519:" + hex.EncodeToString(digest[:])
}

func encryptTestArtifact(t *testing.T, command *agentv1.DeploymentCommand, descriptor *agentv1.ArtifactDescriptor, plaintext, privateKey []byte, keyID string, signingKey ed25519.PrivateKey) []byte {
	t.Helper()
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	receiverKey, err := scheme.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM
	descriptor.RecipientKeyId = &keyID
	descriptor.SizeBytes = uint64(len(plaintext) + scheme.CiphertextSize() + hpkeTagSize)
	info, aad, err := artifactHPKEContext(command, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := artifactHPKESuite.NewSender(receiverKey.Public(), info)
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
	wire := append(bytes.Clone(encapsulation), ciphertext...)
	if uint64(len(wire)) != descriptor.SizeBytes {
		t.Fatalf("HPKE wire size = %d, want %d", len(wire), descriptor.SizeBytes)
	}
	digest := sha256.Sum256(wire)
	descriptor.Sha256 = digest[:]
	descriptor.Signature = ed25519.Sign(signingKey, wire)
	return wire
}

func newUUID(t *testing.T) string {
	t.Helper()
	return uuid.NewString()
}
