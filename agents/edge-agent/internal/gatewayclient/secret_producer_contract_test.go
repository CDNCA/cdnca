package gatewayclient

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/urlauth"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func TestControlSecretProducersMatchAgentConsumers(t *testing.T) {
	output := t.TempDir()
	if err := os.Chmod(output, 0o700); err != nil {
		t.Fatal(err)
	}
	producer := exec.CommandContext(t.Context(), "go", "test",
		"./internal/certificatepublish", "./internal/challengepublication", "./internal/urlauthpolicy",
		"-run", "^Test(Certificate|Challenge|URLAuth)ProducerConsumerContract$", "-count=1")
	producer.Dir = "../../../../services/control-api"
	producer.Env = append(os.Environ(), "GOWORK=off", "CDNCA_SECRET_ARTIFACT_CONTRACT_OUTPUT="+output)
	if result, err := producer.CombinedOutput(); err != nil {
		t.Fatalf("Control producers failed: %v\n%s", err, result)
	}
	for _, kind := range []string{"certificate", "challenge", "url-auth"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(output, kind+".json")
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatal("producer fixture is not a private regular file")
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(raw)
			var fixture map[string][]byte
			if err := json.Unmarshal(raw, &fixture); err != nil {
				t.Fatal(err)
			}
			defer clear(fixture["recipient_private_key"])
			command := new(agentv1.DeploymentCommand)
			if err := proto.Unmarshal(fixture["command"], command); err != nil {
				t.Fatal(err)
			}
			if len(command.Artifacts) != 1 || !ed25519.Verify(ed25519.PublicKey(fixture["signing_public_key"]), fixture["wire"], command.Artifacts[0].Signature) {
				t.Fatal("Control did not produce a signed artifact")
			}
			for _, scenario := range []string{"valid", "bad-signature", "tampered-wire", "wrong-recipient", "event-replay", "attempt-replay", "configuration-replay"} {
				t.Run(scenario, func(t *testing.T) {
					candidate := proto.Clone(command).(*agentv1.DeploymentCommand)
					descriptor := candidate.Artifacts[0]
					wire := bytes.Clone(fixture["wire"])
					config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
					config.ArtifactEncryptionKeyID = descriptor.GetRecipientKeyId()
					config.ArtifactDecryptionPrivateKey = bytes.Clone(fixture["recipient_private_key"])
					defer clear(config.ArtifactDecryptionPrivateKey)
					switch scenario {
					case "bad-signature":
						descriptor.Signature[0] ^= 0x80
					case "tampered-wire":
						wire[len(wire)-1] ^= 0x80
					case "wrong-recipient":
						config.ArtifactDecryptionPrivateKey, _ = newArtifactRecipient(t)
						defer clear(config.ArtifactDecryptionPrivateKey)
					case "event-replay":
						candidate.Event.EventId = uuid.NewString()
					case "attempt-replay":
						candidate.Attempt++
					case "configuration-replay":
						candidate.ConfigVersionId = uuid.NewString()
					}
					trust, err := NewTrustStore(map[string]crypto.PublicKey{
						descriptor.SigningKeyId: ed25519.PublicKey(fixture["signing_public_key"]),
					})
					if err != nil {
						t.Fatal(err)
					}
					store, err := newDurableStore(config.JournalDir, config.MaxCommandBytes, config.MaxStatusBytes)
					if err != nil {
						t.Fatal(err)
					}
					record, _, err := store.putCommand(candidate, deliveredStatus(candidate))
					if err != nil {
						t.Fatal(err)
					}
					gateway := newFetchGatewayClient(t, wire)
					// These are the production download, signature, HPKE and
					// consumer decoder paths, not a test-side decryptor.
					switch kind {
					case "certificate":
						document, fetchErr := fetchCertificateArtifact(t.Context(), gateway, store, record, candidate, descriptor, 1<<20, config, trust, time.Now)
						err = fetchErr
						defer clearCertificateDocument(&document)
						if err == nil {
							if len(document.Activation.Certificates) != 1 || len(document.Bundle.Bindings) != 1 ||
								document.Activation.Certificates[0].Version != 9 || document.Activation.Certificates[0].BindingRevision != 4 ||
								document.Bundle.VersionID != command.ConfigVersionId {
								t.Fatal("certificate identity or revision was lost")
							}
							binding := document.Bundle.Bindings[0]
							if _, parseErr := tls.X509KeyPair([]byte(binding.CertificateChainPEM), []byte(binding.PrivateKeyPEM)); parseErr != nil {
								t.Fatal("Control certificate/key did not survive the consumer")
							}
						}
					case "challenge":
						decoded, binding, fetchErr := fetchChallengeArtifact(t.Context(), gateway, store, record, candidate, descriptor, 1<<20, config, trust, time.Now)
						err = fetchErr
						defer clear(decoded)
						if err == nil && (binding.PolicyVersion != 7 || binding.EventID != command.Event.EventId || binding.RecipientKeyID != descriptor.GetRecipientKeyId()) {
							t.Fatal("challenge activation binding was lost")
						}
					case "url-auth":
						decoded, fetchErr := fetchURLAuthArtifact(t.Context(), gateway, store, record, candidate, descriptor, 1<<20, config, trust, time.Now)
						err = fetchErr
						defer clear(decoded)
						if err == nil {
							binding, decodeErr := urlauth.DecodeArtifactBinding(decoded)
							if decodeErr != nil || binding.PolicyVersion != 7 || binding.EventID != command.Event.EventId || binding.RecipientKeyID != descriptor.GetRecipientKeyId() {
								t.Fatal("URL auth activation binding was lost")
							}
						}
					}
					if scenario == "valid" {
						if err != nil {
							t.Fatalf("Control artifact rejected by Agent consumer: %v", err)
						}
						persisted, readErr := store.record(record.RecordKey)
						if readErr != nil || persisted.ArtifactOffset != descriptor.SizeBytes {
							t.Fatal("verified ciphertext transfer was not durable")
						}
					} else if err == nil {
						t.Fatal("invalid signed artifact was accepted")
					}
				})
			}
		})
	}
}
