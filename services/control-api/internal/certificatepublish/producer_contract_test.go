package certificatepublish

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCertificateProducerConsumerContract(t *testing.T) {
	if [3]string{hpkeBindingDomain, hpkeInfoDomain, hpkeAADDomain} != [3]string{
		"cdnca-edge-artifact-hpke-binding-v1\x00", "cdnca-edge-artifact-hpke-info-v1\x00", "cdnca-edge-artifact-hpke-aad-v1\x00",
	} {
		t.Fatal("producer drifted from the published Agent HPKE protocol domains")
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := recipient.PublicKey().Bytes()
	private := recipient.Bytes()
	defer clear(private)
	digest := sha256.Sum256(public)
	recipientID := "x25519:" + hex.EncodeToString(digest[:])
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signingPrivate)
	request, _ := frozenBuildRequest(t)
	request.RecipientKeyID, request.RecipientPublicKey = recipientID, public
	certificatePublic, certificatePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(certificatePrivate)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"edge.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, certificatePublic, certificatePrivate)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificatePrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyDER)
	request.Materials[0].CertificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	request.Materials[0].PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer clear(request.Materials[0].PrivateKeyPEM)
	producer, err := NewProducer(&testArtifactSigner{id: "certificate-contract-key", private: signingPrivate})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := producer.Build(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}

	if !ed25519.Verify(signingPublic, artifact.WireBytes, artifact.Signature) {
		t.Fatal("production artifact signature is invalid")
	}
	// Only the Agent contract test supplies this private directory. This
	// exchange never prints generated test keys or decrypted secret material.
	output := os.Getenv("CDNCA_SECRET_ARTIFACT_CONTRACT_OUTPUT")
	if output == "" {
		return
	}
	info, err := os.Lstat(output)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatal("cross-module output must be a private directory")
	}
	command := &agentv1.DeploymentCommand{
		Event:        &commonv1.EventMetadata{EventId: request.EventID.String(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(), CorrelationId: uuid.NewString()},
		DeploymentId: request.DeploymentID.String(), Attempt: request.Attempt, RolloutId: uuid.NewString(),
		ConfigVersionId: request.ConfigVersionID.String(), Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		DeadlineTime: timestamppb.New(time.Now().Add(time.Hour)),
		Artifacts: []*agentv1.ArtifactDescriptor{{ArtifactId: artifact.ID.String(), Kind: artifact.Kind, SizeBytes: artifact.SizeBytes,
			Sha256: artifact.SHA256, Signature: artifact.Signature, SigningKeyId: artifact.SigningKeyID,
			SignatureAlgorithm: artifact.SignatureAlgorithm, Compression: artifact.Compression, MediaType: artifact.MediaType,
			EncryptionAlgorithm: artifact.EncryptionAlgorithm, RecipientKeyId: artifact.RecipientKeyID}},
	}
	commandBytes, err := proto.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	fixture := map[string][]byte{"command": commandBytes, "wire": artifact.WireBytes, "recipient_private_key": private, "signing_public_key": signingPublic}
	encoded, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	file, err := os.OpenFile(filepath.Join(output, "certificate.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(encoded)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("cross-module fixture write failed")
	}
}
