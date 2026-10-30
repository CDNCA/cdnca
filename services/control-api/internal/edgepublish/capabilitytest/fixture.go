//go:build integration

// Package capabilitytest supplies real enrollment facts for publication integration tests.
package capabilitytest

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type IdentityForTest struct {
	Authorization nodeidentity.Authorization
	Completion    nodeidentity.EnrollmentCompletion
	Service       *nodeidentity.Service
	Clock         time.Time
	CSRDER        []byte
	CAEpochID     uuid.UUID
	// ArtifactPrivateKey opens configuration artifacts sealed to the node's
	// artifact key, which is active once the identity is complete.
	ArtifactPrivateKey []byte
}

// SeedNodePublicationIdentityForTest uses the real Authorize and Complete transactions.
// The fixed CA is test-only, reused within the isolated schema; no production key is read.
func SeedNodePublicationIdentityForTest(
	t *testing.T, pool *pgxpool.Pool, scopeID, userID, nodeID uuid.UUID,
	capabilities *agentv1.AgentCapabilities, now time.Time, complete bool,
) *IdentityForTest {
	t.Helper()
	result := &IdentityForTest{Clock: now.UTC().Truncate(time.Second)}
	seed := sha256.Sum256([]byte("publication-capability-integration-test-only-ca"))
	caKey := ed25519.NewKeyFromSeed(seed[:])
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Publication capability test CA"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:      true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, template, template, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(ca.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	caHash, publicHash := sha256.Sum256(caDER), sha256.Sum256(publicDER)
	if _, err := pool.Exec(t.Context(), `INSERT INTO control_installation_entitlement(installation_id)
		VALUES('publication-capability-test') ON CONFLICT(singleton) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	var installationID string
	if err := pool.QueryRow(t.Context(), `SELECT installation_id FROM control_installation_entitlement
		WHERE singleton`).Scan(&installationID); err != nil {
		t.Fatal(err)
	}
	result.CAEpochID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(installationID+"/publication-test-ca"))
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_ca_key_epochs(
		id,installation_id,epoch,key_id,ca_certificate_pem,ca_certificate_sha256,public_key_sha256,
		not_before,not_after,status,request_id,request_digest,created_by_scope_id,created_by_user_id,created_at)
		VALUES($1,$2,1,'publication-capability-test-ca',$3,$4,$5,$6,$7,'active',$8,$9,$10,$11,$12)
		ON CONFLICT(id) DO NOTHING`, result.CAEpochID, installationID,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), caHash[:], publicHash[:],
		ca.NotBefore, ca.NotAfter, uuid.New(), seed[:], scopeID, userID, result.Clock); err != nil {
		t.Fatal(err)
	}
	_, nodeKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result.CSRDER, err = x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: nodeID.String()}}, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	artifactKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result.ArtifactPrivateKey = artifactKey.Bytes()
	tokenBytes := sha256.Sum256([]byte(uuid.NewString()))
	token := base64.RawURLEncoding.EncodeToString(tokenBytes[:])
	tokenHash := sha256.Sum256([]byte(token))
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_enrollment_tokens(
		id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at)
		VALUES($1,$2,'initial_enrollment',$3,$4,$5,$6)`, uuid.New(), nodeID, tokenHash[:], userID,
		result.Clock.Add(-time.Minute), result.Clock.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	config := nodeidentity.DefaultConfig()
	config.Clock = func() time.Time { return result.Clock }
	result.Service, err = nodeidentity.NewService(nodeidentity.NewStore(pool),
		&certificateSignerForTest{ca: ca, key: caKey}, config)
	if err != nil {
		t.Fatal(err)
	}
	result.Authorization, err = result.Service.Authorize(t.Context(), nodeidentity.AuthorizeRequest{
		RequestID: uuid.NewString(), EnrollmentToken: token, CertificateSigningRequestDER: result.CSRDER,
		MachineFingerprintSHA256: seed[:], SupportedProtocolVersions: config.AcceptedProtocols,
		Capabilities: capabilities, ArtifactEncryptionPublicKey: artifactKey.PublicKey().Bytes(),
		GatewayWorkloadIdentity: "spiffe://cdn-platform/gateway/capability-test", GatewayInstanceID: "capability-test",
	})
	if err != nil {
		t.Fatalf("authorize real test identity: %v", err)
	}
	if complete {
		result.Completion, err = result.Service.Complete(t.Context(), nodeidentity.CompleteRequest{
			RequestID: uuid.NewString(), AuthorizationID: result.Authorization.ID,
			GatewayWorkloadIdentity: "spiffe://cdn-platform/gateway/capability-test", GatewayInstanceID: "capability-test",
		})
		if err != nil {
			t.Fatalf("complete real test identity: %v", err)
		}
	}
	return result
}

type certificateSignerForTest struct {
	ca  *x509.Certificate
	key ed25519.PrivateKey
}

func (signer *certificateSignerForTest) SignNodeCertificate(
	_ context.Context, request nodeidentity.SignRequest,
) (nodeidentity.SignedCertificate, error) {
	csr, err := x509.ParseCertificateRequest(request.CertificateSigningRequestDER)
	if err != nil {
		return nodeidentity.SignedCertificate{}, err
	}
	uri, err := url.Parse(request.URISAN)
	if err != nil {
		return nodeidentity.SignedCertificate{}, err
	}
	serial := uuid.New()
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serial[:]), Subject: pkix.Name{CommonName: request.NodeID.String()},
		NotBefore: request.NotBefore, NotAfter: request.NotAfter, URIs: []*url.URL{uri},
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer.ca, csr.PublicKey, signer.key)
	if err != nil {
		return nodeidentity.SignedCertificate{}, err
	}
	return nodeidentity.SignedCertificate{
		LeafCertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		IssuingChainPEM:    [][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signer.ca.Raw})},
	}, nil
}
