package nodecertlifecycle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidSerialRequiresCanonicalLowercaseHex(t *testing.T) {
	for _, value := range []string{"1", "a", "10", "abcdef0123456789"} {
		if !validSerial(value) {
			t.Errorf("validSerial(%q) = false", value)
		}
	}
	for _, value := range []string{"", "0", "00", "01", "A", "0a", "-1", "xyz", " 1"} {
		if validSerial(value) {
			t.Errorf("validSerial(%q) = true", value)
		}
	}
}

func TestGatewayMTLSProofMessageIsDeterministicAndBound(t *testing.T) {
	fact := RenewalProofFact{
		RenewalRequestID:     uuid.MustParse("018f0000-0000-7000-8000-000000000001"),
		NodeID:               uuid.MustParse("018f0000-0000-7000-8000-000000000002"),
		InstallationID:       "control-primary",
		CurrentSerialNumber:  "a1",
		CurrentLeafDERSHA256: sha256.Sum256([]byte("leaf")),
		CSRSHA256:            sha256.Sum256([]byte("csr")),
		TargetCAEpochID:      uuid.MustParse("018f0000-0000-7000-8000-000000000003"),
	}
	principal := GatewayMTLSPrincipal{workloadIdentity: "spiffe://cdn-platform/gateway/control", instanceID: "gateway-test"}
	first, err := GatewayMTLSProofMessage(fact, principal)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GatewayMTLSProofMessage(fact, principal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("proof message changed: %q != %q", first, second)
	}
	const wantV2 = `{"schema":"cdnca.node-certificate-gateway-mtls-proof/v2","renewal_request_id":"018f0000-0000-7000-8000-000000000001","node_id":"018f0000-0000-7000-8000-000000000002","installation_id":"control-primary","current_serial_number":"a1","current_leaf_der_sha256":"9f91161f43433e49a6de6db680d79f60159f2e4ac9172621a12846428158440b","csr_sha256":"c27338c453067b437471afbce792704d816112c6031bb996b62c698ea599ef80","target_ca_epoch_id":"018f0000-0000-7000-8000-000000000003","gateway_workload_identity":"spiffe://cdn-platform/gateway/control","gateway_instance_id":"gateway-test"}`
	if string(first) != wantV2 {
		t.Fatalf("v2 proof message = %q, want %q", first, wantV2)
	}
	legacy, err := legacyGatewayMTLSProofMessage(fact, principal)
	if err != nil {
		t.Fatal(err)
	}
	const wantV1 = `{"schema":"cdnca.node-certificate-gateway-mtls-proof/v1","renewal_request_id":"018f0000-0000-7000-8000-000000000001","node_id":"018f0000-0000-7000-8000-000000000002","installation_id":"control-primary","current_serial_number":"a1","current_leaf_der_sha256":"9f91161f43433e49a6de6db680d79f60159f2e4ac9172621a12846428158440b","csr_sha256":"c27338c453067b437471afbce792704d816112c6031bb996b62c698ea599ef80","target_ca_epoch_id":"018f0000-0000-7000-8000-000000000003","gateway_workload_identity":"spiffe://cdn-platform/gateway/control"}`
	if string(legacy) != wantV1 {
		t.Fatalf("v1 proof message = %q, want %q", legacy, wantV1)
	}
	if sha256.Sum256(first) == sha256.Sum256(legacy) {
		t.Fatal("v2 proof digest did not separate the legacy schema")
	}
	legacyInstanceBound, err := legacyInstanceBoundGatewayMTLSProofMessage(fact, principal)
	if err != nil {
		t.Fatal(err)
	}
	const wantV1InstanceBound = `{"schema":"cdnca.node-certificate-gateway-mtls-proof/v1","renewal_request_id":"018f0000-0000-7000-8000-000000000001","node_id":"018f0000-0000-7000-8000-000000000002","installation_id":"control-primary","current_serial_number":"a1","current_leaf_der_sha256":"9f91161f43433e49a6de6db680d79f60159f2e4ac9172621a12846428158440b","csr_sha256":"c27338c453067b437471afbce792704d816112c6031bb996b62c698ea599ef80","target_ca_epoch_id":"018f0000-0000-7000-8000-000000000003","gateway_workload_identity":"spiffe://cdn-platform/gateway/control","gateway_instance_id":"gateway-test"}`
	if string(legacyInstanceBound) != wantV1InstanceBound {
		t.Fatalf("instance-bound v1 proof message = %q, want %q", legacyInstanceBound, wantV1InstanceBound)
	}
	changed := fact
	changed.CurrentLeafDERSHA256 = sha256.Sum256([]byte("other leaf"))
	otherLeaf, err := GatewayMTLSProofMessage(changed, principal)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(first) == sha256.Sum256(otherLeaf) {
		t.Fatal("proof digest did not bind the leaf DER digest")
	}
	otherPrincipal := GatewayMTLSPrincipal{
		workloadIdentity: principal.workloadIdentity,
		instanceID:       "gateway-other",
	}
	otherInstance, err := GatewayMTLSProofMessage(fact, otherPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(first) == sha256.Sum256(otherInstance) {
		t.Fatal("proof digest did not bind the Gateway instance identity")
	}
	otherPrincipal.workloadIdentity = "spiffe://cdn-platform/gateway/other"
	otherWorkload, err := GatewayMTLSProofMessage(fact, otherPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(first) == sha256.Sum256(otherWorkload) {
		t.Fatal("proof digest did not bind the Gateway workload identity")
	}
}

func TestVerifyLeafRequiresExactDERSerialNodeAndCA(t *testing.T) {
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	nodeID := uuid.MustParse("018f0000-0000-7000-8000-000000000010")
	ca, caKey := testCertificateAuthority(t, now)
	leaf := testLeafCertificate(t, ca, caKey, nodeID, big.NewInt(0x2a), now)
	digest := sha256.Sum256(leaf.Raw)
	if err := verifyLeaf(leaf, ca, nodeID, "2a", digest); err != nil {
		t.Fatalf("verifyLeaf(valid) = %v", err)
	}
	wrongDigest := digest
	wrongDigest[0] ^= 0xff
	for name, err := range map[string]error{
		"serial": verifyLeaf(leaf, ca, nodeID, "2b", digest),
		"node":   verifyLeaf(leaf, ca, uuid.New(), "2a", digest),
		"digest": verifyLeaf(leaf, ca, nodeID, "2a", wrongDigest),
	} {
		if err != ErrCertificateInvalid {
			t.Errorf("verifyLeaf(%s) = %v", name, err)
		}
	}
	otherCA, _ := testCertificateAuthority(t, now)
	if err := verifyLeaf(leaf, otherCA, nodeID, "2a", digest); err != ErrCertificateInvalid {
		t.Fatalf("verifyLeaf(wrong CA) = %v", err)
	}
}

func testCertificateAuthority(t *testing.T, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	return testCertificateAuthorityWithValidity(t, now.Add(-24*time.Hour), now.Add(24*time.Hour))
}

func testCertificateAuthorityWithValidity(t *testing.T, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CDNCA test node CA"},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func testLeafCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, nodeID uuid.UUID,
	serial *big.Int, now time.Time,
) *x509.Certificate {
	return testLeafCertificateWithValidity(t, ca, caKey, nodeID, serial, now.Add(-time.Hour), now.Add(time.Hour))
}

func testLeafCertificateWithValidity(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, nodeID uuid.UUID,
	serial *big.Int, notBefore, notAfter time.Time,
) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := url.Parse("spiffe://cdn-platform/node/" + nodeID.String())
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "node-" + nodeID.String()},
		URIs: []*url.URL{identity}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func certificatePEM(certificate *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
}
