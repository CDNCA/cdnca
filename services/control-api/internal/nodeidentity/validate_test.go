package nodeidentity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
)

func TestCloneCertificatePreservesAndDetachesIssuingChain(t *testing.T) {
	original := Certificate{
		LeafCertificatePEM: []byte("leaf-certificate"),
		IssuingChainPEM:    [][]byte{[]byte("issuing-ca"), []byte("root-ca")},
	}
	cloned := cloneCertificate(original)
	if !bytes.Equal(cloned.LeafCertificatePEM, original.LeafCertificatePEM) ||
		len(cloned.IssuingChainPEM) != len(original.IssuingChainPEM) ||
		!bytes.Equal(cloned.IssuingChainPEM[0], original.IssuingChainPEM[0]) ||
		!bytes.Equal(cloned.IssuingChainPEM[1], original.IssuingChainPEM[1]) {
		t.Fatalf("cloneCertificate() lost public certificate material: %#v", cloned)
	}
	original.LeafCertificatePEM[0] = 'L'
	original.IssuingChainPEM[0][0] = 'I'
	cloned.IssuingChainPEM[1][0] = 'R'
	if bytes.Equal(cloned.LeafCertificatePEM, original.LeafCertificatePEM) ||
		bytes.Equal(cloned.IssuingChainPEM[0], original.IssuingChainPEM[0]) ||
		bytes.Equal(cloned.IssuingChainPEM[1], original.IssuingChainPEM[1]) {
		t.Fatal("cloneCertificate() shares mutable certificate bytes")
	}
}

func TestNormalizeAuthorizeCanonicalAndOptionalPeerIP(t *testing.T) {
	csr := testCSR(t, false)
	request := validAuthorizeRequest(t, csr)
	request.PeerIP = ""
	normalized, err := normalizeAuthorize(request, testProtocolRange())
	if err != nil {
		t.Fatalf("normalizeAuthorize() error = %v", err)
	}
	if normalized.PeerIP != "" || len(normalized.ArtifactKeyID) != 71 || !strings.HasPrefix(normalized.ArtifactKeyID, "x25519:") {
		t.Fatalf("normalized peer/key = %q/%q", normalized.PeerIP, normalized.ArtifactKeyID)
	}
	second, err := normalizeAuthorize(request, testProtocolRange())
	if err != nil || second.RequestDigest != normalized.RequestDigest || second.CapabilitiesHash != normalized.CapabilitiesHash {
		t.Fatal("canonical enrollment digest is not deterministic")
	}
	request.PeerIP = "2001:0db8::1"
	normalized, err = normalizeAuthorize(request, testProtocolRange())
	if err != nil || normalized.PeerIP != "2001:db8::1" {
		t.Fatalf("canonical peer IP = %q, %v", normalized.PeerIP, err)
	}
}

func TestNormalizeAuthorizeRejectsUnsafeInputs(t *testing.T) {
	valid := validAuthorizeRequest(t, testCSR(t, false))
	tests := []struct {
		name string
		edit func(*AuthorizeRequest)
	}{
		{"noncanonical request ID", func(value *AuthorizeRequest) { value.RequestID = strings.ToUpper(value.RequestID) }},
		{"short token", func(value *AuthorizeRequest) { value.EnrollmentToken = "c2hvcnQ" }},
		{"CSR SAN", func(value *AuthorizeRequest) { value.CertificateSigningRequestDER = testCSR(t, true) }},
		{"empty fingerprint", func(value *AuthorizeRequest) { value.MachineFingerprintSHA256 = nil }},
		{"empty artifact key", func(value *AuthorizeRequest) { value.ArtifactEncryptionPublicKey = nil }},
		{"low order artifact key", func(value *AuthorizeRequest) { value.ArtifactEncryptionPublicKey = make([]byte, 32) }},
		{"bad peer", func(value *AuthorizeRequest) { value.PeerIP = "not-an-ip" }},
		{"empty capabilities", func(value *AuthorizeRequest) { value.Capabilities = &agentv1.AgentCapabilities{} }},
		{"duplicate capability", func(value *AuthorizeRequest) {
			value.Capabilities.Features = append(value.Capabilities.Features, value.Capabilities.Features[0])
		}},
		{"unsupported protocol", func(value *AuthorizeRequest) { value.SupportedProtocolVersions = protocolRange(2, 0, 2, 0) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := cloneAuthorizeRequest(valid)
			test.edit(&request)
			if _, err := normalizeAuthorize(request, testProtocolRange()); err == nil {
				t.Fatal("normalizeAuthorize() succeeded")
			}
		})
	}
}

func validAuthorizeRequest(t *testing.T, csr []byte) AuthorizeRequest {
	t.Helper()
	return AuthorizeRequest{
		RequestID: uuid.NewString(), EnrollmentToken: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		CertificateSigningRequestDER: csr, MachineFingerprintSHA256: make([]byte, 32),
		SupportedProtocolVersions: testProtocolRange(), GatewayWorkloadIdentity: "spiffe://cdn-platform/gateway/control",
		GatewayInstanceID: "gateway-01", PeerIP: "192.0.2.10", ArtifactEncryptionPublicKey: bytesOf(32, 7),
		Capabilities: &agentv1.AgentCapabilities{AgentVersion: "1.0.0", BuildId: "build-1", OperatingSystem: "linux",
			Architecture: "amd64", OpenrestyVersion: "1.27.1", Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}}},
	}
}

func cloneAuthorizeRequest(value AuthorizeRequest) AuthorizeRequest {
	result := value
	result.CertificateSigningRequestDER = append([]byte(nil), value.CertificateSigningRequestDER...)
	result.MachineFingerprintSHA256 = append([]byte(nil), value.MachineFingerprintSHA256...)
	result.ArtifactEncryptionPublicKey = append([]byte(nil), value.ArtifactEncryptionPublicKey...)
	result.SupportedProtocolVersions = cloneProtocolRange(value.SupportedProtocolVersions)
	result.Capabilities = &agentv1.AgentCapabilities{AgentVersion: value.Capabilities.AgentVersion, BuildId: value.Capabilities.BuildId,
		OperatingSystem: value.Capabilities.OperatingSystem, Architecture: value.Capabilities.Architecture,
		OpenrestyVersion: value.Capabilities.OpenrestyVersion, Features: append([]*agentv1.Capability(nil), value.Capabilities.Features...)}
	return result
}

func testCSR(t *testing.T, withSAN bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "edge-agent"}}
	if withSAN {
		uri, _ := url.Parse("spiffe://attacker/node/other")
		template.URIs = []*url.URL{uri}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func testProtocolRange() *commonv1.ProtocolVersionRange { return protocolRange(1, 0, 1, 1) }

func protocolRange(minMajor, minMinor, maxMajor, maxMinor uint32) *commonv1.ProtocolVersionRange {
	return &commonv1.ProtocolVersionRange{Minimum: &commonv1.ProtocolVersion{Major: minMajor, Minor: minMinor},
		Maximum: &commonv1.ProtocolVersion{Major: maxMajor, Minor: maxMinor}}
}

func bytesOf(length int, value byte) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}
