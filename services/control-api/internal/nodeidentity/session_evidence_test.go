package nodeidentity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math"
	"math/big"
	"net/url"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func TestVerifySessionFactEvidence(t *testing.T) {
	t.Run("historical-valid-and-detached", func(t *testing.T) {
		value, expected := sessionEvidenceFixture(t, nil)
		facts, err := VerifySessionFactEvidence(value)
		if err != nil || !proto.Equal(facts, expected) {
			t.Fatalf("valid historical facts: %v", err)
		}
		facts.CertificateSha256[0] ^= 1
		facts.Capabilities.Features[0].ApiVersion++
		if again, err := VerifySessionFactEvidence(value); err != nil || !proto.Equal(again, expected) {
			t.Fatal("returned facts alias evidence")
		}
	})
	for name, edit := range map[string]func(*SessionFactEvidence){
		"nil-node":            func(v *SessionFactEvidence) { v.NodeID = uuid.Nil },
		"other-node":          func(v *SessionFactEvidence) { v.NodeID = uuid.New() },
		"zero-epoch":          func(v *SessionFactEvidence) { v.SessionEpoch = 0 },
		"other-epoch":         func(v *SessionFactEvidence) { v.SessionEpoch++ },
		"overflow-epoch":      func(v *SessionFactEvidence) { v.SessionEpoch = math.MaxUint64 },
		"row-protocol":        func(v *SessionFactEvidence) { v.SelectedProtocolMinor++ },
		"zero-time":           func(v *SessionFactEvidence) { v.RegisteredAt = time.Time{} },
		"leaf-before":         func(v *SessionFactEvidence) { v.RegisteredAt = v.RegisteredAt.Add(-2 * time.Hour) },
		"leaf-expired":        func(v *SessionFactEvidence) { v.RegisteredAt = v.RegisteredAt.Add(time.Hour) },
		"short-cert-hash":     func(v *SessionFactEvidence) { v.CertificateSHA256 = v.CertificateSHA256[:31] },
		"other-cert-hash":     func(v *SessionFactEvidence) { v.CertificateSHA256[0] ^= 1 },
		"other-serial":        func(v *SessionFactEvidence) { v.CertificateSerialNumber = "b" },
		"noncanonical-serial": func(v *SessionFactEvidence) { v.CertificateSerialNumber = "0a" },
		"leaf-pem-garbage":    func(v *SessionFactEvidence) { v.LeafCertificatePEM = []byte("not a certificate") },
		"extra-leaf-pem": func(v *SessionFactEvidence) {
			v.LeafCertificatePEM = append(v.LeafCertificatePEM, v.LeafCertificatePEM...)
		},
		"wrong-ca": func(v *SessionFactEvidence) {
			other, _ := sessionEvidenceFixture(t, nil)
			v.CACertificatePEM, v.CACertificateSHA256 = other.CACertificatePEM, other.CACertificateSHA256
		},
		"bad-ca-hash":      func(v *SessionFactEvidence) { v.CACertificateSHA256[0] ^= 1 },
		"short-ca-hash":    func(v *SessionFactEvidence) { v.CACertificateSHA256 = nil },
		"short-public-key": func(v *SessionFactEvidence) { v.ArtifactPublicKey = v.ArtifactPublicKey[:31] },
		"bad-key-hash":     func(v *SessionFactEvidence) { v.ArtifactPublicKeySHA256[0] ^= 1 },
		"wrong-key-id":     func(v *SessionFactEvidence) { v.ArtifactKeyID = "x25519:wrong" },
		"bad-facts-hash":   func(v *SessionFactEvidence) { v.FactsSHA256[0] ^= 1 },
		"short-facts-hash": func(v *SessionFactEvidence) { v.FactsSHA256 = nil },
		"bad-caps-hash":    func(v *SessionFactEvidence) { v.CapabilitiesSHA256[0] ^= 1 },
		"different-caps": func(v *SessionFactEvidence) {
			v.CapabilitiesSnapshot[0] ^= 1
			sum := sha256.Sum256(v.CapabilitiesSnapshot)
			v.CapabilitiesSHA256 = sum[:]
		},
		"oversized-facts": func(v *SessionFactEvidence) { v.FactsSnapshot = make([]byte, (128<<10)+1) },
		"oversized-caps":  func(v *SessionFactEvidence) { v.CapabilitiesSnapshot = make([]byte, (64<<10)+1) },
		"noncanonical-wire": func(v *SessionFactEvidence) {
			v.FactsSnapshot = append(v.FactsSnapshot, 0x08, 0x01)
			sum := sha256.Sum256(v.FactsSnapshot)
			v.FactsSHA256 = sum[:]
		},
	} {
		t.Run(name, func(t *testing.T) {
			value, _ := sessionEvidenceFixture(t, nil)
			edit(&value)
			if _, err := VerifySessionFactEvidence(value); err == nil {
				t.Fatal("invalid historical evidence accepted")
			}
		})
	}
	for name, edit := range map[string]func(*controlv1.GatewaySessionFactsV1){
		"unknown-facts": func(v *controlv1.GatewaySessionFactsV1) { v.ProtoReflect().SetUnknown([]byte{0x80, 0x06, 1}) },
		"unknown-protocol": func(v *controlv1.GatewaySessionFactsV1) {
			v.SelectedProtocolVersion.ProtoReflect().SetUnknown([]byte{0x80, 0x06, 1})
		},
		"unknown-capabilities": func(v *controlv1.GatewaySessionFactsV1) {
			v.Capabilities.ProtoReflect().SetUnknown([]byte{0x80, 0x06, 1})
		},
		"unknown-feature-fields": func(v *controlv1.GatewaySessionFactsV1) {
			v.Capabilities.Features[0].ProtoReflect().SetUnknown([]byte{0x80, 0x06, 1})
		},
		"unknown-feature": func(v *controlv1.GatewaySessionFactsV1) { v.Capabilities.Features[0].Name = 999 },
		"duplicate-feature": func(v *controlv1.GatewaySessionFactsV1) {
			v.Capabilities.Features = append(v.Capabilities.Features, v.Capabilities.Features[0])
		},
		"unordered-features": func(v *controlv1.GatewaySessionFactsV1) {
			v.Capabilities.Features[0], v.Capabilities.Features[1] = v.Capabilities.Features[1], v.Capabilities.Features[0]
		},
		"unknown-schema": func(v *controlv1.GatewaySessionFactsV1) { v.SchemaVersion++ },
		"empty-version":  func(v *controlv1.GatewaySessionFactsV1) { v.Capabilities.AgentVersion = "" },
	} {
		t.Run(name, func(t *testing.T) {
			value, facts := sessionEvidenceFixture(t, nil)
			edit(facts)
			value.FactsSnapshot, _ = (proto.MarshalOptions{Deterministic: true}).Marshal(facts)
			value.CapabilitiesSnapshot, _ = (proto.MarshalOptions{Deterministic: true}).Marshal(facts.Capabilities)
			factsSum, capsSum := sha256.Sum256(value.FactsSnapshot), sha256.Sum256(value.CapabilitiesSnapshot)
			value.FactsSHA256, value.CapabilitiesSHA256 = factsSum[:], capsSum[:]
			if _, err := VerifySessionFactEvidence(value); err == nil {
				t.Fatal("invalid canonical protobuf accepted")
			}
		})
	}
	t.Run("low-order-key-with-consistent-hashes", func(t *testing.T) {
		value, facts := sessionEvidenceFixture(t, nil)
		value.ArtifactPublicKey = make([]byte, 32)
		keyHash := sha256.Sum256(value.ArtifactPublicKey)
		value.ArtifactPublicKeySHA256, value.ArtifactKeyID = keyHash[:], "x25519:"+hex.EncodeToString(keyHash[:])
		facts.ArtifactEncryptionKeyId = value.ArtifactKeyID
		value.FactsSnapshot, _ = (proto.MarshalOptions{Deterministic: true}).Marshal(facts)
		factsHash := sha256.Sum256(value.FactsSnapshot)
		value.FactsSHA256 = factsHash[:]
		if _, err := VerifySessionFactEvidence(value); err == nil {
			t.Fatal("low-order public key accepted")
		}
	})
	for name, edit := range map[string]func(*x509.Certificate){
		"other-node-SAN":    func(v *x509.Certificate) { v.URIs[0], _ = url.Parse(NodeSPIFFEPrefix + uuid.NewString()) },
		"extra-SAN":         func(v *x509.Certificate) { v.URIs = append(v.URIs, v.URIs[0]) },
		"server-only-usage": func(v *x509.Certificate) { v.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"ca-leaf":           func(v *x509.Certificate) { v.IsCA, v.BasicConstraintsValid = true, true },
		"unsigned-usage":    func(v *x509.Certificate) { v.KeyUsage = x509.KeyUsageKeyEncipherment },
		"unknown-critical-extension": func(v *x509.Certificate) {
			v.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			value, _ := sessionEvidenceFixture(t, edit)
			if _, err := VerifySessionFactEvidence(value); err == nil {
				t.Fatal("invalid signed certificate identity accepted")
			}
		})
	}
	for _, offset := range []time.Duration{-25 * time.Hour, 24 * time.Hour} {
		t.Run("CA-validity/"+offset.String(), func(t *testing.T) {
			value, _ := sessionEvidenceFixture(t, func(leaf *x509.Certificate) {
				leaf.NotBefore = leaf.NotBefore.Add(-48 * time.Hour)
				leaf.NotAfter = leaf.NotAfter.Add(48 * time.Hour)
			})
			value.RegisteredAt = value.RegisteredAt.Add(offset)
			if _, err := VerifySessionFactEvidence(value); err == nil {
				t.Fatal("CA outside validity accepted")
			}
		})
	}
}

func sessionEvidenceFixture(t *testing.T, editLeaf func(*x509.Certificate)) (SessionFactEvidence, *controlv1.GatewaySessionFactsV1) {
	t.Helper()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	nodeID := uuid.New()
	leafKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	// Each CA identity is distinct so a valid but unrelated CA is rejected.
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Session evidence CA"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse(NodeSPIFFEPrefix + nodeID.String())
	leaf := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: nodeID.String()}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if editLeaf != nil {
		editLeaf(leaf)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, parsedCA, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	certSHA, caSHA := sha256.Sum256(leafDER), sha256.Sum256(caDER)
	publicKey := bytes.Repeat([]byte{7}, 32)
	publicSHA := sha256.Sum256(publicKey)
	keyID := "x25519:" + hex.EncodeToString(publicSHA[:])
	facts := &controlv1.GatewaySessionFactsV1{SchemaVersion: 1, NodeId: nodeID.String(), SessionEpoch: 1, CertificateSha256: bytes.Clone(certSHA[:]), SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, ArtifactEncryptionKeyId: keyID, Capabilities: &agentv1.AgentCapabilities{AgentVersion: "1.0.22", BuildId: "build", OperatingSystem: "linux", Architecture: "amd64", Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}, {Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1}}}}
	encoded, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(facts)
	caps, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(facts.Capabilities)
	factsSHA, capsSHA := sha256.Sum256(encoded), sha256.Sum256(caps)
	return SessionFactEvidence{NodeID: nodeID, SessionEpoch: 1, RegisteredAt: now, SelectedProtocolMajor: 1, ArtifactKeyID: keyID, FactsSnapshot: encoded, FactsSHA256: factsSHA[:], CapabilitiesSnapshot: caps, CapabilitiesSHA256: capsSHA[:], CertificateSHA256: certSHA[:], CertificateSerialNumber: "a", LeafCertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), CACertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), CACertificateSHA256: caSHA[:], ArtifactPublicKey: publicKey, ArtifactPublicKeySHA256: publicSHA[:]}, facts
}
