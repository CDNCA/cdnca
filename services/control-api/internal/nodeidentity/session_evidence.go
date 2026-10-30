package nodeidentity

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"time"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

// SessionFactEvidence contains public historical bytes and their row bindings.
// Database ownership, installation, enrollment and current authorization are
// separate caller checks, not assertions made by this value.
type SessionFactEvidence struct {
	NodeID                  uuid.UUID `json:"node_id"`
	SessionEpoch            uint64    `json:"session_epoch"`
	RegisteredAt            time.Time `json:"registered_at"`
	SelectedProtocolMajor   uint32    `json:"selected_protocol_major"`
	SelectedProtocolMinor   uint32    `json:"selected_protocol_minor"`
	ArtifactKeyID           string    `json:"artifact_key_id"`
	FactsSnapshot           []byte    `json:"facts_snapshot"`
	FactsSHA256             []byte    `json:"facts_sha256"`
	CapabilitiesSnapshot    []byte    `json:"capabilities_snapshot"`
	CapabilitiesSHA256      []byte    `json:"capabilities_sha256"`
	CertificateSHA256       []byte    `json:"certificate_sha256"`
	CertificateSerialNumber string    `json:"certificate_serial_number"`
	LeafCertificatePEM      []byte    `json:"leaf_certificate_pem"`
	CACertificatePEM        []byte    `json:"ca_certificate_pem"`
	CACertificateSHA256     []byte    `json:"ca_certificate_sha256"`
	ArtifactPublicKey       []byte    `json:"artifact_public_key"`
	ArtifactPublicKeySHA256 []byte    `json:"artifact_public_key_sha256"`
}

// VerifySessionFactEvidence checks historical bytes at RegisteredAt only. It
// does not access a database, authenticate a caller or authorize any upgrade.
func VerifySessionFactEvidence(value SessionFactEvidence) (*controlv1.GatewaySessionFactsV1, error) {
	if value.NodeID == uuid.Nil || value.RegisteredAt.IsZero() || len(value.CertificateSHA256) != sha256.Size ||
		!validSerial(value.CertificateSerialNumber) || len(value.FactsSnapshot) == 0 || len(value.FactsSnapshot) > 128<<10 ||
		len(value.CapabilitiesSnapshot) == 0 || len(value.CapabilitiesSnapshot) > maxCapabilitiesBytes ||
		!validX25519PublicKey(value.ArtifactPublicKey) {
		return nil, ErrInvalidInput
	}
	factsHash, capsHash, keyHash := sha256.Sum256(value.FactsSnapshot), sha256.Sum256(value.CapabilitiesSnapshot), sha256.Sum256(value.ArtifactPublicKey)
	if !bytes.Equal(factsHash[:], value.FactsSHA256) || !bytes.Equal(capsHash[:], value.CapabilitiesSHA256) ||
		!bytes.Equal(keyHash[:], value.ArtifactPublicKeySHA256) || value.ArtifactKeyID != "x25519:"+hex.EncodeToString(keyHash[:]) {
		return nil, ErrInvalidInput
	}
	var decoded controlv1.GatewaySessionFactsV1
	if err := proto.Unmarshal(value.FactsSnapshot, &decoded); err != nil {
		return nil, ErrInvalidInput
	}
	facts, caps, encoded, err := normalizeSessionFacts(GetAuthorizationRequest{NodeID: value.NodeID,
		CertificateSHA256: [32]byte(value.CertificateSHA256), SessionFacts: &decoded})
	if err != nil || !bytes.Equal(encoded, value.FactsSnapshot) || !bytes.Equal(caps, value.CapabilitiesSnapshot) {
		return nil, ErrInvalidInput
	}
	if facts.SessionEpoch != value.SessionEpoch || facts.ArtifactEncryptionKeyId != value.ArtifactKeyID ||
		facts.SelectedProtocolVersion.Major != value.SelectedProtocolMajor || facts.SelectedProtocolVersion.Minor != value.SelectedProtocolMinor {
		return nil, ErrInvalidInput
	}
	leaf, leafErr := parseSinglePEMCertificate(value.LeafCertificatePEM)
	ca, caErr := parseSinglePEMCertificate(value.CACertificatePEM)
	if leafErr != nil || caErr != nil {
		return nil, ErrCertificateInvalid
	}
	leafHash, caHash := sha256.Sum256(leaf.Raw), sha256.Sum256(ca.Raw)
	if !bytes.Equal(leafHash[:], value.CertificateSHA256) || !bytes.Equal(caHash[:], value.CACertificateSHA256) ||
		leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.Text(16) != value.CertificateSerialNumber ||
		leaf.IsCA || !hasClientAuthUsage(leaf.ExtKeyUsage) || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		len(leaf.URIs) != 1 || leaf.URIs[0].String() != NodeSPIFFEPrefix+value.NodeID.String() ||
		value.RegisteredAt.Before(leaf.NotBefore) || !value.RegisteredAt.Before(leaf.NotAfter) ||
		value.RegisteredAt.Before(ca.NotBefore) || !value.RegisteredAt.Before(ca.NotAfter) || leaf.CheckSignatureFrom(ca) != nil {
		return nil, ErrCertificateInvalid
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: value.RegisteredAt, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, ErrCertificateInvalid
	}
	return facts, nil
}
