package nodecertlifecycle

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"

	"github.com/google/uuid"
)

const (
	gatewayMTLSProofSchema       = "cdnca.node-certificate-gateway-mtls-proof/v2"
	legacyGatewayMTLSProofSchema = "cdnca.node-certificate-gateway-mtls-proof/v1"
)

type gatewayMTLSProofDocument struct {
	Schema                  string `json:"schema"`
	RenewalRequestID        string `json:"renewal_request_id"`
	NodeID                  string `json:"node_id"`
	InstallationID          string `json:"installation_id"`
	CurrentSerialNumber     string `json:"current_serial_number"`
	CurrentLeafDERSHA256    string `json:"current_leaf_der_sha256"`
	CSRSHA256               string `json:"csr_sha256"`
	TargetCAEpochID         string `json:"target_ca_epoch_id"`
	GatewayWorkloadIdentity string `json:"gateway_workload_identity"`
	GatewayInstanceID       string `json:"gateway_instance_id,omitempty"`
}

func GatewayMTLSProofMessage(fact RenewalProofFact, principal GatewayMTLSPrincipal) ([]byte, error) {
	return gatewayMTLSProofMessage(fact, principal, gatewayMTLSProofSchema, true)
}

func legacyGatewayMTLSProofMessage(fact RenewalProofFact, principal GatewayMTLSPrincipal) ([]byte, error) {
	return gatewayMTLSProofMessage(fact, principal, legacyGatewayMTLSProofSchema, false)
}

func legacyInstanceBoundGatewayMTLSProofMessage(fact RenewalProofFact, principal GatewayMTLSPrincipal) ([]byte, error) {
	return gatewayMTLSProofMessage(fact, principal, legacyGatewayMTLSProofSchema, true)
}

func gatewayMTLSProofMessage(
	fact RenewalProofFact,
	principal GatewayMTLSPrincipal,
	schema string,
	bindInstance bool,
) ([]byte, error) {
	if fact.RenewalRequestID == uuid.Nil || fact.NodeID == uuid.Nil || fact.InstallationID == "" ||
		!validSerial(fact.CurrentSerialNumber) || !nonzeroDigest(fact.CurrentLeafDERSHA256) ||
		!nonzeroDigest(fact.CSRSHA256) || fact.TargetCAEpochID == uuid.Nil ||
		!validGatewayMTLSPrincipal(principal) {
		return nil, ErrInvalidInput
	}
	document := gatewayMTLSProofDocument{
		Schema: schema, RenewalRequestID: fact.RenewalRequestID.String(),
		NodeID: fact.NodeID.String(), InstallationID: fact.InstallationID,
		CurrentSerialNumber:  fact.CurrentSerialNumber,
		CurrentLeafDERSHA256: hex.EncodeToString(fact.CurrentLeafDERSHA256[:]),
		CSRSHA256:            hex.EncodeToString(fact.CSRSHA256[:]), TargetCAEpochID: fact.TargetCAEpochID.String(),
		GatewayWorkloadIdentity: principal.workloadIdentity,
	}
	if bindInstance {
		document.GatewayInstanceID = principal.instanceID
	}
	return json.Marshal(document)
}

func validGatewayMTLSPrincipal(principal GatewayMTLSPrincipal) bool {
	return validIdentity(principal.workloadIdentity, 256) && validIdentity(principal.instanceID, 128) &&
		strings.HasPrefix(principal.workloadIdentity, "spiffe://cdn-platform/gateway/")
}

func parseCertificatePEM(value []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(value)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrCertificateInvalid
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrCertificateInvalid
	}
	return certificate, nil
}

func validateCACertificate(value []byte) (*x509.Certificate, [32]byte, [32]byte, error) {
	certificate, err := parseCertificatePEM(value)
	if err != nil || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, [32]byte{}, [32]byte{}, ErrCertificateInvalid
	}
	publicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, [32]byte{}, [32]byte{}, ErrCertificateInvalid
	}
	return certificate, sha256.Sum256(certificate.Raw), sha256.Sum256(publicKey), nil
}

func verifyLeaf(certificate, authority *x509.Certificate, nodeID uuid.UUID, serial string, expectedHash [32]byte) error {
	if certificate == nil || authority == nil || nodeID == uuid.Nil || !validSerial(serial) ||
		certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 ||
		certificate.SerialNumber.Text(16) != serial || sha256.Sum256(certificate.Raw) != expectedHash ||
		certificate.CheckSignatureFrom(authority) != nil || len(certificate.URIs) != 1 ||
		certificate.NotBefore.Before(authority.NotBefore) || certificate.NotAfter.After(authority.NotAfter) ||
		certificate.URIs[0].String() != "spiffe://cdn-platform/node/"+nodeID.String() {
		return ErrCertificateInvalid
	}
	return nil
}

func validSerial(value string) bool {
	if len(value) < 1 || len(value) > 128 || value != strings.ToLower(value) || value == "0" ||
		(len(value) > 1 && value[0] == '0') {
		return false
	}
	decoded, ok := new(big.Int).SetString(value, 16)
	return ok && decoded.Sign() > 0 && decoded.Text(16) == value
}

func validIdentity(value string, limit int) bool {
	return value == strings.TrimSpace(value) && len(value) >= 1 && len(value) <= limit
}

func nonzeroDigest(value [32]byte) bool { return value != [32]byte{} }

func digestJSON(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func equalDigest(stored []byte, expected [32]byte) bool {
	return len(stored) == sha256.Size && bytes.Equal(stored, expected[:])
}
