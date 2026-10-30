package nodeidentity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

const (
	maxCSRBytes          = 64 << 10
	maxCapabilitiesBytes = 64 << 10
	maxCapabilities      = 64
)

var identityLabelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

type normalizedAuthorize struct {
	RequestID               uuid.UUID
	TokenHash               [32]byte
	CSRDER                  []byte
	CSR                     *x509.CertificateRequest
	CSRHash                 [32]byte
	MachineFingerprint      [32]byte
	Supported               *commonv1.ProtocolVersionRange
	Selected                *commonv1.ProtocolVersion
	CapabilitiesSnapshot    []byte
	CapabilitiesHash        [32]byte
	GatewayWorkloadIdentity string
	GatewayInstanceID       string
	PeerIP                  string
	ArtifactPublicKey       [32]byte
	ArtifactPublicKeyHash   [32]byte
	ArtifactKeyID           string
	RequestDigest           [32]byte
}

type normalizedRenew struct {
	RequestID                uuid.UUID
	NodeID                   uuid.UUID
	CurrentSerial            string
	CurrentCertificateSHA256 [32]byte
	CSRDER                   []byte
	CSR                      *x509.CertificateRequest
	CSRHash                  [32]byte
	GatewayWorkloadIdentity  string
	GatewayInstanceID        string
	RequestDigest            [32]byte
}

func normalizeAuthorize(request AuthorizeRequest, accepted *commonv1.ProtocolVersionRange) (normalizedAuthorize, error) {
	requestID, err := uuid.Parse(request.RequestID)
	if err != nil || requestID.String() != request.RequestID || !validIdentity(request.GatewayWorkloadIdentity, 256) ||
		!validIdentity(request.GatewayInstanceID, 128) || len(request.MachineFingerprintSHA256) != sha256.Size ||
		!validX25519PublicKey(request.ArtifactEncryptionPublicKey) {
		return normalizedAuthorize{}, ErrInvalidInput
	}
	secret, err := base64.RawURLEncoding.DecodeString(request.EnrollmentToken)
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != request.EnrollmentToken {
		return normalizedAuthorize{}, ErrInvalidInput
	}
	peerIPString := ""
	if request.PeerIP != "" {
		peerIP := net.ParseIP(request.PeerIP)
		if peerIP == nil {
			return normalizedAuthorize{}, ErrInvalidInput
		}
		peerIPString = peerIP.String()
	}
	csr, csrDER, csrHash, err := validateCSR(request.CertificateSigningRequestDER)
	if err != nil {
		return normalizedAuthorize{}, err
	}
	supported, err := normalizeProtocolRange(request.SupportedProtocolVersions)
	if err != nil {
		return normalizedAuthorize{}, err
	}
	selected, ok := negotiateProtocol(supported, accepted)
	if !ok {
		return normalizedAuthorize{}, ErrInvalidInput
	}
	capabilities, capabilitiesHash, err := canonicalCapabilities(request.Capabilities)
	if err != nil {
		return normalizedAuthorize{}, err
	}
	tokenHash := sha256.Sum256([]byte(request.EnrollmentToken))
	publicKeyHash := sha256.Sum256(request.ArtifactEncryptionPublicKey)
	artifactKeyID := "x25519:" + hex.EncodeToString(publicKeyHash[:])
	machineFingerprint := [32]byte(request.MachineFingerprintSHA256)
	artifactPublicKey := [32]byte(request.ArtifactEncryptionPublicKey)
	digestPayload, err := json.Marshal(struct {
		TokenHash             [32]byte `json:"token_hash"`
		CSRHash               [32]byte `json:"csr_sha256"`
		MachineFingerprint    [32]byte `json:"machine_fingerprint_sha256"`
		ProtocolMinimumMajor  uint32   `json:"protocol_minimum_major"`
		ProtocolMinimumMinor  uint32   `json:"protocol_minimum_minor"`
		ProtocolMaximumMajor  uint32   `json:"protocol_maximum_major"`
		ProtocolMaximumMinor  uint32   `json:"protocol_maximum_minor"`
		CapabilitiesHash      [32]byte `json:"capabilities_sha256"`
		GatewayWorkload       string   `json:"gateway_workload_identity"`
		GatewayInstance       string   `json:"gateway_instance_id"`
		PeerIP                string   `json:"peer_ip"`
		ArtifactPublicKeyHash [32]byte `json:"artifact_public_key_sha256"`
	}{tokenHash, csrHash, machineFingerprint, supported.Minimum.Major, supported.Minimum.Minor,
		supported.Maximum.Major, supported.Maximum.Minor, capabilitiesHash,
		request.GatewayWorkloadIdentity, request.GatewayInstanceID, peerIPString, publicKeyHash})
	if err != nil {
		return normalizedAuthorize{}, ErrInvalidInput
	}
	return normalizedAuthorize{
		RequestID: requestID, TokenHash: tokenHash, CSRDER: csrDER, CSR: csr, CSRHash: csrHash,
		MachineFingerprint: machineFingerprint, Supported: supported, Selected: selected,
		CapabilitiesSnapshot: capabilities, CapabilitiesHash: capabilitiesHash,
		GatewayWorkloadIdentity: request.GatewayWorkloadIdentity,
		GatewayInstanceID:       request.GatewayInstanceID, PeerIP: peerIPString,
		ArtifactPublicKey: artifactPublicKey, ArtifactPublicKeyHash: publicKeyHash,
		ArtifactKeyID: artifactKeyID, RequestDigest: sha256.Sum256(digestPayload),
	}, nil
}

func normalizeRenew(request RenewRequest) (normalizedRenew, error) {
	requestID, err := uuid.Parse(request.RequestID)
	if err != nil || requestID.String() != request.RequestID || request.NodeID == uuid.Nil ||
		!validSerial(request.CurrentSerialNumber) || !validIdentity(request.GatewayWorkloadIdentity, 256) ||
		!validIdentity(request.GatewayInstanceID, 128) {
		return normalizedRenew{}, ErrInvalidInput
	}
	csr, csrDER, csrHash, err := validateCSR(request.CertificateSigningRequestDER)
	if err != nil {
		return normalizedRenew{}, err
	}
	payload, err := json.Marshal(struct {
		NodeID                   string   `json:"node_id"`
		CurrentSerial            string   `json:"current_serial_number"`
		CurrentCertificateSHA256 [32]byte `json:"current_certificate_sha256"`
		CSRHash                  [32]byte `json:"csr_sha256"`
		GatewayWorkload          string   `json:"gateway_workload_identity"`
		GatewayInstanceID        string   `json:"gateway_instance_id"`
	}{request.NodeID.String(), request.CurrentSerialNumber, request.CurrentCertificateSHA256, csrHash,
		request.GatewayWorkloadIdentity, request.GatewayInstanceID})
	if err != nil {
		return normalizedRenew{}, ErrInvalidInput
	}
	return normalizedRenew{requestID, request.NodeID, request.CurrentSerialNumber, request.CurrentCertificateSHA256, csrDER, csr, csrHash,
		request.GatewayWorkloadIdentity, request.GatewayInstanceID, sha256.Sum256(payload)}, nil
}

func validateCSR(value []byte) (*x509.CertificateRequest, []byte, [32]byte, error) {
	if len(value) == 0 || len(value) > maxCSRBytes {
		return nil, nil, [32]byte{}, ErrInvalidInput
	}
	csr, err := x509.ParseCertificateRequest(value)
	if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames) != 0 || len(csr.EmailAddresses) != 0 ||
		len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 {
		return nil, nil, [32]byte{}, ErrInvalidInput
	}
	switch key := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if key.Curve.Params().Name != "P-256" {
			return nil, nil, [32]byte{}, ErrInvalidInput
		}
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return nil, nil, [32]byte{}, ErrInvalidInput
		}
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 || key.N.BitLen() > 4096 {
			return nil, nil, [32]byte{}, ErrInvalidInput
		}
	default:
		return nil, nil, [32]byte{}, ErrInvalidInput
	}
	cloned := bytes.Clone(value)
	return csr, cloned, sha256.Sum256(cloned), nil
}

func canonicalCapabilities(value *agentv1.AgentCapabilities) ([]byte, [32]byte, error) {
	if value == nil || !validText(value.AgentVersion, 128, true) || !validText(value.BuildId, 128, true) ||
		!validText(value.OperatingSystem, 64, true) || !validText(value.Architecture, 64, true) ||
		!validText(value.OpenrestyVersion, 128, false) || len(value.Features) > maxCapabilities {
		return nil, [32]byte{}, ErrInvalidInput
	}
	canonical := proto.Clone(value).(*agentv1.AgentCapabilities)
	for _, feature := range canonical.Features {
		if feature == nil || feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED || feature.ApiVersion == 0 {
			return nil, [32]byte{}, ErrInvalidInput
		}
		if _, exists := agentv1.CapabilityName_name[int32(feature.Name)]; !exists {
			return nil, [32]byte{}, ErrInvalidInput
		}
	}
	sort.Slice(canonical.Features, func(i, j int) bool { return canonical.Features[i].Name < canonical.Features[j].Name })
	for index := 1; index < len(canonical.Features); index++ {
		if canonical.Features[index-1].Name == canonical.Features[index].Name {
			return nil, [32]byte{}, ErrInvalidInput
		}
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(canonical)
	if err != nil || len(encoded) == 0 || len(encoded) > maxCapabilitiesBytes {
		return nil, [32]byte{}, ErrInvalidInput
	}
	return encoded, sha256.Sum256(encoded), nil
}

func normalizeProtocolRange(value *commonv1.ProtocolVersionRange) (*commonv1.ProtocolVersionRange, error) {
	if value == nil || value.Minimum == nil || value.Maximum == nil || value.Minimum.Major > 65535 ||
		value.Minimum.Minor > 65535 || value.Maximum.Major > 65535 || value.Maximum.Minor > 65535 ||
		compareProtocol(value.Minimum, value.Maximum) > 0 {
		return nil, ErrInvalidInput
	}
	return proto.Clone(value).(*commonv1.ProtocolVersionRange), nil
}

func negotiateProtocol(left, right *commonv1.ProtocolVersionRange) (*commonv1.ProtocolVersion, bool) {
	if left == nil || right == nil || left.Minimum == nil || left.Maximum == nil || right.Minimum == nil || right.Maximum == nil {
		return nil, false
	}
	minimum := left.Minimum
	if compareProtocol(right.Minimum, minimum) > 0 {
		minimum = right.Minimum
	}
	maximum := left.Maximum
	if compareProtocol(right.Maximum, maximum) < 0 {
		maximum = right.Maximum
	}
	if compareProtocol(minimum, maximum) > 0 {
		return nil, false
	}
	return proto.Clone(maximum).(*commonv1.ProtocolVersion), true
}

func compareProtocol(left, right *commonv1.ProtocolVersion) int {
	if left.Major != right.Major {
		if left.Major < right.Major {
			return -1
		}
		return 1
	}
	if left.Minor < right.Minor {
		return -1
	}
	if left.Minor > right.Minor {
		return 1
	}
	return 0
}

func validIdentity(value string, maximum int) bool {
	return value == strings.TrimSpace(value) && len(value) <= maximum && identityLabelPattern.MatchString(value)
}

func validText(value string, maximum int, required bool) bool {
	return (!required || value != "") && value == strings.TrimSpace(value) && utf8.ValidString(value) && len(value) <= maximum
}

func validSerial(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, current := range value {
		if !(current >= '0' && current <= '9') && !(current >= 'a' && current <= 'f') {
			return false
		}
	}
	return true
}

func validX25519PublicKey(value []byte) bool {
	if len(value) != 32 {
		return false
	}
	curve := ecdh.X25519()
	publicKey, err := curve.NewPublicKey(value)
	if err != nil {
		return false
	}
	// This fixed scalar is a validation probe, not an identity or encryption
	// credential. ECDH rejects X25519 low-order inputs that yield all-zero output.
	probeBytes := [32]byte{1, 17, 29, 43, 59, 71, 83, 97, 101, 113, 127, 139, 151, 163, 179, 191,
		2, 19, 31, 47, 61, 73, 89, 103, 107, 127, 137, 149, 167, 181, 193, 211}
	probe, err := curve.NewPrivateKey(probeBytes[:])
	if err != nil {
		return false
	}
	_, err = probe.ECDH(publicKey)
	return err == nil
}

func cloneProtocolRange(value *commonv1.ProtocolVersionRange) *commonv1.ProtocolVersionRange {
	if value == nil {
		return nil
	}
	return proto.Clone(value).(*commonv1.ProtocolVersionRange)
}

func cloneCertificate(value Certificate) Certificate {
	value.LeafCertificatePEM = bytes.Clone(value.LeafCertificatePEM)
	chain := value.IssuingChainPEM
	value.IssuingChainPEM = make([][]byte, len(chain))
	for index := range chain {
		value.IssuingChainPEM[index] = bytes.Clone(chain[index])
	}
	return value
}

func validConfig(config Config) bool {
	_, rangeErr := normalizeProtocolRange(config.AcceptedProtocols)
	return rangeErr == nil && config.AuthorizationTTL >= time.Minute && config.AuthorizationTTL <= time.Hour &&
		config.RenewalRequestTTL >= time.Minute && config.RenewalRequestTTL <= time.Hour &&
		config.CertificateTTL >= minimumCertificateTTL && config.CertificateTTL <= MaxCertificateTTL &&
		config.RecoveryWindow > 0 && config.RecoveryWindow <= MaxRecoveryWindow &&
		config.CertificateBackdate >= 0 && config.CertificateBackdate <= 5*time.Minute &&
		config.RenewBefore >= time.Minute && config.RenewBefore < config.CertificateTTL &&
		config.SigningLeaseTTL >= time.Second && config.SigningLeaseTTL <= 5*time.Minute &&
		config.SnapshotTTL >= time.Second && config.SnapshotTTL <= 5*time.Minute && config.Clock != nil && config.NewID != nil
}

func canonicalRevocationDigest(nodeID uuid.UUID, serial, reason string) [32]byte {
	return sha256.Sum256([]byte(nodeID.String() + "\x00" + serial + "\x00" + reason))
}

func canonicalEnrollmentLifecycleDigest(
	authorizationID, nodeID, ownerScopeID uuid.UUID,
	installationID string,
	caEpochID uuid.UUID,
	csrHash, leafDERHash [32]byte,
	gatewayWorkloadIdentity, gatewayInstanceID string,
) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		AuthorizationID         uuid.UUID `json:"enrollment_authorization_id"`
		NodeID                  uuid.UUID `json:"node_id"`
		OwnerScopeID            uuid.UUID `json:"owner_scope_id"`
		InstallationID          string    `json:"installation_id"`
		CAEpochID               uuid.UUID `json:"ca_epoch_id"`
		CSRHash                 [32]byte  `json:"csr_sha256"`
		LeafDERHash             [32]byte  `json:"leaf_der_sha256"`
		GatewayWorkloadIdentity string    `json:"gateway_workload_identity"`
		GatewayInstanceID       string    `json:"gateway_instance_id"`
	}{authorizationID, nodeID, ownerScopeID, installationID, caEpochID, csrHash, leafDERHash,
		gatewayWorkloadIdentity, gatewayInstanceID})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func equalDigest(left, right []byte) bool {
	return len(left) == 32 && len(right) == 32 && bytes.Equal(left, right)
}
