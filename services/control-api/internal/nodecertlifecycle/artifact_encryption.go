package nodecertlifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"github.com/cloudflare/circl/hpke"
	"github.com/google/uuid"
)

const (
	identityArtifactBindingSchema = "cdnca.node.identity-artifact-binding/v1"
	identityArtifactWireMagic     = "CDNCAHPKE1\x00"
	identityArtifactInfoDomain    = "cdnca-node-identity-artifact-info/v1\x00"
	identityArtifactAADDomain     = "cdnca-node-identity-artifact-aad/v1\x00"
	maxIdentityArtifactBytes      = 4 << 20
)

var (
	ErrArtifactBinding      = errors.New("node identity artifact binding is invalid")
	ErrArtifactEncryption   = errors.New("node identity artifact encryption failed")
	ErrRecipientUnavailable = errors.New("node identity artifact recipient is unavailable")
)

type RecipientState string

const (
	RecipientActive   RecipientState = "active"
	RecipientDraining RecipientState = "draining"
	RecipientRevoked  RecipientState = "revoked"
)

type ArtifactBinding struct {
	Schema               string    `json:"schema"`
	NodeID               uuid.UUID `json:"node_id"`
	TenantID             uuid.UUID `json:"tenant_id"`
	ConfigVersionID      uuid.UUID `json:"config_version_id"`
	DeploymentID         uuid.UUID `json:"deployment_id"`
	ArtifactID           uuid.UUID `json:"artifact_id"`
	PlaintextSHA256      [32]byte  `json:"plaintext_sha256"`
	RecipientKeyID       string    `json:"recipient_key_id"`
	RecipientKeyRevision uint64    `json:"recipient_key_revision"`
}

type ArtifactSealRequest struct {
	NodeID, TenantID, ConfigVersionID, DeploymentID, ArtifactID uuid.UUID
	Plaintext                                                   []byte
	PlaintextSHA256                                             [32]byte
	RecipientPublicKey                                          []byte
	RecipientKeyID                                              string
	CurrentRecipientKeyID                                       string
	RecipientKeyRevision                                        uint64
	RecipientState                                              RecipientState
}

type SealedArtifact struct {
	Binding    ArtifactBinding
	WireBytes  []byte
	WireSHA256 [32]byte
}

func ArtifactRecipientKeyID(publicKey []byte) string {
	digest := sha256.Sum256(publicKey)
	return "x25519:" + hex.EncodeToString(digest[:])
}

func (request ArtifactSealRequest) Binding() ArtifactBinding {
	return ArtifactBinding{Schema: identityArtifactBindingSchema, NodeID: request.NodeID, TenantID: request.TenantID,
		ConfigVersionID: request.ConfigVersionID, DeploymentID: request.DeploymentID, ArtifactID: request.ArtifactID,
		PlaintextSHA256: request.PlaintextSHA256, RecipientKeyID: request.RecipientKeyID,
		RecipientKeyRevision: request.RecipientKeyRevision}
}

var identityArtifactSuite = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)

func SealArtifact(random io.Reader, request ArtifactSealRequest) (SealedArtifact, error) {
	binding := request.Binding()
	if random == nil || !validArtifactBinding(binding) || len(request.Plaintext) == 0 || len(request.Plaintext) > maxIdentityArtifactBytes ||
		sha256.Sum256(request.Plaintext) != request.PlaintextSHA256 || request.RecipientState != RecipientActive ||
		request.CurrentRecipientKeyID != request.RecipientKeyID || len(request.RecipientPublicKey) != 32 ||
		ArtifactRecipientKeyID(request.RecipientPublicKey) != request.RecipientKeyID {
		if request.RecipientState != RecipientActive || request.CurrentRecipientKeyID != request.RecipientKeyID {
			return SealedArtifact{}, ErrRecipientUnavailable
		}
		return SealedArtifact{}, ErrArtifactBinding
	}
	bindingBytes, err := json.Marshal(binding)
	if err != nil {
		return SealedArtifact{}, ErrArtifactBinding
	}
	recipient, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(request.RecipientPublicKey)
	if err != nil {
		return SealedArtifact{}, ErrArtifactBinding
	}
	info, aad := identityArtifactContext(bindingBytes)
	sender, err := identityArtifactSuite.NewSender(recipient, info)
	if err != nil {
		return SealedArtifact{}, ErrArtifactEncryption
	}
	encapsulation, sealer, err := sender.Setup(random)
	if err != nil {
		return SealedArtifact{}, ErrArtifactEncryption
	}
	ciphertext, err := sealer.Seal(request.Plaintext, aad)
	if err != nil {
		return SealedArtifact{}, ErrArtifactEncryption
	}
	wire := make([]byte, 0, len(identityArtifactWireMagic)+4+len(bindingBytes)+len(encapsulation)+len(ciphertext))
	wire = append(wire, identityArtifactWireMagic...)
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(bindingBytes)))
	wire = append(wire, bindingBytes...)
	wire = append(wire, encapsulation...)
	wire = append(wire, ciphertext...)
	return SealedArtifact{Binding: binding, WireBytes: wire, WireSHA256: sha256.Sum256(wire)}, nil
}

func OpenArtifact(privateKey []byte, sealed SealedArtifact, expected ArtifactBinding) ([]byte, error) {
	if sealed.Binding != expected || !validArtifactBinding(expected) || sha256.Sum256(sealed.WireBytes) != sealed.WireSHA256 {
		return nil, ErrArtifactBinding
	}
	bindingBytes, payload, err := splitIdentityArtifact(sealed.WireBytes)
	if err != nil {
		return nil, err
	}
	expectedBytes, _ := json.Marshal(expected)
	if !bytes.Equal(bindingBytes, expectedBytes) {
		return nil, ErrArtifactBinding
	}
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	key, err := scheme.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil || len(payload) < scheme.CiphertextSize()+16 {
		return nil, ErrArtifactBinding
	}
	info, aad := identityArtifactContext(bindingBytes)
	receiver, err := identityArtifactSuite.NewReceiver(key, info)
	if err != nil {
		return nil, ErrArtifactEncryption
	}
	opener, err := receiver.Setup(payload[:scheme.CiphertextSize()])
	if err != nil {
		return nil, ErrArtifactEncryption
	}
	plaintext, err := opener.Open(payload[scheme.CiphertextSize():], aad)
	if err != nil || sha256.Sum256(plaintext) != expected.PlaintextSHA256 {
		clearArtifactBytes(plaintext)
		return nil, ErrArtifactBinding
	}
	return plaintext, nil
}

func validArtifactBinding(binding ArtifactBinding) bool {
	return binding.Schema == identityArtifactBindingSchema && binding.NodeID != uuid.Nil && binding.TenantID != uuid.Nil &&
		binding.ConfigVersionID != uuid.Nil && binding.DeploymentID != uuid.Nil && binding.ArtifactID != uuid.Nil &&
		binding.PlaintextSHA256 != [32]byte{} && binding.RecipientKeyRevision > 0 &&
		len(binding.RecipientKeyID) == 71 && binding.RecipientKeyID[:7] == "x25519:"
}

func splitIdentityArtifact(wire []byte) ([]byte, []byte, error) {
	prefix := len(identityArtifactWireMagic)
	if len(wire) < prefix+4 || string(wire[:prefix]) != identityArtifactWireMagic {
		return nil, nil, ErrArtifactBinding
	}
	size := int(binary.BigEndian.Uint32(wire[prefix : prefix+4]))
	if size <= 0 || size > maxIdentityArtifactBytes || len(wire) <= prefix+4+size {
		return nil, nil, ErrArtifactBinding
	}
	return slices.Clone(wire[prefix+4 : prefix+4+size]), slices.Clone(wire[prefix+4+size:]), nil
}

func identityArtifactContext(binding []byte) ([]byte, []byte) {
	digest := sha256.Sum256(binding)
	return append([]byte(identityArtifactInfoDomain), digest[:]...), append([]byte(identityArtifactAADDomain), binding...)
}

func clearArtifactBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
