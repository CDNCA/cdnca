package gatewayclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

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

type IdentityArtifactBinding struct {
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

var identityArtifactSuite = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)

var ErrIdentityArtifactIntegrity = errors.New("identity artifact integrity verification failed")

func OpenIdentityArtifact(privateKey, wire []byte, expected IdentityArtifactBinding) ([]byte, error) {
	if !validIdentityArtifactBinding(expected) {
		return nil, fmt.Errorf("%w: identity artifact binding is invalid", ErrIdentityArtifactIntegrity)
	}
	prefix := len(identityArtifactWireMagic)
	if len(wire) < prefix+4 || string(wire[:prefix]) != identityArtifactWireMagic {
		return nil, fmt.Errorf("%w: identity artifact envelope is invalid", ErrIdentityArtifactIntegrity)
	}
	bindingSize := int(binary.BigEndian.Uint32(wire[prefix : prefix+4]))
	if bindingSize <= 0 || bindingSize > maxIdentityArtifactBytes || len(wire) <= prefix+4+bindingSize {
		return nil, fmt.Errorf("%w: identity artifact envelope is invalid", ErrIdentityArtifactIntegrity)
	}
	bindingBytes := wire[prefix+4 : prefix+4+bindingSize]
	expectedBytes, err := json.Marshal(expected)
	if err != nil || !bytes.Equal(bindingBytes, expectedBytes) {
		return nil, fmt.Errorf("%w: identity artifact does not match the expected identity", ErrIdentityArtifactIntegrity)
	}
	var decoded IdentityArtifactBinding
	decoder := json.NewDecoder(bytes.NewReader(bindingBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || decoded != expected {
		return nil, fmt.Errorf("%w: identity artifact binding is invalid", ErrIdentityArtifactIntegrity)
	}
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	receiverKey, err := scheme.UnmarshalBinaryPrivateKey(privateKey)
	payload := wire[prefix+4+bindingSize:]
	if err != nil || len(payload) < scheme.CiphertextSize()+16 {
		return nil, fmt.Errorf("%w: identity artifact recipient is invalid", ErrIdentityArtifactIntegrity)
	}
	publicKey, err := receiverKey.Public().MarshalBinary()
	if err != nil || identityArtifactRecipientKeyID(publicKey) != expected.RecipientKeyID {
		return nil, fmt.Errorf("%w: identity artifact recipient is invalid", ErrIdentityArtifactIntegrity)
	}
	info, aad := identityArtifactContext(bindingBytes)
	receiver, err := identityArtifactSuite.NewReceiver(receiverKey, info)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize identity artifact recipient", ErrIdentityArtifactIntegrity)
	}
	opener, err := receiver.Setup(payload[:scheme.CiphertextSize()])
	if err != nil {
		return nil, fmt.Errorf("%w: initialize identity artifact envelope", ErrIdentityArtifactIntegrity)
	}
	plaintext, err := opener.Open(payload[scheme.CiphertextSize():], aad)
	if err != nil || sha256.Sum256(plaintext) != expected.PlaintextSHA256 {
		clearIdentityArtifactPlaintext(plaintext)
		return nil, fmt.Errorf("%w: identity artifact authentication failed", ErrIdentityArtifactIntegrity)
	}
	return plaintext, nil
}

func validIdentityArtifactBinding(binding IdentityArtifactBinding) bool {
	return binding.Schema == identityArtifactBindingSchema && binding.NodeID != uuid.Nil && binding.TenantID != uuid.Nil &&
		binding.ConfigVersionID != uuid.Nil && binding.DeploymentID != uuid.Nil && binding.ArtifactID != uuid.Nil &&
		binding.PlaintextSHA256 != [32]byte{} && binding.RecipientKeyRevision > 0 &&
		len(binding.RecipientKeyID) == 71 && binding.RecipientKeyID[:7] == "x25519:"
}

func identityArtifactRecipientKeyID(publicKey []byte) string {
	digest := sha256.Sum256(publicKey)
	return "x25519:" + hex.EncodeToString(digest[:])
}

func identityArtifactContext(binding []byte) ([]byte, []byte) {
	digest := sha256.Sum256(binding)
	return append([]byte(identityArtifactInfoDomain), digest[:]...), append([]byte(identityArtifactAADDomain), binding...)
}

func clearIdentityArtifactPlaintext(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
