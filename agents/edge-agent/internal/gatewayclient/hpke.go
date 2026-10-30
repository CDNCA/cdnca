package gatewayclient

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cloudflare/circl/hpke"
)

const (
	hpkeBindingDomain = "cdnca-edge-artifact-hpke-binding-v1\x00"
	hpkeInfoDomain    = "cdnca-edge-artifact-hpke-info-v1\x00"
	hpkeAADDomain     = "cdnca-edge-artifact-hpke-aad-v1\x00"
	hpkeTagSize       = 16
)

var artifactHPKESuite = hpke.NewSuite(
	hpke.KEM_X25519_HKDF_SHA256,
	hpke.KDF_HKDF_SHA256,
	hpke.AEAD_AES256GCM,
)

func decryptArtifactHPKE(command *agentv1.DeploymentCommand, descriptor *agentv1.ArtifactDescriptor, wireBytes, privateKey []byte) ([]byte, error) {
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	encapsulationSize := scheme.CiphertextSize()
	if len(privateKey) != scheme.PrivateKeySize() || len(wireBytes) < encapsulationSize+hpkeTagSize {
		return nil, fmt.Errorf("%w: encrypted artifact envelope is invalid", ErrArtifactIntegrity)
	}
	receiverKey, err := scheme.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: artifact recipient key is invalid", ErrArtifactIntegrity)
	}
	info, aad, err := artifactHPKEContext(command, descriptor)
	if err != nil {
		return nil, err
	}
	receiver, err := artifactHPKESuite.NewReceiver(receiverKey, info)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize artifact decryption", ErrArtifactIntegrity)
	}
	opener, err := receiver.Setup(wireBytes[:encapsulationSize])
	if err != nil {
		return nil, fmt.Errorf("%w: initialize artifact envelope", ErrArtifactIntegrity)
	}
	plaintext, err := opener.Open(wireBytes[encapsulationSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("%w: encrypted artifact authentication failed", ErrArtifactIntegrity)
	}
	return plaintext, nil
}

func artifactHPKEContext(command *agentv1.DeploymentCommand, descriptor *agentv1.ArtifactDescriptor) ([]byte, []byte, error) {
	if command == nil || command.Event == nil || descriptor == nil || descriptor.RecipientKeyId == nil {
		return nil, nil, fmt.Errorf("%w: encrypted artifact binding is incomplete", ErrArtifactIntegrity)
	}
	binding := make([]byte, 0, 512)
	binding = append(binding, hpkeBindingDomain...)
	for _, value := range []string{command.Event.EventId, command.DeploymentId} {
		var err error
		binding, err = appendHPKEString(binding, value)
		if err != nil {
			return nil, nil, err
		}
	}
	binding = binary.BigEndian.AppendUint32(binding, command.Attempt)
	for _, value := range []string{command.ConfigVersionId, descriptor.ArtifactId, descriptor.GetRecipientKeyId()} {
		var err error
		binding, err = appendHPKEString(binding, value)
		if err != nil {
			return nil, nil, err
		}
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(descriptor.Kind))
	binding = binary.BigEndian.AppendUint64(binding, descriptor.SizeBytes)
	var err error
	binding, err = appendHPKEString(binding, descriptor.SigningKeyId)
	if err != nil {
		return nil, nil, err
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(descriptor.SignatureAlgorithm))
	binding = binary.BigEndian.AppendUint32(binding, uint32(descriptor.Compression))
	binding, err = appendHPKEString(binding, descriptor.MediaType)
	if err != nil {
		return nil, nil, err
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(descriptor.EncryptionAlgorithm))
	digest := sha256.Sum256(binding)
	info := make([]byte, 0, len(hpkeInfoDomain)+len(digest))
	info = append(info, hpkeInfoDomain...)
	info = append(info, digest[:]...)
	aad := make([]byte, 0, len(hpkeAADDomain)+len(binding))
	aad = append(aad, hpkeAADDomain...)
	aad = append(aad, binding...)
	return info, aad, nil
}

func appendHPKEString(target []byte, value string) ([]byte, error) {
	if len(value) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: encrypted artifact binding exceeds its limit", ErrArtifactIntegrity)
	}
	target = binary.BigEndian.AppendUint32(target, uint32(len(value)))
	return append(target, value...), nil
}

func clearPlaintext(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
