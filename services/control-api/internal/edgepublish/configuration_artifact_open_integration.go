//go:build integration

package edgepublish

import (
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cloudflare/circl/hpke"
)

// OpenConfigurationArtifactForTest opens a node's HPKE configuration artifact
// as the node does (integration tests of other packages only; not built into
// the service).
func OpenConfigurationArtifactForTest(privateKey []byte, binding edgedeployment.NodeArtifactBinding,
	artifact edgedeployment.ArtifactInput) ([]byte, error) {
	info, aad, err := configurationArtifactContext(configurationArtifactMetadataFrom(binding, artifact))
	if err != nil {
		return nil, err
	}
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	key, err := scheme.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil || len(artifact.WireBytes) < scheme.CiphertextSize()+configurationArtifactHPKETagSize {
		return nil, errors.New("invalid private key or wire")
	}
	receiver, err := configurationArtifactSuite.NewReceiver(key, info)
	if err != nil {
		return nil, err
	}
	opener, err := receiver.Setup(artifact.WireBytes[:scheme.CiphertextSize()])
	if err != nil {
		return nil, err
	}
	return opener.Open(artifact.WireBytes[scheme.CiphertextSize():], aad)
}
