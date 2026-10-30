package nodeca

import (
	"crypto"
	"crypto/x509"
	"strings"
)

// ManagedKey is the complete key surface required from a KMS or HSM. It does
// not expose private-key bytes or an export operation.
type ManagedKey interface {
	crypto.Signer
	KeyID() string
}

func NewManagedSigner(key ManagedKey, expectedKeyID string, issuingCA *x509.Certificate, orderedChain []*x509.Certificate) (*Signer, error) {
	if isNil(key) || expectedKeyID == "" || len(expectedKeyID) > 255 || strings.TrimSpace(expectedKeyID) != expectedKeyID || key.KeyID() != expectedKeyID {
		return nil, ErrInvalidConfiguration
	}
	return NewSigner(key, issuingCA, orderedChain)
}
