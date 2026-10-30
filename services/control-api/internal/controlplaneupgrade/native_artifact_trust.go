package controlplaneupgrade

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"

	"github.com/cdnca/cdnca/libs/entitlement"
)

// DecodeNativeArtifactTrust reads publisher keys, never keys supplied by the
// artifact itself. These durable provenance keys are separate from plan grants.
func DecodeNativeArtifactTrust(encoded []byte) (map[string]ed25519.PublicKey, error) {
	var document struct {
		Version int `json:"version"`
		Keys    []struct {
			KeyID        string `json:"key_id"`
			PublicKeyPEM string `json:"public_key_pem"`
		} `json:"keys"`
	}
	if len(encoded) == 0 || len(encoded) > 65536 || decodeNativeJSON(encoded, &document) != nil ||
		document.Version != 1 || len(document.Keys) < 1 || len(document.Keys) > 32 {
		return nil, ErrInvalidConfig
	}
	keys := make(map[string]ed25519.PublicKey, len(document.Keys))
	for _, item := range document.Keys {
		if !nativeArtifactKeyID.MatchString(item.KeyID) || keys[item.KeyID] != nil || len(item.PublicKeyPEM) > 4096 ||
			!bytes.HasPrefix([]byte(item.PublicKeyPEM), []byte("-----BEGIN PUBLIC KEY-----\n")) {
			return nil, ErrInvalidConfig
		}
		block, rest := pem.Decode([]byte(item.PublicKeyPEM))
		if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ErrInvalidConfig
		}
		public, err := x509.ParsePKIXPublicKey(block.Bytes)
		key, ok := public.(ed25519.PublicKey)
		if err != nil || !ok || entitlement.ValidateEd25519PublicKey(key) != nil {
			return nil, ErrInvalidConfig
		}
		keys[item.KeyID] = append(ed25519.PublicKey(nil), key...)
	}
	return keys, nil
}

func validNativeArtifactKeys(keys map[string]ed25519.PublicKey) bool {
	if len(keys) < 1 || len(keys) > 32 {
		return false
	}
	for keyID, public := range keys {
		if !nativeArtifactKeyID.MatchString(keyID) || entitlement.ValidateEd25519PublicKey(public) != nil {
			return false
		}
	}
	return true
}
