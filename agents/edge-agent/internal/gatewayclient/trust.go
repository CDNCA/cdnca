package gatewayclient

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"sync"
)

type TrustStore struct {
	keys map[string]crypto.PublicKey
	// overlay is the node signer trust from the control plane (signer_trust.go):
	// extra platform keys and revocations over the installed artifacts.json.
	mu      sync.RWMutex
	overlay *signerTrustOverlay
}

type trustAnchorFile struct {
	Version int                `json:"version"`
	Keys    []trustAnchorEntry `json:"keys"`
}

type trustAnchorEntry struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem"`
}

func NewTrustStore(keys map[string]crypto.PublicKey) (*TrustStore, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: at least one artifact trust anchor is required", ErrInvalidConfiguration)
	}
	copyKeys := make(map[string]crypto.PublicKey, len(keys))
	for keyID, publicKey := range keys {
		if keyID == "" || len(keyID) > 255 {
			return nil, fmt.Errorf("%w: invalid trust anchor key ID", ErrInvalidConfiguration)
		}
		switch key := publicKey.(type) {
		case ed25519.PublicKey:
			if len(key) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("%w: invalid Ed25519 public key", ErrInvalidConfiguration)
			}
			copyKeys[keyID] = append(ed25519.PublicKey(nil), key...)
		case *ecdsa.PublicKey:
			if key == nil || key.Curve != elliptic.P256() || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
				return nil, fmt.Errorf("%w: artifact ECDSA key must use P-256", ErrInvalidConfiguration)
			}
			copyKeys[keyID] = &ecdsa.PublicKey{Curve: key.Curve, X: new(big.Int).Set(key.X), Y: new(big.Int).Set(key.Y)}
		default:
			return nil, fmt.Errorf("%w: unsupported artifact public key", ErrInvalidConfiguration)
		}
	}
	return &TrustStore{keys: copyKeys}, nil
}

func LoadTrustStore(path string) (*TrustStore, error) {
	if err := validateSecureRegularFile(path, true); err != nil {
		return nil, err
	}
	content, err := readSecureRegularFile(path, true)
	if err != nil {
		return nil, fmt.Errorf("read trust anchors: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document trustAnchorFile
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("%w: invalid trust anchor document", ErrInvalidConfiguration)
	}
	if document.Version != 1 || len(document.Keys) == 0 {
		return nil, fmt.Errorf("%w: unsupported or empty trust anchor document", ErrInvalidConfiguration)
	}
	keys := make(map[string]crypto.PublicKey, len(document.Keys))
	for _, entry := range document.Keys {
		if _, exists := keys[entry.KeyID]; exists {
			return nil, fmt.Errorf("%w: duplicate trust anchor key ID", ErrInvalidConfiguration)
		}
		block, remainder := pem.Decode([]byte(entry.PublicKeyPEM))
		if block == nil || block.Type != "PUBLIC KEY" || len(remainder) != 0 {
			return nil, fmt.Errorf("%w: invalid trust anchor PEM", ErrInvalidConfiguration)
		}
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid trust anchor key", ErrInvalidConfiguration)
		}
		keys[entry.KeyID] = publicKey
	}
	return NewTrustStore(keys)
}

// key resolves keyID in the effective trust: artifacts.json plus the
// overlay's trusted keys, minus every revoked key (by ID or public key).
func (s *TrustStore) key(keyID string) (crypto.PublicKey, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	overlay := s.overlay
	s.mu.RUnlock()
	key, ok := s.keys[keyID]
	if !ok && overlay != nil {
		key, ok = overlay.trusted[keyID]
	}
	if !ok || overlay.revokes(keyID, key) {
		return nil, false
	}
	return key, true
}

// Revoked reports whether the overlay revokes keyID or publicKey (for
// verifiers that hold keys outside this store, such as the WAF extension's
// transitional keys). With publicKey nil the key this store knows under keyID
// is checked too, so a revocation by fingerprint is found.
func (s *TrustStore) Revoked(keyID string, publicKey crypto.PublicKey) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	overlay := s.overlay
	s.mu.RUnlock()
	if overlay == nil {
		return false
	}
	if publicKey == nil {
		if known, ok := s.keys[keyID]; ok {
			publicKey = known
		} else if known, ok := overlay.trusted[keyID]; ok {
			publicKey = known
		}
	}
	return overlay.revokes(keyID, publicKey)
}

// RevokedEd25519 is Revoked for verifiers holding raw Ed25519 keys (the WAF
// extension): an empty key means "the key this store knows under keyID".
func (s *TrustStore) RevokedEd25519(keyID string, key ed25519.PublicKey) bool {
	if len(key) == 0 {
		return s.Revoked(keyID, nil)
	}
	return s.Revoked(keyID, key)
}

// Ed25519Key returns the trusted Ed25519 publication key with keyID. Signer trust bundles and WAF extensions are
// verified with the same trust anchors as deployments, under their own signature domains.
func (s *TrustStore) Ed25519Key(keyID string) (ed25519.PublicKey, bool) {
	key, ok := s.key(keyID)
	typed, isEd25519 := key.(ed25519.PublicKey)
	if !ok || !isEd25519 || len(typed) != ed25519.PublicKeySize {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), typed...), true
}

// Ed25519Subset returns every Ed25519 anchor (ECDSA anchors are skipped). The
// artifact trust document mixes both; the release-signed artifacts that only
// use Ed25519 (the OWASP CRS engine extension) take this subset.
func (s *TrustStore) Ed25519Subset() map[string]ed25519.PublicKey {
	result := map[string]ed25519.PublicKey{}
	if s == nil {
		return result
	}
	s.mu.RLock()
	overlay := s.overlay
	s.mu.RUnlock()
	ids := make([]string, 0, len(s.keys))
	for keyID := range s.keys {
		ids = append(ids, keyID)
	}
	if overlay != nil {
		for keyID := range overlay.trusted {
			ids = append(ids, keyID)
		}
	}
	for _, keyID := range ids {
		if key, ok := s.Ed25519Key(keyID); ok {
			result[keyID] = key
		}
	}
	return result
}
