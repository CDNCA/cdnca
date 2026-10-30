package entitlementguard

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

type TrustStore struct {
	mu   sync.RWMutex
	pins map[string]ed25519.PublicKey
	keys map[string]VerificationKey
	ring *entitlement.KeyRing

	revocationGate atomic.Pointer[signerRevocationGateHolder]
}

type trustedKeysJSON struct {
	Keys []verificationKeyJSON `json:"keys"`
}

type verificationKeyJSON struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

func DecodeTrustedKeys(encoded []byte) (*TrustStore, error) {
	if len(encoded) == 0 || len(encoded) > maxInstallBundleBytes {
		return nil, ErrInvalidTrustStore
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire trustedKeysJSON
	if err := decoder.Decode(&wire); err != nil {
		return nil, ErrInvalidTrustStore
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidTrustStore
	}
	keys := make([]VerificationKey, 0, len(wire.Keys))
	for _, item := range wire.Keys {
		publicKey, err := base64.RawURLEncoding.DecodeString(item.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, ErrInvalidTrustStore
		}
		keys = append(keys, VerificationKey{KeyID: item.KeyID, PublicKey: publicKey})
	}
	return NewTrustStore(keys)
}

func NewTrustStore(keys []VerificationKey) (*TrustStore, error) {
	if len(keys) == 0 {
		return nil, ErrInvalidTrustStore
	}
	store := &TrustStore{pins: make(map[string]ed25519.PublicKey, len(keys))}
	for _, key := range keys {
		if entitlement.ValidateKeyID(key.KeyID) != nil || len(key.PublicKey) != ed25519.PublicKeySize {
			return nil, ErrInvalidTrustStore
		}
		if _, exists := store.pins[key.KeyID]; exists {
			return nil, ErrKeyConflict
		}
		store.pins[key.KeyID] = append(ed25519.PublicKey(nil), key.PublicKey...)
	}
	if err := store.applyVerifiedKeys(keys); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *TrustStore) Verify(signed entitlement.SignedLease, options entitlement.VerifyOptions) (entitlement.Result, error) {
	if store == nil {
		return entitlement.Result{}, ErrTrustUnavailable
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.ring == nil || len(store.keys) == 0 {
		return entitlement.Result{}, ErrTrustUnavailable
	}
	key, found := store.keys[signed.KeyID]
	if !found {
		return entitlement.Result{}, entitlement.ErrUnknownKey
	}
	if err := verificationKeyWindow(key, time.Unix(signed.Lease.NotBefore, 0).UTC(), options.Now); err != nil {
		return entitlement.Result{}, err
	}
	result, err := store.ring.Verify(signed, options)
	if err != nil {
		return result, err
	}
	if err := store.CheckSignerRevocation(SignerArtifactLease, signed.KeyID); err != nil {
		return entitlement.Result{}, err
	}
	return result, nil
}

func (store *TrustStore) VerifyUpgradePlanArtifactBundle(encoded []byte,
	options entitlement.UpgradePlanArtifactBundleVerifyOptions) (entitlement.UpgradePlanArtifactBundle, error) {
	signed, err := entitlement.DecodeUpgradePlanArtifactBundle(encoded)
	if err != nil {
		return entitlement.UpgradePlanArtifactBundle{}, err
	}
	if store == nil {
		return entitlement.UpgradePlanArtifactBundle{}, ErrTrustUnavailable
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.ring == nil || len(store.keys) == 0 {
		return entitlement.UpgradePlanArtifactBundle{}, ErrTrustUnavailable
	}
	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	signedAt := time.Unix(signed.Bundle.IssuedAt, 0).UTC()
	for _, keyID := range []string{signed.KeyID, signed.Bundle.Forward.SignatureKeyID, signed.Bundle.Rollback.SignatureKeyID} {
		key, found := store.keys[keyID]
		if !found {
			return entitlement.UpgradePlanArtifactBundle{}, entitlement.ErrUnknownUpgradePlanArtifactBundleKey
		}
		if err := verificationKeyWindow(key, signedAt, now); err != nil {
			return entitlement.UpgradePlanArtifactBundle{}, err
		}
	}
	bundle, err := store.ring.VerifyUpgradePlanArtifactBundle(signed, options)
	if err != nil {
		return bundle, err
	}
	for _, keyID := range []string{signed.KeyID, signed.Bundle.Forward.SignatureKeyID, signed.Bundle.Rollback.SignatureKeyID} {
		if err := store.CheckSignerRevocation(SignerArtifactRelease, keyID); err != nil {
			return entitlement.UpgradePlanArtifactBundle{}, err
		}
	}
	return bundle, nil
}

func (store *TrustStore) PublicKey(keyID string) (ed25519.PublicKey, bool) {
	if store == nil {
		return nil, false
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	key, found := store.keys[keyID]
	if !found {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), key.PublicKey...), true
}

func (store *TrustStore) PinnedKeys() []VerificationKey {
	if store == nil {
		return nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := make([]VerificationKey, 0, len(store.pins))
	for keyID, publicKey := range store.pins {
		result = append(result, VerificationKey{KeyID: keyID,
			PublicKey: append(ed25519.PublicKey(nil), publicKey...)})
	}
	return result
}

func (store *TrustStore) ApplyVerifiedKeys(keys []VerificationKey) error {
	if store == nil {
		return ErrTrustUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.applyVerifiedKeys(keys)
}

func (store *TrustStore) applyVerifiedKeys(keys []VerificationKey) error {
	ring := entitlement.NewKeyRing()
	verified := make(map[string]VerificationKey, len(keys))
	for _, key := range keys {
		if entitlement.ValidateKeyID(key.KeyID) != nil || len(key.PublicKey) != ed25519.PublicKeySize ||
			(!key.NotBefore.IsZero() && key.SignUntil != nil && !key.SignUntil.After(key.NotBefore)) ||
			(key.VerifyUntil != nil && key.SignUntil != nil && key.VerifyUntil.Before(*key.SignUntil)) {
			return ErrInvalidTrustStore
		}
		if _, exists := verified[key.KeyID]; exists {
			return ErrKeyConflict
		}
		if err := ring.Add(key.KeyID, key.PublicKey); err != nil {
			return ErrInvalidTrustStore
		}
		verified[key.KeyID] = cloneVerificationKey(key)
	}
	for keyID, pinned := range store.pins {
		key, found := verified[keyID]
		if !found || !bytes.Equal(key.PublicKey, pinned) {
			return ErrInvalidTrustStore
		}
	}
	store.keys = verified
	store.ring = ring
	return nil
}

func (store *TrustStore) VerifyDetached(keyID string, payload, signature []byte, signedAt, now time.Time) error {
	if store == nil || len(payload) == 0 || len(signature) != ed25519.SignatureSize || signedAt.IsZero() || now.IsZero() {
		return ErrTrustUnavailable
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	key, found := store.keys[keyID]
	if !found {
		return entitlement.ErrUnknownKey
	}
	if err := verificationKeyWindow(key, signedAt.UTC(), now.UTC()); err != nil {
		return err
	}
	if !ed25519.Verify(key.PublicKey, payload, signature) {
		return entitlement.ErrInvalidSignature
	}
	return nil
}

func verificationKeyWindow(key VerificationKey, signedAt, now time.Time) error {
	if (!key.NotBefore.IsZero() && signedAt.Before(key.NotBefore)) ||
		(key.SignUntil != nil && !signedAt.Before(*key.SignUntil)) ||
		(key.VerifyUntil != nil && !now.Before(*key.VerifyUntil)) {
		return ErrKeyOutsideWindow
	}
	return nil
}

func cloneVerificationKey(key VerificationKey) VerificationKey {
	key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
	if key.SignUntil != nil {
		value := *key.SignUntil
		key.SignUntil = &value
	}
	if key.VerifyUntil != nil {
		value := *key.VerifyUntil
		key.VerifyUntil = &value
	}
	return key
}
