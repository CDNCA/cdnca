package entitlementsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

const (
	publicKeysetSchema          = "cdnca.signing-keyset/v2"
	rotationPoPDomain           = "cdnca.signing-key-rotation-pop/v1"
	rotationAuthorizationDomain = "cdnca.signing-key-rotation-authorization/v1"
)

var (
	ErrInvalidKeyset  = errors.New("invalid signing keyset")
	ErrKeysetRollback = errors.New("signing keyset rollback detected")
)

type keysetFetch struct {
	ETag        string
	Body        []byte
	NotModified bool
}

type publicKeysetWire struct {
	Schema      string               `json:"schema"`
	ActiveKeyID string               `json:"active_key_id"`
	Keys        []publicKeyWire      `json:"keys"`
	Rotations   []publicRotationWire `json:"rotations"`
}

type publicKeyWire struct {
	KeyID       string  `json:"key_id"`
	Algorithm   string  `json:"algorithm"`
	PublicKey   string  `json:"public_key"`
	Fingerprint string  `json:"fingerprint"`
	Status      string  `json:"status"`
	NotBefore   string  `json:"not_before"`
	SignUntil   *string `json:"sign_until,omitempty"`
	VerifyUntil *string `json:"verify_until,omitempty"`
}

type publicRotationWire struct {
	RotationID             string `json:"rotation_id"`
	NewKeyID               string `json:"new_key_id"`
	AuthorizedByKeyID      string `json:"authorized_by_key_id"`
	ChallengeDocument      string `json:"challenge_document"`
	PoPSignature           string `json:"pop_signature"`
	PoPVerifiedAt          string `json:"pop_verified_at"`
	AuthorizationDocument  string `json:"authorization_document"`
	AuthorizationSignature string `json:"authorization_signature"`
	AuthorizedAt           string `json:"authorized_at"`
	AuthorizationExpiresAt string `json:"authorization_expires_at"`
	ActivatedAt            string `json:"activated_at"`
}

type rotationPoPDocument struct {
	Domain               string  `json:"domain"`
	RotationID           string  `json:"rotation_id"`
	NewKeyID             string  `json:"new_key_id"`
	PublicKeyFingerprint string  `json:"public_key_fingerprint"`
	NotBefore            string  `json:"not_before"`
	SignUntil            string  `json:"sign_until"`
	VerifyUntil          *string `json:"verify_until"`
	Nonce                string  `json:"nonce"`
	ChallengeExpiresAt   string  `json:"challenge_expires_at"`
}

type rotationAuthorizationDocument struct {
	Domain                 string  `json:"domain"`
	RotationID             string  `json:"rotation_id"`
	OldKeyID               string  `json:"old_key_id"`
	NewKeyID               string  `json:"new_key_id"`
	PublicKeyFingerprint   string  `json:"public_key_fingerprint"`
	NotBefore              string  `json:"not_before"`
	SignUntil              string  `json:"sign_until"`
	VerifyUntil            *string `json:"verify_until"`
	AuthorizedAt           string  `json:"authorized_at"`
	AuthorizationExpiresAt string  `json:"authorization_expires_at"`
}

type VerifiedKeyset struct {
	Schema      string
	ActiveKeyID string
	Chain       []string
	Keys        []entitlementguard.VerificationKey
	KeyStates   []VerifiedKeyState
	Payload     []byte
}

type VerifiedKeyState struct {
	Key    entitlementguard.VerificationKey
	Status string
}

func (client *Client) fetchKeyset(ctx context.Context, etag string) (keysetFetch, error) {
	if client == nil || client.baseURL == nil || client.http == nil {
		return keysetFetch{}, ErrInvalidConfiguration
	}
	target := *client.baseURL
	target.Path += "/public/v1/signing-keyset"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return keysetFetch{}, fmt.Errorf("create signing-keyset request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return keysetFetch{}, fmt.Errorf("fetch signing keyset: %w", err)
	}
	defer response.Body.Close()
	responseETag := response.Header.Get("ETag")
	if response.StatusCode == http.StatusNotModified {
		if etag == "" || responseETag != etag {
			return keysetFetch{}, ErrInvalidResponse
		}
		limited, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
		if readErr != nil || len(limited) != 0 {
			return keysetFetch{}, ErrInvalidResponse
		}
		return keysetFetch{ETag: etag, NotModified: true}, nil
	}
	if response.StatusCode != http.StatusOK {
		return keysetFetch{}, decodeHTTPError(response)
	}
	mediaType, _, mediaTypeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if mediaTypeErr != nil || mediaType != "application/json" || err != nil || len(body) == 0 ||
		len(body) > maxResponseBytes || !validKeysetETag(responseETag, body) {
		return keysetFetch{}, ErrInvalidResponse
	}
	return keysetFetch{ETag: responseETag, Body: body}, nil
}

func validKeysetETag(etag string, body []byte) bool {
	digest := sha256.Sum256(body)
	return etag == `"`+base64.RawURLEncoding.EncodeToString(digest[:])+`"`
}

func VerifyPublicKeyset(encoded []byte, pins []entitlementguard.VerificationKey,
	previous *VerifiedKeyset, now time.Time) (*VerifiedKeyset, error) {
	if len(encoded) == 0 || len(encoded) > maxResponseBytes || len(pins) == 0 || now.IsZero() {
		return nil, ErrInvalidKeyset
	}
	var wire publicKeysetWire
	if err := decodeCanonicalJSON(encoded, &wire); err != nil || wire.Schema != publicKeysetSchema ||
		entitlement.ValidateKeyID(wire.ActiveKeyID) != nil || len(wire.Keys) == 0 ||
		wire.Rotations == nil || len(wire.Rotations) != len(wire.Keys)-1 {
		return nil, ErrInvalidKeyset
	}

	pinned := make(map[string]ed25519.PublicKey, len(pins))
	for _, pin := range pins {
		if entitlement.ValidateKeyID(pin.KeyID) != nil || entitlement.ValidateEd25519PublicKey(pin.PublicKey) != nil {
			return nil, ErrInvalidKeyset
		}
		if _, exists := pinned[pin.KeyID]; exists {
			return nil, ErrInvalidKeyset
		}
		pinned[pin.KeyID] = append(ed25519.PublicKey(nil), pin.PublicKey...)
	}

	type decodedKey struct {
		wire        publicKeyWire
		publicKey   ed25519.PublicKey
		notBefore   time.Time
		signUntil   *time.Time
		verifyUntil *time.Time
	}
	decodedKeys := make(map[string]decodedKey, len(wire.Keys))
	activeCount := 0
	for _, item := range wire.Keys {
		publicKey, decodeErr := base64.RawURLEncoding.DecodeString(item.PublicKey)
		fingerprint, fingerprintErr := base64.RawURLEncoding.DecodeString(item.Fingerprint)
		notBefore, timeErr := parseCanonicalTime(item.NotBefore)
		signUntil, signErr := parseOptionalCanonicalTime(item.SignUntil)
		verifyUntil, verifyErr := parseOptionalCanonicalTime(item.VerifyUntil)
		digest := sha256.Sum256(publicKey)
		if entitlement.ValidateKeyID(item.KeyID) != nil || item.Algorithm != entitlement.Algorithm ||
			decodeErr != nil || len(publicKey) != ed25519.PublicKeySize || fingerprintErr != nil ||
			len(fingerprint) != sha256.Size || !bytes.Equal(fingerprint, digest[:]) || timeErr != nil ||
			signErr != nil || verifyErr != nil || (signUntil != nil && !signUntil.After(notBefore)) ||
			(verifyUntil != nil && signUntil != nil && !verifyUntil.After(*signUntil)) ||
			(item.Status != "active" && item.Status != "verify_only" && item.Status != "retired") ||
			entitlement.ValidateEd25519PublicKey(ed25519.PublicKey(publicKey)) != nil {
			return nil, ErrInvalidKeyset
		}
		if pinnedKey, found := pinned[item.KeyID]; found && !bytes.Equal(pinnedKey, publicKey) {
			return nil, ErrInvalidKeyset
		}
		if _, exists := decodedKeys[item.KeyID]; exists {
			return nil, ErrInvalidKeyset
		}
		if item.Status == "active" {
			activeCount++
		}
		decodedKeys[item.KeyID] = decodedKey{wire: item, publicKey: ed25519.PublicKey(publicKey),
			notBefore: notBefore, signUntil: signUntil, verifyUntil: verifyUntil}
	}
	if activeCount != 1 || decodedKeys[wire.ActiveKeyID].wire.Status != "active" {
		return nil, ErrInvalidKeyset
	}

	rotations := make(map[string]publicRotationWire, len(wire.Rotations))
	for _, rotation := range wire.Rotations {
		if entitlement.ValidateKeyID(rotation.NewKeyID) != nil ||
			entitlement.ValidateKeyID(rotation.AuthorizedByKeyID) != nil || rotation.NewKeyID == rotation.AuthorizedByKeyID {
			return nil, ErrInvalidKeyset
		}
		if _, exists := rotations[rotation.NewKeyID]; exists {
			return nil, ErrInvalidKeyset
		}
		rotations[rotation.NewKeyID] = rotation
	}

	reverseChain := make([]string, 0, len(wire.Keys))
	seen := make(map[string]struct{}, len(wire.Keys))
	current := wire.ActiveKeyID
	for {
		if _, duplicate := seen[current]; duplicate {
			return nil, ErrInvalidKeyset
		}
		seen[current] = struct{}{}
		reverseChain = append(reverseChain, current)
		rotation, found := rotations[current]
		if !found {
			break
		}
		current = rotation.AuthorizedByKeyID
		if _, found := decodedKeys[current]; !found {
			return nil, ErrInvalidKeyset
		}
	}
	rootKey, rootPinned := pinned[current]
	if !rootPinned || len(reverseChain) != len(wire.Keys) || !bytes.Equal(rootKey, decodedKeys[current].publicKey) {
		return nil, ErrInvalidKeyset
	}
	chain := make([]string, len(reverseChain))
	for index := range reverseChain {
		chain[len(reverseChain)-1-index] = reverseChain[index]
	}

	policies := make(map[string]entitlementguard.VerificationKey, len(pins)+len(chain))
	for keyID, publicKey := range pinned {
		policies[keyID] = entitlementguard.VerificationKey{KeyID: keyID,
			PublicKey: append(ed25519.PublicKey(nil), publicKey...)}
	}
	projectedPolicies := make(map[string]entitlementguard.VerificationKey, len(chain))
	for _, keyID := range chain {
		decoded := decodedKeys[keyID]
		projectedPolicies[keyID] = entitlementguard.VerificationKey{KeyID: keyID,
			PublicKey: append(ed25519.PublicKey(nil), decoded.publicKey...), NotBefore: decoded.notBefore,
			SignUntil: cloneTime(decoded.signUntil), VerifyUntil: cloneTime(decoded.verifyUntil)}
	}
	for index := 1; index < len(chain); index++ {
		oldKeyID, newKeyID := chain[index-1], chain[index]
		rotation := rotations[newKeyID]
		newKey := decodedKeys[newKeyID]
		oldPolicy := policies[oldKeyID]
		if err := verifyRotation(rotation, oldKeyID, newKey, oldPolicy.PublicKey); err != nil {
			return nil, err
		}
		authorization, _, _ := decodeAuthorization(rotation.AuthorizationDocument)
		notBefore, _ := parseCanonicalTime(authorization.NotBefore)
		signUntil, _ := parseCanonicalTime(authorization.SignUntil)
		verifyUntil, _ := parseOptionalCanonicalTime(authorization.VerifyUntil)
		authorizationExpiresAt, _ := parseCanonicalTime(authorization.AuthorizationExpiresAt)
		if oldPolicy.SignUntil == nil || authorizationExpiresAt.Before(*oldPolicy.SignUntil) {
			oldPolicy.SignUntil = &authorizationExpiresAt
			policies[oldKeyID] = oldPolicy
		}
		oldProjected := projectedPolicies[oldKeyID]
		if oldProjected.SignUntil == nil || authorizationExpiresAt.Before(*oldProjected.SignUntil) {
			oldProjected.SignUntil = cloneTime(&authorizationExpiresAt)
			projectedPolicies[oldKeyID] = oldProjected
		}
		verifiedNewPolicy := entitlementguard.VerificationKey{KeyID: newKeyID,
			PublicKey: append(ed25519.PublicKey(nil), newKey.publicKey...), NotBefore: notBefore,
			SignUntil: &signUntil, VerifyUntil: verifyUntil}
		policies[newKeyID] = cloneVerificationKey(verifiedNewPolicy)
		projectedPolicies[newKeyID] = cloneVerificationKey(verifiedNewPolicy)
	}

	keyStates := make([]VerifiedKeyState, 0, len(chain))
	for _, keyID := range chain {
		keyStates = append(keyStates, VerifiedKeyState{Key: cloneVerificationKey(projectedPolicies[keyID]),
			Status: decodedKeys[keyID].wire.Status})
	}
	keys := make([]entitlementguard.VerificationKey, 0, len(policies))
	for _, pin := range pins {
		if key, found := policies[pin.KeyID]; found {
			if projected, canonical := projectedPolicies[pin.KeyID]; canonical {
				key = projected
			}
			keys = append(keys, key)
			delete(policies, pin.KeyID)
		}
	}
	for _, keyID := range chain {
		if key, found := policies[keyID]; found {
			keys = append(keys, key)
			delete(policies, keyID)
		}
	}
	if len(policies) != 0 {
		return nil, ErrInvalidKeyset
	}
	result := &VerifiedKeyset{Schema: wire.Schema, ActiveKeyID: wire.ActiveKeyID,
		Chain: append([]string(nil), chain...), Keys: keys, KeyStates: keyStates,
		Payload: append([]byte(nil), encoded...)}
	if previous != nil && !keysetExtends(previous, result) {
		return nil, ErrKeysetRollback
	}
	return result, nil
}

func verifyRotation(rotation publicRotationWire, oldKeyID string, newKey struct {
	wire        publicKeyWire
	publicKey   ed25519.PublicKey
	notBefore   time.Time
	signUntil   *time.Time
	verifyUntil *time.Time
}, oldPublicKey ed25519.PublicKey) error {
	if len(oldPublicKey) != ed25519.PublicKeySize || rotation.AuthorizedByKeyID != oldKeyID ||
		rotation.NewKeyID != newKey.wire.KeyID {
		return ErrInvalidKeyset
	}
	rotationID, idErr := uuid.Parse(rotation.RotationID)
	challenge, challengeBytes, challengeErr := decodePoP(rotation.ChallengeDocument)
	authorization, authorizationBytes, authorizationErr := decodeAuthorization(rotation.AuthorizationDocument)
	popSignature, popErr := base64.RawURLEncoding.DecodeString(rotation.PoPSignature)
	authorizationSignature, signatureErr := base64.RawURLEncoding.DecodeString(rotation.AuthorizationSignature)
	popVerifiedAt, popTimeErr := parseCanonicalTime(rotation.PoPVerifiedAt)
	authorizedAt, authorizedTimeErr := parseCanonicalTime(rotation.AuthorizedAt)
	authorizationExpiresAt, expiryErr := parseCanonicalTime(rotation.AuthorizationExpiresAt)
	activatedAt, activationErr := parseCanonicalTime(rotation.ActivatedAt)
	nonce, nonceErr := base64.RawURLEncoding.DecodeString(challenge.Nonce)
	challengeExpiresAt, challengeExpiryErr := parseCanonicalTime(challenge.ChallengeExpiresAt)
	if idErr != nil || rotationID == uuid.Nil || challengeErr != nil || authorizationErr != nil || popErr != nil ||
		len(popSignature) != ed25519.SignatureSize || signatureErr != nil ||
		len(authorizationSignature) != ed25519.SignatureSize || popTimeErr != nil || authorizedTimeErr != nil ||
		expiryErr != nil || activationErr != nil || nonceErr != nil || len(nonce) != 32 || challengeExpiryErr != nil {
		return ErrInvalidKeyset
	}
	authorizedNotBefore, authorizedNotBeforeErr := parseCanonicalTime(authorization.NotBefore)
	authorizedSignUntil, authorizedSignUntilErr := parseCanonicalTime(authorization.SignUntil)
	authorizedVerifyUntil, authorizedVerifyUntilErr := parseOptionalCanonicalTime(authorization.VerifyUntil)
	if challenge.Domain != rotationPoPDomain || challenge.RotationID != rotation.RotationID ||
		challenge.NewKeyID != newKey.wire.KeyID || challenge.PublicKeyFingerprint != newKey.wire.Fingerprint ||
		challenge.NotBefore != authorization.NotBefore || challenge.SignUntil != authorization.SignUntil ||
		!equalOptionalString(challenge.VerifyUntil, authorization.VerifyUntil) ||
		authorization.Domain != rotationAuthorizationDomain || authorization.RotationID != rotation.RotationID ||
		authorization.OldKeyID != oldKeyID || authorization.NewKeyID != newKey.wire.KeyID ||
		authorization.PublicKeyFingerprint != newKey.wire.Fingerprint ||
		authorizedNotBeforeErr != nil || authorizedSignUntilErr != nil || authorizedVerifyUntilErr != nil ||
		!authorizedNotBefore.Equal(newKey.notBefore) || !authorizedSignUntil.After(authorizedNotBefore) ||
		(authorizedVerifyUntil != nil && !authorizedVerifyUntil.After(authorizedSignUntil)) ||
		authorization.AuthorizedAt != rotation.AuthorizedAt ||
		authorization.AuthorizationExpiresAt != rotation.AuthorizationExpiresAt || popVerifiedAt.After(challengeExpiresAt) ||
		!authorizationExpiresAt.After(authorizedAt) || activatedAt.Before(popVerifiedAt) || activatedAt.Before(authorizedAt) ||
		activatedAt.Before(authorizedNotBefore) || activatedAt.After(authorizationExpiresAt) ||
		!ed25519.Verify(newKey.publicKey, challengeBytes, popSignature) ||
		!ed25519.Verify(oldPublicKey, authorizationBytes, authorizationSignature) {
		return ErrInvalidKeyset
	}
	return nil
}

func decodePoP(encoded string) (rotationPoPDocument, []byte, error) {
	var document rotationPoPDocument
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || decodeCanonicalJSON(decoded, &document) != nil {
		return rotationPoPDocument{}, nil, ErrInvalidKeyset
	}
	return document, decoded, nil
}

func decodeAuthorization(encoded string) (rotationAuthorizationDocument, []byte, error) {
	var document rotationAuthorizationDocument
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || decodeCanonicalJSON(decoded, &document) != nil {
		return rotationAuthorizationDocument{}, nil, ErrInvalidKeyset
	}
	return document, decoded, nil
}

func decodeCanonicalJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidKeyset
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalidKeyset
	}
	return nil
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || value != parsed.UTC().Format(time.RFC3339Nano) {
		return time.Time{}, ErrInvalidKeyset
	}
	return parsed.UTC(), nil
}

func parseOptionalCanonicalTime(value *string) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	parsed, err := parseCanonicalTime(*value)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func canonicalTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func equalOptionalString(left, right *string) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func keysetExtends(previous, candidate *VerifiedKeyset) bool {
	if previous == nil || candidate == nil || len(candidate.Chain) < len(previous.Chain) {
		return false
	}
	for index := range previous.Chain {
		if candidate.Chain[index] != previous.Chain[index] {
			return false
		}
	}
	statusOrder := map[string]int{"active": 0, "verify_only": 1, "retired": 2}
	candidateStatuses := make(map[string]string, len(candidate.KeyStates))
	for _, state := range candidate.KeyStates {
		candidateStatuses[state.Key.KeyID] = state.Status
	}
	for _, state := range previous.KeyStates {
		oldOrder, oldValid := statusOrder[state.Status]
		candidateStatus, found := candidateStatuses[state.Key.KeyID]
		newOrder, newValid := statusOrder[candidateStatus]
		if !oldValid || !found || !newValid || newOrder < oldOrder {
			return false
		}
	}
	previousKeys := make(map[string]entitlementguard.VerificationKey, len(previous.Keys))
	for _, key := range previous.Keys {
		previousKeys[key.KeyID] = key
	}
	for _, key := range candidate.Keys {
		old, found := previousKeys[key.KeyID]
		if !found {
			continue
		}
		if !bytes.Equal(old.PublicKey, key.PublicKey) || !old.NotBefore.Equal(key.NotBefore) ||
			!equalTimePointer(old.VerifyUntil, key.VerifyUntil) {
			return false
		}
		if key.KeyID != previous.ActiveKeyID || len(candidate.Chain) == len(previous.Chain) {
			if !equalTimePointer(old.SignUntil, key.SignUntil) {
				return false
			}
		} else if old.SignUntil != nil && (key.SignUntil == nil || key.SignUntil.After(*old.SignUntil)) {
			return false
		}
	}
	return true
}

func equalTimePointer(left, right *time.Time) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && left.Equal(*right))
}

func cloneVerificationKey(key entitlementguard.VerificationKey) entitlementguard.VerificationKey {
	key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
	key.SignUntil = cloneTime(key.SignUntil)
	key.VerifyUntil = cloneTime(key.VerifyUntil)
	return key
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
