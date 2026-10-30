package entitlementsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

type keysetFixture struct {
	body       []byte
	pins       []entitlementguard.VerificationKey
	privateKey map[string]ed25519.PrivateKey
}

type keysetRefreshFunc func(context.Context) error

func (refresh keysetRefreshFunc) Refresh(ctx context.Context) error { return refresh(ctx) }

func TestPublicKeysetChainEstablishesOnlyPinnedCanonicalDescendants(t *testing.T) {
	now := time.Unix(1_850_000_000, 0).UTC()
	fixture := makeKeysetFixture(t, now, "root", "next")
	verified, err := VerifyPublicKeyset(fixture.body, fixture.pins, nil, now)
	if err != nil {
		t.Fatalf("verify keyset: %v", err)
	}
	if verified.ActiveKeyID != "next" || len(verified.Chain) != 2 || verified.Chain[0] != "root" || verified.Chain[1] != "next" {
		t.Fatalf("verified chain = %#v", verified)
	}
	trust, err := entitlementguard.NewTrustStore(fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.ApplyVerifiedKeys(verified.Keys); err != nil {
		t.Fatal(err)
	}
	for _, key := range verified.Keys {
		if key.KeyID == "root" && key.NotBefore.IsZero() {
			t.Fatal("pinned root lost the keyset not-before window")
		}
	}
	installationID := uuid.New()
	rootLease := testLease(now, installationID, 1)
	rootLease.NotBefore = now.Add(-5 * time.Hour).Unix()
	rootLease.ExpiresAt = now.Add(time.Hour).Unix()
	rootLease.GraceUntil = now.Add(2 * time.Hour).Unix()
	rootSigned := mustSignedLease(t, testSigner{"root", fixture.privateKey["root"]}, rootLease)
	if _, err := trust.Verify(rootSigned, entitlement.VerifyOptions{Now: now,
		ExpectedAudience: entitlement.ControlAudience, ExpectedInstallationID: installationID.String()}); err != nil {
		t.Fatalf("overlap root lease rejected: %v", err)
	}
	nextSigned := mustSignedLease(t, testSigner{"next", fixture.privateKey["next"]},
		testLease(now, installationID, 2))
	if _, err := trust.Verify(nextSigned, entitlement.VerifyOptions{Now: now,
		ExpectedAudience: entitlement.ControlAudience, ExpectedInstallationID: installationID.String()}); err != nil {
		t.Fatalf("rotated lease rejected: %v", err)
	}
	artifact := []byte("canonical release artifact manifest")
	artifactSignature := ed25519.Sign(fixture.privateKey["root"], artifact)
	if err := trust.VerifyDetached("root", artifact, artifactSignature, now.Add(-5*time.Hour), now); err != nil {
		t.Fatalf("historical artifact rejected during overlap: %v", err)
	}
	if err := trust.VerifyDetached("root", artifact, artifactSignature, now.Add(30*time.Hour), now); !errors.Is(err, entitlementguard.ErrKeyOutsideWindow) {
		t.Fatalf("old key accepted after signed rotation cutoff: %v", err)
	}

	unknownPublic, _, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	if _, err := VerifyPublicKeyset(fixture.body, []entitlementguard.VerificationKey{{
		KeyID: "unknown-root", PublicKey: unknownPublic,
	}}, nil, now); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("unknown root error = %v", err)
	}

	var tampered publicKeysetWire
	if err := json.Unmarshal(fixture.body, &tampered); err != nil {
		t.Fatal(err)
	}
	signature, _ := base64.RawURLEncoding.DecodeString(tampered.Rotations[0].AuthorizationSignature)
	signature[0] ^= 0xff
	tampered.Rotations[0].AuthorizationSignature = base64.RawURLEncoding.EncodeToString(signature)
	if _, err := VerifyPublicKeyset(mustMarshalKeyset(t, tampered), fixture.pins, nil, now); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("tampered authorization error = %v", err)
	}
	nonCanonical := append([]byte{' '}, fixture.body...)
	if _, err := VerifyPublicKeyset(nonCanonical, fixture.pins, nil, now); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("non-canonical keyset error = %v", err)
	}
}

func TestPublicKeysetExtensionRejectsAncestorReplayAndConflictingIdentity(t *testing.T) {
	now := time.Unix(1_850_100_000, 0).UTC()
	old := makeKeysetFixture(t, now, "root", "middle")
	oldVerified, err := VerifyPublicKeyset(old.body, old.pins, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	newer := extendKeysetFixture(t, now, old, "leaf")
	newVerified, err := VerifyPublicKeyset(newer.body, newer.pins, oldVerified, now)
	if err != nil || newVerified.ActiveKeyID != "leaf" || len(newVerified.Chain) != 3 {
		t.Fatalf("extended keyset = (%#v, %v)", newVerified, err)
	}
	if _, err := VerifyPublicKeyset(old.body, old.pins, newVerified, now); !errors.Is(err, ErrKeysetRollback) {
		t.Fatalf("ancestor replay error = %v", err)
	}
	var conflict publicKeysetWire
	if err := json.Unmarshal(newer.body, &conflict); err != nil {
		t.Fatal(err)
	}
	conflict.Keys[0].PublicKey = conflict.Keys[1].PublicKey
	conflict.Keys[0].Fingerprint = conflict.Keys[1].Fingerprint
	if _, err := VerifyPublicKeyset(mustMarshalKeyset(t, conflict), newer.pins, oldVerified, now); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("conflicting root identity error = %v", err)
	}
}

func TestPublicKeysetRejectsIdentityRotationForgery(t *testing.T) {
	now := time.Unix(1_850_150_000, 0).UTC()
	fixture := makeKeysetFixture(t, now, "root", "next")
	var wire publicKeysetWire
	if err := json.Unmarshal(fixture.body, &wire); err != nil {
		t.Fatal(err)
	}
	identity := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identity[0] = 1
	digest := sha256.Sum256(identity)
	wire.Keys[0].PublicKey = base64.RawURLEncoding.EncodeToString(identity)
	wire.Keys[0].Fingerprint = base64.RawURLEncoding.EncodeToString(digest[:])
	forged := make([]byte, ed25519.SignatureSize)
	forged[0] = 1
	wire.Rotations[0].AuthorizationSignature = base64.RawURLEncoding.EncodeToString(forged)
	pins := []entitlementguard.VerificationKey{{KeyID: "root", PublicKey: identity}}
	if _, err := VerifyPublicKeyset(mustMarshalKeyset(t, wire), pins, nil, now); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("identity rotation forgery error = %v", err)
	}
}

func TestPublicKeysetRejectsInvalidPinAndWirePoints(t *testing.T) {
	now := time.Unix(1_850_160_000, 0).UTC()
	fixture := makeKeysetFixture(t, now, "root", "next")
	identity := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identity[0] = 1
	invalidPins := []entitlementguard.VerificationKey{{KeyID: "root", PublicKey: identity}}
	if _, err := VerifyPublicKeyset(fixture.body, invalidPins, nil, now); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("invalid pin error = %v", err)
	}

	var wire publicKeysetWire
	if err := json.Unmarshal(fixture.body, &wire); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(identity)
	wire.Keys[1].PublicKey = base64.RawURLEncoding.EncodeToString(identity)
	wire.Keys[1].Fingerprint = base64.RawURLEncoding.EncodeToString(digest[:])
	if _, err := VerifyPublicKeyset(mustMarshalKeyset(t, wire), fixture.pins, nil, now); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("invalid wire key error = %v", err)
	}
}

func TestPublicKeysetRejectsBootstrapPinWireKeyIDCollision(t *testing.T) {
	now := time.Unix(1_850_170_000, 0).UTC()
	fixture := makeKeysetFixture(t, now, "root", "next")
	conflictingPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pins := append([]entitlementguard.VerificationKey(nil), fixture.pins...)
	pins = append(pins, entitlementguard.VerificationKey{KeyID: "next", PublicKey: conflictingPublic})
	if _, err := VerifyPublicKeyset(fixture.body, pins, nil, now); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("bootstrap pin collision error = %v", err)
	}
}

func TestVerifiedKeyStatesContainOnlyCanonicalWireKeys(t *testing.T) {
	now := time.Unix(1_850_175_000, 0).UTC()
	fixture := makeKeysetFixture(t, now, "root", "next")
	extraPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pins := append([]entitlementguard.VerificationKey(nil), fixture.pins...)
	pins = append(pins, entitlementguard.VerificationKey{KeyID: "bootstrap-extra", PublicKey: extraPublic})
	verified, err := VerifyPublicKeyset(fixture.body, pins, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.KeyStates) != 2 || verified.KeyStates[0].Key.KeyID != "root" ||
		verified.KeyStates[0].Status != "verify_only" || verified.KeyStates[1].Key.KeyID != "next" ||
		verified.KeyStates[1].Status != "active" {
		t.Fatalf("verified key states = %#v", verified.KeyStates)
	}
	for _, state := range verified.KeyStates {
		if state.Key.KeyID == "bootstrap-extra" {
			t.Fatal("extra bootstrap pin was projected")
		}
	}
	if verified.KeyStates[0].Key.NotBefore.IsZero() || verified.KeyStates[0].Key.SignUntil == nil ||
		verified.KeyStates[1].Key.NotBefore.IsZero() || verified.KeyStates[1].Key.SignUntil == nil {
		t.Fatalf("effective key windows missing: %#v", verified.KeyStates)
	}
}

func TestVerifiedKeyStatesPreserveRetiredWireStatus(t *testing.T) {
	now := time.Unix(1_850_180_000, 0).UTC()
	fixture := makeKeysetFixture(t, now, "root", "next")
	var wire publicKeysetWire
	if err := json.Unmarshal(fixture.body, &wire); err != nil {
		t.Fatal(err)
	}
	wire.Keys[0].Status = "retired"
	verified, err := VerifyPublicKeyset(mustMarshalKeyset(t, wire), fixture.pins, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.KeyStates) != 2 || verified.KeyStates[0].Status != "retired" ||
		verified.KeyStates[1].Status != "active" {
		t.Fatalf("retired key states = %#v", verified.KeyStates)
	}
}

func TestPublicKeysetStatusTransitionsAreMonotonic(t *testing.T) {
	now := time.Unix(1_850_190_000, 0).UTC()
	active := makeKeysetFixture(t, now, "root")
	activeVerified, err := VerifyPublicKeyset(active.body, active.pins, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	verifyOnly := extendKeysetFixture(t, now, active, "next")
	verifyOnlyVerified, err := VerifyPublicKeyset(verifyOnly.body, verifyOnly.pins, activeVerified, now)
	if err != nil {
		t.Fatalf("active to verify_only: %v", err)
	}
	var retiredWire publicKeysetWire
	if err := json.Unmarshal(verifyOnly.body, &retiredWire); err != nil {
		t.Fatal(err)
	}
	retiredWire.Keys[0].Status = "retired"
	retiredBody := mustMarshalKeyset(t, retiredWire)
	retiredVerified, err := VerifyPublicKeyset(retiredBody, verifyOnly.pins, verifyOnlyVerified, now)
	if err != nil {
		t.Fatalf("verify_only to retired: %v", err)
	}
	if _, err := VerifyPublicKeyset(retiredBody, verifyOnly.pins, retiredVerified, now); err != nil {
		t.Fatalf("same retired payload repair: %v", err)
	}
	if _, err := VerifyPublicKeyset(verifyOnly.body, verifyOnly.pins, retiredVerified, now); !errors.Is(err, ErrKeysetRollback) {
		t.Fatalf("retired to verify_only replay error = %v", err)
	}
}

func TestKeysetClientUsesStrongContentETagAndConditionalRequest(t *testing.T) {
	now := time.Unix(1_850_200_000, 0).UTC()
	fixture := makeKeysetFixture(t, now, "root")
	digest := sha256.Sum256(fixture.body)
	etag := `"` + base64.RawURLEncoding.EncodeToString(digest[:]) + `"`
	attempt := 0
	client, err := NewClient("https://license.example.test", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempt++
		if request.URL.Path != "/public/v1/signing-keyset" {
			t.Fatalf("keyset path = %q", request.URL.Path)
		}
		if attempt == 1 {
			return keysetHTTPResponse(http.StatusOK, fixture.body, etag), nil
		}
		if request.Header.Get("If-None-Match") != etag {
			t.Fatalf("If-None-Match = %q", request.Header.Get("If-None-Match"))
		}
		return keysetHTTPResponse(http.StatusNotModified, nil, etag), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.fetchKeyset(context.Background(), "")
	if err != nil || first.ETag != etag || !bytes.Equal(first.Body, fixture.body) {
		t.Fatalf("first keyset fetch = (%#v, %v)", first, err)
	}
	second, err := client.fetchKeyset(context.Background(), etag)
	if err != nil || !second.NotModified || second.ETag != etag {
		t.Fatalf("conditional keyset fetch = (%#v, %v)", second, err)
	}
	badClient, _ := NewClient("https://license.example.test", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return keysetHTTPResponse(http.StatusOK, fixture.body, `"wrong"`), nil
	})})
	if _, err := badClient.fetchKeyset(context.Background(), ""); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("mismatched ETag error = %v", err)
	}
}

func TestSyncRefreshesVerifiedKeysetBeforeAcceptingRotatedLease(t *testing.T) {
	now := time.Unix(1_850_250_000, 0).UTC()
	fixture := makeKeysetFixture(t, now, "root", "next")
	verified, err := VerifyPublicKeyset(fixture.body, fixture.pins, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore(fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	installationID := uuid.New()
	_, installationPrivate := mustKeyPair(t)
	current := mustSignedLease(t, testSigner{"root", fixture.privateKey["root"]}, testLease(now, installationID, 9))
	next := mustSignedLease(t, testSigner{"next", fixture.privateKey["next"]}, testLease(now, installationID, 10))
	store := &memoryStore{current: &current}
	client, err := NewClient("https://license.example.test", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost {
			t.Fatalf("unexpected request method %s", request.Method)
		}
		return jsonResponse(http.StatusOK, string(mustJSON(t, leaseResponse{LeaseID: uuid.New(), SignedLease: next})), nil), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	refreshes := 0
	syncer, err := New(Config{Client: client, Store: store, Trust: trust,
		Keysets: keysetRefreshFunc(func(context.Context) error {
			refreshes++
			if refreshes == 1 {
				return nil
			}
			return trust.ApplyVerifiedKeys(verified.Keys)
		}), InstallationID: installationID, InstallationName: "Rotated control",
		PrivateKey: installationPrivate, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := syncer.SyncOnce(context.Background())
	if err != nil || refreshes != 2 || result.Serial != 10 || len(store.installs) != 1 {
		t.Fatalf("rotated sync result=%#v refreshes=%d installs=%d err=%v", result, refreshes, len(store.installs), err)
	}
}

func makeKeysetFixture(t *testing.T, now time.Time, keyIDs ...string) keysetFixture {
	t.Helper()
	if len(keyIDs) == 0 {
		t.Fatal("keyset fixture requires a root")
	}
	privateKeys := make(map[string]ed25519.PrivateKey, len(keyIDs))
	publicKeys := make(map[string]ed25519.PublicKey, len(keyIDs))
	for _, keyID := range keyIDs {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		privateKeys[keyID], publicKeys[keyID] = privateKey, publicKey
	}
	return buildKeysetFixture(t, now, keyIDs, privateKeys, publicKeys)
}

func extendKeysetFixture(t *testing.T, now time.Time, fixture keysetFixture, newKeyID string) keysetFixture {
	t.Helper()
	var existing publicKeysetWire
	if err := json.Unmarshal(fixture.body, &existing); err != nil {
		t.Fatal(err)
	}
	keyIDs := make([]string, len(existing.Keys), len(existing.Keys)+1)
	privateKeys := make(map[string]ed25519.PrivateKey, len(existing.Keys)+1)
	publicKeys := make(map[string]ed25519.PublicKey, len(existing.Keys)+1)
	for index, key := range existing.Keys {
		keyIDs[index] = key.KeyID
		privateKeys[key.KeyID] = fixture.privateKey[key.KeyID]
		decoded, _ := base64.RawURLEncoding.DecodeString(key.PublicKey)
		publicKeys[key.KeyID] = ed25519.PublicKey(decoded)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyIDs = append(keyIDs, newKeyID)
	privateKeys[newKeyID], publicKeys[newKeyID] = privateKey, publicKey
	return buildKeysetFixture(t, now, keyIDs, privateKeys, publicKeys)
}

func buildKeysetFixture(t *testing.T, now time.Time, keyIDs []string,
	privateKeys map[string]ed25519.PrivateKey, publicKeys map[string]ed25519.PublicKey) keysetFixture {
	t.Helper()
	base := now.Add(-6 * time.Hour)
	wire := publicKeysetWire{Schema: publicKeysetSchema, ActiveKeyID: keyIDs[len(keyIDs)-1],
		Keys: make([]publicKeyWire, 0, len(keyIDs)), Rotations: make([]publicRotationWire, 0, len(keyIDs)-1)}
	for index, keyID := range keyIDs {
		publicKey := publicKeys[keyID]
		fingerprint := sha256.Sum256(publicKey)
		notBefore := base.Add(time.Duration(index) * time.Hour)
		status := "verify_only"
		if index == len(keyIDs)-1 {
			status = "active"
		}
		var signUntil *string
		if index > 0 {
			value := canonicalTime(base.Add(time.Duration(index)*time.Hour + 30*24*time.Hour))
			signUntil = &value
		}
		wire.Keys = append(wire.Keys, publicKeyWire{KeyID: keyID, Algorithm: entitlement.Algorithm,
			PublicKey:   base64.RawURLEncoding.EncodeToString(publicKey),
			Fingerprint: base64.RawURLEncoding.EncodeToString(fingerprint[:]), Status: status,
			NotBefore: canonicalTime(notBefore), SignUntil: signUntil})
	}
	for index := 1; index < len(keyIDs); index++ {
		oldKeyID, newKeyID := keyIDs[index-1], keyIDs[index]
		newKey := wire.Keys[index]
		rotationID := uuid.NewString()
		authorizedAt := base.Add(time.Duration(index)*time.Hour + 5*time.Minute)
		authorizationExpiresAt := authorizedAt.Add(24 * time.Hour)
		challengeExpiresAt := authorizedAt.Add(10 * time.Minute)
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal(err)
		}
		challenge := rotationPoPDocument{Domain: rotationPoPDomain, RotationID: rotationID,
			NewKeyID: newKeyID, PublicKeyFingerprint: newKey.Fingerprint, NotBefore: newKey.NotBefore,
			SignUntil: *newKey.SignUntil, VerifyUntil: newKey.VerifyUntil,
			Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), ChallengeExpiresAt: canonicalTime(challengeExpiresAt)}
		authorization := rotationAuthorizationDocument{Domain: rotationAuthorizationDomain,
			RotationID: rotationID, OldKeyID: oldKeyID, NewKeyID: newKeyID,
			PublicKeyFingerprint: newKey.Fingerprint, NotBefore: newKey.NotBefore, SignUntil: *newKey.SignUntil,
			VerifyUntil: newKey.VerifyUntil, AuthorizedAt: canonicalTime(authorizedAt),
			AuthorizationExpiresAt: canonicalTime(authorizationExpiresAt)}
		challengeBytes, _ := json.Marshal(challenge)
		authorizationBytes, _ := json.Marshal(authorization)
		wire.Rotations = append(wire.Rotations, publicRotationWire{RotationID: rotationID, NewKeyID: newKeyID,
			AuthorizedByKeyID: oldKeyID, ChallengeDocument: base64.RawURLEncoding.EncodeToString(challengeBytes),
			PoPSignature:           base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKeys[newKeyID], challengeBytes)),
			PoPVerifiedAt:          canonicalTime(authorizedAt),
			AuthorizationDocument:  base64.RawURLEncoding.EncodeToString(authorizationBytes),
			AuthorizationSignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKeys[oldKeyID], authorizationBytes)),
			AuthorizedAt:           canonicalTime(authorizedAt), AuthorizationExpiresAt: canonicalTime(authorizationExpiresAt),
			ActivatedAt: canonicalTime(authorizedAt.Add(time.Minute))})
	}
	return keysetFixture{body: mustMarshalKeyset(t, wire),
		pins:       []entitlementguard.VerificationKey{{KeyID: keyIDs[0], PublicKey: publicKeys[keyIDs[0]]}},
		privateKey: privateKeys}
}

func mustMarshalKeyset(t *testing.T, value publicKeysetWire) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func keysetHTTPResponse(status int, body []byte, etag string) *http.Response {
	header := make(http.Header)
	header.Set("ETag", etag)
	if status == http.StatusOK {
		header.Set("Content-Type", "application/json")
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body))}
}
