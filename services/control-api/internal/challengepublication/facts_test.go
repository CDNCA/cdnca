package challengepublication

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"slices"
	"testing"

	"github.com/google/uuid"
)

type keyFactSourceStub struct{ facts []KeyFact }

func (source keyFactSourceStub) LoadChallengeKeyFacts(context.Context, PublicationSnapshot) ([]KeyFact, error) {
	return append([]KeyFact(nil), source.facts...), nil
}

func TestFactKeyResolverBindsCurrentPreviousAndAppReferenceToExactPolicyRevision(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrappingKey := make([]byte, 32)
	for index := range wrappingKey {
		wrappingKey[index] = byte(index + 1)
	}
	cipher, err := NewAESGCMFactCipher("challenge-kek-v1", wrappingKey)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := PublicationSnapshot{
		PolicyID: uuid.New(), TenantScopeID: uuid.New(), TenantID: uuid.New(), SiteID: uuid.New(),
		Host: "challenge.example.test", Revision: 7, KeyReference: "keyref:challenge-current",
		ExternalProvider: &ExternalProviderReference{Provider: "tencent", AppReference: "appref:challenge-app"},
	}
	externalSecret, err := json.Marshal(ExternalCredentialSecret{
		SchemaVersion: ExternalCredentialSchemaVersion, Provider: "tencent", AppID: "2060000000",
		Secret: []byte("tencent-controlled-secret-0001"), Environment: "production",
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := []KeyFact{
		newSignedKeyFact(t, cipher, privateKey, snapshot, KeyRoleCurrent, snapshot.KeyReference, "current-v7", slices.Repeat([]byte{0x41}, 32)),
		newSignedKeyFact(t, cipher, privateKey, snapshot, KeyRolePrevious, "keyref:challenge-previous", "previous-v6", slices.Repeat([]byte{0x42}, 32)),
		newSignedKeyFact(t, cipher, privateKey, snapshot, KeyRoleApp, snapshot.ExternalProvider.AppReference, "tencent-app-v1", externalSecret),
	}
	resolver, err := NewFactKeyResolver(keyFactSourceStub{facts: facts}, cipher,
		NewEd25519FactVerifier(map[string]ed25519.PublicKey{"challenge-sign-v1": publicKey}))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveChallengeKeys(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("ResolveChallengeKeys() error = %v", err)
	}
	if resolved.Current.KeyID != "current-v7" || resolved.Previous == nil || resolved.Previous.KeyID != "previous-v6" ||
		resolved.ExternalCredential == nil || resolved.ExternalCredential.Provider != "tencent" ||
		resolved.ExternalCredential.AppID != "2060000000" || resolved.ExternalCredential.Environment != "production" ||
		string(resolved.ExternalCredential.Secret) != "tencent-controlled-secret-0001" {
		t.Fatalf("resolved facts = %+v", resolved)
	}
}

func TestFactKeyResolverRejectsExternalCredentialProviderAndDocumentTamper(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	cipher, _ := NewAESGCMFactCipher("challenge-kek-v1", slices.Repeat([]byte{0x31}, 32))
	snapshot := PublicationSnapshot{PolicyID: uuid.New(), TenantScopeID: uuid.New(), TenantID: uuid.New(),
		SiteID: uuid.New(), Host: "challenge.example.test", Revision: 7, KeyReference: "keyref:challenge-current",
		ExternalProvider: &ExternalProviderReference{Provider: "tencent", AppReference: "appref:challenge-app"}}
	current := newSignedKeyFact(t, cipher, privateKey, snapshot, KeyRoleCurrent, snapshot.KeyReference,
		"current-v7", slices.Repeat([]byte{0x41}, 32))
	for name, plaintext := range map[string][]byte{
		"provider": []byte(`{"schema_version":"cdnca.challenge.external-credential/v1","provider":"geetest-v4","app_id":"captcha-id","secret":"c2VjcmV0LXNlY3JldC1zZWNyZXQ=","environment":"production"}`),
		"unknown":  []byte(`{"schema_version":"cdnca.challenge.external-credential/v1","provider":"tencent","app_id":"2060000000","secret":"c2VjcmV0LXNlY3JldC1zZWNyZXQ=","environment":"production","future":true}`),
	} {
		t.Run(name, func(t *testing.T) {
			app := newSignedKeyFact(t, cipher, privateKey, snapshot, KeyRoleApp,
				snapshot.ExternalProvider.AppReference, "tencent-app-v1", plaintext)
			resolver, err := NewFactKeyResolver(keyFactSourceStub{facts: []KeyFact{current, app}}, cipher,
				NewEd25519FactVerifier(map[string]ed25519.PublicKey{"challenge-sign-v1": publicKey}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.ResolveChallengeKeys(context.Background(), snapshot); err != ErrKeyUnavailable {
				t.Fatalf("ResolveChallengeKeys() error = %v", err)
			}
		})
	}
}

func TestFactKeyResolverRejectsCrossSiteTamperAndConflictingRoles(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	cipher, _ := NewAESGCMFactCipher("challenge-kek-v1", slices.Repeat([]byte{0x31}, 32))
	snapshot := PublicationSnapshot{PolicyID: uuid.New(), TenantScopeID: uuid.New(), TenantID: uuid.New(),
		SiteID: uuid.New(), Host: "challenge.example.test", Revision: 7, KeyReference: "keyref:challenge-current"}
	base := newSignedKeyFact(t, cipher, privateKey, snapshot, KeyRoleCurrent, snapshot.KeyReference,
		"current-v7", slices.Repeat([]byte{0x41}, 32))
	verifier := NewEd25519FactVerifier(map[string]ed25519.PublicKey{"challenge-sign-v1": publicKey})
	for name, mutate := range map[string]func([]KeyFact) []KeyFact{
		"cross site":        func(facts []KeyFact) []KeyFact { facts[0].SiteID = uuid.New(); return facts },
		"wrong revision":    func(facts []KeyFact) []KeyFact { facts[0].PolicyRevision++; return facts },
		"ciphertext tamper": func(facts []KeyFact) []KeyFact { facts[0].Ciphertext[0] ^= 1; return facts },
		"duplicate current": func(facts []KeyFact) []KeyFact { return append(facts, facts[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			facts := []KeyFact{cloneKeyFact(base)}
			facts = mutate(facts)
			resolver, err := NewFactKeyResolver(keyFactSourceStub{facts: facts}, cipher, verifier)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.ResolveChallengeKeys(context.Background(), snapshot); err != ErrKeyUnavailable {
				t.Fatalf("ResolveChallengeKeys() error = %v, want %v", err, ErrKeyUnavailable)
			}
		})
	}
}

func newSignedKeyFact(t *testing.T, factCipher *AESGCMFactCipher, privateKey ed25519.PrivateKey,
	snapshot PublicationSnapshot, role, reference, materialKeyID string, plaintext []byte) KeyFact {
	t.Helper()
	fact := KeyFact{TenantScopeID: snapshot.TenantScopeID, TenantID: snapshot.TenantID, SiteID: snapshot.SiteID,
		Host: snapshot.Host, PolicyID: snapshot.PolicyID, PolicyRevision: snapshot.Revision, Role: role,
		Reference: reference, MaterialKeyID: materialKeyID, WrappingKeyID: factCipher.KeyID(), SigningKeyID: "challenge-sign-v1"}
	aad, err := challengeKeyFactAAD(fact)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(factCipher.key)
	aead, _ := cipher.NewGCM(block)
	nonce := slices.Repeat([]byte{byte(len(reference))}, aead.NonceSize())
	fact.Ciphertext = append(nonce, aead.Seal(nil, nonce, plaintext, aad)...)
	fact.Signature = ed25519.Sign(privateKey, challengeKeyFactMessage(aad, fact.Ciphertext))
	return fact
}

func cloneKeyFact(fact KeyFact) KeyFact {
	fact.Ciphertext = slices.Clone(fact.Ciphertext)
	fact.Signature = slices.Clone(fact.Signature)
	return fact
}
