package challengepublication

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFactWriterPersistsResolverCompatibleRotationAtomically(t *testing.T) {
	t.Parallel()
	fixture := newFactWriterFixture(t)
	request := fixture.request()

	result, err := fixture.writer.Write(t.Context(), request)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if result.Replayed || result.FactCount != 3 || len(fixture.store.facts) != 3 {
		t.Fatalf("Write() result = %#v, persisted = %d", result, len(fixture.store.facts))
	}
	for _, fact := range fixture.store.facts {
		if fact.CreatedByScopeID != request.ActorScopeID || fact.CreatedByUserID != request.ActorUserID ||
			fact.TenantScopeID != request.TenantScopeID || fact.TenantID != request.TenantID ||
			fact.SiteID != request.SiteID || fact.Host != request.Host || fact.PolicyID != request.PolicyID ||
			fact.PolicyRevision != request.PolicyRevision || bytes.Contains(fact.Ciphertext, request.Materials[0].Plaintext) ||
			len(fact.Signature) != ed25519.SignatureSize {
			t.Fatalf("persisted fact lost scope/provenance or plaintext escaped: %#v", fact)
		}
	}

	snapshot := PublicationSnapshot{
		TenantScopeID: request.TenantScopeID, TenantID: request.TenantID, SiteID: request.SiteID,
		Host: request.Host, PolicyID: request.PolicyID, Revision: request.PolicyRevision,
		KeyReference:     "keyref:current-v2",
		ExternalProvider: &ExternalProviderReference{Provider: "geetest-v4", AppReference: "appref:geetest-primary"},
	}
	resolver, err := NewFactKeyResolver(factSourceStub{facts: fixture.store.keyFacts()}, fixture.cipher,
		NewEd25519FactVerifier(map[string]ed25519.PublicKey{fixture.signer.KeyID(): fixture.signer.PublicKey()}))
	if err != nil {
		t.Fatalf("NewFactKeyResolver() error = %v", err)
	}
	resolved, err := resolver.ResolveChallengeKeys(t.Context(), snapshot)
	if err != nil {
		t.Fatalf("ResolveChallengeKeys() error = %v", err)
	}
	defer clearResolvedKeys(&resolved)
	if !bytes.Equal(resolved.Current.Secret, request.Materials[0].Plaintext) || resolved.Previous == nil ||
		!bytes.Equal(resolved.Previous.Secret, request.Materials[1].Plaintext) ||
		resolved.ExternalCredential == nil || resolved.ExternalCredential.AppID != "app-primary" ||
		!bytes.Equal(resolved.ExternalCredential.Secret, []byte("external-secret-material")) {
		t.Fatalf("resolver result did not preserve current/previous/app roles: %#v", resolved)
	}
}

func TestFactWriterExactReplayAndConflict(t *testing.T) {
	t.Parallel()
	fixture := newFactWriterFixture(t)
	request := fixture.request()
	if _, err := fixture.writer.Write(t.Context(), request); err != nil {
		t.Fatalf("initial Write() error = %v", err)
	}
	original := fixture.store.cloneFacts()

	replayed, err := fixture.writer.Write(t.Context(), request)
	if err != nil || !replayed.Replayed || replayed.FactCount != 3 {
		t.Fatalf("replay Write() = %#v, %v", replayed, err)
	}
	if fixture.store.insertCalls != 3 || !equalStoredFacts(original, fixture.store.facts) {
		t.Fatal("exact replay mutated durable facts")
	}

	conflict := cloneFactWriteRequest(request)
	conflict.Materials[0].Plaintext[0] ^= 0xff
	if _, err := fixture.writer.Write(t.Context(), conflict); !errors.Is(err, ErrFactWriteConflict) {
		t.Fatalf("different-payload replay error = %v, want %v", err, ErrFactWriteConflict)
	}
	if fixture.store.insertCalls != 3 || !equalStoredFacts(original, fixture.store.facts) {
		t.Fatal("conflicting replay mutated durable facts")
	}
}

func TestFactWriterRejectsInvalidFactsBeforeTransaction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*FactWriteRequest)
	}{
		{name: "noncanonical host", mutate: func(r *FactWriteRequest) { r.Host = "Challenge.Example.com" }},
		{name: "missing actor scope", mutate: func(r *FactWriteRequest) { r.ActorScopeID = uuid.Nil }},
		{name: "duplicate role", mutate: func(r *FactWriteRequest) { r.Materials[1].Role = KeyRoleCurrent }},
		{name: "unknown role", mutate: func(r *FactWriteRequest) { r.Materials[1].Role = "backup" }},
		{name: "previous aliases current", mutate: func(r *FactWriteRequest) { r.Materials[1].Reference = r.Materials[0].Reference }},
		{name: "invalid app payload", mutate: func(r *FactWriteRequest) { r.Materials[2].Plaintext = []byte(`{"provider":"geetest-v4"}`) }},
		{name: "missing current", mutate: func(r *FactWriteRequest) { r.Materials = r.Materials[1:] }},
		{name: "duplicate material id", mutate: func(r *FactWriteRequest) { r.Materials[1].MaterialKeyID = r.Materials[0].MaterialKeyID }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFactWriterFixture(t)
			request := fixture.request()
			test.mutate(&request)
			if _, err := fixture.writer.Write(t.Context(), request); !errors.Is(err, ErrInvalidFactWrite) {
				t.Fatalf("Write() error = %v, want %v", err, ErrInvalidFactWrite)
			}
			if fixture.store.transactions != 0 || len(fixture.store.facts) != 0 {
				t.Fatal("invalid request reached durable transaction")
			}
		})
	}
}

func TestFactWriterFailureAndCancellationLeaveNoPartialFacts(t *testing.T) {
	t.Parallel()
	t.Run("second insert", func(t *testing.T) {
		fixture := newFactWriterFixture(t)
		fixture.store.failInsertAt = 2
		if _, err := fixture.writer.Write(t.Context(), fixture.request()); !errors.Is(err, errFactStoreTest) {
			t.Fatalf("Write() error = %v, want injected DB error", err)
		}
		if len(fixture.store.facts) != 0 || !fixture.store.rolledBack {
			t.Fatal("failed transaction retained a partial fact")
		}
	})
	t.Run("commit", func(t *testing.T) {
		fixture := newFactWriterFixture(t)
		fixture.store.failCommit = true
		if _, err := fixture.writer.Write(t.Context(), fixture.request()); !errors.Is(err, errFactStoreTest) {
			t.Fatalf("Write() error = %v, want injected commit error", err)
		}
		if len(fixture.store.facts) != 0 {
			t.Fatal("failed commit retained facts")
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		fixture := newFactWriterFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := fixture.writer.Write(ctx, fixture.request()); !errors.Is(err, context.Canceled) {
			t.Fatalf("Write() error = %v, want context cancellation", err)
		}
		if fixture.store.transactions != 0 || len(fixture.store.facts) != 0 {
			t.Fatal("cancelled write opened or mutated a transaction")
		}
	})
}

func TestFactWriterAcceptsPlatformActorAndVaultReferences(t *testing.T) {
	t.Parallel()
	fixture := newFactWriterFixture(t)
	request := fixture.request()
	request.ActorScopeID = uuid.New()
	request.Materials[0].Reference = "vault:challenge/current-v2"
	request.Materials[1].Reference = "kms:challenge/current-v1"
	fixture.store.policyKeyReference = request.Materials[0].Reference
	if _, err := fixture.writer.Write(t.Context(), request); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	for _, fact := range fixture.store.facts {
		if fact.CreatedByScopeID != request.ActorScopeID {
			t.Fatal("platform actor provenance was not retained")
		}
	}
}

func TestFactWriterRejectsPolicyKeyMismatchBeforeInsert(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*FactWriteRequest)
	}{
		{name: "missing required app", mutate: func(request *FactWriteRequest) { request.Materials = request.Materials[:2] }},
		{name: "provider mismatch", mutate: func(request *FactWriteRequest) {
			var credential ExternalCredentialSecret
			_ = json.Unmarshal(request.Materials[2].Plaintext, &credential)
			credential.Provider = "tencent"
			request.Materials[2].Plaintext, _ = json.Marshal(credential)
			clear(credential.Secret)
		}},
		{name: "current reference mismatch", mutate: func(request *FactWriteRequest) {
			request.Materials[0].Reference = "kms:challenge/unbound"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFactWriterFixture(t)
			request := fixture.request()
			test.mutate(&request)
			if _, err := fixture.writer.Write(t.Context(), request); !errors.Is(err, ErrInvalidFactWrite) {
				t.Fatalf("Write() error = %v, want %v", err, ErrInvalidFactWrite)
			}
			if fixture.store.insertCalls != 0 || len(fixture.store.facts) != 0 {
				t.Fatal("policy mismatch reached an INSERT")
			}
		})
	}
}

func TestProductionFactAdapters(t *testing.T) {
	t.Parallel()
	baseCipher, err := NewAESGCMFactCipher("challenge-wrap-1", bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatalf("NewAESGCMFactCipher() error = %v", err)
	}
	nonce := bytes.Repeat([]byte{0x61}, baseCipher.aead.NonceSize())
	writerCipher, err := newAESGCMFactWriterCipher(baseCipher, bytes.NewReader(nonce))
	if err != nil {
		t.Fatalf("newAESGCMFactWriterCipher() error = %v", err)
	}
	plaintext, aad := []byte("production-adapter-secret"), []byte("bound-aad")
	ciphertext, err := writerCipher.EncryptBound(t.Context(), plaintext, aad)
	if err != nil {
		t.Fatalf("EncryptBound() error = %v", err)
	}
	if !bytes.Equal(ciphertext[:len(nonce)], nonce) || bytes.Contains(ciphertext, plaintext) {
		t.Fatal("writer cipher did not use the injected nonce or exposed plaintext")
	}
	decrypted, err := writerCipher.DecryptBound(writerCipher.KeyID(), ciphertext, aad)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("DecryptBound() = %q, %v", decrypted, err)
	}
	clear(decrypted)

	_, privateKey, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x62}, 64)))
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	artifactSigner := &factSignerStub{keyID: "challenge-signing-1", privateKey: privateKey}
	factSigner, err := NewArtifactFactSigner(artifactSigner)
	if err != nil {
		t.Fatalf("NewArtifactFactSigner() error = %v", err)
	}
	message := []byte("canonical-fact-message")
	signature, err := factSigner.Sign(t.Context(), message)
	if err != nil || factSigner.KeyID() != artifactSigner.keyID ||
		!ed25519.Verify(factSigner.PublicKey(), message, signature) {
		t.Fatalf("artifact signer adapter produced an invalid signature: %v", err)
	}
}

type factWriterFixture struct {
	writer *FactWriter
	store  *factStoreStub
	cipher *factCipherStub
	signer *factSignerStub
	ids    []uuid.UUID
}

func newFactWriterFixture(t *testing.T) *factWriterFixture {
	t.Helper()
	store := &factStoreStub{}
	cipher := newFactCipherStub(t)
	_, privateKey, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)))
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer := &factSignerStub{keyID: "challenge-signing-1", privateKey: privateKey}
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	writer, err := newFactWriter(store.run, cipher, signer, func() time.Time {
		return time.Date(2026, 8, 8, 1, 2, 3, 0, time.UTC)
	}, func() (uuid.UUID, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	})
	if err != nil {
		t.Fatalf("newFactWriter() error = %v", err)
	}
	return &factWriterFixture{writer: writer, store: store, cipher: cipher, signer: signer, ids: ids}
}

func (fixture *factWriterFixture) request() FactWriteRequest {
	tenantScopeID, tenantID, siteID, policyID, actorUserID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	app, _ := json.Marshal(ExternalCredentialSecret{SchemaVersion: ExternalCredentialSchemaVersion,
		Provider: "geetest-v4", AppID: "app-primary", Secret: []byte("external-secret-material"), Environment: "production"})
	request := FactWriteRequest{
		TenantScopeID: tenantScopeID, TenantID: tenantID, SiteID: siteID, Host: "challenge.example.com",
		PolicyID: policyID, PolicyRevision: 7, ActorScopeID: tenantScopeID, ActorUserID: actorUserID,
		Materials: []FactMaterial{
			{Role: KeyRoleCurrent, Reference: "keyref:current-v2", MaterialKeyID: "challenge-current-v2", Plaintext: bytes.Repeat([]byte{0x11}, 32)},
			{Role: KeyRolePrevious, Reference: "keyref:current-v1", MaterialKeyID: "challenge-current-v1", Plaintext: bytes.Repeat([]byte{0x22}, 32)},
			{Role: KeyRoleApp, Reference: "appref:geetest-primary", MaterialKeyID: "geetest-app-v1", Plaintext: app},
		},
	}
	fixture.store.policyKeyReference = request.Materials[0].Reference
	fixture.store.policyExternalProvider = "geetest-v4"
	fixture.store.policyExternalAppReference = request.Materials[2].Reference
	return request
}

type factCipherStub struct {
	aead cipher.AEAD
}

func newFactCipherStub(t *testing.T) *factCipherStub {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &factCipherStub{aead: aead}
}

func (*factCipherStub) KeyID() string { return "challenge-wrap-1" }

func (cipherStub *factCipherStub) EncryptBound(_ context.Context, plaintext, aad []byte) ([]byte, error) {
	nonce := bytes.Repeat([]byte{0x7a}, cipherStub.aead.NonceSize())
	return cipherStub.aead.Seal(slices.Clone(nonce), nonce, plaintext, aad), nil
}

func (cipherStub *factCipherStub) DecryptBound(keyID string, ciphertext, aad []byte) ([]byte, error) {
	if keyID != cipherStub.KeyID() || len(ciphertext) <= cipherStub.aead.NonceSize() {
		return nil, ErrKeyUnavailable
	}
	return cipherStub.aead.Open(nil, ciphertext[:cipherStub.aead.NonceSize()], ciphertext[cipherStub.aead.NonceSize():], aad)
}

type factSignerStub struct {
	keyID      string
	privateKey ed25519.PrivateKey
}

func (signer *factSignerStub) KeyID() string { return signer.keyID }
func (signer *factSignerStub) PublicKey() ed25519.PublicKey {
	return signer.privateKey.Public().(ed25519.PublicKey)
}
func (signer *factSignerStub) Sign(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(signer.privateKey, message), nil
}
func (signer *factSignerStub) ArtifactSigningKeyID() string { return signer.KeyID() }
func (signer *factSignerStub) ArtifactSigningPublicKey() ed25519.PublicKey {
	return signer.PublicKey()
}
func (signer *factSignerStub) SignArtifact(ctx context.Context, message []byte) ([]byte, error) {
	return signer.Sign(ctx, message)
}

type factSourceStub struct{ facts []KeyFact }

func (source factSourceStub) LoadChallengeKeyFacts(context.Context, PublicationSnapshot) ([]KeyFact, error) {
	return slices.Clone(source.facts), nil
}

var errFactStoreTest = errors.New("fact store test failure")

type factStoreStub struct {
	facts                      []storedKeyFact
	transactions               int
	insertCalls                int
	failInsertAt               int
	failCommit                 bool
	rolledBack                 bool
	policyKeyReference         string
	policyExternalProvider     string
	policyExternalAppReference string
}

func (store *factStoreStub) run(ctx context.Context, operation func(factWriteTransaction) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.transactions++
	working := store.cloneFacts()
	tx := &factTransactionStub{store: store, working: &working}
	if err := operation(tx); err != nil {
		store.rolledBack = true
		return err
	}
	if store.failCommit {
		store.rolledBack = true
		return errFactStoreTest
	}
	store.facts = working
	return nil
}

func (store *factStoreStub) cloneFacts() []storedKeyFact {
	result := make([]storedKeyFact, len(store.facts))
	for index := range store.facts {
		result[index] = cloneStoredKeyFact(store.facts[index])
	}
	return result
}

func (store *factStoreStub) keyFacts() []KeyFact {
	result := make([]KeyFact, len(store.facts))
	for index, stored := range store.facts {
		result[index] = stored.KeyFact
		result[index].Ciphertext = slices.Clone(stored.Ciphertext)
		result[index].Signature = slices.Clone(stored.Signature)
	}
	return result
}

type factTransactionStub struct {
	store   *factStoreStub
	working *[]storedKeyFact
}

func (tx *factTransactionStub) LockScope(_ context.Context, request FactWriteRequest) error {
	current, provider, appReference := requestedPolicyKeys(request)
	if current != tx.store.policyKeyReference || provider == nil || *provider != tx.store.policyExternalProvider ||
		appReference == nil || *appReference != tx.store.policyExternalAppReference {
		return ErrInvalidFactWrite
	}
	return nil
}

func (tx *factTransactionStub) LoadPolicyFacts(_ context.Context, policyID uuid.UUID, revision int64) ([]storedKeyFact, error) {
	var result []storedKeyFact
	for _, fact := range *tx.working {
		if fact.PolicyID == policyID && fact.PolicyRevision == revision {
			result = append(result, cloneStoredKeyFact(fact))
		}
	}
	return result, nil
}

func (tx *factTransactionStub) InsertFact(ctx context.Context, fact storedKeyFact) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx.store.insertCalls++
	if tx.store.failInsertAt > 0 && tx.store.insertCalls == tx.store.failInsertAt {
		return errFactStoreTest
	}
	*tx.working = append(*tx.working, cloneStoredKeyFact(fact))
	return nil
}

func cloneFactWriteRequest(request FactWriteRequest) FactWriteRequest {
	request.Materials = append([]FactMaterial(nil), request.Materials...)
	for index := range request.Materials {
		request.Materials[index].Plaintext = slices.Clone(request.Materials[index].Plaintext)
	}
	return request
}

func cloneStoredKeyFact(fact storedKeyFact) storedKeyFact {
	fact.Ciphertext = slices.Clone(fact.Ciphertext)
	fact.Signature = slices.Clone(fact.Signature)
	return fact
}

func equalStoredFacts(left, right []storedKeyFact) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].ID != right[index].ID || left[index].KeyFact.TenantScopeID != right[index].KeyFact.TenantScopeID ||
			left[index].KeyFact.TenantID != right[index].KeyFact.TenantID || left[index].KeyFact.SiteID != right[index].KeyFact.SiteID ||
			left[index].KeyFact.Host != right[index].KeyFact.Host || left[index].KeyFact.PolicyID != right[index].KeyFact.PolicyID ||
			left[index].KeyFact.PolicyRevision != right[index].KeyFact.PolicyRevision || left[index].KeyFact.Role != right[index].KeyFact.Role ||
			left[index].KeyFact.Reference != right[index].KeyFact.Reference || left[index].KeyFact.MaterialKeyID != right[index].KeyFact.MaterialKeyID ||
			left[index].KeyFact.WrappingKeyID != right[index].KeyFact.WrappingKeyID || left[index].KeyFact.SigningKeyID != right[index].KeyFact.SigningKeyID ||
			!bytes.Equal(left[index].Ciphertext, right[index].Ciphertext) || !bytes.Equal(left[index].Signature, right[index].Signature) ||
			left[index].CreatedByScopeID != right[index].CreatedByScopeID || left[index].CreatedByUserID != right[index].CreatedByUserID ||
			!left[index].CreatedAt.Equal(right[index].CreatedAt) {
			return false
		}
	}
	return true
}
