package challengepolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"

	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
)

type testFactSigner struct {
	key ed25519.PrivateKey
}

func (signer testFactSigner) KeyID() string { return "test-fact-signer" }
func (signer testFactSigner) PublicKey() ed25519.PublicKey {
	return signer.key.Public().(ed25519.PublicKey)
}
func (signer testFactSigner) Sign(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(signer.key, message), nil
}

// challenge_key_facts_138 had no production writer, so no policy
// could publish. Creating or editing an enabled policy writes its HMAC key
// fact in the revision's transaction, resolvable by the production resolver.
func TestChallengePolicyWritesResolvableKeyFacts(t *testing.T) {
	ctx := context.Background()
	fixture := newFixture(t, allowGate())
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := testFactSigner{key: private}
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO artifact_signing_keys(id,algorithm,public_key,created_at) VALUES($1,'ed25519',$2,$3)`,
		signer.KeyID(), []byte(signer.PublicKey()), fixture.now); err != nil {
		t.Fatal(err)
	}
	factCipher, err := challengepublication.NewAESGCMFactCipher("test-kek", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	writerCipher, err := challengepublication.NewAESGCMFactWriterCipher(factCipher)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := challengepublication.NewKeyFactIssuer(writerCipher, signer)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.store.UseKeyFactIssuer(issuer)
	source, err := challengepublication.NewPostgresKeyFactSource(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := challengepublication.NewFactKeyResolver(source, factCipher,
		challengepublication.NewEd25519FactVerifier(map[string]ed25519.PublicKey{signer.KeyID(): signer.PublicKey()}))
	if err != nil {
		t.Fatal(err)
	}
	var policyID, tenantID uuid.UUID
	resolve := func(revision int64, reference string) challengepublication.ResolvedKeys {
		t.Helper()
		keys, err := resolver.ResolveChallengeKeys(ctx, challengepublication.PublicationSnapshot{
			PolicyID: policyID, TenantScopeID: fixture.tenantA, TenantID: tenantID,
			SiteID: fixture.siteA, Host: "a.example.test", Revision: revision, KeyReference: reference,
		})
		if err != nil {
			t.Fatalf("resolve revision %d: %v", revision, err)
		}
		return keys
	}
	created, err := fixture.service.Create(ctx, fixture.ownerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Host: "a.example.test", Enabled: true,
		Config: validConfig(ModeSlider), WriteMetadata: metadata("key-create"),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := fixture.pool.QueryRow(ctx, `SELECT tenant_id FROM challenge_policy_revisions WHERE policy_id=$1 AND revision=1`, created.Policy.ID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	policyID = created.Policy.ID
	first := resolve(1, "keyref:challenge-2026-07")
	if len(first.Current.Secret) != 32 || first.Previous != nil {
		t.Fatalf("revision 1 keys = %d bytes, previous %v", len(first.Current.Secret), first.Previous)
	}

	config := validConfig(ModeSlider)
	config.Priority = 11
	updated, err := fixture.service.Update(ctx, fixture.ownerA, UpdateRequest{
		TargetScopeID: fixture.tenantA, ID: created.Policy.ID, ExpectedRevision: 1, Config: config, WriteMetadata: metadata("key-edit"),
	})
	if err != nil || updated.Policy.Revision != 2 {
		t.Fatalf("edit: %v", err)
	}
	second := resolve(2, "keyref:challenge-2026-07")
	if !bytes.Equal(first.Current.Secret, second.Current.Secret) || first.Current.KeyID != second.Current.KeyID {
		t.Fatal("an edit with the same key reference must keep the secret")
	}

	config.KeyReference = "keyref:challenge-rotated"
	if _, err := fixture.service.Update(ctx, fixture.ownerA, UpdateRequest{
		TargetScopeID: fixture.tenantA, ID: created.Policy.ID, ExpectedRevision: 2, Config: config, WriteMetadata: metadata("key-rotate"),
	}); err != nil {
		t.Fatalf("rotate reference: %v", err)
	}
	third := resolve(3, "keyref:challenge-rotated")
	if bytes.Equal(third.Current.Secret, second.Current.Secret) || third.Previous == nil ||
		!bytes.Equal(third.Previous.Secret, second.Current.Secret) {
		t.Fatal("a changed key reference must mint a new secret and keep the old one as previous")
	}
}
