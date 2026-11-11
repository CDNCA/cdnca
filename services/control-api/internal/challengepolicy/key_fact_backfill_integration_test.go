package challengepolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
)

type failingIssuer struct {
	inner  KeyFactIssuer
	failID uuid.UUID
}

func (issuer failingIssuer) IssueTx(ctx context.Context, tx pgx.Tx, request challengepublication.KeyFactIssueRequest) error {
	if request.PolicyID == issuer.failID {
		return errors.New("injected issuer failure")
	}
	return issuer.inner.IssueTx(ctx, tx, request)
}

// policies created before the key fact writer existed
// have no challenge_key_facts_138 row and cannot publish; the startup
// backfill gives them one, once, and a failing policy does not stop the rest.
func TestBackfillKeyFactsForPreexistingPolicies(t *testing.T) {
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
	// No issuer on the store: this is how policies were created before the fix.
	create := func(actor Actor, scope, site uuid.UUID, host string, enabled bool) uuid.UUID {
		t.Helper()
		result, err := fixture.service.Create(ctx, actor, CreateRequest{
			TargetScopeID: scope, SiteID: site, Host: host, Enabled: enabled,
			Config: validConfig(ModeSlider), WriteMetadata: metadata("bf-" + host),
		})
		if err != nil {
			t.Fatalf("create %s: %v", host, err)
		}
		return result.Policy.ID
	}
	enabledA := create(fixture.ownerA, fixture.tenantA, fixture.siteA, "a.example.test", true)
	offSite := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, "off.example.test")
	disabledA := create(fixture.ownerA, fixture.tenantA, offSite, "off.example.test", true)
	if _, err := fixture.service.SetEnabled(ctx, fixture.ownerA, StateRequest{TargetScopeID: fixture.tenantA,
		ID: disabledA, ExpectedRevision: 1, Enabled: false, WriteMetadata: metadata("bf-off")}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	enabledB := create(fixture.ownerB, fixture.tenantB, fixture.siteB, "b.example.test", true)
	facts := func(id uuid.UUID) int {
		t.Helper()
		var count int
		if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM challenge_key_facts_138 WHERE policy_id=$1 AND role='current' AND active`, id).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if facts(enabledA)+facts(enabledB) != 0 {
		t.Fatal("fixture policies must start without key facts")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// One policy fails: it is logged and counted, the other tenant still gets its fact.
	issued, failed, err := BackfillKeyFacts(ctx, fixture.pool, failingIssuer{inner: issuer, failID: enabledA}, logger)
	if err != nil || issued != 1 || failed != 1 {
		t.Fatalf("first run issued=%d failed=%d err=%v", issued, failed, err)
	}
	if facts(enabledA) != 0 || facts(enabledB) != 1 {
		t.Fatalf("after failing run: A=%d B=%d", facts(enabledA), facts(enabledB))
	}

	// A normal run fills the remaining one; a disabled policy is left alone.
	issued, failed, err = BackfillKeyFacts(ctx, fixture.pool, issuer, logger)
	if err != nil || issued != 1 || failed != 0 {
		t.Fatalf("second run issued=%d failed=%d err=%v", issued, failed, err)
	}
	if facts(enabledA) != 1 || facts(disabledA) != 0 {
		t.Fatalf("after second run: A=%d disabled=%d", facts(enabledA), facts(disabledA))
	}

	// Idempotent: nothing left to do, the stored secret is unchanged.
	var before []byte
	if err := fixture.pool.QueryRow(ctx, `SELECT ciphertext FROM challenge_key_facts_138 WHERE policy_id=$1 AND role='current'`, enabledA).Scan(&before); err != nil {
		t.Fatal(err)
	}
	issued, failed, err = BackfillKeyFacts(ctx, fixture.pool, issuer, logger)
	if err != nil || issued != 0 || failed != 0 {
		t.Fatalf("third run issued=%d failed=%d err=%v", issued, failed, err)
	}
	var after []byte
	if err := fixture.pool.QueryRow(ctx, `SELECT ciphertext FROM challenge_key_facts_138 WHERE policy_id=$1 AND role='current'`, enabledA).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rerun changed the stored key fact")
	}

	// The backfilled fact resolves like one written by Create.
	source, err := challengepublication.NewPostgresKeyFactSource(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := challengepublication.NewFactKeyResolver(source, factCipher,
		challengepublication.NewEd25519FactVerifier(map[string]ed25519.PublicKey{signer.KeyID(): signer.PublicKey()}))
	if err != nil {
		t.Fatal(err)
	}
	var tenantID uuid.UUID
	if err := fixture.pool.QueryRow(ctx, `SELECT tenant_id FROM challenge_policies WHERE id=$1`, enabledA).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	keys, err := resolver.ResolveChallengeKeys(ctx, challengepublication.PublicationSnapshot{
		PolicyID: enabledA, TenantScopeID: fixture.tenantA, TenantID: tenantID, SiteID: fixture.siteA,
		Host: "a.example.test", Revision: 1, KeyReference: "keyref:challenge-2026-07",
	})
	if err != nil || len(keys.Current.Secret) != 32 {
		t.Fatalf("resolve backfilled fact: %v", err)
	}
}
