package originauthcontrol

import (
	"bytes"
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

// fix-mktsiteconf5: the subscriber reads a site's live rule with its
// credential (SiteRulesSystem), the leaf writes it on its own site under its
// own keyring as the tenant owner (SetSiteSystem): verified without the
// cloud verifier, published, audited with actor kind system, nothing in
// clear at rest; the same write again changes nothing; prune deletes a rule
// whose endpoint changes.
func TestSiteSystemReadWriteRoundTrip(t *testing.T) {
	fixture := newOriginAuthFixture(t)
	ctx := t.Context()
	subscriber := fixtureService(t, fixture, "old", CredentialVerifierFunc(func(context.Context, VerificationRequest) error { return nil }), audit.New(fixture.pool))
	credential := createCredential(t, subscriber, fixture.owner, "subscriber-key", "mk5-create")
	verified, err := subscriber.VerifyCredential(ctx, fixture.owner, mutationRequest(fixture.tenantScopeID,
		credential.ID, credential.Revision, "mk5-verify"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := subscriber.CreateRule(ctx, fixture.owner, CreateRuleRequest{TargetScopeID: fixture.tenantScopeID,
		SiteID: fixture.siteA, SourcePosition: 1, Enabled: true,
		Config: s3RuleConfig(verified.Credential.ID, verified.Credential.Revision), WriteMetadata: metadata("mk5-rule")}); err != nil {
		t.Fatal(err)
	}
	rules, err := subscriber.SiteRulesSystem(ctx, fixture.siteA)
	if err != nil || len(rules) != 1 || rules[0].Current.Secret.SecretAccessKey != "SK-subscriber-key" ||
		rules[0].Current.RevisionRef != verified.Credential.RevisionRef {
		t.Fatalf("SiteRulesSystem = %+v, %v", rules, err)
	}
	// The verified revision's ciphertext was sealed under the create revision.
	if rules[0].Current.Seed == ([32]byte{}) {
		t.Fatal("no seed")
	}

	// The leaf: another keyring, the second site stands in for its market site.
	leaf := fixtureService(t, fixture, "new", nil, audit.New(fixture.pool))
	if err := leaf.ValidateSiteRule(rules[0]); err != nil {
		t.Fatalf("ValidateSiteRule = %v", err)
	}
	write := SystemSiteWrite{ScopeID: fixture.tenantScopeID, SiteID: fixture.siteB, OwnerUserID: fixture.owner.UserID,
		Rules: rules, RequestID: "market-auth-set-1", ActorRef: "job:market_leaf_sync"}
	if changed, err := leaf.SetSiteSystem(ctx, write); err != nil || !changed {
		t.Fatalf("SetSiteSystem = %v, %v", changed, err)
	}
	written, err := leaf.SiteRulesSystem(ctx, fixture.siteB)
	if err != nil || len(written) != 1 || written[0].Current.Secret.SecretAccessKey != "SK-subscriber-key" {
		t.Fatalf("leaf rules = %+v, %v", written, err)
	}
	ClearSiteRules(written)
	var keyID string
	var ciphertext []byte
	if err := fixture.pool.QueryRow(ctx, `SELECT revision.envelope_key_id, revision.secret_ciphertext
		FROM origin_auth_credential_revisions revision JOIN origin_auth_credentials identity ON identity.id=revision.credential_id
		WHERE identity.name=$1 AND revision.revision=2`, marketCredentialName(rules[0].Current.RevisionRef)).
		Scan(&keyID, &ciphertext); err != nil {
		t.Fatal(err)
	}
	if keyID != "new" || bytes.Contains(ciphertext, []byte("SK-subscriber-key")) {
		t.Fatalf("leaf credential key %q, clear text at rest", keyID)
	}
	var systemEvents, publications int
	if err := fixture.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM audit_events WHERE request_id='market-auth-set-1' AND actor_kind='system'
			AND actor_ref='job:market_leaf_sync' AND result='success'),
		(SELECT count(*) FROM origin_auth_publications WHERE request_id='market-auth-set-1')`).
		Scan(&systemEvents, &publications); err != nil {
		t.Fatal(err)
	}
	// credential create + verify, rule create, publication create.
	if systemEvents != 4 || publications != 1 {
		t.Fatalf("system audit events %d, publications %d", systemEvents, publications)
	}
	var leaked bool
	if err := fixture.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_events
		WHERE request_id='market-auth-set-1' AND payload::text LIKE '%SK-subscriber-key%')`).Scan(&leaked); err != nil || leaked {
		t.Fatalf("secret in audit payload: %v %v", leaked, err)
	}

	write.RequestID = "market-auth-set-2"
	if changed, err := leaf.SetSiteSystem(ctx, write); err != nil || changed {
		t.Fatalf("same write again = %v, %v", changed, err)
	}
	moved := rules[0]
	moved.Endpoint = "https://other.s3.us-east-1.amazonaws.com"
	if changed, err := leaf.SetSiteSystem(ctx, SystemSiteWrite{ScopeID: fixture.tenantScopeID, SiteID: fixture.siteB,
		OwnerUserID: fixture.owner.UserID, Rules: []SiteRule{moved}, PruneOnly: true, RequestID: "market-auth-prune-3",
		ActorRef: "job:market_leaf_sync"}); err != nil || !changed {
		t.Fatalf("prune = %v, %v", changed, err)
	}
	if left, err := leaf.SiteRulesSystem(ctx, fixture.siteB); err != nil || len(left) != 0 {
		t.Fatalf("after prune = %+v, %v", left, err)
	}
	ClearSiteRules(rules)
	if _, err := leaf.SetSiteSystem(ctx, SystemSiteWrite{ScopeID: fixture.tenantScopeID, SiteID: fixture.siteB,
		OwnerUserID: fixture.viewer.UserID, RequestID: "market-auth-x", ActorRef: "job:market_leaf_sync"}); err == nil {
		t.Fatal("a non-owner wrote the site")
	}
}
