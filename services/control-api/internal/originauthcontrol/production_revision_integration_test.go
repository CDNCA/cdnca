package originauthcontrol

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fix-mktsiteconf6: a verified credential revision copies the ciphertext of
// the create/replace revision before it, sealed under that revision's AAD.
// ProductionSource.Build used the verified revision number as AAD, so every
// verified credential failed to decrypt for edge delivery (ErrEncryption
// Unavailable). Both a create→verify (sealed at 1, read at 2) and a
// create→verify→replace→verify (sealed at 3, read at 4) credential must
// decrypt and be delivered with their own secret.
func TestProductionSourceDecryptsVerifiedRevisionsSealedEarlier(t *testing.T) {
	fixture := newOriginAuthFixture(t)
	ctx := t.Context()
	service := fixtureService(t, fixture, "new",
		CredentialVerifierFunc(func(context.Context, VerificationRequest) error { return nil }), nil)

	first := createCredential(t, service, fixture.owner, "first", "msc6-first-create")
	firstVerified, err := service.VerifyCredential(ctx, fixture.owner,
		mutationRequest(fixture.tenantScopeID, first.ID, 1, "msc6-first-verify"))
	if err != nil || firstVerified.Credential.Revision != 2 {
		t.Fatalf("verify first = %+v, %v", firstVerified, err)
	}

	second := createCredential(t, service, fixture.owner, "second", "msc6-second-create")
	if _, err := service.VerifyCredential(ctx, fixture.owner,
		mutationRequest(fixture.tenantScopeID, second.ID, 1, "msc6-second-verify")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReplaceCredential(ctx, fixture.owner, ReplaceCredentialRequest{
		TargetScopeID: fixture.tenantScopeID, CredentialID: second.ID, ExpectedRevision: 2,
		Secret: credentialSecret("second-rotated"), WriteMetadata: metadata("msc6-second-replace"),
	}); err != nil {
		t.Fatal(err)
	}
	secondVerified, err := service.VerifyCredential(ctx, fixture.owner,
		mutationRequest(fixture.tenantScopeID, second.ID, 3, "msc6-second-reverify"))
	if err != nil || secondVerified.Credential.Revision != 4 {
		t.Fatalf("verify replaced second = %+v, %v", secondVerified, err)
	}

	for _, rule := range []struct {
		site     uuid.UUID
		id       uuid.UUID
		revision int64
		key      string
	}{
		{fixture.siteA, first.ID, 2, "msc6-rule-a"},
		{fixture.siteB, second.ID, 4, "msc6-rule-b"},
	} {
		if _, err := service.CreateRule(ctx, fixture.owner, CreateRuleRequest{
			TargetScopeID: fixture.tenantScopeID, SiteID: rule.site, SourcePosition: 1, Enabled: true,
			Config: s3RuleConfig(rule.id, rule.revision), WriteMetadata: metadata(rule.key),
		}); err != nil {
			t.Fatalf("create rule %s: %v", rule.key, err)
		}
	}
	if _, err := service.CreatePublication(ctx, fixture.owner, CreatePublicationRequest{
		TargetScopeID: fixture.tenantScopeID, WriteMetadata: metadata("msc6-publication"),
	}); err != nil {
		t.Fatal(err)
	}

	source, err := NewProductionSource(service)
	if err != nil {
		t.Fatal(err)
	}
	var material ProductionMaterial
	if err := pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
		var buildErr error
		material, buildErr = source.Build(ctx, tx, fixture.tenantScopeID)
		return buildErr
	}); err != nil {
		if errors.Is(err, ErrEncryptionUnavailable) {
			t.Fatalf("Build decrypted a verified revision with the wrong AAD revision: %v", err)
		}
		t.Fatalf("Build = %v", err)
	}
	defer clearProductionMaterial(&material)
	secrets := map[uuid.UUID]string{}
	for _, credential := range material.Credentials {
		secrets[credential.RevisionRef] = credential.Secret.SecretAccessKey
	}
	if len(material.Credentials) != 2 ||
		secrets[firstVerified.Credential.RevisionRef] != "SK-first" ||
		secrets[secondVerified.Credential.RevisionRef] != "SK-second-rotated" {
		t.Fatalf("delivered credentials = %d, first ok %v, second ok %v", len(material.Credentials),
			secrets[firstVerified.Credential.RevisionRef] == "SK-first",
			secrets[secondVerified.Credential.RevisionRef] == "SK-second-rotated")
	}
}
