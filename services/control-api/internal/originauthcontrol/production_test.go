package originauthcontrol

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSITE09ProductionMaterialBindsExactTenantOriginAndCredentialRevisions(t *testing.T) {
	scopeID, tenantID := uuid.New(), uuid.New()
	currentRef, previousRef := uuid.New(), uuid.New()
	material := ProductionMaterial{
		PublicationID: uuid.New(), TenantID: tenantID, TenantScopeID: scopeID, PublicationRevision: 7,
		Snapshot: PublicationSnapshot{SchemaVersion: publicationSchema, TenantScopeID: scopeID, PublicationRevision: 7,
			Rules: []PublicationRule{{RuleID: uuid.New(), SiteID: uuid.New(), SourcePosition: 2, Provider: ProviderS3,
				Algorithm: AlgorithmS3, Endpoint: "https://s3.us-east-1.amazonaws.com", PathPrefix: "/", Region: "us-east-1",
				Service: "s3", SignatureTTLSeconds: 300, CurrentCredentialRevisionRef: currentRef,
				PreviousCredentialRevisionRef: &previousRef, ActivateCurrentAtUnix: 1_800_000_000}}},
		Credentials: []ProductionCredentialMaterial{
			{RevisionRef: currentRef, Provider: ProviderS3, Secret: productionSecret("AKIA-CURRENT")},
			{RevisionRef: previousRef, Provider: ProviderS3, Secret: productionSecret("AKIA-PREVIOUS")},
		},
	}
	canonical, err := encodeJSON(material.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	material.CanonicalSnapshot = canonical
	if err := validateProductionMaterial(&material); err != nil {
		t.Fatalf("valid production material rejected: %v", err)
	}
	if bytes.Contains(material.CanonicalSnapshot, []byte("AKIA-CURRENT")) || bytes.Contains(material.CanonicalSnapshot, []byte("secret-value")) {
		t.Fatal("secret entered canonical rollout snapshot")
	}

	crossProvider := cloneProductionMaterial(material)
	crossProvider.Credentials[0].Provider = ProviderOSS
	if err := validateProductionMaterial(&crossProvider); err == nil {
		t.Fatal("cross-provider credential binding was accepted")
	}
	missing := cloneProductionMaterial(material)
	missing.Credentials = missing.Credentials[:1]
	if err := validateProductionMaterial(&missing); err == nil {
		t.Fatal("missing previous revision was accepted")
	}
	extra := cloneProductionMaterial(material)
	extra.Credentials = append(extra.Credentials, ProductionCredentialMaterial{RevisionRef: uuid.New(), Provider: ProviderS3, Secret: productionSecret("AKIA-EXTRA")})
	if err := validateProductionMaterial(&extra); err == nil {
		t.Fatal("unreferenced credential revision was accepted")
	}
}

func TestSITE09ProductionSourceQueriesExactImmutableRevisionRefs(t *testing.T) {
	raw, err := os.ReadFile("production.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{
		"origin_auth_publications", "canonical_snapshot", "snapshot_sha256", "revision_ref = ANY($2)",
		"origin_auth_credential_revisions", "secret_ciphertext_sha256", "credentialAAD(", "StatusVerified",
		// a verified revision's ciphertext is sealed under its create/replace revision
		"sealedRevisionColumn",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("production source is missing %q", required)
		}
	}
}

func productionSecret(accessKey string) CredentialSecret {
	return CredentialSecret{AccessKeyID: accessKey, SecretAccessKey: "secret-value", NotBefore: time.Unix(1_700_000_000, 0).UTC(), ExpiresAt: time.Unix(1_900_000_000, 0).UTC()}
}
