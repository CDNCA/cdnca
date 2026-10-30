package edgepublish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallactioncontrol"
	"github.com/google/uuid"
)

func TestFirewallActionCarrierIsDeterministicAndBindsEveryIdentity(t *testing.T) {
	scopeID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7101")
	siteID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103")
	policyID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	raw := firewallActionControlPolicy(t, scopeID, siteID, policyID, 7)
	fact := firewallActionFact{siteID: siteID, policyID: policyID, revision: 7, document: raw, digest: sha256.Sum256(raw)}

	firstDocument := firewallActionSiteRuntimeDocument(t)
	first, err := compileFirewallActionArtifacts(scopeID, &firstDocument, []firewallActionFact{fact})
	if err != nil {
		t.Fatal(err)
	}
	secondDocument := firewallActionSiteRuntimeDocument(t)
	second, err := compileFirewallActionArtifacts(scopeID, &secondDocument, []firewallActionFact{fact})
	if err != nil {
		t.Fatal(err)
	}
	firstCanonical, _ := json.Marshal(firstDocument)
	secondCanonical, _ := json.Marshal(secondDocument)
	path := firewallActionArtifactPath(siteID)
	if !bytes.Equal(firstCanonical, secondCanonical) || !bytes.Equal(first[path], second[path]) ||
		firstDocument.Sites[0].FirewallAction.ArtifactPath != path ||
		firstDocument.Sites[0].FirewallAction.DocumentSHA256 != hex.EncodeToString(fact.digest[:]) {
		t.Fatalf("carrier is not deterministic: %s / %s", firstCanonical, secondCanonical)
	}
	if err := validateSiteRuntimeV2FirewallActionArtifacts(firstCanonical, first); err != nil {
		t.Fatalf("valid carrier rejected: %v", err)
	}

	t.Run("tenant", func(t *testing.T) {
		bad := fact
		bad.document = firewallActionControlPolicy(t, uuid.New(), siteID, policyID, 7)
		bad.digest = sha256.Sum256(bad.document)
		assertFirewallActionCompileRejected(t, scopeID, bad)
	})
	t.Run("site", func(t *testing.T) {
		bad := fact
		bad.document = firewallActionControlPolicy(t, scopeID, uuid.New(), policyID, 7)
		bad.digest = sha256.Sum256(bad.document)
		assertFirewallActionCompileRejected(t, scopeID, bad)
	})
	t.Run("policy", func(t *testing.T) {
		bad := fact
		bad.policyID = uuid.New()
		assertFirewallActionCompileRejected(t, scopeID, bad)
	})
	t.Run("revision", func(t *testing.T) {
		bad := fact
		bad.revision++
		assertFirewallActionCompileRejected(t, scopeID, bad)
	})
	t.Run("sha", func(t *testing.T) {
		document := firstDocument
		document.Sites[0].FirewallAction.DocumentSHA256 = strings.Repeat("a", 64)
		canonical, _ := json.Marshal(document)
		if err := validateSiteRuntimeV2FirewallActionArtifacts(canonical, first); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("SHA drift error = %v", err)
		}
	})
	t.Run("path", func(t *testing.T) {
		document := firstDocument
		document.Sites[0].FirewallAction.ArtifactPath = siteRuntimeV2FirewallActionPrefix + uuid.NewString() + ".json"
		canonical, _ := json.Marshal(document)
		if err := validateSiteRuntimeV2FirewallActionArtifacts(canonical, first); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("path drift error = %v", err)
		}
	})
}

func TestFirewallActionFactSelectionUsesPendingCandidateOtherwiseDurableLKG(t *testing.T) {
	for _, fragment := range []string{
		"CASE WHEN head.deployment_state='pending' THEN head.revision ELSE head.lkg_revision END",
		"head.deployment_state='pending' OR head.lkg_revision>0",
	} {
		if !strings.Contains(loadFirewallActionFactsSQL, fragment) {
			t.Fatalf("fact selection query missing %q", fragment)
		}
	}
}

func assertFirewallActionCompileRejected(t *testing.T, scopeID uuid.UUID, fact firewallActionFact) {
	t.Helper()
	document := firewallActionSiteRuntimeDocument(t)
	if _, err := compileFirewallActionArtifacts(scopeID, &document, []firewallActionFact{fact}); !errors.Is(err, ErrPersistence) {
		t.Fatalf("identity drift error = %v", err)
	}
}

func firewallActionSiteRuntimeDocument(t *testing.T) siteRuntimeV2Document {
	t.Helper()
	var document siteRuntimeV2Document
	if err := json.Unmarshal(siteRuntimeV2DocumentFixture(), &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func firewallActionControlPolicy(t *testing.T, scopeID, siteID, policyID uuid.UUID, revision uint64) []byte {
	t.Helper()
	policy := firewallactioncontrol.EdgePolicy{
		SchemaVersion: firewallactioncontrol.SchemaVersion, PolicyVersion: revision,
		TenantID: scopeID.String(), SiteID: siteID.String(), PolicyID: policyID.String(),
		ExpectedActivePolicyVersion: revision - 1,
		NormalAction:                firewallactioncontrol.ActionDisconnect, EscalatedAction: firewallactioncontrol.ActionNFTables,
		EngageThreshold: 100, RecoverThreshold: 20, RecoveryWindows: 2,
		BlockNetworks: []string{"198.51.100.0/24"}, TrustedProxies: []string{},
		TrustedCrawlers: []firewallactioncontrol.TrustedCrawler{},
		ReturnPage:      firewallactioncontrol.ReturnPage{Status: 429, ContentType: "text/html; charset=utf-8", Body: "Request limited"},
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
