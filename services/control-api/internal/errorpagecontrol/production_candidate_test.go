package errorpagecontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestSITE13ProductionCandidatePrefersExactSiteThenPlatformGlobal(t *testing.T) {
	tenantID, scopeID, siteID := uuid.New(), uuid.New(), uuid.New()
	request := ProductionCandidateRequest{
		TenantID: tenantID, ScopeID: scopeID, SiteID: siteID,
		Category: CategoryEdgeRoute, StatusCode: 404,
	}
	platformScopeID := uuid.New()
	global := productionCandidate{
		scopeKind: "platform", scopeID: platformScopeID, ruleID: uuid.New(), revision: 3,
		category: CategoryEdgeRoute, codeFrom: 400, codeTo: 499,
		asset: Asset{ID: uuid.New(), ScopeID: platformScopeID, Status: StatusReady, objectState: "final"},
	}
	site := productionCandidate{
		scopeKind: "tenant", scopeID: scopeID, tenantID: &tenantID, siteID: &siteID,
		ruleID: uuid.New(), revision: 7, category: CategoryEdgeRoute, codeFrom: 404, codeTo: 404,
		asset: Asset{ID: uuid.New(), ScopeID: scopeID, TenantID: &tenantID, Status: StatusReady, objectState: "final"},
	}
	selected, err := chooseProductionCandidate(request, []productionCandidate{global, site})
	if err != nil || selected.ruleID != site.ruleID {
		t.Fatalf("selected=%+v err=%v", selected, err)
	}
	selected, err = chooseProductionCandidate(request, []productionCandidate{global})
	if err != nil || selected.ruleID != global.ruleID {
		t.Fatalf("global selected=%+v err=%v", selected, err)
	}
	otherTenant := uuid.New()
	site.tenantID = &otherTenant
	if _, err := chooseProductionCandidate(request, []productionCandidate{site}); err == nil {
		t.Fatal("cross-tenant site candidate was accepted")
	}
}

func TestSITE13PlatformGlobalCandidateBuildsTenantSiteBoundArtifact(t *testing.T) {
	tenantID, scopeID, siteID, platformScopeID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	body := []byte("platform fallback\n")
	bodyDigest := sha256.Sum256(body)
	digest := fmtSHA256(bodyDigest)
	asset := Asset{
		ID: uuid.New(), ScopeID: platformScopeID, MIMEType: "text/plain", SizeBytes: int64(len(body)),
		SHA256: digest, Status: StatusReady, ScanStatus: "passed", Revision: 2,
		storageObjectKey: "error-pages/objects/" + platformScopeID.String() + "/" + digest, objectState: "final",
	}
	store := &site13BundleStore{
		ref: assetObjectRef(asset, asset.storageObjectKey), body: body,
		info: ObjectInfo{Size: int64(len(body)), SHA256: digest, MIMEType: asset.MIMEType, ImmutableToken: "sha256:" + digest},
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	compiler, err := NewProductionCandidateCompiler(store, site13BundleSigner{private: private})
	if err != nil {
		t.Fatal(err)
	}
	request := ProductionCandidateRequest{TenantID: tenantID, ScopeID: scopeID, SiteID: siteID, Category: CategoryEdgeRoute, StatusCode: 404}
	candidate := productionCandidate{
		scopeKind: "platform", scopeID: platformScopeID, ruleID: uuid.New(), revision: 9, category: CategoryEdgeRoute,
		codeFrom: 404, codeTo: 404, asset: asset,
	}
	artifact, err := compiler.buildSelected(t.Context(), request, candidate)
	if err != nil {
		t.Fatal(err)
	}
	var document ProductionBundleDocument
	if err := json.Unmarshal(artifact.WireBytes, &document); err != nil {
		t.Fatal(err)
	}
	if document.Binding.TenantID != tenantID.String() || document.Binding.SiteID != siteID.String() ||
		document.Binding.Revision != 9 || document.Binding.AssetSHA256 != digest ||
		artifact.SourceScopeID != platformScopeID || artifact.RuleID != candidate.ruleID.String() ||
		!ed25519.Verify(private.Public().(ed25519.PublicKey), artifact.WireBytes, artifact.Signature) {
		t.Fatalf("artifact=%+v document=%+v", artifact, document)
	}
}
