package edgepublish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/google/uuid"
)

func TestHTTPPolicyArtifactBindsCanonicalFactsIntoSignedSiteRuntime(t *testing.T) {
	document := mustHTTPPolicyRuntimeDocument(t)
	scopeID := uuid.MustParse(document.ConfigurationScopeID)
	firstSiteID := uuid.MustParse(document.Sites[0].ID)
	secondSiteID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7199")
	secondSite := document.Sites[0]
	secondSite.ID, secondSite.Revision, secondSite.Domains = secondSiteID.String(), 8, []string{"second.example.test"}
	document.Sites = append(document.Sites, secondSite)
	slices.SortFunc(document.Sites, func(left, right siteRuntimeV2Site) int { return bytes.Compare([]byte(left.ID), []byte(right.ID)) })

	first := httpPolicyFactFixture(t, scopeID, firstSiteID, 41, 3)
	second := httpPolicyFactFixture(t, scopeID, secondSiteID, 41, 9)
	second.document.MaxUploadBytes = 2048
	artifact, digest, err := compileHTTPPolicyArtifact(scopeID, 41, 12, &document, []httpPolicyFact{second, first})
	if err != nil {
		t.Fatal(err)
	}
	wantSnapshot := httppolicycontrol.EdgeSnapshot{
		SchemaVersion: httppolicycontrol.EdgeSchemaVersion, PolicyVersion: 12,
		Sites: []httppolicycontrol.EdgeSitePolicy{first.document.edgeSite(), second.document.edgeSite()},
	}
	wantArtifact, err := json.Marshal(wantSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	wantArtifact = append(wantArtifact, '\n')
	if !bytes.Equal(artifact, wantArtifact) || digest != sha256.Sum256(wantArtifact) {
		t.Fatalf("artifact/digest not canonical:\n got=%s/%x\nwant=%s/%x", artifact, digest, wantArtifact, sha256.Sum256(wantArtifact))
	}
	for _, site := range document.Sites {
		if site.HTTPPolicy == nil || site.HTTPPolicy.ArtifactSHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("site %s HTTP policy binding = %+v", site.ID, site.HTTPPolicy)
		}
		fact := first
		if site.ID == secondSiteID.String() {
			fact = second
		}
		if site.HTTPPolicy.PolicyID != fact.policyID.String() || site.HTTPPolicy.PolicyRevision != fact.revision {
			t.Fatalf("site %s identity binding = %+v, fact=%+v", site.ID, site.HTTPPolicy, fact)
		}
	}
	// An HTTP policy no longer raises site_runtime above the 1.0.35 baseline.
	if got := siteRuntimeCapabilityVersion(document.RequiredCapabilities, "site_runtime"); got != edgeconfig.MinSiteRuntimeVersion {
		t.Fatalf("site_runtime capability version=%d, want %d", got, edgeconfig.MinSiteRuntimeVersion)
	}
	canonical, _, _, _, err := compileSiteRuntimeV2Document(mustMarshalHTTPPolicyDocument(t, document))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := marshalSiteRuntimeV2BundleWithHTTPPolicy(canonical, nil, nil, artifact)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := edgeconfig.UnmarshalBundle(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bundle.Files[siteRuntimeV2HTTPPolicyArtifactPath], artifact) {
		t.Fatal("signed bundle omitted the exact canonical HTTP policy artifact")
	}

	reordered := mustHTTPPolicyRuntimeDocument(t)
	reordered.Sites = append(reordered.Sites, secondSite)
	slices.SortFunc(reordered.Sites, func(left, right siteRuntimeV2Site) int { return bytes.Compare([]byte(left.ID), []byte(right.ID)) })
	secondArtifact, secondDigest, err := compileHTTPPolicyArtifact(scopeID, 41, 12, &reordered, []httpPolicyFact{first, second})
	if err != nil || !bytes.Equal(secondArtifact, artifact) || secondDigest != digest {
		t.Fatalf("fact order changed canonical artifact: err=%v artifact=%s digest=%x", err, secondArtifact, secondDigest)
	}
}

func TestHTTPPolicyArtifactFailsClosedOnIdentityRevisionAndDigestDrift(t *testing.T) {
	baseDocument := mustHTTPPolicyRuntimeDocument(t)
	scopeID := uuid.MustParse(baseDocument.ConfigurationScopeID)
	siteID := uuid.MustParse(baseDocument.Sites[0].ID)
	baseFact := httpPolicyFactFixture(t, scopeID, siteID, 41, 3)

	tests := []struct {
		name   string
		mutate func(*siteRuntimeV2Document, *httpPolicyFact)
	}{
		{"cross tenant", func(_ *siteRuntimeV2Document, fact *httpPolicyFact) { fact.tenantScopeID = uuid.New() }},
		{"stale source revision", func(_ *siteRuntimeV2Document, fact *httpPolicyFact) { fact.sourceRevision-- }},
		{"missing site", func(_ *siteRuntimeV2Document, fact *httpPolicyFact) {
			fact.siteID = uuid.New()
			fact.document.SiteID = fact.siteID
		}},
		{"stale projection revision", func(_ *siteRuntimeV2Document, fact *httpPolicyFact) { fact.document.Revision-- }},
		{"cross policy document", func(_ *siteRuntimeV2Document, fact *httpPolicyFact) { fact.document.PolicyID = uuid.New() }},
		{"disabled document", func(_ *siteRuntimeV2Document, fact *httpPolicyFact) { fact.document.Enabled = false }},
		{"deleted document", func(_ *siteRuntimeV2Document, fact *httpPolicyFact) { fact.document.Deleted = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, fact := baseDocument, baseFact
			test.mutate(&document, &fact)
			if _, _, err := compileHTTPPolicyArtifact(scopeID, 41, 12, &document, []httpPolicyFact{fact}); !errors.Is(err, ErrPersistence) {
				t.Fatalf("compileHTTPPolicyArtifact() error=%v, want ErrPersistence", err)
			}
		})
	}

	document := baseDocument
	artifact, digest, err := compileHTTPPolicyArtifact(scopeID, 41, 12, &document, []httpPolicyFact{baseFact})
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, _, _, err := compileSiteRuntimeV2Document(mustMarshalHTTPPolicyDocument(t, document))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("binding digest", func(t *testing.T) {
		var drifted siteRuntimeV2Document
		if err := json.Unmarshal(canonical, &drifted); err != nil {
			t.Fatal(err)
		}
		drifted.Sites[0].HTTPPolicy.ArtifactSHA256 = hex.EncodeToString(sha256.New().Sum(nil))
		driftedCanonical, _, _, _, err := compileSiteRuntimeV2Document(mustMarshalHTTPPolicyDocument(t, drifted))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := marshalSiteRuntimeV2BundleWithHTTPPolicy(driftedCanonical, nil, nil, artifact); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("digest drift error=%v, want ErrInvalidInput (canonical digest %x)", err, digest)
		}
	})
	t.Run("artifact bytes", func(t *testing.T) {
		tampered := bytes.Clone(artifact)
		tampered[len(tampered)-2] ^= 1
		if _, err := marshalSiteRuntimeV2BundleWithHTTPPolicy(canonical, nil, nil, tampered); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("artifact drift error=%v, want ErrInvalidInput", err)
		}
	})
	t.Run("missing artifact", func(t *testing.T) {
		if _, err := marshalSiteRuntimeV2BundleWithHTTPPolicy(canonical, nil, nil, nil); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("missing artifact error=%v, want ErrInvalidInput", err)
		}
	})
}

func TestHTTPPolicyDisabledStateProducesNoArtifactOrBinding(t *testing.T) {
	document := mustHTTPPolicyRuntimeDocument(t)
	document.SourceRevision = 42
	scopeID := uuid.MustParse(document.ConfigurationScopeID)
	artifact, digest, err := compileHTTPPolicyArtifact(scopeID, 42, 13, &document, nil)
	if err != nil {
		t.Fatal(err)
	}
	if artifact != nil || digest != ([sha256.Size]byte{}) || document.Sites[0].HTTPPolicy != nil {
		t.Fatalf("disabled policy artifact/digest/binding=%q/%x/%+v", artifact, digest, document.Sites[0].HTTPPolicy)
	}
	if got := siteRuntimeCapabilityVersion(document.RequiredCapabilities, "site_runtime"); got != edgeconfig.MinSiteRuntimeVersion {
		t.Fatalf("site_runtime capability version=%d, want the baseline %d", got, edgeconfig.MinSiteRuntimeVersion)
	}
	canonical, _, _, _, err := compileSiteRuntimeV2Document(mustMarshalHTTPPolicyDocument(t, document))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := marshalSiteRuntimeV2BundleWithHTTPPolicy(canonical, nil, nil, nil); err != nil {
		t.Fatalf("policy-free bundle rejected: %v", err)
	}
}

func mustHTTPPolicyRuntimeDocument(t *testing.T) siteRuntimeV2Document {
	t.Helper()
	var document siteRuntimeV2Document
	if err := json.Unmarshal(siteRuntimeV2DocumentFixture(), &document); err != nil {
		t.Fatal(err)
	}
	l2Enabled := false
	document.Sites[0].OriginPools = document.Sites[0].OriginPools[:1]
	document.Sites[0].DefaultPoolID = document.Sites[0].OriginPools[0].ID
	document.Sites[0].L2.Enabled = &l2Enabled
	document.Sites[0].L2.DirectFallbackPoolID = nil
	return document
}

func httpPolicyFactFixture(t *testing.T, scopeID, siteID uuid.UUID, sourceRevision, policyRevision int64) httpPolicyFact {
	t.Helper()
	policyID := uuid.New()
	return httpPolicyFact{
		tenantScopeID: scopeID, siteID: siteID, policyID: policyID,
		sourceRevision: sourceRevision, revision: policyRevision,
		document: httpPolicyRevisionDocument{
			SchemaVersion: httppolicycontrol.DocumentSchema, PolicyID: policyID, TenantScopeID: scopeID,
			SiteID: siteID, SiteOwnerUserID: uuid.New(), Revision: policyRevision, Enabled: true,
			Config: httppolicycontrol.Config{
				MaxUploadBytes:  1024,
				RequestHeaders:  []httppolicycontrol.HeaderAction{{Kind: httppolicycontrol.HeaderSet, Name: "x-origin", Values: []string{"one", "two"}}},
				ResponseHeaders: []httppolicycontrol.HeaderAction{{Kind: httppolicycontrol.HeaderDelete, Name: "x-remove", Values: []string{}}},
				Rewrites:        []httppolicycontrol.RewriteRule{}, RedirectAllowedHosts: []string{},
				Redirects: []httppolicycontrol.RedirectRule{}, CORS: nil,
			},
		},
	}
}

func mustMarshalHTTPPolicyDocument(t *testing.T, document siteRuntimeV2Document) []byte {
	t.Helper()
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func siteRuntimeCapabilityVersion(values []siteRuntimeV2Capability, name string) uint32 {
	for _, value := range values {
		if value.Name == name {
			return value.APIVersion
		}
	}
	return 0
}
