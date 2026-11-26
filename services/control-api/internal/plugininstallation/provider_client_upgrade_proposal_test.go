package plugininstallation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// License 176: the regular candidate sync asks for v2; an installed market row may carry an upgrade proposal, which
// becomes the remote view's AvailableUpgrade. A proposal in a v1 (pending) batch or an invalid one refuses the page.
func TestCandidateSyncUpgradeProposal(t *testing.T) {
	now := time.Date(2026, 11, 20, 3, 4, 5, 0, time.UTC)
	installationPublic, installationPrivate, _ := ed25519.GenerateKey(rand.Reader)
	licensePublic, licensePrivate, _ := ed25519.GenerateKey(rand.Reader)
	tenantID, installationID := uuid.New(), uuid.New()
	authorizationID, verificationID, proposedID := uuid.New(), uuid.New(), uuid.New()
	valid := func() *candidateSyncUpgradeProposalWire {
		return &candidateSyncUpgradeProposalWire{VerificationID: proposedID, PluginVersion: "1.0.4",
			ManifestScopes: []string{"plugin.read"}, ApprovedScopes: []string{"plugin.read"},
			SensitiveScopes: []string{"plugin.read"}, NewScopes: []string{}}
	}
	var proposal *candidateSyncUpgradeProposalWire
	var answerSchema string
	var requestSchemas []string
	doer := activationDoerFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		var wire candidateSyncRequestWire
		if json.Unmarshal(body, &wire) != nil {
			t.Fatalf("request=%s", body)
		}
		requestSchemas = append(requestSchemas, wire.Schema)
		canonical, _ := json.Marshal(wire.candidateSyncRequestPayload)
		proof, _ := base64.RawURLEncoding.DecodeString(wire.Proof)
		if !ed25519.Verify(installationPublic, framed(candidateSyncRequestDomain, canonical), proof) {
			t.Fatal("request proof invalid")
		}
		requestDigest := sha256.Sum256(framed("cdnca-plugin-installation-candidate-sync-idempotency/v1",
			append(canonical, proof...)))
		schema := answerSchema
		if schema == "" {
			schema = candidateSyncBatchSchemaFor(wire.Schema)
		}
		batch := candidateSyncBatchWire{Schema: schema, RequestID: wire.RequestID,
			RequestDigest: hex.EncodeToString(requestDigest[:]), CustomerID: uuid.New(), InstallationID: installationID,
			Candidates: []candidateSyncCandidateWire{{AuthorizationID: authorizationID, VerificationID: verificationID,
				PluginID: "acme.market", PluginVersion: "1.0.1", ResourceScope: "tenant", EntrypointType: "external_https",
				ManifestSHA256: digest("a"), ConfigurationSchemaSHA256: digest("b"),
				ManifestScopes: []string{"plugin.read"}, ApprovedScopes: []string{"plugin.read"},
				SensitiveScopes: []string{"plugin.read"}, NewScopes: []string{}, Status: StatusEnabled, Revision: 4,
				IdentityGeneration: 2, LKGVerificationID: verificationID, LKGVersion: "1.0.1", UpdatedAt: now,
				UpgradeProposal: proposal}},
			IssuedAt: now, ExpiresAt: now.Add(time.Minute), Algorithm: "Ed25519", KeyID: "license-plugin-key-1"}
		unsigned, _ := json.Marshal(batch)
		batch.Signature = base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(licensePrivate, framed(candidateSyncBatchDomain, unsigned)))
		responseBody, _ := json.Marshal(batch)
		return &http.Response{StatusCode: http.StatusOK,
			Body: io.NopCloser(bytes.NewReader(append(responseBody, '\n')))}, nil
	})
	client, err := NewActivationClient(ActivationClientConfig{BaseURL: "https://license.example", HTTP: doer,
		InstallationID: installationID, PrivateKey: installationPrivate,
		Trust: activationTrustForTest{keyID: "license-plugin-key-1", public: licensePublic},
		Now:   func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	discover := func() (Page, error) {
		return client.Discover(context.Background(), CandidateDiscoveryRequest{RequestID: "proposal-sync",
			TenantID: tenantID, Limit: 50})
	}

	// No proposal: the page is as before.
	page, err := discover()
	if err != nil || len(page.Items) != 1 || page.Items[0].AvailableUpgrade != nil {
		t.Fatalf("page without proposal=%+v err=%v", page, err)
	}
	if requestSchemas[0] != "cdnca.plugin-installation-candidate-sync-request/v2" {
		t.Fatalf("regular sync request schema=%s", requestSchemas[0])
	}
	proposal = valid()
	page, err = discover()
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("page with proposal=%+v err=%v", page, err)
	}
	upgrade := page.Items[0].AvailableUpgrade
	if upgrade == nil || upgrade.VerificationID != proposedID || upgrade.Version != "1.0.4" ||
		len(upgrade.ApprovedScopes) != 1 || len(upgrade.NewScopes) != 0 ||
		page.Items[0].Installation.VerificationID != verificationID {
		t.Fatalf("proposal view=%+v", page.Items[0])
	}

	// A v1 batch never carries a proposal.
	answerSchema = candidateSyncBatchSchema
	if _, err := discover(); !errors.Is(err, ErrActivationInvalid) {
		t.Fatalf("v1 answer to a v2 request err=%v", err)
	}
	answerSchema = ""
	invalid := map[string]func(*candidateSyncUpgradeProposalWire){
		"same verification": func(p *candidateSyncUpgradeProposalWire) { p.VerificationID = verificationID },
		"not newer":         func(p *candidateSyncUpgradeProposalWire) { p.PluginVersion = "1.0.1" },
		"bad version":       func(p *candidateSyncUpgradeProposalWire) { p.PluginVersion = "1.0" },
		"scope outside":     func(p *candidateSyncUpgradeProposalWire) { p.NewScopes = []string{"dns.write"} },
	}
	for name, mutate := range invalid {
		proposal = valid()
		mutate(proposal)
		if _, err := discover(); !errors.Is(err, ErrActivationInvalid) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

func TestAnnotateInstallationUpgradeProposal(t *testing.T) {
	authorizationID, running, proposed := uuid.New(), uuid.New(), uuid.New()
	local := func() InstallationView {
		return InstallationView{Installation: Installation{AuthorizationID: authorizationID, VerificationID: running,
			Version: "1.0.1", Status: StatusEnabled}}
	}
	remote := func(upgrade *AvailableUpgrade) map[uuid.UUID]InstallationView {
		return map[uuid.UUID]InstallationView{authorizationID: {Installation: Installation{
			AuthorizationID: authorizationID, VerificationID: running, Version: "1.0.1"},
			AuthorizationStatus: StatusEnabled, AvailableUpgrade: upgrade}}
	}
	offered := &AvailableUpgrade{VerificationID: proposed, Version: "1.0.4", ManifestScopes: []string{"plugin.read"},
		ApprovedScopes: []string{"plugin.read"}, SensitiveScopes: []string{"plugin.read"}, NewScopes: []string{}}

	view := local()
	annotateInstallation(&view, remote(offered))
	if view.AvailableUpgrade == nil || view.AvailableUpgrade.VerificationID != proposed ||
		view.AvailableUpgrade.Version != "1.0.4" || view.AuthorizationStatus != StatusEnabled {
		t.Fatalf("proposal not offered: %+v", view)
	}
	view.AvailableUpgrade.ApprovedScopes[0] = "changed"
	if offered.ApprovedScopes[0] != "plugin.read" {
		t.Fatal("annotation shares the remote proposal's slices")
	}

	// Already running the proposed version, or a proposal not newer than the local head: nothing to offer.
	view = local()
	view.Installation.VerificationID, view.Installation.Version = proposed, "1.0.4"
	annotateInstallation(&view, remote(offered))
	if view.AvailableUpgrade != nil {
		t.Fatalf("proposal offered for the running version: %+v", view.AvailableUpgrade)
	}
	view = local()
	view.Installation.Version = "1.0.5"
	annotateInstallation(&view, remote(offered))
	if view.AvailableUpgrade != nil {
		t.Fatalf("older proposal offered: %+v", view.AvailableUpgrade)
	}

	// An operator-moved authorization (license row already on the new version) still wins, as before.
	moved := remote(nil)
	entry := moved[authorizationID]
	entry.Installation.VerificationID, entry.Installation.Version = proposed, "1.1.0"
	moved[authorizationID] = entry
	view = local()
	annotateInstallation(&view, moved)
	if view.AvailableUpgrade == nil || view.AvailableUpgrade.Version != "1.1.0" {
		t.Fatalf("operator upgrade not offered: %+v", view.AvailableUpgrade)
	}
}
