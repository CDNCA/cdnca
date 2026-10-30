//go:build integration

package edgepublish

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A site runtime v2 (TLS) scope with unpublished edits still gets a system
// stop and its release: the release is recompiled from the published facts
// and references only (the certificate by version, re-validated), encrypted
// for each target node, and carries no draft; the stored compile source holds
// no key material.
func TestSystemRepublishSiteRuntimeV2StopOverlayNeverCarriesDrafts(t *testing.T) {
	fixture := newPublishFixture(t)
	tlsSite := fixture.createSiteWithPortSets(t, "overlay-v2-tls.example", []string{"80"}, []string{"443"}, true).Site
	certificateVersion := seedSiteRuntimeV2CertificateBinding(t, fixture, tlsSite)
	plainSite := fixture.createSite(t, "overlay-v2-plain.example", 8081, false).Site
	privateKey := capabilitytest.SeedNodePublicationIdentityForTest(t, fixture.pool, fixture.scopeID, fixture.userID,
		fixture.nodeID, &agentv1.AgentCapabilities{AgentVersion: "1.0.35", BuildId: "overlay-v2", OperatingSystem: "linux",
			Architecture: "amd64", Features: siteRuntimeV2NodeFeatures()}, publishTestClock.Add(-10*time.Minute), true).
		ArtifactPrivateKey
	base, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "overlay-v2-base", fixture.nodeID,
		siteRuntimeV2Schema))
	if err != nil {
		t.Fatal(err)
	}
	finishPublishDeployment(t, fixture, base, &base.ConfigVersionID, nil)
	republisher, err := NewSystemRepublisher(fixture.service, SystemRepublisherConfig{WorkerID: "syspub-v2", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	scope := &SystemRepublishScope{Pool: fixture.pool, ScopeID: fixture.scopeID, UserID: fixture.userID,
		SiteID: plainSite.ID, fixture: fixture, republisher: republisher}

	// Drafts: both sites' origins, and a new site.
	scope.EditSiteOrigin(t, tlsSite.ID, "203.0.113.177")
	scope.EditSiteOrigin(t, plainSite.ID, "203.0.113.188")
	fixture.createSite(t, "overlay-v2-draft-only.example", 8082, false)
	drafts := [][]byte{[]byte("203.0.113.177"), []byte("203.0.113.188"), []byte("overlay-v2-draft-only.example")}

	scope.HoldForSecondaryVerification(t, plainSite.ID, true, SystemTriggerTrafficEnforcement)
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != SystemOutcomePublished {
		t.Fatalf("v2 stop with drafts: %+v error=%v", attempt, attempt.ErrorClass)
	}
	stopped := scope.LatestPublication(t)
	if bytes.Contains(stopped.Snapshot, []byte(plainSite.ID.String())) || !bytes.Contains(stopped.Snapshot, []byte(tlsSite.ID.String())) ||
		!bytes.Contains(stopped.Snapshot, []byte(certificateVersion.String())) {
		t.Fatal("v2 stop overlay did not take out exactly the stopped site, keeping the certificate reference")
	}
	plaintext := openLatestNodeArtifact(t, fixture, privateKey)
	for _, draft := range drafts {
		if bytes.Contains(stopped.Snapshot, draft) || bytes.Contains(plaintext, draft) {
			t.Fatalf("v2 stop overlay carries draft %s", draft)
		}
	}
	if !bytes.Contains(plaintext, []byte("203.0.113.10")) {
		t.Fatal("decrypted node artifact lacks the published origin")
	}

	// The compile source is facts and references, never key material.
	var stored []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT convert_to(string_agg(COALESCE(spec::text,'')||
		COALESCE(site_runtime_v2::text,''),''),'UTF8') FROM edge_publication_compile_inputs
		WHERE configuration_scope_id=$1`, fixture.scopeID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stored, []byte(certificateVersion.String())) {
		t.Fatal("v2 compile source lacks the certificate reference")
	}
	for _, secret := range [][]byte{[]byte("PRIVATE KEY"), []byte("site-runtime-v2:" + certificateVersion.String()),
		[]byte("site-runtime-v2-test-key"), []byte(hex.EncodeToString(bytes.Repeat([]byte{0x01}, 16))),
		[]byte("private_key"), []byte("ciphertext"), []byte(hex.EncodeToString(privateKey)), plaintext[:64]} {
		if bytes.Contains(stored, secret) {
			t.Fatalf("compile source carries secret material %q", secret)
		}
	}

	// Release: the site comes back from the published facts, without drafts.
	scope.SettleDeployments(t)
	scope.HoldForSecondaryVerification(t, plainSite.ID, false, SystemTriggerTrafficEnforcement)
	scope.Run(t)
	released := scope.LatestPublication(t)
	if !bytes.Contains(released.Snapshot, []byte(plainSite.ID.String())) {
		t.Fatal("v2 release did not put the site back")
	}
	plaintext = openLatestNodeArtifact(t, fixture, privateKey)
	for _, draft := range drafts {
		if bytes.Contains(released.Snapshot, draft) || bytes.Contains(plaintext, draft) {
			t.Fatalf("v2 release carries draft %s", draft)
		}
	}

	// A revoked certificate version is not redelivered by reference.
	scope.SettleDeployments(t)
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO certificate_asset_revocation_facts(tenant_scope_id,asset_id,version_id,actor_scope_id,
			expected_asset_revision,resulting_asset_revision,reason,request_id,revoked_by_user_id,revoked_at)
			SELECT tenant_scope_id,asset_id,id,tenant_scope_id,2,3,'overlay test','overlay-revoke',$2,clock_timestamp()
			FROM certificate_asset_versions WHERE id=$1`, certificateVersion, fixture.userID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	scope.HoldForSecondaryVerification(t, plainSite.ID, true, SystemTriggerTrafficEnforcement)
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome == SystemOutcomePublished || attempt.ErrorClass == nil {
		t.Fatalf("v2 overlay redelivered a revoked certificate reference: %+v", attempt)
	}
}

// openLatestNodeArtifact decrypts the latest publication's artifact for the
// fixture node with its private key, as the node does.
func openLatestNodeArtifact(t *testing.T, fixture *publishFixture, privateKey []byte) []byte {
	t.Helper()
	var deploymentID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT deployment.id
		FROM edge_config_publications publication
		JOIN node_deployments deployment ON deployment.rollout_id=publication.rollout_id AND deployment.node_id=$2
		WHERE publication.configuration_scope_id=$1 ORDER BY publication.source_revision DESC LIMIT 1`,
		fixture.scopeID, fixture.nodeID).Scan(&deploymentID); err != nil {
		t.Fatal(err)
	}
	release, err := OpenSiteObjectReleaseForTest(t.Context(), fixture.pool, deploymentID, privateKey)
	if err != nil {
		t.Fatalf("node release: %v", err)
	}
	bundle := release.Bundle
	var rendered []byte
	for _, content := range bundle.Files {
		rendered = append(rendered, content...)
	}
	return rendered
}
