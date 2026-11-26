//go:build integration

package edgepublish

import (
	"bytes"
	"strconv"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// control 1129 rev3: a site rebound to another certificate whose publication
// reached the nodes kept serving the old one, the site object still named the
// old version. The binding's republication (certificate_renewal, as
// certificatepublish.RequestBindingRepublicationTx queues it for a manual
// scope) moves the site object to the new version: on the clean path by
// recompiling, with unpublished drafts through the stop overlay, which only
// switches to another certificate once its publication succeeded (material
// first). StaleCertificateBindingTx finds a binding left so, once.
func TestCertificateRebindRepublishesSiteObjectOnceDelivered(t *testing.T) {
	fixture := newPublishFixture(t)
	ctx := t.Context()
	tlsSite := fixture.createSiteWithPortSets(t, "rebind-tls.example", []string{"80"}, []string{"443"}, true).Site
	versionA := seedSiteRuntimeV2CertificateBinding(t, fixture, tlsSite)
	// The next certificates, each held by an HTTP site and covering both
	// domains, published with the base (the tenant's chain is clean).
	holder := func(domain string, port int) siteRuntimeV2CertificateSeed {
		t.Helper()
		site := fixture.createSite(t, domain, port, false).Site
		return seedSiteRuntimeV2CertificateBindingWithOptions(t, fixture, site, siteRuntimeV2CertificateSeedOptions{
			sans: []string{tlsSite.Domain, site.Domain}})
	}
	certificateB, certificateC := holder("rebind-holder-b.example", 8091), holder("rebind-holder-c.example", 8092)
	capabilitytest.SeedNodePublicationIdentityForTest(t, fixture.pool, fixture.scopeID, fixture.userID,
		fixture.nodeID, &agentv1.AgentCapabilities{AgentVersion: "1.0.35", BuildId: "rebind", OperatingSystem: "linux",
			Architecture: "amd64", Features: siteRuntimeV2NodeFeatures()}, publishTestClock.Add(-10*time.Minute), true)
	base, err := fixture.service.Publish(ctx, siteRuntimeV2PublishRequest(fixture, "rebind-base", fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatal(err)
	}
	finishPublishDeployment(t, fixture, base, &base.ConfigVersionID, nil)
	republisher, err := NewSystemRepublisher(fixture.service, SystemRepublisherConfig{WorkerID: "syspub-rebind", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	scope := &SystemRepublishScope{Pool: fixture.pool, ScopeID: fixture.scopeID, UserID: fixture.userID,
		SiteID: tlsSite.ID, fixture: fixture, republisher: republisher}
	var rolloutRevision int64
	if err := fixture.pool.QueryRow(ctx, `SELECT revision FROM rollouts WHERE id=$1`, base.RolloutID).Scan(&rolloutRevision); err != nil {
		t.Fatal(err)
	}
	// settle marks the site's binding revision published to every node.
	settle := func(siteID uuid.UUID, revision int64) {
		t.Helper()
		key := "certificate.publication/" + fixture.scopeID.String() + "/" + siteID.String() + "/" + strconv.FormatInt(revision, 10)
		if err := pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
			for _, state := range []string{"leased", "succeeded"} {
				var result *uuid.UUID
				var resultRevision *int64
				if state == "succeeded" {
					id := uuid.New()
					result, resultRevision = &id, &rolloutRevision
				}
				var config, rollout *uuid.UUID
				if state == "succeeded" {
					config, rollout = &base.ConfigVersionID, &base.RolloutID
				}
				if _, err := tx.Exec(ctx, `INSERT INTO certificate_publication_intent_state_facts(
					tenant_scope_id,site_id,binding_revision,sequence,state,attempt,idempotency_key,
					lease_owner,lease_token,lease_expires_at,occurred_at,
					publication_id,publication_revision,config_version_id,rollout_id,rollout_revision)
					SELECT $1,$2,$3,max(sequence)+1,$4,1,$5,'rebind-test',$6,transaction_timestamp()+interval '1 minute',
					  transaction_timestamp(),$7,$8,$9,$10,$8
					FROM certificate_publication_intent_state_facts
					WHERE tenant_scope_id=$1 AND site_id=$2 AND binding_revision=$3`,
					fixture.scopeID, siteID, revision, state, key, uuid.NewSHA1(siteID, []byte(key)),
					result, resultRevision, config, rollout); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// rebind binds the TLS site to the certificate at revision, its
	// publication in flight.
	rebind := func(seeded siteRuntimeV2CertificateSeed, revision int64) uuid.UUID {
		t.Helper()
		if err := pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO certificate_site_binding_facts(
				tenant_scope_id,site_id,sequence,action,asset_id,version_id,is_default,expected_revision,
				resulting_revision,request_id,actor_scope_id,changed_by_user_id,changed_at
				) VALUES($1,$2,$3::bigint,'bind',$4,$5,true,$3::bigint-1,$3::bigint,$6,$1,$7,$8)`, fixture.scopeID, tlsSite.ID, revision,
				seeded.assetID, seeded.versionID, "rebind-"+strconv.FormatInt(revision, 10), fixture.userID, publishTestClock); err != nil {
				return err
			}
			insertSiteRuntimeV2PublicationIntent(t, tx, fixture.scopeID, tlsSite.ID, revision)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return seeded.versionID
	}
	// request is the manual scope's half of RequestBindingRepublicationTx.
	request := func() {
		t.Helper()
		if err := pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
			var current int64
			if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
				fixture.scopeID).Scan(&current); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, fixture.scopeID); err != nil {
				return err
			}
			if err := RecordSystemRevisionSegmentTx(ctx, tx, fixture.scopeID, current, SystemTriggerCertificateRenewal); err != nil {
				return err
			}
			return RequestSystemRepublicationTx(ctx, tx, SystemRepublicationRequest{ScopeID: fixture.scopeID,
				Trigger: SystemTriggerCertificateRenewal})
		}); err != nil {
			t.Fatal(err)
		}
	}
	stale := func() (uuid.UUID, int64, bool) {
		t.Helper()
		var siteID uuid.UUID
		var revision int64
		var found bool
		if err := pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
			var err error
			siteID, revision, found, err = StaleCertificateBindingTx(ctx, tx, fixture.scopeID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return siteID, revision, found
	}
	expectServing := func(phase string, overlay bool, serving, retired uuid.UUID, absent ...[]byte) {
		t.Helper()
		if attempt := scope.LatestAttempt(t); attempt.Outcome != SystemOutcomePublished {
			t.Fatalf("%s: republication %+v error=%v", phase, attempt, attempt.ErrorClass)
		}
		var overlaid bool
		if err := fixture.pool.QueryRow(ctx, `SELECT inputs.overlay FROM edge_config_publications publication
			JOIN edge_publication_compile_inputs inputs ON inputs.config_version_id=publication.config_version_id
			WHERE publication.configuration_scope_id=$1 ORDER BY publication.source_revision DESC LIMIT 1`,
			fixture.scopeID).Scan(&overlaid); err != nil || overlaid != overlay {
			t.Fatalf("%s: republication overlay=%t (want %t) err=%v", phase, overlaid, overlay, err)
		}
		snapshot := scope.LatestPublication(t).Snapshot
		if !bytes.Contains(snapshot, []byte(serving.String())) || bytes.Contains(snapshot, []byte(retired.String())) {
			t.Fatalf("BUG %s: site object does not name certificate version %s only", phase, serving)
		}
		for _, value := range absent {
			if bytes.Contains(snapshot, value) {
				t.Fatalf("%s: republication carries draft %s", phase, value)
			}
		}
		scope.SettleDeployments(t)
	}
	settle(tlsSite.ID, 1)
	if _, _, found := stale(); found {
		t.Fatal("the published binding is reported stale")
	}

	// Clean path, the stock case: B reached the nodes, nothing republished.
	versionB := rebind(certificateB, 2)
	if _, _, found := stale(); found {
		t.Fatal("a binding whose publication is in flight is reported stale")
	}
	settle(tlsSite.ID, 2)
	if siteID, revision, found := stale(); !found || siteID != tlsSite.ID || revision != 2 {
		t.Fatalf("stale binding = %s/%d found=%t, want %s/2", siteID, revision, found, tlsSite.ID)
	}
	request()
	if _, _, found := stale(); found {
		t.Fatal("a binding whose republication is queued is reported stale again")
	}
	scope.Run(t)
	expectServing("clean rebind", false, versionB, versionA)
	if _, _, found := stale(); found {
		t.Fatal("the republished binding is still reported stale")
	}

	// Overlay path: an unpublished draft, then a rebind to C. In flight the
	// overlay keeps B (the nodes may not hold C yet); delivered, it names C.
	draft := []byte("203.0.113.199")
	scope.EditSiteOrigin(t, tlsSite.ID, string(draft))
	versionC := rebind(certificateC, 3)
	request()
	scope.Run(t)
	expectServing("overlay, C in flight", true, versionB, versionC, draft)
	settle(tlsSite.ID, 3)
	if siteID, revision, found := stale(); !found || siteID != tlsSite.ID || revision != 3 {
		t.Fatalf("stale binding after the overlay = %s/%d found=%t", siteID, revision, found)
	}
	request()
	scope.Run(t)
	expectServing("overlay, C delivered", true, versionC, versionB, draft)
	if _, _, found := stale(); found {
		t.Fatal("the overlay-republished binding is still reported stale")
	}
}
