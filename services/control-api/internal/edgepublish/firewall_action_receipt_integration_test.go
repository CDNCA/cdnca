//go:build integration

package edgepublish

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallactioncontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// the receipt worker settles firewall action candidates from the
// node deployments of the real releases carrying them.

type receiptAllowAuthorizer struct{}

func (receiptAllowAuthorizer) Authorize(context.Context, pgx.Tx, firewallcontrol.Actor, uuid.UUID, string) error {
	return nil
}

type firewallReceiptFixture struct {
	*publishFixture
	service *firewallactioncontrol.Service
	worker  *firewallactioncontrol.ReceiptWorker
	actor   firewallcontrol.Actor
	clock   time.Time
}

func newFirewallReceiptFixture(t *testing.T) (*firewallReceiptFixture, uuid.UUID) {
	t.Helper()
	base := newPublishFixture(t)
	site := base.createSite(t, "fw-receipt.example.test", 80, false)
	fixture := &firewallReceiptFixture{publishFixture: base, clock: publishTestClock.Add(time.Minute)}
	now := func() time.Time { return fixture.clock }
	store := firewallactioncontrol.NewStore(base.pool, receiptAllowAuthorizer{}, now)
	fixture.service = firewallactioncontrol.NewService(store)
	worker, err := firewallactioncontrol.NewReceiptWorker(base.pool, now)
	if err != nil {
		t.Fatal(err)
	}
	fixture.worker = worker
	fixture.actor = firewallcontrol.Actor{UserID: base.userID, ScopeID: base.scopeID, ScopeKind: "tenant",
		Permissions: []string{firewallcontrol.PermissionRead, firewallcontrol.PermissionManage}}
	return fixture, site.Site.ID
}

func receiptPolicy(engage uint64) firewallactioncontrol.PolicyInput {
	return firewallactioncontrol.PolicyInput{
		NormalAction: firewallactioncontrol.ActionDisconnect, EscalatedAction: firewallactioncontrol.ActionNFTables,
		EngageThreshold: engage, RecoverThreshold: 10, RecoveryWindows: 5,
		BlockNetworks: []string{"203.0.113.0/24"}, TrustedProxies: []string{}, TrustedCrawlers: []firewallactioncontrol.TrustedCrawler{},
		ReturnPage: firewallactioncontrol.ReturnPage{Status: 429, ContentType: "text/plain; charset=utf-8", Body: "limited"},
	}
}

func (fixture *firewallReceiptFixture) put(t *testing.T, siteID uuid.UUID, expected int64, engage uint64) firewallactioncontrol.Policy {
	t.Helper()
	fixture.clock = fixture.clock.Add(time.Second)
	result, err := fixture.service.Put(t.Context(), firewallactioncontrol.PutRequest{Actor: fixture.actor,
		TargetScopeID: fixture.scopeID, SiteID: siteID, ExpectedRevision: expected, IdempotencyKey: uuid.NewString(),
		RequestID: uuid.NewString(), Policy: receiptPolicy(engage)})
	if err != nil {
		t.Fatal(err)
	}
	return result.Policy
}

func (fixture *firewallReceiptFixture) putDefault(t *testing.T, expected int64, engage uint64) {
	t.Helper()
	fixture.clock = fixture.clock.Add(time.Second)
	if _, err := fixture.service.PutDefault(t.Context(), firewallactioncontrol.DefaultPutRequest{Actor: fixture.actor,
		TargetScopeID: fixture.scopeID, ExpectedRevision: expected, IdempotencyKey: uuid.NewString(),
		RequestID: uuid.NewString(), Policy: receiptPolicy(engage)}); err != nil {
		t.Fatal(err)
	}
}

func (fixture *firewallReceiptFixture) get(t *testing.T, siteID uuid.UUID) firewallactioncontrol.Policy {
	t.Helper()
	policy, err := fixture.service.Get(t.Context(), firewallactioncontrol.ReadRequest{Actor: fixture.actor,
		TargetScopeID: fixture.scopeID, SiteID: siteID})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func (fixture *firewallReceiptFixture) publish(t *testing.T, key string) PublishResult {
	t.Helper()
	result, err := fixture.publishFixture.service.Publish(t.Context(), fixture.publishRequest(key, fixture.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (fixture *firewallReceiptFixture) tick(t *testing.T) {
	t.Helper()
	fixture.clock = fixture.clock.Add(time.Second)
	if _, err := fixture.worker.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// deliveredBinding is the firewall action binding siteID carries in the
// release (nil: none).
func deliveredBinding(t *testing.T, fixture *firewallReceiptFixture, result PublishResult, siteID uuid.UUID) *siteRuntimeV2FirewallActionBinding {
	t.Helper()
	var snapshot []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT canonical_snapshot FROM config_versions WHERE id=$1`,
		result.ConfigVersionID).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	var document siteRuntimeV2Document
	if err := json.Unmarshal(snapshot, &document); err != nil {
		t.Fatal(err)
	}
	for _, site := range document.Sites {
		if site.ID == siteID.String() {
			return site.FirewallAction
		}
	}
	t.Fatalf("site %s not in release %s", siteID, result.ConfigVersionID)
	return nil
}

// failPublishDeployment is the node refusing the release.
func failPublishDeployment(t *testing.T, fixture *firewallReceiptFixture, publication PublishResult) {
	t.Helper()
	payload := []byte("fw-receipt-node-refused")
	digest := sha256.Sum256(payload)
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		var deploymentID uuid.UUID
		var attempt int
		if err := tx.QueryRow(t.Context(), `SELECT id,attempt FROM node_deployments WHERE rollout_id=$1 AND node_id=$2`,
			publication.RolloutID, fixture.nodeID).Scan(&deploymentID, &attempt); err != nil {
			return err
		}
		for index, state := range []string{"delivered", "failed"} {
			at := publishTestClock.Add(time.Duration(index+1) * time.Second)
			if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(
				id,deployment_id,event_id,attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, uuid.New(), deploymentID, uuid.New(), attempt,
				index+1, state, payload, digest[:], at); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state=$2,updated_at=$3 WHERE id=$1 AND attempt=$4`,
				deploymentID, state, at, attempt); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func outboxStates(t *testing.T, fixture *firewallReceiptFixture, siteID uuid.UUID) map[int64]string {
	t.Helper()
	rows, err := fixture.pool.Query(t.Context(), `SELECT revision,state FROM firewall_action_publication_outbox
		WHERE tenant_scope_id=$1 AND site_id=$2`, fixture.scopeID, siteID)
	if err != nil {
		t.Fatal(err)
	}
	result := map[int64]string{}
	for rows.Next() {
		var revision int64
		var state string
		if err := rows.Scan(&revision, &state); err != nil {
			t.Fatal(err)
		}
		result[revision] = state
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestFirewallActionReceiptAppliedThenRejectedKeepsLKG(t *testing.T) {
	fixture, siteID := newFirewallReceiptFixture(t)
	saved := fixture.put(t, siteID, 0, 200)
	// Nothing carries revision 1 yet: it stays pending without spending attempts.
	fixture.tick(t)
	if states := outboxStates(t, fixture, siteID); states[1] != "pending" {
		t.Fatalf("unpublished candidate outbox = %v", states)
	}

	first := fixture.publish(t, "fw-receipt-first")
	if binding := deliveredBinding(t, fixture, first, siteID); binding == nil || binding.PolicyRevision != 1 {
		t.Fatalf("first release binding = %+v", binding)
	}
	fixture.tick(t)
	if states := outboxStates(t, fixture, siteID); states[1] != "published" {
		t.Fatalf("carried candidate outbox = %v", states)
	}
	if view := fixture.get(t, siteID); view.DeploymentState != firewallactioncontrol.StatePending || view.ActiveRevision != 0 {
		t.Fatalf("view before the node report = %+v", view)
	}
	finishPublishDeployment(t, fixture.publishFixture, first, &first.ConfigVersionID, nil)
	fixture.tick(t)
	view := fixture.get(t, siteID)
	if view.DeploymentState != firewallactioncontrol.StateActive || view.ActiveRevision != 1 || view.LKGRevision != 1 || view.ID != saved.ID {
		t.Fatalf("applied view = %+v", view)
	}
	if states := outboxStates(t, fixture, siteID); states[1] != "acked" {
		t.Fatalf("applied outbox = %v", states)
	}

	fixture.put(t, siteID, 1, 300)
	second := fixture.publish(t, "fw-receipt-second")
	if binding := deliveredBinding(t, fixture, second, siteID); binding == nil || binding.PolicyRevision != 2 {
		t.Fatalf("second release binding = %+v", binding)
	}
	failPublishDeployment(t, fixture, second)
	fixture.tick(t)
	view = fixture.get(t, siteID)
	if view.DeploymentState != firewallactioncontrol.StateFailed || view.Revision != 2 || view.ActiveRevision != 1 || view.LKGRevision != 1 {
		t.Fatalf("rejected view = %+v", view)
	}
	if states := outboxStates(t, fixture, siteID); states[2] != "failed" || states[1] != "acked" {
		t.Fatalf("rejected outbox = %v", states)
	}
	// The scope's next release delivers the LKG, not the rejected candidate.
	if _, err := fixture.pool.Exec(t.Context(), `SELECT advance_edge_configuration_scope_revision($1)`, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	third := fixture.publish(t, "fw-receipt-third")
	if binding := deliveredBinding(t, fixture, third, siteID); binding == nil || binding.PolicyRevision != 1 {
		t.Fatalf("release after the rejection binding = %+v, want the LKG revision 1", binding)
	}
}

func TestFirewallActionReceiptSupersededCandidateIsClosed(t *testing.T) {
	fixture, siteID := newFirewallReceiptFixture(t)
	fixture.put(t, siteID, 0, 200)
	fixture.put(t, siteID, 1, 300) // replaces revision 1 before any release
	fixture.tick(t)
	if states := outboxStates(t, fixture, siteID); states[1] != "failed" || states[2] != "pending" {
		t.Fatalf("superseded outbox = %v", states)
	}
	release := fixture.publish(t, "fw-receipt-superseded")
	finishPublishDeployment(t, fixture.publishFixture, release, &release.ConfigVersionID, nil)
	fixture.tick(t)
	if view := fixture.get(t, siteID); view.DeploymentState != firewallactioncontrol.StateActive || view.ActiveRevision != 2 {
		t.Fatalf("view = %+v", view)
	}
}

func TestFirewallActionReceiptTenantDefaultKeepsLKG(t *testing.T) {
	fixture, siteID := newFirewallReceiptFixture(t)
	fixture.putDefault(t, 0, 200)
	first := fixture.publish(t, "fw-receipt-default-first")
	if binding := deliveredBinding(t, fixture, first, siteID); binding == nil || binding.PolicyRevision != 1 ||
		binding.PolicyID != firewallactioncontrol.InheritedPolicyID(fixture.scopeID, siteID).String() {
		t.Fatalf("inherited binding = %+v", binding)
	}
	finishPublishDeployment(t, fixture.publishFixture, first, &first.ConfigVersionID, nil)
	fixture.tick(t)
	if state, active, lkg := defaultReceipt(t, fixture); state != "active" || active != 1 || lkg != 1 {
		t.Fatalf("applied default = %s/%d/%d", state, active, lkg)
	}

	fixture.putDefault(t, 1, 300)
	if state, active, lkg := defaultReceipt(t, fixture); state != "pending" || active != 1 || lkg != 1 {
		t.Fatalf("saved default = %s/%d/%d", state, active, lkg)
	}
	second := fixture.publish(t, "fw-receipt-default-second")
	if binding := deliveredBinding(t, fixture, second, siteID); binding == nil || binding.PolicyRevision != 2 {
		t.Fatalf("second inherited binding = %+v", binding)
	}
	failPublishDeployment(t, fixture, second)
	fixture.tick(t)
	if state, active, lkg := defaultReceipt(t, fixture); state != "failed" || active != 1 || lkg != 1 {
		t.Fatalf("rejected default = %s/%d/%d", state, active, lkg)
	}
	if _, err := fixture.pool.Exec(t.Context(), `SELECT advance_edge_configuration_scope_revision($1)`, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	third := fixture.publish(t, "fw-receipt-default-third")
	if binding := deliveredBinding(t, fixture, third, siteID); binding == nil || binding.PolicyRevision != 1 {
		t.Fatalf("release after the rejected default binding = %+v, want the LKG revision 1", binding)
	}
}

func defaultReceipt(t *testing.T, fixture *firewallReceiptFixture) (string, int64, int64) {
	t.Helper()
	var state string
	var active, lkg int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT deployment_state,active_revision,lkg_revision
		FROM firewall_action_tenant_defaults WHERE tenant_scope_id=$1`, fixture.scopeID).Scan(&state, &active, &lkg); err != nil {
		t.Fatal(err)
	}
	return state, active, lkg
}
