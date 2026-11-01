//go:build integration

package edgepublish

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallactioncontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// autodefense-ux3 / migration 608: the firewall action on/off switch keeps
// the revision, a disabled own policy is not delivered (the real
// loadFirewallActionFacts), the guard refuses anything but the toggle, and
// the switch is the own policy's: an inheriting site cannot be switched.

type allowFirewallActionAuthorizer struct{}

func (allowFirewallActionAuthorizer) Authorize(context.Context, pgx.Tx, firewallcontrol.Actor, uuid.UUID, string) error {
	return nil
}

type firewallEnabledFixture struct {
	publish *publishFixture
	service *firewallactioncontrol.Service
	actor   firewallcontrol.Actor
	siteID  uuid.UUID
}

func newFirewallEnabledFixture(t *testing.T) firewallEnabledFixture {
	t.Helper()
	publish := newPublishFixture(t)
	created := publish.createSite(t, "fw-enabled-608.example.test", 80, false)
	store := firewallactioncontrol.NewStore(publish.pool, allowFirewallActionAuthorizer{}, func() time.Time { return publishTestClock })
	return firewallEnabledFixture{publish: publish, service: firewallactioncontrol.NewService(store), siteID: created.Site.ID,
		actor: firewallcontrol.Actor{UserID: publish.userID, ScopeID: publish.scopeID, ScopeKind: "tenant",
			Permissions: []string{firewallcontrol.PermissionRead, firewallcontrol.PermissionManage}}}
}

func enabledTestPolicy(engage uint64) firewallactioncontrol.PolicyInput {
	return firewallactioncontrol.PolicyInput{
		NormalAction: firewallactioncontrol.ActionDisconnect, EscalatedAction: firewallactioncontrol.ActionNFTables,
		EngageThreshold: engage, RecoverThreshold: 10, RecoveryWindows: 5,
		BlockNetworks: []string{"203.0.113.0/24"}, TrustedProxies: []string{}, TrustedCrawlers: []firewallactioncontrol.TrustedCrawler{},
		ReturnPage: firewallactioncontrol.ReturnPage{Status: 429, ContentType: "text/plain; charset=utf-8", Body: "limited"},
	}
}

func (fixture firewallEnabledFixture) put(t *testing.T, expected int64, engage uint64) firewallactioncontrol.Policy {
	t.Helper()
	result, err := fixture.service.Put(t.Context(), firewallactioncontrol.PutRequest{Actor: fixture.actor,
		TargetScopeID: fixture.publish.scopeID, SiteID: fixture.siteID, ExpectedRevision: expected,
		IdempotencyKey: uuid.NewString(), RequestID: uuid.NewString(), Policy: enabledTestPolicy(engage)})
	if err != nil {
		t.Fatalf("Put(%d) error = %v", expected, err)
	}
	return result.Policy
}

func (fixture firewallEnabledFixture) setEnabled(t *testing.T, expected int64, enabled bool) (firewallactioncontrol.WriteResult, error) {
	t.Helper()
	return fixture.service.SetEnabled(t.Context(), firewallactioncontrol.SetEnabledRequest{Actor: fixture.actor,
		TargetScopeID: fixture.publish.scopeID, SiteID: fixture.siteID, ExpectedRevision: expected,
		IdempotencyKey: uuid.NewString(), RequestID: uuid.NewString(), Enabled: enabled})
}

// delivered reports whether the edge compile would deliver the site's own
// firewall action (the real fact query, no tenant default saved).
func (fixture firewallEnabledFixture) delivered(t *testing.T) bool {
	t.Helper()
	var facts []firewallActionFact
	err := pgx.BeginFunc(t.Context(), fixture.publish.pool, func(tx pgx.Tx) error {
		var err error
		facts, err = loadFirewallActionFacts(t.Context(), tx, fixture.publish.scopeID, []siteRuntimeV2Site{{ID: fixture.siteID.String()}})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return len(facts) == 1 && facts[0].siteID == fixture.siteID
}

func (fixture firewallEnabledFixture) head(t *testing.T) (revision int64, enabled bool, digest []byte) {
	t.Helper()
	if err := fixture.publish.pool.QueryRow(t.Context(), `SELECT revision,enabled,document_sha256 FROM firewall_action_policy_heads
		WHERE tenant_scope_id=$1 AND site_id=$2`, fixture.publish.scopeID, fixture.siteID).Scan(&revision, &enabled, &digest); err != nil {
		t.Fatal(err)
	}
	return revision, enabled, digest
}

func (fixture firewallEnabledFixture) auditCount(t *testing.T, action string) int {
	t.Helper()
	var count int
	if err := fixture.publish.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action=$2`,
		fixture.publish.scopeID, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestFirewallActionEnabled608ToggleKeepsRevisionAndStopsDelivery(t *testing.T) {
	fixture := newFirewallEnabledFixture(t)
	first := fixture.put(t, 0, 300)
	if !first.Enabled || !first.Delivered || !fixture.delivered(t) {
		t.Fatalf("new policy enabled=%v delivered=%v", first.Enabled, first.Delivered)
	}
	revision, _, digest := fixture.head(t)
	before := fixture.publish.sourceRevision()

	off, err := fixture.setEnabled(t, revision, false)
	if err != nil || off.Policy.Enabled || off.Policy.Delivered || off.Policy.Revision != revision {
		t.Fatalf("disable = (%+v, %v)", off.Policy, err)
	}
	afterRevision, enabled, afterDigest := fixture.head(t)
	if afterRevision != revision || enabled || string(afterDigest) != string(digest) {
		t.Fatalf("disable changed the head: revision %d->%d enabled=%v", revision, afterRevision, enabled)
	}
	if fixture.delivered(t) {
		t.Fatal("a disabled policy is still delivered")
	}
	if after := fixture.publish.sourceRevision(); after <= before {
		t.Fatalf("disable did not advance the source revision: %d -> %d", before, after)
	}
	var revisions int
	if err := fixture.publish.pool.QueryRow(t.Context(), `SELECT count(*) FROM firewall_action_policy_revisions WHERE site_id=$1`,
		fixture.siteID).Scan(&revisions); err != nil || revisions != 1 {
		t.Fatalf("disable wrote a revision: %d (%v)", revisions, err)
	}
	if view, err := fixture.service.Get(t.Context(), firewallactioncontrol.ReadRequest{Actor: fixture.actor,
		TargetScopeID: fixture.publish.scopeID, SiteID: fixture.siteID}); err != nil || view.Enabled || view.Delivered || view.Inherited {
		t.Fatalf("Get() after disable = (%+v, %v)", view, err)
	}

	// A save while disabled keeps it disabled (and undelivered).
	second := fixture.put(t, revision, 400)
	if second.Enabled || second.Revision != revision+1 || fixture.delivered(t) {
		t.Fatalf("save while disabled = %+v delivered=%v", second, fixture.delivered(t))
	}
	if _, err := fixture.setEnabled(t, revision, true); !errors.Is(err, firewallactioncontrol.ErrRevisionConflict) {
		t.Fatalf("stale If-Match error = %v", err)
	}
	on, err := fixture.setEnabled(t, second.Revision, true)
	if err != nil || !on.Policy.Enabled || on.Policy.Revision != second.Revision || !fixture.delivered(t) {
		t.Fatalf("enable = (%+v, %v)", on.Policy, err)
	}
	if fixture.auditCount(t, "firewall.action.disable") != 1 || fixture.auditCount(t, "firewall.action.enable") != 1 {
		t.Fatal("enable/disable audit events missing")
	}
	// Setting the current state is an audited no-op: no source revision.
	before = fixture.publish.sourceRevision()
	if _, err := fixture.setEnabled(t, second.Revision, true); err != nil {
		t.Fatal(err)
	}
	if after := fixture.publish.sourceRevision(); after != before {
		t.Fatalf("no-op toggle advanced the source revision: %d -> %d", before, after)
	}
}

func TestFirewallActionEnabled608GuardAllowsOnlyTheToggle(t *testing.T) {
	fixture := newFirewallEnabledFixture(t)
	fixture.put(t, 0, 300)
	pool, scopeID, siteID := fixture.publish.pool, fixture.publish.scopeID, fixture.siteID
	for name, statement := range map[string]string{
		"toggle_with_revision":  `UPDATE firewall_action_policy_heads SET enabled=false,revision=revision+1 WHERE tenant_scope_id=$1 AND site_id=$2`,
		"toggle_with_state":     `UPDATE firewall_action_policy_heads SET enabled=false,deployment_state='failed' WHERE tenant_scope_id=$1 AND site_id=$2`,
		"toggle_with_inherited": `UPDATE firewall_action_policy_heads SET enabled=false,inherited=true WHERE tenant_scope_id=$1 AND site_id=$2`,
	} {
		_, err := pool.Exec(t.Context(), statement, scopeID, siteID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P6061" {
			t.Fatalf("%s: error = %v", name, err)
		}
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM firewall_action_policy_heads WHERE tenant_scope_id=$1 AND site_id=$2`, scopeID, siteID); err == nil {
		t.Fatal("head delete accepted")
	}
	if _, err := pool.Exec(t.Context(), `UPDATE firewall_action_policy_heads SET enabled=false WHERE tenant_scope_id=$1 AND site_id=$2`, scopeID, siteID); err != nil {
		t.Fatalf("plain toggle refused: %v", err)
	}
}

func TestFirewallActionEnabled608InheritingSiteHasNoSwitch(t *testing.T) {
	fixture := newFirewallEnabledFixture(t)
	if _, err := fixture.setEnabled(t, 1, false); !errors.Is(err, firewallactioncontrol.ErrNotFound) {
		t.Fatalf("never configured site error = %v", err)
	}
	first := fixture.put(t, 0, 300)
	if _, err := fixture.setEnabled(t, first.Revision, false); err != nil {
		t.Fatal(err)
	}
	inherited, err := fixture.service.Inherit(t.Context(), firewallactioncontrol.InheritRequest{Actor: fixture.actor,
		TargetScopeID: fixture.publish.scopeID, SiteID: fixture.siteID, ExpectedRevision: first.Revision,
		IdempotencyKey: uuid.NewString(), RequestID: uuid.NewString()})
	if err != nil || !inherited.Policy.Inherited || !inherited.Policy.Enabled {
		t.Fatalf("inherit = (%+v, %v)", inherited.Policy, err)
	}
	if _, err := fixture.setEnabled(t, inherited.Policy.Revision, true); !errors.Is(err, firewallactioncontrol.ErrNotFound) {
		t.Fatalf("inheriting site switch error = %v", err)
	}
	// The next own policy starts enabled, though the head was disabled before it inherited.
	again := fixture.put(t, inherited.Policy.Revision, 500)
	if !again.Enabled || again.Inherited || !fixture.delivered(t) {
		t.Fatalf("override after disabled inherit = %+v delivered=%v", again, fixture.delivered(t))
	}
}
