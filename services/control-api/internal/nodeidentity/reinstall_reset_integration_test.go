//go:build integration

package nodeidentity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// After "重装此节点" the new host
// got no service ticket, no signer trust and no site configuration, because
// every distributor still read the previous host's "delivered / applied"
// state. A re_enrollment resets that state in the enrollment transaction and
// republishes the node's scopes; history is kept.
func TestReEnrollmentResetsHostDeliveryState(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)
	republished := &republishRecorder{}
	service.store.WithReinstallRepublisher(republished.record)
	ctx := context.Background()

	fixture := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	first := validAuthorizeRequest(t, testCSR(t, false))
	first.EnrollmentToken = fixture.token
	enrollIdentity(t, service, first)

	// What the previous host left: a running configuration, a healthy
	// deployment of it and every distributor's "applied" state.
	configVersionID := seedTelemetryCurrentConfig(t, pool, fixture, uuid.New(), now.Add(-time.Hour))
	seedTelemetryDeploymentFact(t, pool, fixture, configVersionID, uuid.Nil, "apply", "healthy", "", now.Add(2*time.Minute))
	seedPreviousHostDeliveryState(t, pool, fixture.nodeID, now)
	if healthyCurrentHostDeployments(t, pool, fixture.nodeID) != 1 {
		t.Fatal("the previous host's healthy deployment does not count before the reinstall")
	}

	clock.set(now.Add(10 * time.Minute))
	reinstall := reenrollRequest(t, pool, fixture, clock)
	reinstall.EnrollmentToken = issueIdentityToken(t, pool, fixture, clock.now(), "re_enrollment")
	reinstall.GatewayInstanceID = "gateway-reinstall"
	enrollIdentity(t, service, reinstall)

	var count int
	for name, query := range map[string]string{
		// installationban.deliveryDue: no row, the ticket is due.
		"installation ban state":   `SELECT count(*) FROM installation_ban_node_state WHERE node_id=$1`,
		"signer trust enforced":    `SELECT count(*) FROM edge_signer_trust_node_state WHERE node_id=$1`,
		"security bans applied":    `SELECT count(*) FROM security_ban_node_state WHERE node_id=$1 AND applied_revision>=revision`,
		"autodefense answered":     `SELECT count(*) FROM autodefense_node_snapshots WHERE node_id=$1 AND receipt_revision IS NOT NULL`,
		"capability baseline":      `SELECT count(*) FROM edge_node_capability_marks WHERE node_id=$1`,
		"ssh access not pending":   `SELECT count(*) FROM node_ssh_access WHERE node_id=$1 AND state<>'pending'`,
		"configuration running":    `SELECT count(*) FROM node_config_state WHERE node_id=$1 AND current_config_version_id IS NOT NULL`,
		"current host deployments": `SELECT count(*) FROM node_deployments deployment WHERE node_id=$1 AND state='healthy' AND ` + edgedeployment.CurrentHostDeployment("deployment"),
	} {
		if err := pool.QueryRow(ctx, query, fixture.nodeID).Scan(&count); err != nil || count != 0 {
			t.Errorf("%s after reinstall = %d, %v", name, count, err)
		}
	}
	// History stays: the deployment and the security ban revision.
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM node_deployments WHERE node_id=$1)
		+ (SELECT count(*) FROM security_ban_node_state WHERE node_id=$1 AND revision=7)`, fixture.nodeID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("history after reinstall = %d, %v", count, err)
	}
	var revision int64
	var state string
	if err := pool.QueryRow(ctx, `SELECT revision,state FROM node_ssh_access WHERE node_id=$1`, fixture.nodeID).Scan(&revision, &state); err != nil ||
		revision != 4 || state != "pending" {
		t.Fatalf("ssh access after reinstall = %d %s, %v", revision, state, err)
	}
	// The node's scope is republished, inside the enrollment transaction.
	if len(republished.calls) != 1 || republished.calls[0].nodeID != fixture.nodeID ||
		len(republished.calls[0].scopes) != 1 || republished.calls[0].scopes[0] != fixture.scopeID ||
		republished.calls[0].cleared != 1 {
		t.Fatalf("republication after reinstall = %+v", republished.calls)
	}
	var reset bool
	if err := pool.QueryRow(ctx, `SELECT (payload->>'host_delivery_reset')::boolean FROM audit_events
		WHERE action='node_certificate.lifecycle.enroll' AND payload->>'authorization_id' IS NOT NULL
		ORDER BY stream_position DESC LIMIT 1`).Scan(&reset); err != nil || !reset {
		t.Fatalf("enroll audit host_delivery_reset = %v, %v", reset, err)
	}
}

// A node's first enrollment resets nothing and republishes nothing.
func TestFirstEnrollmentKeepsDeliveryState(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	service := newIdentityTestService(t, pool, newIdentityTestCA(t, now), &identityTestClock{value: now})
	republished := &republishRecorder{}
	service.store.WithReinstallRepublisher(republished.record)
	fixture := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	seedPreviousHostDeliveryState(t, pool, fixture.nodeID, now)
	request := validAuthorizeRequest(t, testCSR(t, false))
	request.EnrollmentToken = fixture.token
	enrollIdentity(t, service, request)

	var rows int
	if err := pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM installation_ban_node_state WHERE node_id=$1 AND applied_revision=3)
		+ (SELECT count(*) FROM edge_signer_trust_node_state WHERE node_id=$1)
		+ (SELECT count(*) FROM node_ssh_access WHERE node_id=$1 AND state='confirmed')`, fixture.nodeID).Scan(&rows); err != nil ||
		rows != 3 || len(republished.calls) != 0 {
		t.Fatalf("delivery state after first enrollment = %d rows, republished %+v, %v", rows, republished.calls, err)
	}
}

func seedPreviousHostDeliveryState(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID, now time.Time) {
	t.Helper()
	var scopeID uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT scope_id FROM nodes WHERE id=$1`, nodeID).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at) VALUES($2,1,$3) ON CONFLICT DO NOTHING`,
		`INSERT INTO installation_ban_node_state(node_id,revision,status,applied,updated_at,applied_revision)
			VALUES($1,3,'serving',true,$3,3)`,
		`INSERT INTO edge_signer_trust_node_state(node_id,bundle_sha256,enforced_revision,result,reason,reported_at,recorded_at)
			VALUES($1,decode(repeat('ab',32),'hex'),1,'applied','',$3,$3)`,
		`INSERT INTO security_ban_node_state(node_id,revision,content_sha256,list_sha256,published_at,applied_revision,
			applied_sha256,applied,applied_bans,applied_releases,error_code,reported_at)
			VALUES($1,7,decode(repeat('01',32),'hex'),decode(repeat('02',32),'hex'),$3,7,decode(repeat('02',32),'hex'),true,1,0,'',$3)`,
		`INSERT INTO autodefense_node_snapshots(node_id,revision,issued_at,content_sha256,sites,published_at,receipt_revision,
			receipt_applied,receipt_sites,receipt_signatures,receipt_mitigations,receipt_at,updated_at,publish_count)
			VALUES($1,5,$3,decode(repeat('03',32),'hex'),1,$3,5,true,1,0,0,$3,$3,1)`,
		`INSERT INTO edge_node_capability_marks(node_id,session_epoch,capabilities_sha256,observed_at)
			VALUES($1,1,decode(repeat('04',32),'hex'),$3)`,
		`INSERT INTO node_ssh_access(node_id,scope_id,enabled,ssh_port,controller_cidrs,allow_cidrs,revision,state,
			failure_code,published_revision,published_operation,updated_at)
			VALUES($1,$2,true,22,ARRAY['192.0.2.0/24'],ARRAY[]::text[],3,'confirmed','',3,'confirm',$3)`,
	} {
		// Each statement names $1 node, $2 scope and $3 time; unused ones are typed here.
		typed := `WITH arguments AS (SELECT $1::uuid AS node, $2::uuid AS scope, $3::timestamptz AS at) ` + statement
		if _, err := pool.Exec(context.Background(), typed, nodeID, scopeID, now); err != nil {
			t.Fatalf("seed previous host state: %v\n%s", err, statement)
		}
	}
}

// republishRecorder stands in for edgeautopublish.RepublishReinstalledNodeTx
// (edgeautopublish imports nodeidentity through capabilitytest). cleared counts
// the node's configuration states already cleared when it is called (same transaction).
type republishRecorder struct {
	calls []struct {
		nodeID  uuid.UUID
		scopes  []uuid.UUID
		cleared int
	}
}

func (recorder *republishRecorder) record(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, scopes []uuid.UUID, _ string) error {
	var cleared int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM node_config_state WHERE node_id=$1 AND current_config_version_id IS NULL`,
		nodeID).Scan(&cleared); err != nil {
		return err
	}
	recorder.calls = append(recorder.calls, struct {
		nodeID  uuid.UUID
		scopes  []uuid.UUID
		cleared int
	}{nodeID, scopes, cleared})
	return nil
}

func healthyCurrentHostDeployments(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM node_deployments deployment
		WHERE node_id=$1 AND state='healthy' AND `+edgedeployment.CurrentHostDeployment("deployment"), nodeID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// control-api reset-node-host-delivery: the field repair for a node reinstalled
// before the enrollment reset existed. A node enrolled once
// is refused; a reinstalled one is reset, republished and audited.
func TestResetReinstalledHostRepairsStaleState(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	service := newIdentityTestService(t, pool, newIdentityTestCA(t, now), clock)
	republished := &republishRecorder{}
	service.store.WithReinstallRepublisher(republished.record)
	ctx := context.Background()
	fixture := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	first := validAuthorizeRequest(t, testCSR(t, false))
	first.EnrollmentToken = fixture.token
	enrollIdentity(t, service, first)
	if _, err := service.store.ResetReinstalledHost(ctx, fixture.nodeID, "repair-once"); !errors.Is(err, ErrNodeNotReinstalled) {
		t.Fatalf("ResetReinstalledHost(enrolled once) error = %v", err)
	}
	seedTelemetryCurrentConfig(t, pool, fixture, uuid.New(), now.Add(-time.Hour))
	clock.set(now.Add(10 * time.Minute))
	reinstall := reenrollRequest(t, pool, fixture, clock)
	reinstall.EnrollmentToken = issueIdentityToken(t, pool, fixture, clock.now(), "re_enrollment")
	enrollIdentity(t, service, reinstall)
	// The state an older control plane left after the reinstall.
	seedPreviousHostDeliveryState(t, pool, fixture.nodeID, now)
	if _, err := pool.Exec(ctx, `UPDATE node_config_state SET current_config_version_id=(SELECT id FROM config_versions
		WHERE configuration_scope_id=$2 LIMIT 1) WHERE node_id=$1`, fixture.nodeID, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	republished.calls = nil

	result, err := service.store.ResetReinstalledHost(ctx, fixture.nodeID, "repair-reinstalled")
	if err != nil || result.NodeID != fixture.nodeID || len(result.RepublishedScopes) != 1 ||
		result.RepublishedScopes[0] != fixture.scopeID.String() || len(republished.calls) != 1 {
		t.Fatalf("ResetReinstalledHost() = %+v, %v (republished %+v)", result, err, republished.calls)
	}
	var stale int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM installation_ban_node_state WHERE node_id=$1)
		+ (SELECT count(*) FROM edge_signer_trust_node_state WHERE node_id=$1)
		+ (SELECT count(*) FROM node_config_state WHERE node_id=$1 AND current_config_version_id IS NOT NULL)
		+ (SELECT count(*) FROM node_ssh_access WHERE node_id=$1 AND state<>'pending')`, fixture.nodeID).Scan(&stale); err != nil || stale != 0 {
		t.Fatalf("stale delivery state after repair = %d, %v", stale, err)
	}
	var audited int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='node.host_delivery.reset'
		AND resource_id=$1 AND request_id='repair-reinstalled'`, fixture.nodeID.String()).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("repair audit = %d, %v", audited, err)
	}
}
