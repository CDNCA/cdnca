//go:build integration

package edgepublish

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SystemRepublishScope is a manual-mode tenant scope (no automatic policy)
// with one plaintext website, for system republication tests that save L4
// streams through the real l4forward service (edgepublish_test).
type SystemRepublishScope struct {
	Pool                            *pgxpool.Pool
	ScopeID, UserID, SubscriptionID uuid.UUID
	SiteID                          uuid.UUID
	fixture                         *publishFixture
	republisher                     *SystemRepublisher
	publications                    int
}

type SystemRepublishAttempt struct {
	Outcome       string
	ErrorClass    *string
	Triggers      []string
	NodeIDs       []uuid.UUID
	RefusedNodes  []uuid.UUID
	PublicationID *uuid.UUID
}

type SystemRepublishPublication struct {
	SourceRevision int64
	NodeIDs        []uuid.UUID
	Snapshot       []byte
}

func NewSystemRepublishScope(t *testing.T) *SystemRepublishScope {
	t.Helper()
	fixture := newL4V2ContractFixture(t)
	site := fixture.createSite(t, "system-republish.example.com", 18081, false).Site
	republisher, err := NewSystemRepublisher(fixture.service, SystemRepublisherConfig{
		WorkerID: "syspub-test", LeaseDuration: time.Minute, RetryDelay: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &SystemRepublishScope{Pool: fixture.pool, ScopeID: fixture.scopeID, UserID: fixture.userID,
		SubscriptionID: fixture.subscriptionID, SiteID: site.ID, fixture: fixture, republisher: republisher}
}

func systemRepublishFeatures(l4 uint32) []*agentv1.Capability {
	return append(siteRuntimeV2NodeFeatures(),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
		// A 1.0.35 agent runs listener security (site runtime v2 waf / cc)
		// with the adaptive managed WAF (RI-03: WAF v3).
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: edgeconfig.WAFAdaptiveAPIVersion},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_CC, ApiVersion: 4},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: l4},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY, ApiVersion: l4})
}

// AddNode enrolls a node of the scope declaring tcp/udp version l4 at
// enrollment and on its session.
func (scope *SystemRepublishScope) AddNode(t *testing.T, l4 uint32) uuid.UUID {
	t.Helper()
	nodeID := uuid.New()
	seedPublishNode(t, scope.Pool, scope.ScopeID, scope.UserID, nodeID)
	scope.fixture.nodeKeys[nodeID] = capabilitytest.SeedNodePublicationIdentityForTest(t, scope.Pool, scope.ScopeID, scope.UserID, nodeID,
		&agentv1.AgentCapabilities{AgentVersion: "1.0.35", BuildId: "syspub", OperatingSystem: "linux",
			Architecture: "amd64", Features: systemRepublishFeatures(6)}, publishTestClock.Add(-10*time.Minute), true).ArtifactPrivateKey
	scope.UpgradeNode(t, nodeID, l4)
	return nodeID
}

// UpgradeNode records a new Connect session declaring tcp/udp version l4.
func (scope *SystemRepublishScope) UpgradeNode(t *testing.T, nodeID uuid.UUID, l4 uint32) {
	t.Helper()
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeID, fmt.Sprintf("1.0.35-l4v%d", l4), systemRepublishFeatures(l4))
}

// PublishManually publishes the scope's current facts as the platform operator.
func (scope *SystemRepublishScope) PublishManually(t *testing.T, key string, nodeIDs ...uuid.UUID) error {
	t.Helper()
	request := scope.fixture.publishRequest(key, nodeIDs[0])
	request.NodeIDs = slices.Clone(nodeIDs)
	_, err := scope.fixture.service.Publish(t.Context(), request)
	return err
}

// SettleDeployments marks every running deployment of the scope healthy, so
// its nodes take the next publication.
func (scope *SystemRepublishScope) SettleDeployments(t *testing.T) {
	t.Helper()
	rows, err := scope.Pool.Query(t.Context(), `SELECT deployment.id,deployment.attempt,deployment.node_id,
		deployment.config_version_id,COALESCE(max(event.transition_sequence),0)
		FROM node_deployments deployment
		LEFT JOIN deployment_status_events event ON event.deployment_id=deployment.id AND event.attempt=deployment.attempt
		WHERE deployment.configuration_scope_id=$1
		  AND deployment.state NOT IN ('healthy','failed','reverted','rollback_failed','cancelled')
		GROUP BY deployment.id,deployment.attempt,deployment.node_id,deployment.config_version_id`, scope.ScopeID)
	if err != nil {
		t.Fatal(err)
	}
	type running struct {
		id, nodeID, configID uuid.UUID
		attempt              int
		sequence             int64
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (running, error) {
		var item running
		return item, row.Scan(&item.id, &item.attempt, &item.nodeID, &item.configID, &item.sequence)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		for index, state := range []string{"delivered", "staged", "prechecked", "activated", "healthy"} {
			item.sequence++
			payload := []byte("syspub-status-" + state)
			digest := sha256.Sum256(payload)
			if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
				if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(
					id,deployment_id,event_id,attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
					SELECT $1,$2,$3,$4,$5,$6,$7,$8,
					  GREATEST(deployment.created_at,deployment.updated_at)+$9::int*interval '1 millisecond',
					  GREATEST(deployment.created_at,deployment.updated_at)+$9::int*interval '1 millisecond'
					FROM node_deployments deployment WHERE deployment.id=$2 AND deployment.attempt=$4`,
					uuid.New(), item.id, uuid.New(), item.attempt, item.sequence, state, payload, digest[:], index+1); err != nil {
					return err
				}
				_, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state=$3,
					updated_at=GREATEST(created_at,updated_at)+interval '1 millisecond' WHERE id=$1 AND attempt=$2`,
					item.id, item.attempt, state)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := scope.Pool.Exec(t.Context(), `UPDATE node_config_state SET current_config_version_id=$3,
			revision=revision+1,updated_at=clock_timestamp() WHERE node_id=$1 AND configuration_scope_id=$2`,
			item.nodeID, scope.ScopeID, item.configID); err != nil {
			t.Fatal(err)
		}
	}
}

// Request queues a system republication with no debounce, as a trigger does.
func (scope *SystemRepublishScope) Request(t *testing.T, trigger string) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT 1 FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`, scope.ScopeID); err != nil {
			return err
		}
		return RequestSystemRepublicationTx(t.Context(), tx, SystemRepublicationRequest{ScopeID: scope.ScopeID, Trigger: trigger})
	}); err != nil {
		t.Fatal(err)
	}
}

// MakeDue ends the scope's debounce window.
func (scope *SystemRepublishScope) MakeDue(t *testing.T) {
	t.Helper()
	if _, err := scope.Pool.Exec(t.Context(), `UPDATE edge_system_republication_heads SET due_at=clock_timestamp()
		WHERE scope_id=$1 AND state='pending'`, scope.ScopeID); err != nil {
		t.Fatal(err)
	}
}

// Run runs the system republisher until no scope is due and returns the runs.
func (scope *SystemRepublishScope) Run(t *testing.T) int {
	t.Helper()
	runs := 0
	for ; runs < 20; runs++ {
		worked, err := scope.republisher.RunOnce(t.Context())
		if err != nil {
			t.Fatalf("system republisher: %v", err)
		}
		if !worked {
			return runs
		}
	}
	t.Fatal("system republisher did not drain")
	return runs
}

func (scope *SystemRepublishScope) LatestAttempt(t *testing.T) SystemRepublishAttempt {
	t.Helper()
	var attempt SystemRepublishAttempt
	var refused []byte
	if err := scope.Pool.QueryRow(t.Context(), `SELECT outcome,triggers,node_ids,refused_nodes,publication_id,error_class
		FROM edge_system_republication_attempts WHERE scope_id=$1 ORDER BY occurred_at DESC,id DESC LIMIT 1`,
		scope.ScopeID).Scan(&attempt.Outcome, &attempt.Triggers, &attempt.NodeIDs, &refused, &attempt.PublicationID, &attempt.ErrorClass); err != nil {
		t.Fatal(err)
	}
	var nodes []struct {
		NodeID uuid.UUID `json:"node_id"`
	}
	if err := json.Unmarshal(refused, &nodes); err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		attempt.RefusedNodes = append(attempt.RefusedNodes, node.NodeID)
	}
	return attempt
}

func (scope *SystemRepublishScope) Count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var count int
	if err := scope.Pool.QueryRow(t.Context(), query, append([]any{scope.ScopeID}, args...)...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func (scope *SystemRepublishScope) LatestPublication(t *testing.T) SystemRepublishPublication {
	t.Helper()
	var publication SystemRepublishPublication
	if err := scope.Pool.QueryRow(t.Context(), `SELECT publication.source_revision,config.canonical_snapshot,
		ARRAY(SELECT DISTINCT node_id FROM node_deployments WHERE rollout_id=publication.rollout_id ORDER BY node_id)
		FROM edge_config_publications publication JOIN config_versions config ON config.id=publication.config_version_id
		WHERE publication.configuration_scope_id=$1 ORDER BY publication.source_revision DESC LIMIT 1`, scope.ScopeID).
		Scan(&publication.SourceRevision, &publication.Snapshot, &publication.NodeIDs); err != nil {
		t.Fatal(err)
	}
	return publication
}

// EditOrigin is a tenant edit that has not been published.
func (scope *SystemRepublishScope) EditOrigin(t *testing.T, host string) {
	t.Helper()
	if _, err := scope.Pool.Exec(t.Context(), `UPDATE site_origins SET host=$2 WHERE site_id=$1`, scope.SiteID, host); err != nil {
		t.Fatal(err)
	}
}

// SuspendSite stops (status traffic_exceeded) or releases (status active)
// siteID the way traffic enforcement does: under the scope lock, recording or
// closing the suspension, attributing the advance, then requesting the
// republication.
func (scope *SystemRepublishScope) SuspendSite(t *testing.T, status string, siteIDs ...uuid.UUID) {
	t.Helper()
	siteID := scope.SiteID
	if len(siteIDs) > 0 {
		siteID = siteIDs[0]
	}
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		var from int64
		if err := tx.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
			scope.ScopeID).Scan(&from); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE sites SET status=$2,revision=revision+1 WHERE id=$1`, siteID, status); err != nil {
			return err
		}
		if status == "traffic_exceeded" {
			if _, err := tx.Exec(t.Context(), `INSERT INTO package_traffic_site_suspensions(suspension_id,tenant_scope_id,
				subscription_id,site_id,period_key,head_revision,suspended_at) VALUES($1,$2,$3,$4,'2026-10',1,clock_timestamp())`,
				uuid.New(), scope.ScopeID, scope.SubscriptionID, siteID); err != nil {
				return err
			}
		} else if _, err := tx.Exec(t.Context(), `UPDATE package_traffic_site_suspensions SET recovered_at=clock_timestamp(),
			recovered_period_key='2026-11',recovered_reason='new_cycle',recovered_site_status='active'
			WHERE site_id=$1 AND recovered_at IS NULL`, siteID); err != nil {
			return err
		}
		if err := RecordSystemRevisionSegmentTx(t.Context(), tx, scope.ScopeID, from, SystemTriggerTrafficEnforcement); err != nil {
			return err
		}
		return RequestSystemRepublicationTx(t.Context(), tx, SystemRepublicationRequest{
			ScopeID: scope.ScopeID, Trigger: SystemTriggerTrafficEnforcement})
	}); err != nil {
		t.Fatal(err)
	}
}

// AddSite adds another plaintext website to the scope.
func (scope *SystemRepublishScope) AddSite(t *testing.T, domain string, port int) uuid.UUID {
	t.Helper()
	return scope.fixture.createSite(t, domain, port, false).Site.ID
}

// EditSiteOrigin is a tenant edit of siteID that has not been published.
func (scope *SystemRepublishScope) EditSiteOrigin(t *testing.T, siteID uuid.UUID, host string) {
	t.Helper()
	if _, err := scope.Pool.Exec(t.Context(), `UPDATE site_origins SET host=$2 WHERE site_id=$1`, siteID, host); err != nil {
		t.Fatal(err)
	}
}

// LatestBundle is the rendered content (every file, decoded) of the latest
// publication's signed bundle.
func (scope *SystemRepublishScope) LatestBundle(t *testing.T) []byte {
	t.Helper()
	var result PublishResult
	var nodeID uuid.UUID
	if err := scope.Pool.QueryRow(t.Context(), `SELECT publication.rollout_id,publication.config_version_id,
		(SELECT min(deployment.node_id::text)::uuid FROM node_deployments deployment WHERE deployment.rollout_id=publication.rollout_id)
		FROM edge_config_publications publication
		WHERE publication.configuration_scope_id=$1 ORDER BY publication.source_revision DESC LIMIT 1`, scope.ScopeID).
		Scan(&result.RolloutID, &result.ConfigVersionID, &nodeID); err != nil {
		t.Fatal(err)
	}
	bundle := receivedV2Bundle(t, scope.fixture, result, nodeID, scope.fixture.nodeKeys[nodeID])
	var rendered []byte
	for _, content := range bundle.Files {
		rendered = append(rendered, content...)
	}
	return rendered
}

// EnableAutomaticPolicy gives the scope an automatic publication policy over
// nodeIDs, acting as the tenant owner.
func (scope *SystemRepublishScope) EnableAutomaticPolicy(t *testing.T, nodeIDs ...uuid.UUID) {
	t.Helper()
	if _, err := scope.Pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_policy_facts(target_scope_id,revision,mode,
		node_ids,activation_timeout_ms,observation_window_ms,required_consecutive_successes,max_attempts,deadline_window_seconds,
		actor_scope_id,actor_user_id,reason,created_at) VALUES($1,1,'automatic',$2,30000,15000,2,3,600,$1,$3,'syspub_test',
		clock_timestamp())`, scope.ScopeID, sortedPolicyNodes(nodeIDs), scope.UserID); err != nil {
		t.Fatal(err)
	}
}

// AutomaticService is the edge publication service of the automatic worker.
func (scope *SystemRepublishScope) AutomaticService(t *testing.T, coordinator AutomaticPublicationCoordinator) *Service {
	t.Helper()
	config := scope.fixture.config(nil, nil)
	service, err := NewAutomaticService(scope.Pool, scope.fixture.deploymentStore(t), scope.fixture.signer, config, coordinator)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func sortedPolicyNodes(nodes []uuid.UUID) []uuid.UUID {
	sorted := slices.Clone(nodes)
	slices.SortFunc(sorted, compareUUID)
	return slices.Compact(sorted)
}

// AssertStoredInputsReproduceBundle rebuilds the latest publication from its
// stored compile inputs and requires the signed bundle bytes back.
func (scope *SystemRepublishScope) AssertStoredInputsReproduceBundle(t *testing.T) {
	t.Helper()
	tx, err := scope.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	inputs, err := scanCompileInputs(tx.QueryRow(t.Context(), `SELECT `+compileInputsColumns+`
		FROM edge_publication_compile_inputs inputs JOIN config_versions config ON config.id=inputs.config_version_id
		WHERE inputs.configuration_scope_id=$1 ORDER BY inputs.source_revision DESC LIMIT 1`, scope.ScopeID))
	if err != nil {
		t.Fatal(err)
	}
	latest := scope.LatestPublication(t)
	var published siteRuntimeV2Document
	if err := json.Unmarshal(latest.Snapshot, &published); err != nil {
		t.Fatal(err)
	}
	if inputs.v2 == nil || inputs.sourceRevision != latest.SourceRevision ||
		len(inputs.v2.Document.Sites) != len(published.Sites) {
		t.Fatalf("stored compile inputs do not describe the latest publication: %+v", inputs.v2)
	}
	for index, site := range published.Sites {
		stored, _ := json.Marshal(inputs.v2.Document.Sites[index].OriginPools)
		sent, _ := json.Marshal(site.OriginPools)
		if inputs.v2.Document.Sites[index].ID != site.ID || !bytes.Equal(stored, sent) {
			t.Fatalf("stored site %d differs from the published one", index)
		}
	}
}

// DropCompileInputs forgets the stored source of every publication (as for a
// publication made before migration 316).
func (scope *SystemRepublishScope) DropCompileInputs(t *testing.T) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `DELETE FROM edge_publication_compile_inputs WHERE configuration_scope_id=$1`, scope.ScopeID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// HoldForSecondaryVerification stops (hold=true) or restores siteID the way
// an overdue secondary verification does (migration 317 hold, site disabled),
// under the scope lock with the advance attributed. trigger is the
// republication trigger the hold is queued with.
func (scope *SystemRepublishScope) HoldForSecondaryVerification(t *testing.T, siteID uuid.UUID, hold bool, trigger string) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		var from int64
		if err := tx.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
			scope.ScopeID).Scan(&from); err != nil {
			return err
		}
		if hold {
			if _, err := tx.Exec(t.Context(), `INSERT INTO identity_user_secondary_verification(scope_id,user_id,revision,enabled,
				deadline,expiry_action,requested_at,enforced_at,updated_by_user_id,updated_at)
				VALUES($1,$2,1,true,clock_timestamp(),'lock_sites',clock_timestamp(),clock_timestamp(),$2,clock_timestamp())
				ON CONFLICT (scope_id,user_id) DO NOTHING`, scope.ScopeID, scope.UserID); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `UPDATE sites SET enabled=false,status='disabled',revision=revision+1 WHERE id=$1`,
				siteID); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO identity_secondary_verification_site_holds(site_id,held_at,scope_id,
				user_id,request_revision,disabled_site,locked_site) VALUES($1,clock_timestamp(),$2,$3,1,true,false)`,
				siteID, scope.ScopeID, scope.UserID); err != nil {
				return err
			}
		} else {
			if _, err := tx.Exec(t.Context(), `UPDATE sites SET enabled=true,status='active',revision=revision+1 WHERE id=$1`,
				siteID); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `UPDATE identity_secondary_verification_site_holds SET released_at=clock_timestamp()
				WHERE site_id=$1 AND released_at IS NULL`, siteID); err != nil {
				return err
			}
		}
		if err := RecordSystemRevisionSegmentTx(t.Context(), tx, scope.ScopeID, from, trigger); err != nil {
			return err
		}
		return RequestSystemRepublicationTx(t.Context(), tx, SystemRepublicationRequest{ScopeID: scope.ScopeID, Trigger: trigger})
	}); err != nil {
		t.Fatal(err)
	}
}

// ActivateDDoSProtection activates a platform system configuration with DDoS
// protection on, so publications carry
// system.ddos.node_networks.
func (scope *SystemRepublishScope) ActivateDDoSProtection(t *testing.T) {
	t.Helper()
	activateTestSystemConfigurationWith(t, scope.fixture, func(configuration *systemconfig.Configuration) {
		configuration.DDoSProtection = &edgeconfig.DDoSProtection{MaxConnectionsPerIP: 300, AllowNetworks: []string{},
			CCKernelBan: edgeconfig.CCKernelBanOff}
	})
}

// Exec runs a statement against the fixture database.
func (scope *SystemRepublishScope) Exec(t *testing.T, statement string, args ...any) {
	t.Helper()
	if _, err := scope.Pool.Exec(t.Context(), statement, args...); err != nil {
		t.Fatal(err)
	}
}
