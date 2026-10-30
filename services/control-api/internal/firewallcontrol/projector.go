package firewallcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type CommandSigner interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

type ProjectorConfig struct {
	PollInterval time.Duration
	BatchSize    int
	CommandTTL   time.Duration
	Now          func() time.Time
}

type Projector struct {
	pool   *pgxpool.Pool
	signer CommandSigner
	config ProjectorConfig
}

func NewProjector(pool *pgxpool.Pool, signer CommandSigner, config ProjectorConfig) (*Projector, error) {
	if config.PollInterval == 0 {
		config.PollInterval = 500 * time.Millisecond
	}
	if config.BatchSize == 0 {
		config.BatchSize = 1
	}
	if config.CommandTTL == 0 {
		config.CommandTTL = 24 * time.Hour
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if pool == nil || signer == nil || config.PollInterval <= 0 || config.BatchSize < 1 || config.BatchSize > 16 ||
		config.CommandTTL < time.Minute || config.CommandTTL > 24*time.Hour || signer.KeyID() == "" {
		return nil, ErrUnavailable
	}
	return &Projector{pool: pool, signer: signer, config: config}, nil
}

func (projector *Projector) Run(ctx context.Context) error {
	for {
		projected, err := projector.ProjectBatch(ctx)
		if err != nil {
			return err
		}
		if projected > 0 {
			continue
		}
		timer := time.NewTimer(projector.config.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (projector *Projector) ProjectBatch(ctx context.Context) (int, error) {
	projected := 0
	for projected < projector.config.BatchSize {
		didProject, err := projector.projectOne(ctx)
		if err != nil {
			return projected, err
		}
		if !didProject {
			break
		}
		projected++
	}
	return projected, nil
}

type globalPublication struct {
	ID, TenantScopeID, PolicyID uuid.UUID
	Revision                    int64
	Operation                   string
	RecoveryReason              string
	Document                    PolicyInput
	DocumentSHA256              [32]byte
}

func (projector *Projector) projectOne(ctx context.Context) (bool, error) {
	now := projector.config.Now().UTC().Truncate(time.Microsecond)
	projected := false
	err := pgx.BeginFunc(ctx, projector.pool, func(tx pgx.Tx) error {
		publication, found, err := claimGlobalPublication(ctx, tx, now)
		if err != nil || !found {
			return err
		}
		installationID, sites, nodes, err := globalTargets(ctx, tx, publication.TenantScopeID)
		if err != nil {
			return err
		}
		if len(nodes) == 0 {
			// No node of its own: host rules have nowhere to go (A08); end the
			// publication instead of waiting for a node it may never own.
			projected = true
			return failUnownedPublication(ctx, tx, publication, now, failureSharedNodeOnly)
		}
		if len(sites) == 0 {
			// Commands are per (site, node) (outbox FK to sites, the agent
			// requires a site id): a scope with nodes but no enabled site (the
			// platform scope, a tenant before its first site) has nothing to
			// address. It used to retry every 30 seconds forever (P0-a);
			// settle it like the no-node case, the next save publishes again.
			projected = true
			return failUnownedPublication(ctx, tx, publication, now, failureNoEnabledSites)
		}
		serving, err := siteServingNodes(ctx, tx, publication.TenantScopeID, sites)
		if err != nil {
			return err
		}
		for _, siteID := range sites {
			for _, nodeID := range nodes {
				command, digest, err := projector.command(ctx, tx, publication, siteID, nodeID, servesSite(serving, siteID, nodeID), now)
				if err != nil {
					return err
				}
				encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(command)
				if err != nil {
					return ErrUnavailable
				}
				commandID := uuid.NewSHA1(publication.ID, []byte(siteID.String()+"\x00"+nodeID.String()))
				_, err = tx.Exec(ctx, `INSERT INTO firewall_command_outbox(
					id,installation_id,tenant_scope_id,site_id,policy_id,policy_kind,binding_id,publication_id,node_id,
					policy_version,expected_active_policy_version,idempotency_key,command_bytes,command_sha256,
					publication_bundle_sha256,canonical_payload_sha256,runtime_snapshot_sha256,signing_key_id,
					signature_algorithm,state,attempts,available_at,created_at,updated_at,global_revision)
					VALUES($1,$2,$3,$4,$5,'global',NULL,$6,$7,$8,$9,$10,$11,$12,$13,$13,$13,$14,'ed25519','pending',0,$15,$15,$15,$16)
					ON CONFLICT(publication_id,node_id,site_id) DO NOTHING`, commandID, installationID,
					publication.TenantScopeID, siteID, publication.PolicyID, publication.ID, nodeID,
					int64(command.PolicyVersion), int64(command.ExpectedActivePolicyVersion), command.IdempotencyKey,
					encoded, digest[:], publication.DocumentSHA256[:], projector.signer.KeyID(), now, publication.Revision)
				if err != nil {
					return err
				}
			}
		}
		result, err := tx.Exec(ctx, `UPDATE global_firewall_publication_outbox SET state='projected',attempts=attempts+1,
			projected_at=$2,last_error=NULL,updated_at=$2 WHERE id=$1 AND state IN ('pending','retryable')`, publication.ID, now)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrUnavailable
		}
		_, err = tx.Exec(ctx, `UPDATE global_firewall_policies SET deployment_state='canary',updated_at=$3
			WHERE tenant_scope_id=$1 AND id=$2 AND revision=$4`, publication.TenantScopeID, publication.PolicyID, now, publication.Revision)
		projected = err == nil
		return err
	})
	return projected, err
}

// Why a publication was settled without commands (global_firewall_publication_outbox.last_error).
const (
	failureSharedNodeOnly = "shared_node_host_firewall_unsupported"
	failureNoEnabledSites = "no_enabled_sites"
)

// failUnownedPublication settles a publication with no command target (the
// scope owns no active node, or has no enabled site): projected with no
// command, then active (a disabled policy: nothing to apply anywhere) or
// failed with reason (the 134 transitions).
func failUnownedPublication(ctx context.Context, tx pgx.Tx, publication globalPublication, now time.Time, reason string) error {
	if _, err := tx.Exec(ctx, `UPDATE global_firewall_publication_outbox SET state='projected',attempts=LEAST(attempts+1,16),
		projected_at=$2,updated_at=$2 WHERE id=$1 AND state IN ('pending','retryable')`, publication.ID, now); err != nil {
		return err
	}
	if !publication.Document.Enabled {
		state := DeploymentActive
		if publication.Operation == "recover" {
			state = DeploymentRolledBack
		}
		if _, err := tx.Exec(ctx, `UPDATE global_firewall_publication_outbox SET state=$3,last_error=NULL,updated_at=$2
			WHERE id=$1 AND state='projected'`, publication.ID, now, state); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE global_firewall_policies SET active_revision=$4,active_sha256=$5,
			deployment_state=CASE WHEN revision=$4 THEN $6 ELSE deployment_state END,updated_at=$3
			WHERE tenant_scope_id=$1 AND id=$2`, publication.TenantScopeID, publication.PolicyID, now, publication.Revision,
			publication.DocumentSHA256[:], state)
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE global_firewall_publication_outbox SET state='failed',
		last_error=$3,updated_at=$2 WHERE id=$1 AND state='projected'`, publication.ID, now, reason); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE global_firewall_policies SET deployment_state='failed',updated_at=$3
		WHERE tenant_scope_id=$1 AND id=$2 AND revision=$4`, publication.TenantScopeID, publication.PolicyID, now, publication.Revision)
	return err
}

func claimGlobalPublication(ctx context.Context, tx pgx.Tx, now time.Time) (globalPublication, bool, error) {
	var publication globalPublication
	var document []byte
	var digest []byte
	err := tx.QueryRow(ctx, `SELECT id,tenant_scope_id,policy_id,revision,operation,COALESCE(recovery_reason,''),document,document_sha256
		FROM global_firewall_publication_outbox outbox
		WHERE state IN ('pending','retryable') AND available_at<=$1 AND NOT EXISTS(
			SELECT 1 FROM global_firewall_publication_outbox older WHERE older.tenant_scope_id=outbox.tenant_scope_id
			AND older.revision<outbox.revision AND older.state NOT IN ('active','failed','rolled_back')
			AND outbox.operation<>'recover')
		ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1`, now).Scan(&publication.ID, &publication.TenantScopeID,
		&publication.PolicyID, &publication.Revision, &publication.Operation, &publication.RecoveryReason, &document, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return globalPublication{}, false, nil
	}
	if err != nil || len(digest) != sha256.Size {
		return globalPublication{}, false, err
	}
	copy(publication.DocumentSHA256[:], digest)
	if err := strictJSON(document, &publication.Document); err != nil {
		return globalPublication{}, false, err
	}
	return publication, true, nil
}

func globalTargets(ctx context.Context, tx pgx.Tx, tenantScopeID uuid.UUID) (string, []uuid.UUID, []uuid.UUID, error) {
	var installationID string
	if err := tx.QueryRow(ctx, `SELECT installation_id FROM control_installation_entitlement WHERE singleton=true FOR SHARE`).Scan(&installationID); err != nil {
		return "", nil, nil, err
	}
	sites, err := queryUUIDs(ctx, tx, `SELECT id FROM sites WHERE scope_id=$1 AND deleted_at IS NULL AND enabled=true ORDER BY id`, tenantScopeID)
	if err != nil {
		return "", nil, nil, err
	}
	// Host rules are not isolated by tenant, site or destination address
	// (one nftables input chain per host), so only the nodes this scope owns
	// receive them: never a shared platform node carrying the tenant (A08).
	// The platform scope owns the platform nodes.
	nodes, err := queryUUIDs(ctx, tx, ownedFirewallNodesSQL, tenantScopeID)
	return installationID, sites, nodes, err
}

// ownedFirewallNodesSQL selects the active nodes owned by the scope: the only
// nodes a scope's host firewall rules may reach.
const ownedFirewallNodesSQL = `SELECT id FROM nodes WHERE admin_state='active' AND scope_id=$1 ORDER BY id`

// siteServingNodes maps each of sites whose line groups resolve (at least
// one live group: its own, its package's main and backup, its escalation
// route's; as edgepublish systemTargetNodes) to the nodes serving them, the
// enabled endpoints of the groups' current revisions.
// A site absent from the map has no line group to go by.
func siteServingNodes(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, sites []uuid.UUID) (map[uuid.UUID]map[uuid.UUID]struct{}, error) {
	rows, err := tx.Query(ctx, `SELECT site.id,endpoint.node_id FROM sites site
		LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
		 AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
		LEFT JOIN escalate_site_routes route ON route.tenant_scope_id=site.scope_id AND route.site_id=site.id
		JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND line_group.id IN (
		     site.node_group_id,
		     (subscription.product_snapshot->'spec'->>'node_group_id')::uuid,
		     (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid,
		     route.line_group_id, route.next_group_id)
		LEFT JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=line_group.tenant_scope_id
		 AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision
		 AND endpoint.enabled AND endpoint.node_id IS NOT NULL
		 AND line_group.tenant_scope_id IN (site.scope_id,(SELECT scope_id FROM nodes WHERE id=endpoint.node_id))
		WHERE site.scope_id=$1 AND site.id=ANY($2::uuid[]) AND site.deleted_at IS NULL`, scopeID, sites)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[uuid.UUID]map[uuid.UUID]struct{})
	for rows.Next() {
		var siteID uuid.UUID
		var nodeID *uuid.UUID
		if err := rows.Scan(&siteID, &nodeID); err != nil {
			return nil, err
		}
		nodes := result[siteID]
		if nodes == nil {
			nodes = make(map[uuid.UUID]struct{})
			result[siteID] = nodes
		}
		if nodeID != nil {
			nodes[*nodeID] = struct{}{}
		}
	}
	return result, rows.Err()
}

// servesSite: nodeID serves siteID, or the site has no line group to go by.
func servesSite(serving map[uuid.UUID]map[uuid.UUID]struct{}, siteID, nodeID uuid.UUID) bool {
	nodes, resolved := serving[siteID]
	if !resolved {
		return true
	}
	_, serves := nodes[nodeID]
	return serves
}

func queryUUIDs(ctx context.Context, tx pgx.Tx, query string, argument uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, query, argument)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]uuid.UUID, 0)
	for rows.Next() {
		var value uuid.UUID
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (projector *Projector) command(ctx context.Context, tx pgx.Tx, publication globalPublication, siteID, nodeID uuid.UUID,
	servesSite bool, now time.Time) (*agentv1.FirewallCommand, [32]byte, error) {
	var activeVersion int64
	err := tx.QueryRow(ctx, `SELECT COALESCE(max(active_policy_version),0) FROM firewall_command_outbox
		WHERE tenant_scope_id=$1 AND site_id=$2 AND node_id=$3 AND policy_kind='global' AND policy_id=$4
		AND terminal_state IN ('applied','rolled_back')`, publication.TenantScopeID, siteID, nodeID, publication.PolicyID).Scan(&activeVersion)
	if err != nil {
		return nil, [32]byte{}, err
	}
	targets, err := globalCommandTargets(publication, siteID, servesSite)
	if err != nil {
		return nil, [32]byte{}, err
	}
	taskID := publication.ID.String()
	operation := agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY
	recovery := agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE
	if publication.Operation == "recover" {
		operation = agentv1.FirewallOperation_FIREWALL_OPERATION_RECOVER
		recovery = globalRecoveryReason(publication.RecoveryReason)
		if recovery == agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_UNSPECIFIED {
			return nil, [32]byte{}, ErrInvalidInput
		}
	}
	idempotency := uuid.NewSHA1(publication.ID, []byte("global-firewall\x00"+siteID.String()+"\x00"+nodeID.String())).String()
	command := &agentv1.FirewallCommand{
		Event: &commonv1.EventMetadata{EventId: uuid.NewSHA1(publication.ID, []byte("event\x00"+siteID.String()+"\x00"+nodeID.String())).String(),
			RequestId: publication.ID.String(), OccurredTime: timestamppb.New(now), CorrelationId: publication.PolicyID.String(), TaskId: &taskID},
		Schema: agentv1.FirewallSchema_FIREWALL_SCHEMA_V1, TaskId: taskID, TaskRevision: uint64(publication.Revision),
		IdempotencyKey: idempotency, TenantId: publication.TenantScopeID.String(), SiteId: siteID.String(), NodeId: nodeID.String(),
		PolicyVersion: uint64(activeVersion + 1), ExpectedActivePolicyVersion: uint64(activeVersion), PolicyKind: "global", PolicyId: publication.PolicyID.String(),
		Operation: operation, RecoveryReason: recovery, Targets: targets, DeadlineTime: timestamppb.New(now.Add(projector.config.CommandTTL)),
		SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519, SigningKeyId: projector.signer.KeyID(),
	}
	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(command)
	if err != nil {
		return nil, [32]byte{}, err
	}
	signature, err := projector.signer.Sign(ctx, canonical)
	if err != nil || len(signature) != 64 {
		return nil, [32]byte{}, ErrUnavailable
	}
	command.Signature = signature
	digest := sha256.Sum256(canonical)
	command.CommandSha256 = digest[:]
	return command, digest, nil
}

// globalCommandTargets is the policy's targets for siteID on one node. Host
// rules are one input chain per host, so a rule bound to sites reaches only
// a node that serves siteID (servesSite); rules of every site and the
// default deny reach every owned node as before.
func globalCommandTargets(publication globalPublication, siteID uuid.UUID, servesSite bool) ([]*agentv1.FirewallCIDRTarget, error) {
	targets := make([]*agentv1.FirewallCIDRTarget, 0)
	covered := make(map[string]struct{})
	if !publication.Document.Enabled {
		return targets, nil
	}
	for _, rule := range publication.Document.Rules {
		if len(rule.SiteIDs) > 0 && (!servesSite || !slices.Contains(rule.SiteIDs, siteID)) {
			continue
		}
		for _, cidr := range rule.CIDRs {
			if rule.Protocol == ProtocolAny {
				covered[cidr] = struct{}{}
			}
			target := &agentv1.FirewallCIDRTarget{Ordinal: uint32(len(targets) + 1),
				TenantId: publication.TenantScopeID.String(), SiteId: siteID.String(), Action: globalAction(rule.Action),
				Cidr: cidr, Source: "global:" + publication.PolicyID.String(), ReasonCode: "rule:" + rule.ID.String(),
				Protocol: globalProtocol(rule.Protocol), PortStart: uint32(rule.PortStart), PortEnd: uint32(rule.PortEnd)}
			if rule.ExpiresAt != nil {
				target.ExpirationTime = timestamppb.New(*rule.ExpiresAt)
			}
			targets = append(targets, target)
		}
	}
	if publication.Document.DefaultAction == ActionDeny {
		for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
			if _, exists := covered[cidr]; exists {
				continue
			}
			targets = append(targets, &agentv1.FirewallCIDRTarget{Ordinal: uint32(len(targets) + 1), TenantId: publication.TenantScopeID.String(),
				SiteId: siteID.String(), Action: agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_DENY, Cidr: cidr,
				Source: "global:" + publication.PolicyID.String(), ReasonCode: "default-deny", Protocol: agentv1.FirewallProtocol_FIREWALL_PROTOCOL_ANY})
		}
	}
	return targets, nil
}

func globalAction(value string) agentv1.FirewallCIDRAction {
	if value == ActionAllow {
		return agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_ALLOW
	}
	return agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_DENY
}

func globalProtocol(value string) agentv1.FirewallProtocol {
	switch value {
	case ProtocolTCP:
		return agentv1.FirewallProtocol_FIREWALL_PROTOCOL_TCP
	case ProtocolUDP:
		return agentv1.FirewallProtocol_FIREWALL_PROTOCOL_UDP
	case ProtocolICMP:
		return agentv1.FirewallProtocol_FIREWALL_PROTOCOL_ICMP
	default:
		return agentv1.FirewallProtocol_FIREWALL_PROTOCOL_ANY
	}
}

func globalRecoveryReason(value string) agentv1.FirewallRecoveryReason {
	switch value {
	case RecoveryFalsePositive:
		return agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_FALSE_POSITIVE
	case RecoveryHealthFailure:
		return agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_HEALTH_FAILURE
	case RecoveryOperator:
		return agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_OPERATOR_REQUEST
	default:
		return agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_UNSPECIFIED
	}
}

func strictJSON(encoded []byte, target any) error {
	if len(encoded) == 0 {
		return fmt.Errorf("%w: empty publication", ErrUnavailable)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode publication", ErrUnavailable)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: publication contains trailing data", ErrUnavailable)
	}
	return nil
}
