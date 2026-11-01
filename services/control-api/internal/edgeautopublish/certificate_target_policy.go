package edgeautopublish

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CertificateTargetPolicy struct {
	PolicyRevision               int64
	NodeIDs                      []uuid.UUID
	RequiredCapabilities         []*agentv1.Capability
	ActivationTimeout            time.Duration
	ObservationWindow            time.Duration
	RequiredConsecutiveSuccesses uint32
	Deadline                     time.Time
}

type CertificateTargetResolver struct {
	pool      *pgxpool.Pool
	snapshots edgepublish.TargetResolver
}

func NewCertificateTargetResolver(
	pool *pgxpool.Pool,
	snapshots edgepublish.TargetResolver,
) (*CertificateTargetResolver, error) {
	if pool == nil || snapshots == nil {
		return nil, ErrInvalidInput
	}
	return &CertificateTargetResolver{pool: pool, snapshots: snapshots}, nil
}

func (resolver *CertificateTargetResolver) ResolveCertificateTarget(
	ctx context.Context,
	command certificateasset.CertificatePublicationCommandV1,
) (CertificateTargetPolicy, error) {
	if resolver == nil || resolver.pool == nil || ctx == nil || command.TenantScopeID == uuid.Nil {
		return CertificateTargetPolicy{}, ErrInvalidInput
	}
	var result CertificateTargetPolicy
	err := pgx.BeginTxFunc(ctx, resolver.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		policy, found, err := loadCurrentPolicy(ctx, tx, command.TenantScopeID)
		if err != nil {
			return err
		}
		if !found || policy.Mode != ModeAutomatic {
			return rejectCertificateTarget(CertificateTargetPolicyNotAutomatic, uuid.Nil, false)
		}
		var databaseNow time.Time
		if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&databaseNow); err != nil {
			return err
		}
		nodeIDs := slices.Clone(policy.NodeIDs)
		if policy.TargetSnapshot != nil {
			reference := edgepublish.TargetSnapshotReference{
				ID: policy.TargetSnapshot.ID, Revision: policy.TargetSnapshot.Revision,
				SHA256: policy.TargetSnapshot.SHA256,
			}
			resolved, resolveErr := resolver.snapshots.ResolveTarget(ctx, tx, command.TenantScopeID, reference)
			if resolveErr != nil || resolved.Reference != reference {
				return rejectCertificateTarget(CertificateTargetSnapshotUnresolved, uuid.Nil, true)
			}
			nodeIDs = slices.Clone(resolved.NodeIDs)
		} else if len(nodeIDs) == 0 {
			// A package policy names no nodes (migration 457): the scope's
			// line groups do, as for its site publications.
			if nodeIDs, err = publicationNodeIDs(ctx, tx, command.TenantScopeID, nil); err != nil {
				return err
			}
		}
		if err := validateCertificatePublicationNodes(ctx, tx, command.TenantScopeID, nodeIDs, databaseNow); err != nil {
			return err
		}
		result = CertificateTargetPolicy{
			PolicyRevision: policy.Revision, NodeIDs: nodeIDs,
			RequiredCapabilities: certificatePublicationCapabilities(),
			ActivationTimeout:    policy.ActivationTimeout, ObservationWindow: policy.ObservationWindow,
			RequiredConsecutiveSuccesses: policy.RequiredConsecutiveSuccesses,
			Deadline:                     databaseNow.Add(policy.DeadlineWindow),
		}
		if !validCertificateTargetPolicy(result, databaseNow) {
			return rejectCertificateTarget(CertificateTargetPolicyInvalid, uuid.Nil, false)
		}
		return nil
	})
	if err != nil {
		return CertificateTargetPolicy{}, fmt.Errorf("resolve certificate publication target: %w", err)
	}
	return result, nil
}

func CertificatePublicationCapabilities() []*agentv1.Capability {
	return certificatePublicationCapabilities()
}

func certificatePublicationCapabilities() []*agentv1.Capability {
	return []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
	}
}

func validCertificateTargetPolicy(policy CertificateTargetPolicy, now time.Time) bool {
	if policy.PolicyRevision < 1 || len(policy.NodeIDs) == 0 || len(policy.NodeIDs) > 10000 ||
		policy.ActivationTimeout <= 0 || policy.ObservationWindow <= 0 ||
		policy.RequiredConsecutiveSuccesses < 1 || !policy.Deadline.After(now) ||
		len(policy.RequiredCapabilities) != 2 {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(policy.NodeIDs))
	for _, nodeID := range policy.NodeIDs {
		if nodeID == uuid.Nil {
			return false
		}
		if _, found := seen[nodeID]; found {
			return false
		}
		seen[nodeID] = struct{}{}
	}
	want := certificatePublicationCapabilities()
	for index := range want {
		if policy.RequiredCapabilities[index] == nil ||
			policy.RequiredCapabilities[index].Name != want[index].Name ||
			policy.RequiredCapabilities[index].ApiVersion != want[index].ApiVersion {
			return false
		}
	}
	return true
}

func validateCertificatePublicationNodes(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	nodeIDs []uuid.UUID,
	now time.Time,
) error {
	if len(nodeIDs) == 0 {
		return rejectCertificateTarget(CertificateTargetNoNodes, uuid.Nil, false)
	}
	rows, err := tx.Query(ctx, `SELECT node.id
		FROM unnest($2::uuid[]) WITH ORDINALITY AS target(node_id,ordinality)
		JOIN nodes node ON node.id=target.node_id AND node.admin_state='active'
		 AND tenant_carries_node_287($1,node.id)
		JOIN node_presence presence ON presence.node_id=node.id AND presence.status='online'
		ORDER BY target.ordinality FOR SHARE OF node,presence`, scopeID, nodeIDs)
	if err != nil {
		return err
	}
	seen := 0
	for rows.Next() {
		var nodeID uuid.UUID
		if err := rows.Scan(&nodeID); err != nil {
			rows.Close()
			return err
		}
		if seen >= len(nodeIDs) || nodeID != nodeIDs[seen] {
			rows.Close()
			if seen >= len(nodeIDs) {
				return ErrInvalidInput
			}
			return diagnoseCertificatePublicationNode(ctx, tx, scopeID, nodeIDs[seen])
		}
		seen++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if seen != len(nodeIDs) {
		return diagnoseCertificatePublicationNode(ctx, tx, scopeID, nodeIDs[seen])
	}
	capabilities, err := edgepublish.LoadNodePublicationCapabilities(ctx, tx, nodeIDs, now)
	if errors.Is(err, edgepublish.ErrTargetIneligible) {
		// node identity certificate or issued capabilities not usable now
		// (for example mid-rotation): retried with backoff
		return rejectCertificateTarget(CertificateTargetNodeIdentity, uuid.Nil, true)
	}
	if err != nil {
		return err
	}
	for _, nodeID := range nodeIDs {
		if !supportsCertificatePublication(capabilities[nodeID].Features) {
			return rejectCertificateTarget(CertificateTargetNodeCapabilityAbsent, nodeID, false)
		}
	}
	return nil
}

// diagnoseCertificatePublicationNode names the first condition nodeID fails
// in validateCertificatePublicationNodes (read in the same transaction).
func diagnoseCertificatePublicationNode(ctx context.Context, tx pgx.Tx, scopeID, nodeID uuid.UUID) error {
	var exists, active, carried, online bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE id=$2),
		EXISTS(SELECT 1 FROM nodes WHERE id=$2 AND admin_state='active'),
		tenant_carries_node_287($1,$2),
		EXISTS(SELECT 1 FROM node_presence WHERE node_id=$2 AND status='online')`,
		scopeID, nodeID).Scan(&exists, &active, &carried, &online)
	switch {
	case err != nil:
		return err
	case !exists:
		return rejectCertificateTarget(CertificateTargetNodeMissing, nodeID, false)
	case !active:
		return rejectCertificateTarget(CertificateTargetNodeInactive, nodeID, false)
	case !carried:
		return rejectCertificateTarget(CertificateTargetNodeNotCarried, nodeID, false)
	case !online:
		return rejectCertificateTarget(CertificateTargetNodeOffline, nodeID, true)
	default:
		// duplicate or reordered target: a policy defect
		return rejectCertificateTarget(CertificateTargetPolicyInvalid, nodeID, false)
	}
}

func supportsCertificatePublication(features []*agentv1.Capability) bool {
	required := certificatePublicationCapabilities()
	found := make(map[agentv1.CapabilityName]uint32, len(features))
	for _, capability := range features {
		if capability == nil || capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED ||
			capability.ApiVersion == 0 {
			return false
		}
		if _, exists := found[capability.Name]; exists {
			return false
		}
		found[capability.Name] = capability.ApiVersion
	}
	for _, capability := range required {
		if found[capability.Name] < capability.ApiVersion {
			return false
		}
	}
	return true
}
