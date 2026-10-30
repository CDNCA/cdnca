package controlupgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

type RolloutTargetCohort struct {
	Platform        string
	Architecture    string
	CurrentVersion  string
	ProtocolVersion uint32
	Targets         []PlanTarget
}

type rolloutNodeCapabilityFact struct {
	NodeID           string
	PresenceVersion  string
	ProtocolVersion  uint32
	CapabilityBytes  []byte
	CapabilitySHA256 []byte
}

func (s *Store) LoadRolloutTargetCohort(ctx context.Context, actor Actor,
	nodeIDs []string) (RolloutTargetCohort, error) {
	if s == nil || s.pool == nil || !validRolloutActor(actor) || len(nodeIDs) == 0 ||
		len(nodeIDs) > 1000 || !strictCanonicalUUIDs(nodeIDs) {
		return RolloutTargetCohort{}, ErrInvalidInput
	}
	parsed := make([]uuid.UUID, len(nodeIDs))
	for index, nodeID := range nodeIDs {
		parsed[index] = uuid.MustParse(nodeID)
	}

	var cohort RolloutTargetCohort
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRolloutTx(ctx, tx, actor, rolloutManagePermission); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id FROM nodes
			WHERE scope_id=$1 AND id=ANY($2::uuid[]) ORDER BY id FOR SHARE`, actor.ScopeID, parsed)
		if err != nil {
			return err
		}
		found := 0
		for rows.Next() {
			found++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if found != len(parsed) {
			return ErrNodeNotFound
		}
		if err := lockUpgradeSessionAuthority(ctx, tx, parsed); err != nil {
			return err
		}

		var transactionNow time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&transactionNow); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT node.id,presence.confirmed_agent_version,
			node_authority.selected_protocol_major,node_authority.capabilities_snapshot,
			node_authority.capabilities_sha256
			FROM unnest($2::uuid[]) WITH ORDINALITY AS target(node_id,ordinality)
			JOIN nodes node ON node.id=target.node_id AND node.scope_id=$1 AND node.admin_state='active'
			JOIN node_presence presence ON presence.node_id=node.id AND presence.status='online'
			  AND presence.confirmed_agent_version IS NOT NULL
			JOIN LATERAL (`+upgradeSessionAuthoritySQL+` FOR SHARE OF facts,state,artifact,auth,initial,installation NOWAIT) node_authority ON true
			ORDER BY target.ordinality FOR SHARE OF node,presence`, actor.ScopeID, parsed, transactionNow)
		if err != nil {
			return err
		}
		facts := make([]rolloutNodeCapabilityFact, 0, len(parsed))
		for rows.Next() {
			var fact rolloutNodeCapabilityFact
			if err := rows.Scan(&fact.NodeID, &fact.PresenceVersion, &fact.ProtocolVersion,
				&fact.CapabilityBytes, &fact.CapabilitySHA256); err != nil {
				rows.Close()
				return err
			}
			facts = append(facts, fact)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(facts) != len(parsed) {
			return ErrCohortIncompatible
		}
		cohort, err = rolloutCohortFromFacts(facts)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrNodeNotFound) ||
			errors.Is(err, ErrCohortIncompatible) || errors.Is(err, ErrInvalidInput) {
			return RolloutTargetCohort{}, err
		}
		return RolloutTargetCohort{}, fmt.Errorf("load control upgrade target cohort: %w", err)
	}
	return cohort, nil
}

func rolloutCohortFromFacts(facts []rolloutNodeCapabilityFact) (RolloutTargetCohort, error) {
	if len(facts) == 0 {
		return RolloutTargetCohort{}, ErrCohortIncompatible
	}
	cohort := RolloutTargetCohort{Targets: make([]PlanTarget, 0, len(facts))}
	for index, fact := range facts {
		if !validCanonicalPlanUUID(fact.NodeID) || !validCanonicalVersion(fact.PresenceVersion) ||
			fact.ProtocolVersion == 0 || len(fact.CapabilitySHA256) != sha256.Size {
			return RolloutTargetCohort{}, ErrCohortIncompatible
		}
		digest := sha256.Sum256(fact.CapabilityBytes)
		if !bytes.Equal(digest[:], fact.CapabilitySHA256) {
			return RolloutTargetCohort{}, ErrCohortIncompatible
		}
		var capabilities agentv1.AgentCapabilities
		if proto.Unmarshal(fact.CapabilityBytes, &capabilities) != nil ||
			len(capabilities.ProtoReflect().GetUnknown()) != 0 {
			return RolloutTargetCohort{}, ErrCohortIncompatible
		}
		canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&capabilities)
		if err != nil || !bytes.Equal(canonical, fact.CapabilityBytes) ||
			capabilities.AgentVersion != fact.PresenceVersion ||
			!codePattern.MatchString(capabilities.OperatingSystem) ||
			!codePattern.MatchString(capabilities.Architecture) ||
			!hasUpgradeCapability(capabilities.Features) {
			return RolloutTargetCohort{}, ErrCohortIncompatible
		}
		if index == 0 {
			cohort.Platform = capabilities.OperatingSystem
			cohort.Architecture = capabilities.Architecture
			cohort.CurrentVersion = capabilities.AgentVersion
			cohort.ProtocolVersion = fact.ProtocolVersion
		} else if cohort.Platform != capabilities.OperatingSystem ||
			cohort.Architecture != capabilities.Architecture ||
			cohort.CurrentVersion != capabilities.AgentVersion ||
			cohort.ProtocolVersion != fact.ProtocolVersion {
			return RolloutTargetCohort{}, ErrCohortIncompatible
		}
		cohort.Targets = append(cohort.Targets, PlanTarget{NodeID: fact.NodeID,
			AgentVersion: fact.PresenceVersion, ProtocolVersion: fact.ProtocolVersion})
	}
	return cohort, nil
}

func hasUpgradeCapability(features []*agentv1.Capability) bool {
	var previous agentv1.CapabilityName
	found := false
	for index, feature := range features {
		if feature == nil || feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED ||
			feature.ApiVersion == 0 || index > 0 && feature.Name <= previous {
			return false
		}
		if _, known := agentv1.CapabilityName_name[int32(feature.Name)]; !known {
			return false
		}
		if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE && feature.ApiVersion == 1 {
			found = true
		}
		previous = feature.Name
	}
	return found
}
