package controlupgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

type RolloutTargetCohort struct {
	Platform        string
	Architecture    string
	CurrentVersion  string
	ProtocolVersion uint32
	// CurrentReleaseSequence is the highest installed release_sequence
	// when every node declares SAME_VERSION_UPGRADE with one; 0 otherwise.
	CurrentReleaseSequence uint64
	Targets                []PlanTarget
}

type rolloutNodeCapabilityFact struct {
	NodeID           string
	PresenceVersion  string
	ProtocolVersion  uint32
	CapabilityBytes  []byte
	CapabilitySHA256 []byte
	// LastExecutionSequence is the highest execution_sequence of the node's stored v3 commands.
	LastExecutionSequence uint64
}

// LoadRolloutTargetCohort is the unlocked preliminary read the License grants are
// requested for: FinalizeCreateRollout re-reads the cohort under row locks and
// refuses any difference, so row locks here would only make creation fail or
// wait on unrelated writers (a NOWAIT share lock on the installation
// entitlement row, the mutex of every entitlement-guarded write, returned 500).
func (s *Store) LoadRolloutTargetCohort(ctx context.Context, actor Actor,
	nodeIDs []string) (RolloutTargetCohort, error) {
	if s == nil || s.pool == nil || !validRolloutActor(actor) || len(nodeIDs) == 0 ||
		len(nodeIDs) > 1000 || !strictCanonicalUUIDs(nodeIDs) {
		return RolloutTargetCohort{}, ErrInvalidInput
	}
	var cohort RolloutTargetCohort
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error {
			if err := authorizeUpgradeAccessTx(ctx, tx, actor, rolloutManagePermission, false); err != nil {
				return err
			}
			var err error
			cohort, err = loadRolloutTargetCohortTx(ctx, tx, actor.ScopeID, nodeIDs, false)
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
	allRerelease := true
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
		sequence := installedReleaseSequence(&capabilities)
		cohort.Targets = append(cohort.Targets, PlanTarget{NodeID: fact.NodeID,
			AgentVersion: fact.PresenceVersion, ProtocolVersion: fact.ProtocolVersion,
			ReceiptSequence: max(sequence, fact.LastExecutionSequence)})
		allRerelease = allRerelease && sequence != 0
		cohort.CurrentReleaseSequence = max(cohort.CurrentReleaseSequence, sequence)
	}
	if !allRerelease {
		cohort.CurrentReleaseSequence = 0
	}
	return cohort, nil
}

// installedReleaseSequence is the node's installed release_sequence when it
// declares SAME_VERSION_UPGRADE v1; 0 when it cannot re-release.
func installedReleaseSequence(capabilities *agentv1.AgentCapabilities) uint64 {
	for _, feature := range capabilities.GetFeatures() {
		if feature.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SAME_VERSION_UPGRADE && feature.GetApiVersion() == 1 {
			return capabilities.GetInstalledReleaseSequence()
		}
	}
	return 0
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
