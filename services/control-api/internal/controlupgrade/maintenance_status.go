package controlupgrade

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/jackc/pgx/v5"
	"golang.org/x/mod/semver"
)

// MaintenanceRuntime contains process facts, never versions inferred from rollout history.
type MaintenanceRuntime struct {
	CurrentVersion    string
	ConfiguredVersion string
	Build             *MaintenanceBuild
	ProtocolVersion   int
	Candidates        MaintenanceCandidateReader
	ControlRuntime    func(context.Context) MaintenanceRuntimeState
	NodeReady         func() error
	OfflineAfter      time.Duration
}

type MaintenanceBuild struct {
	SourceCommit *string    `json:"source_commit"`
	SourceTree   *string    `json:"source_tree"`
	BuiltAt      *time.Time `json:"built_at"`
	BinarySHA256 *string    `json:"binary_sha256"`
}

type MaintenanceCandidateReader interface {
	ReadCandidate(context.Context, string, string, int) (MaintenanceCandidate, error)
}

type MaintenanceCandidate struct {
	State     string     `json:"state"`
	Reason    string     `json:"reason"`
	Version   *string    `json:"version"`
	ExpiresAt *time.Time `json:"expires_at"`
	Channel   string     `json:"-"`
}

type MaintenanceAuthorization struct {
	State   string `json:"state"`
	Reason  string `json:"reason"`
	Channel string `json:"channel,omitempty"`
}

type MaintenanceRuntimeState struct {
	Ready  bool   `json:"ready"`
	Reason string `json:"reason"`
}

type MaintenanceControlStatus struct {
	Component                string                   `json:"component"`
	CurrentVersion           *string                  `json:"current_version"`
	Build                    *MaintenanceBuild        `json:"build,omitempty"`
	ConfiguredVersionMatches *bool                    `json:"configured_version_matches"`
	Authorization            MaintenanceAuthorization `json:"authorization"`
	Candidate                MaintenanceCandidate     `json:"candidate"`
	Runtime                  MaintenanceRuntimeState  `json:"runtime"`
}

type MaintenanceNodeStatus struct {
	NodeID         string                  `json:"node_id"`
	CurrentVersion *string                 `json:"current_version"`
	Candidate      MaintenanceCandidate    `json:"candidate"`
	Runtime        MaintenanceRuntimeState `json:"runtime"`
	Reason         string                  `json:"reason"`
	Eligible       bool                    `json:"eligible"`
}

type MaintenanceStatus struct {
	Schema     string                   `json:"schema"`
	ObservedAt time.Time                `json:"observed_at"`
	Control    MaintenanceControlStatus `json:"control"`
	Nodes      []MaintenanceNodeStatus  `json:"nodes"`
}

type maintenanceNodeFact struct {
	Status   MaintenanceNodeStatus
	Version  string
	Protocol int
}

func (s *Service) ReadMaintenanceStatus(ctx context.Context, actor Actor, runtime MaintenanceRuntime, nodeIDs []string) (MaintenanceStatus, error) {
	if !validRolloutActor(actor) {
		return MaintenanceStatus{}, ErrPermissionDenied
	}
	nodeIDs = append([]string(nil), nodeIDs...)
	sort.Strings(nodeIDs)
	if len(nodeIDs) > 100 || len(nodeIDs) > 0 && !strictCanonicalUUIDs(nodeIDs) {
		return MaintenanceStatus{}, ErrInvalidInput
	}
	if s == nil || s.store == nil || s.store.pool == nil {
		return MaintenanceStatus{}, ErrRuntimeUnavailable
	}
	now := s.store.now().UTC()
	result := MaintenanceStatus{Schema: "cdnca.maintenance-upgrade-status/v1", ObservedAt: now, Nodes: []MaintenanceNodeStatus{}}
	result.Control = maintenanceControlFacts(runtime)
	var grant entitlementguard.VersionGrant
	var facts []maintenanceNodeFact
	err := pgx.BeginTxFunc(ctx, s.store.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := authorizeUpgradeAccessTx(ctx, tx, actor, rolloutReadPermission, false); err != nil {
			return err
		}
		if len(nodeIDs) > 0 {
			if err := authorizeUpgradeAccessTx(ctx, tx, actor, "nodes.read", false); err != nil {
				return err
			}
		}
		var err error
		grant, err = s.store.guard.ReadValidVersion(ctx, tx)
		result.Control.Authorization, err = maintenanceAuthorization(grant, err)
		if err != nil {
			return err
		}
		if result.Control.Authorization.State == "valid" {
			policy, _, _ := s.store.releaseDecision(grant.Channel)
			if !policy.Allowed {
				result.Control.Authorization.State = "denied"
				result.Control.Authorization.Reason = policy.Reason
			}
		}
		facts, err = readMaintenanceNodeFacts(ctx, tx, actor, nodeIDs, now, runtime.OfflineAfter)
		return err
	})
	if err != nil {
		return MaintenanceStatus{}, err
	}
	// Do not hold a database transaction open while contacting the license service.
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	result.Control.Runtime = maintenanceControlRuntime(ctx, runtime.ControlRuntime)
	type candidateKey struct {
		component, version string
		protocol           int
	}
	cache := make(map[candidateKey]MaintenanceCandidate)
	readCandidate := func(component, version string, protocol int) MaintenanceCandidate {
		key := candidateKey{component, version, protocol}
		if candidate, ok := cache[key]; ok {
			return candidate
		}
		candidate := maintenanceReadCandidate(ctx, runtime.Candidates, component, version, protocol, result.Control.Authorization, grant, s.store.now)
		cache[key] = candidate
		return candidate
	}
	result.Control.Candidate = readCandidate("control-api", runtime.CurrentVersion, runtime.ProtocolVersion)
	nodeRuntime := MaintenanceRuntimeState{Reason: "node_upgrade_runtime_unavailable"}
	if s.rollout != nil && runtime.NodeReady != nil && runtime.NodeReady() == nil {
		nodeRuntime = MaintenanceRuntimeState{Ready: true, Reason: "ready"}
	}
	for _, fact := range facts {
		status := fact.Status
		status.Candidate = readCandidate("edge-agent", fact.Version, fact.Protocol)
		status.Runtime = nodeRuntime
		status = maintenanceNodeEligibility(status)
		result.Nodes = append(result.Nodes, status)
	}
	result.ObservedAt = s.store.now().UTC()
	if result.Control.Candidate.ExpiresAt != nil && !result.Control.Candidate.ExpiresAt.After(result.ObservedAt) {
		result.Control.Candidate = unavailableMaintenanceCandidate("candidate_expired")
	}
	for index := range result.Nodes {
		node := &result.Nodes[index]
		if node.Candidate.ExpiresAt != nil && !node.Candidate.ExpiresAt.After(result.ObservedAt) {
			node.Candidate = unavailableMaintenanceCandidate("candidate_expired")
			node.Eligible, node.Reason = false, "candidate_expired"
		}
	}
	return result, nil
}

func maintenanceControlFacts(runtime MaintenanceRuntime) MaintenanceControlStatus {
	status := MaintenanceControlStatus{Component: "control-api", Build: runtime.Build,
		Runtime: MaintenanceRuntimeState{Reason: "control_upgrade_plan_writer_unconfigured"}}
	if validCanonicalVersion(runtime.CurrentVersion) {
		value := runtime.CurrentVersion
		status.CurrentVersion = &value
		if runtime.ConfiguredVersion != "" {
			matches := runtime.ConfiguredVersion == value
			status.ConfiguredVersionMatches = &matches
		}
	}
	return status
}

func maintenanceAuthorization(grant entitlementguard.VersionGrant, err error) (MaintenanceAuthorization, error) {
	status := MaintenanceAuthorization{Channel: grant.Channel}
	switch {
	case err == nil:
		status.State, status.Reason = "valid", "eligible"
	case errors.Is(err, entitlementguard.ErrUnavailable):
		status.State, status.Reason = "unavailable", ReasonEntitlementUnavailable
	case errors.Is(err, entitlementguard.ErrInvalid):
		status.State, status.Reason = "invalid", ReasonEntitlementInvalid
	case errors.Is(err, entitlementguard.ErrStateDenied):
		status.State, status.Reason = "denied", ReasonEntitlementStateDenied
	default:
		return MaintenanceAuthorization{}, err
	}
	return status, nil
}

func unavailableMaintenanceCandidate(reason string) MaintenanceCandidate {
	return MaintenanceCandidate{State: "unavailable", Reason: reason}
}

func maintenanceReadCandidate(ctx context.Context, reader MaintenanceCandidateReader, component, version string, protocol int,
	authorization MaintenanceAuthorization, grant entitlementguard.VersionGrant, now func() time.Time) MaintenanceCandidate {
	if !validCanonicalVersion(version) {
		return unavailableMaintenanceCandidate("version_unavailable")
	}
	if authorization.State != "valid" {
		return unavailableMaintenanceCandidate(authorization.Reason)
	}
	if protocol <= 0 {
		return unavailableMaintenanceCandidate("protocol_unavailable")
	}
	if reader == nil {
		return unavailableMaintenanceCandidate("candidate_service_unconfigured")
	}
	if ctx.Err() != nil {
		return unavailableMaintenanceCandidate("candidate_service_unavailable")
	}
	candidate, err := reader.ReadCandidate(ctx, component, version, protocol)
	if err != nil {
		return unavailableMaintenanceCandidate("candidate_service_unavailable")
	}
	if candidate.ExpiresAt == nil || !candidate.ExpiresAt.After(now()) {
		return unavailableMaintenanceCandidate("candidate_expired")
	}
	if candidate.State == "unavailable" {
		if candidate.Version != nil {
			return unavailableMaintenanceCandidate("candidate_not_authorized")
		}
		return candidate
	}
	if candidate.Version == nil || !validCanonicalVersion(*candidate.Version) || candidate.Channel != grant.Channel || !grant.AllowsVersion(candidate.Channel, *candidate.Version) {
		return unavailableMaintenanceCandidate("candidate_not_authorized")
	}
	comparison := semver.Compare("v"+*candidate.Version, "v"+version)
	validDirection := candidate.State == "available" && candidate.Reason == "upgrade_available" && comparison > 0 ||
		candidate.State == "up_to_date" && candidate.Reason == "same_version" && comparison == 0 ||
		candidate.State == "rollback_required" && candidate.Reason == "target_is_older" && comparison < 0
	if !validDirection {
		return unavailableMaintenanceCandidate("candidate_not_authorized")
	}
	return candidate
}

func maintenanceNodeEligibility(status MaintenanceNodeStatus) MaintenanceNodeStatus {
	status.Eligible = false
	if status.Reason != "" {
		return status
	}
	if status.Candidate.State != "available" {
		status.Reason = status.Candidate.Reason
		return status
	}
	if !status.Runtime.Ready {
		status.Reason = status.Runtime.Reason
		return status
	}
	status.Eligible, status.Reason = true, "eligible"
	return status
}

func readMaintenanceNodeFacts(ctx context.Context, tx pgx.Tx, actor Actor, nodeIDs []string, now time.Time, offlineAfter time.Duration) ([]maintenanceNodeFact, error) {
	if len(nodeIDs) == 0 {
		return nil, nil
	}
	if offlineAfter <= 0 {
		offlineAfter = 45 * time.Second
	}
	rows, err := tx.Query(ctx, `SELECT node.id,node.admin_state,
		presence.confirmed_agent_version,presence.status,presence.last_seen_at,presence.confirmed_session_epoch,
		node_authority.selected_protocol_major,node_authority.capabilities_snapshot,node_authority.capabilities_sha256
		FROM nodes node LEFT JOIN node_presence presence ON presence.node_id=node.id
		LEFT JOIN LATERAL (`+upgradeSessionAuthoritySQL+`) node_authority ON true
		WHERE node.scope_id=$1 AND node.id=ANY($2::uuid[]) ORDER BY node.id`, actor.ScopeID, nodeIDs, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	facts := make([]maintenanceNodeFact, 0, len(nodeIDs))
	for rows.Next() {
		var fact maintenanceNodeFact
		var adminState string
		var presence, version *string
		var seen *time.Time
		var epoch *int64
		var protocol *uint32
		var capabilities, digest []byte
		if err := rows.Scan(&fact.Status.NodeID, &adminState, &version, &presence, &seen, &epoch, &protocol, &capabilities, &digest); err != nil {
			return nil, err
		}
		if epoch != nil && version != nil && validCanonicalVersion(*version) {
			fact.Status.CurrentVersion, fact.Version = version, *version
		}
		if protocol != nil {
			fact.Protocol = int(*protocol)
		}
		cohortFact := rolloutNodeCapabilityFact{NodeID: fact.Status.NodeID, PresenceVersion: fact.Version, ProtocolVersion: uint32(fact.Protocol), CapabilityBytes: capabilities, CapabilitySHA256: digest}
		_, capabilityErr := rolloutCohortFromFacts([]rolloutNodeCapabilityFact{cohortFact})
		switch {
		case adminState != "active":
			fact.Status.Reason = "node_disabled"
		case fact.Version == "":
			fact.Status.Reason = "version_unavailable"
		case presence == nil || *presence != "online" || seen == nil || !seen.After(now.Add(-offlineAfter)) || seen.After(now.Add(30*time.Second)):
			fact.Status.Reason = "node_offline"
		case capabilityErr != nil:
			fact.Status.Reason = "node_capability_unavailable"
		}
		facts = append(facts, fact)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(facts) != len(nodeIDs) {
		return nil, ErrNodeNotFound
	}
	return facts, nil
}
