package edgepublish

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ChallengeSecretGeneratorName is the generator of challenge secret rollouts
// (challengepublication.DurableSecretPublisher): their config version's
// canonical snapshot is the challenge policy document the node installs as
// <StateRoot>/challenge/policies/<rule_id>/versions/<policy_version>.json.
const ChallengeSecretGeneratorName = "cdnca-challengepublication"

// challengePolicyTarget is one site's JS challenge in a release: the node
// must hold the policy file the engine loads at master start.
type challengePolicyTarget struct {
	SiteID, Domain string
	PolicyID       string
	PolicyVersion  uint64
}

// ChallengePolicyUnavailableError refuses a release that loads a JS
// challenge policy version a target node has not installed: the challenge
// secret rollout has not succeeded there. nginx -t accepts the release, but
// the node's master would not start (init_by_lua: no valid challenge policy).
// It unwraps to ErrTargetIneligible.
type ChallengePolicyUnavailableError struct {
	NodeID        uuid.UUID
	SiteID        string
	Domain        string
	PolicyID      string
	PolicyVersion uint64
	// OtherNodeIDs are the further target nodes, in target order, missing
	// this or another challenge policy of the release.
	OtherNodeIDs []uuid.UUID
}

func (e *ChallengePolicyUnavailableError) Error() string {
	message := fmt.Sprintf("node %s has not installed the JS challenge policy of site %s (%s): policy %s version %d "+
		"(节点尚未安装该站点的 JS 挑战策略); publish the site's challenge to the node first",
		e.NodeID, e.Domain, e.SiteID, e.PolicyID, e.PolicyVersion)
	if len(e.OtherNodeIDs) != 0 {
		others := make([]string, len(e.OtherNodeIDs))
		for index, nodeID := range e.OtherNodeIDs {
			others[index] = nodeID.String()
		}
		message += "; also missing on nodes " + strings.Join(others, ", ")
	}
	return message
}

func (e *ChallengePolicyUnavailableError) Unwrap() error { return ErrTargetIneligible }

func siteRuntimeV2ChallengePolicyTargets(canonical []byte) ([]challengePolicyTarget, error) {
	var document siteRuntimeV2Document
	if err := json.Unmarshal(canonical, &document); err != nil {
		return nil, ErrInvalidInput
	}
	var targets []challengePolicyTarget
	for _, site := range document.Sites {
		domain := ""
		if len(site.Domains) != 0 {
			domain = site.Domains[0]
		}
		for _, listener := range site.Listeners {
			if listener.Security != nil && listener.Security.Challenge != nil {
				challenge := listener.Security.Challenge
				targets = append(targets, challengePolicyTarget{SiteID: site.ID, Domain: domain,
					PolicyID: challenge.PolicyID, PolicyVersion: challenge.PolicyVersion})
			}
		}
	}
	return uniqueChallengePolicyTargets(targets), nil
}

func uniqueChallengePolicyTargets(targets []challengePolicyTarget) []challengePolicyTarget {
	slices.SortFunc(targets, func(left, right challengePolicyTarget) int {
		return strings.Compare(left.SiteID+"\x00"+left.PolicyID, right.SiteID+"\x00"+right.PolicyID)
	})
	return slices.CompactFunc(targets, func(left, right challengePolicyTarget) bool { return left == right })
}

// validateChallengePolicyTargets refuses the release unless every target
// node holds a healthy challenge secret rollout of the scope for each
// challenge policy version the release loads. The first missing node (in
// target order) and site are named.
func validateChallengePolicyTargets(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, nodeIDs []uuid.UUID,
	targets []challengePolicyTarget) error {
	if len(targets) == 0 || len(nodeIDs) == 0 {
		return nil
	}
	policyIDs := make([]string, len(targets))
	versions := make([]int64, len(targets))
	for index, target := range targets {
		policyIDs[index], versions[index] = target.PolicyID, int64(target.PolicyVersion)
	}
	// The snapshot is decoded only for the scope's challenge secret
	// rollouts (CASE: the planner may evaluate predicates in any order).
	rows, err := tx.Query(ctx, `WITH wanted AS (
			SELECT policy_id,policy_version FROM unnest($3::text[],$4::bigint[]) AS item(policy_id,policy_version)),
		installed AS (
			SELECT DISTINCT deployment.node_id,
			       CASE WHEN version.generator_name=$5 THEN convert_from(version.canonical_snapshot,'UTF8')::jsonb END AS policy
			FROM rollouts rollout
			JOIN config_versions version ON version.id=rollout.config_version_id
			 AND version.configuration_scope_id=rollout.configuration_scope_id
			JOIN node_deployments deployment ON deployment.rollout_id=rollout.id AND deployment.state='healthy'
			WHERE rollout.configuration_scope_id=$1 AND version.generator_name=$5
			  AND deployment.node_id=ANY($2::uuid[]))
		SELECT installed.node_id,wanted.policy_id,wanted.policy_version FROM installed JOIN wanted
		  ON (installed.policy->>'policy_version')::bigint=wanted.policy_version
		 AND jsonb_path_exists(installed.policy,'strict $.rules[*] ? (@.rule_id == $id)',
		       jsonb_build_object('id',wanted.policy_id))`,
		scopeID, nodeIDs, policyIDs, versions, ChallengeSecretGeneratorName)
	if err != nil {
		return fmt.Errorf("%w: read installed challenge policies", ErrPersistence)
	}
	installed := map[string]bool{}
	for rows.Next() {
		var nodeID uuid.UUID
		var policyID string
		var version int64
		if err := rows.Scan(&nodeID, &policyID, &version); err != nil {
			rows.Close()
			return fmt.Errorf("%w: scan installed challenge policies", ErrPersistence)
		}
		installed[fmt.Sprintf("%s\x00%s\x00%d", nodeID, policyID, version)] = true
	}
	rows.Close()
	if rows.Err() != nil {
		return fmt.Errorf("%w: iterate installed challenge policies", ErrPersistence)
	}
	var refusal *ChallengePolicyUnavailableError
	for _, nodeID := range nodeIDs {
		for _, target := range targets {
			if installed[fmt.Sprintf("%s\x00%s\x00%d", nodeID, target.PolicyID, target.PolicyVersion)] {
				continue
			}
			if refusal == nil {
				refusal = &ChallengePolicyUnavailableError{NodeID: nodeID, SiteID: target.SiteID, Domain: target.Domain,
					PolicyID: target.PolicyID, PolicyVersion: target.PolicyVersion}
			} else if nodeID != refusal.NodeID && !slices.Contains(refusal.OtherNodeIDs, nodeID) {
				refusal.OtherNodeIDs = append(refusal.OtherNodeIDs, nodeID)
			}
		}
	}
	if refusal != nil {
		return refusal
	}
	return nil
}
