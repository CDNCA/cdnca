package edgepublish

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/rulepack"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RulePackUnavailableError refuses a dynamic routing release whose sites
// need rule packs (mounted packs, the managed WAF's CRS profile pack) a
// target node has not applied from its node artifact set: the node would
// refuse the sites (precheck / managed WAF check). Like the IP library gate,
// the refusal is held and the release is published once the node's applied
// set gains the packs (artifactsetdist announce). It unwraps to
// ErrTargetIneligible.
type RulePackUnavailableError struct {
	NodeID uuid.UUID
	// SHA256 are the packs the node lacks, sorted.
	SHA256 []string
	// OtherNodeIDs are the further target nodes, in target order, lacking a
	// pack of the release.
	OtherNodeIDs []uuid.UUID
	// Required are every pack the release's sites use, sorted (a waiting
	// request is resumed once every target node holds them all).
	Required []string
	// AutoResume: the caller recorded the refused request and starts it once
	// the packs reach the nodes (securityactivation rule pack wait).
	AutoResume bool
}

func (e *RulePackUnavailableError) Error() string {
	message := fmt.Sprintf("node %s has not installed the rule packs %s the release's sites use (节点尚未安装网站引用的规则包); "+
		"the release is published automatically once the packs reach the node", e.NodeID, strings.Join(e.SHA256, ", "))
	if len(e.OtherNodeIDs) != 0 {
		others := make([]string, len(e.OtherNodeIDs))
		for index, nodeID := range e.OtherNodeIDs {
			others[index] = nodeID.String()
		}
		message += "; also missing on nodes " + strings.Join(others, ", ")
	}
	return message
}

func (e *RulePackUnavailableError) Unwrap() error { return ErrTargetIneligible }

// siteObjectsRulePacks are the rule pack digests the sites read from the
// node object store: every mount's pack and every managed WAF's CRS
// profile pack, sorted and distinct.
func siteObjectsRulePacks(built siteObjectsV2) []string {
	var digests []string
	for _, site := range built.Sites {
		for _, mount := range site.Site.Security.Mounts {
			digests = append(digests, mount.SHA256)
		}
		if waf := site.Site.Security.ManagedWAF; waf != nil {
			digests = append(digests, waf.CRSProfile.SHA256)
		}
	}
	slices.Sort(digests)
	return slices.Compact(digests)
}

// ValidateRulePackTargets is validateRulePackTargets for a caller holding a
// refused request (securityactivation resumes a rule pack wait once it
// passes): RulePackUnavailableError while a node still lacks a pack.
func ValidateRulePackTargets(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID, packs []string) error {
	return validateRulePackTargets(ctx, tx, nodeIDs, packs)
}

// validateRulePackTargets refuses the release for target nodes whose
// applied node artifact set lacks one of packs (node_artifact_applied_items,
// written from the node's own receipt).
func validateRulePackTargets(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID, packs []string) error {
	if len(packs) == 0 || len(nodeIDs) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT node_id, sha256 FROM node_artifact_applied_items
		WHERE node_id=ANY($1::uuid[]) AND media_type=$2 AND sha256=ANY($3::text[])`,
		nodeIDs, artifactset.MediaTypeRulePack, packs)
	if err != nil {
		return fmt.Errorf("%w: read node rule packs", ErrPersistence)
	}
	defer rows.Close()
	applied := make(map[uuid.UUID]map[string]bool, len(nodeIDs))
	for rows.Next() {
		var nodeID uuid.UUID
		var digest string
		if err := rows.Scan(&nodeID, &digest); err != nil {
			return fmt.Errorf("%w: scan node rule packs", ErrPersistence)
		}
		if applied[nodeID] == nil {
			applied[nodeID] = map[string]bool{}
		}
		applied[nodeID][digest] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: iterate node rule packs", ErrPersistence)
	}
	return rulePackTargetsError(nodeIDs, packs, applied)
}

func rulePackTargetsError(nodeIDs []uuid.UUID, packs []string, applied map[uuid.UUID]map[string]bool) error {
	var refusal *RulePackUnavailableError
	for _, nodeID := range nodeIDs {
		var missing []string
		for _, digest := range packs {
			if !applied[nodeID][digest] {
				missing = append(missing, digest)
			}
		}
		switch {
		case len(missing) == 0:
		case refusal == nil:
			refusal = &RulePackUnavailableError{NodeID: nodeID, SHA256: missing, Required: slices.Clone(packs)}
		default:
			refusal.OtherNodeIDs = append(refusal.OtherNodeIDs, nodeID)
		}
	}
	if refusal == nil {
		return nil
	}
	return refusal
}

// rulePackCapabilities are the node capabilities the mounted packs' rules
// need beyond the site runtime (rulepack.CompiledPack.Requires): a pack
// using multipart_* inspect targets (system/waf-php-vpatch)
// needs CAPABILITY_NAME_WAF v5. JA4 / IP intelligence pack
// rules are refused by the node's own precheck today; only the WAF version
// is gated here.
func rulePackCapabilities(packs []*rulepack.CompiledPack) []*agentv1.Capability {
	for _, pack := range packs {
		if pack != nil && slices.Contains(pack.Requires, rulepack.RequiresWAFMultipart) {
			return []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF,
				ApiVersion: edgeconfig.WAFMultipartAPIVersion}}
		}
	}
	return nil
}

// validateRulePackCapabilityTargets refuses, like any gated feature
// (TargetCapabilityError: held, published automatically once the nodes are
// upgraded), a release whose sites mount a pack the target nodes' agents
// cannot run. digests are the mounted packs (siteObjectsRulePacks);
// advertised what each target declares (latest session, else enrollment:
// loadSiteRuntimeV2TargetCapabilities).
func validateRulePackCapabilityTargets(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID, digests []string,
	advertised map[uuid.UUID][]*agentv1.Capability) error {
	if len(digests) == 0 || len(nodeIDs) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (sha256) sha256, content FROM rule_pack_artifacts
		WHERE sha256=ANY($1::text[]) AND content IS NOT NULL ORDER BY sha256`, digests)
	if err != nil {
		return fmt.Errorf("%w: read mounted rule packs", ErrPersistence)
	}
	defer rows.Close()
	var packs []*rulepack.CompiledPack
	for rows.Next() {
		var digest string
		var content []byte
		if err := rows.Scan(&digest, &content); err != nil {
			return fmt.Errorf("%w: scan mounted rule packs", ErrPersistence)
		}
		load := rulepack.Load
		if rulepack.IsSealed(content) {
			load = rulepack.OpenManifest
		}
		compiled, err := load(content, digest)
		if err != nil {
			return fmt.Errorf("%w: stored rule pack %s: %v", ErrInvalidInput, digest, err)
		}
		packs = append(packs, compiled)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: iterate mounted rule packs", ErrPersistence)
	}
	rows.Close()
	required := rulePackCapabilities(packs)
	if len(required) == 0 {
		return nil
	}
	sessions, err := loadSessionCapabilities(ctx, tx, nodeIDs)
	if err != nil {
		return err
	}
	return siteRuntimeV2CapabilityRefusal(nodeIDs, required, advertised, sessions)
}
