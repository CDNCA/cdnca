package edgepublish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrCrossScopeConflict rejects a publication that cannot share a node with
// another configuration scope (docs/architecture/multi-tenant-node-sharing.md
// 6.2.1, decisions/multitenant-composition-compat-2026-10-16): a domain or site
// is already served there, or the port-sharing rules of
// edgeconfig.FindPortConflicts refuse two scopes' sockets. Everything else the
// agent composes: plaintext and TLS on one port, TLS split by SNI, several
// scopes with L4, CC v2 or the OWASP CRS managed WAF (waf-share: dynamic
// routing, the only node runtime of 1.0.35, prepares the managed WAF from
// every scope's sites at once, one tier location per CRS profile pack and
// limits, the site's exclusions, allow CIDRs and inspection mode in each
// request's transaction ID; docs/edge/dynroute-managed-waf.md). The message
// names the node and the rule, never the other tenant.
var ErrCrossScopeConflict = errors.New("edge publication conflicts with another tenant on a shared node")

// CrossScopeConflictError says which node refused the publication and why;
// it unwraps to ErrCrossScopeConflict.
type CrossScopeConflictError struct {
	NodeID uuid.UUID
	Reason string
}

func (e *CrossScopeConflictError) Error() string {
	return ErrCrossScopeConflict.Error() + ": node " + e.NodeID.String() + ": " + e.Reason
}

func (e *CrossScopeConflictError) Unwrap() error { return ErrCrossScopeConflict }

// CrossScopeConflictAction is the audit action recorded for every refused
// publication, so administrators can see why a tenant is not on a node.
const CrossScopeConflictAction = "edge_publication.node_scope_conflict"

// scopeFootprint is what one scope's configuration claims on a node.
type scopeFootprint struct {
	domains map[string]struct{}
	sites   map[string]struct{}
	ports   []edgeconfig.PortClaim
}

// decodeScopeFootprint reads a canonical snapshot of either schema.
func decodeScopeFootprint(raw []byte) (scopeFootprint, error) {
	var head struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return scopeFootprint{}, err
	}
	footprint := scopeFootprint{domains: map[string]struct{}{}, sites: map[string]struct{}{}}
	switch head.Schema {
	case siteRuntimeV2Schema:
		var document siteRuntimeV2Document
		if err := json.Unmarshal(raw, &document); err != nil {
			return scopeFootprint{}, err
		}
		for _, site := range document.Sites {
			footprint.sites[site.ID] = struct{}{}
			for _, domain := range site.Domains {
				footprint.domains[strings.ToLower(domain)] = struct{}{}
			}
			for _, listener := range site.Listeners {
				footprint.ports = append(footprint.ports, edgeconfig.SiteListenerPortClaims("", site.ID, uint16(listener.Port),
					listener.TLS != nil, slices.Contains(listener.Protocols, "http3"), site.Domains)...)
			}
		}
		if document.Streams != nil {
			for _, stream := range document.Streams.StreamsV2 {
				footprint.ports = append(footprint.ports, edgeconfig.L4StreamPortClaims("", stream)...)
			}
		}
	default:
		return scopeFootprint{}, fmt.Errorf("unknown canonical snapshot schema %q", head.Schema)
	}
	return footprint, nil
}

// portUser names what holds the other side of a port conflict.
func portUser(claim edgeconfig.PortClaim) string {
	switch claim.Kind {
	case edgeconfig.PortClaimPlainL4, edgeconfig.PortClaimTLSL4:
		return "L4 forwarding"
	case edgeconfig.PortClaimQUIC:
		return "HTTP/3 website"
	default:
		return "website"
	}
}

// conflict reports the first rule two scopes' footprints break, or "".
func (footprint scopeFootprint) conflict(other scopeFootprint) string {
	for domain := range footprint.domains {
		if _, taken := other.domains[domain]; taken {
			return "domain " + domain + " is already served by another tenant"
		}
	}
	for site := range footprint.sites {
		if _, taken := other.sites[site]; taken {
			return "site " + site + " is already served by another tenant"
		}
	}
	claims := make([]edgeconfig.PortClaim, 0, len(footprint.ports)+len(other.ports))
	for _, claim := range footprint.ports {
		claim.Owner = "mine"
		claims = append(claims, claim)
	}
	for _, claim := range other.ports {
		claim.Owner = "other"
		claims = append(claims, claim)
	}
	for _, conflict := range edgeconfig.FindPortConflicts(claims) {
		if conflict.Claim.Owner == conflict.Other.Owner {
			continue // a scope's own sockets are checked when it is saved
		}
		theirs := conflict.Other
		if theirs.Owner == "mine" {
			theirs = conflict.Claim
		}
		if conflict.ProxyProtocol {
			return fmt.Sprintf("tcp port %d is shared with another tenant, so its streams cannot use PROXY protocol", theirs.Port)
		}
		if conflict.Name != "" {
			return fmt.Sprintf("SNI %s on tcp port %d is already used by another tenant's %s",
				conflict.Name, theirs.Port, portUser(theirs))
		}
		return fmt.Sprintf("%s port %d is already used by another tenant's %s", theirs.Protocol, theirs.Port, portUser(theirs))
	}
	return ""
}

// validateCrossScopeComposition checks the new snapshot against every other
// scope on the target nodes: its current configuration and any apply still
// in flight. validateEligibleNodes holds the node rows, so another scope's
// publication to the same node cannot slip in between.
func validateCrossScopeComposition(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, nodeIDs []uuid.UUID,
	snapshot []byte,
) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT other.node_id, version.id, version.canonical_snapshot
		FROM (
			SELECT state.node_id, state.configuration_scope_id, state.current_config_version_id AS version_id
			FROM node_config_state state
			WHERE state.node_id=ANY($1::uuid[]) AND state.configuration_scope_id<>$2
			  AND state.current_config_version_id IS NOT NULL
			UNION
			SELECT deployment.node_id, deployment.configuration_scope_id, deployment.config_version_id
			FROM node_deployments deployment
			WHERE deployment.node_id=ANY($1::uuid[]) AND deployment.configuration_scope_id<>$2
			  AND deployment.action='apply' AND NOT EXISTS (SELECT 1 FROM configuration_artifacts node_artifact
			      WHERE node_artifact.config_version_id=deployment.config_version_id
			        AND node_artifact.media_type=ANY($3::text[]))
			  AND deployment.state NOT IN ('healthy','failed','reverted','rollback_failed','cancelled')
		) other
		JOIN config_versions version ON version.id=other.version_id
		  AND version.configuration_scope_id=other.configuration_scope_id
		ORDER BY other.node_id, version.id`, nodeIDs, scopeID,
		[]string{artifactset.MediaTypeSet, artifactset.MediaTypeSegment})
	if err != nil {
		return fmt.Errorf("%w: read co-located configurations", ErrPersistence)
	}
	var others []colocatedConfiguration
	for rows.Next() {
		var item colocatedConfiguration
		var versionID uuid.UUID
		if err := rows.Scan(&item.node, &versionID, &item.snapshot); err != nil {
			rows.Close()
			return fmt.Errorf("%w: scan co-located configuration", ErrPersistence)
		}
		others = append(others, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: iterate co-located configurations", ErrPersistence)
	}
	if len(others) == 0 {
		return nil
	}
	mine, err := decodeScopeFootprint(snapshot)
	if err != nil {
		return fmt.Errorf("%w: decode publication snapshot", ErrInvalidInput)
	}
	return firstCrossScopeConflict(ctx, mine, others)
}

// colocatedConfiguration is another scope's configuration on a target node.
type colocatedConfiguration struct {
	node     uuid.UUID
	snapshot []byte
}

// firstCrossScopeConflict returns the first rule mine breaks against the
// co-located configurations, or nil.
func firstCrossScopeConflict(ctx context.Context, mine scopeFootprint, others []colocatedConfiguration) error {
	for _, other := range others {
		theirs, err := decodeScopeFootprint(other.snapshot)
		if err != nil {
			// Another tenant's unreadable configuration must not block this
			// one; the agent's own composition precheck still guards the node.
			slog.WarnContext(ctx, "cross-scope check skipped an unreadable co-located configuration",
				"node_id", other.node, "error", err)
			continue
		}
		if reason := mine.conflict(theirs); reason != "" {
			return &CrossScopeConflictError{NodeID: other.node, Reason: reason}
		}
	}
	return nil
}

// recordCrossScopeConflict audits a refused publication. The publication's
// transaction rolled back with it (it had already claimed the nodes), so the
// record commits on its own; failing to write it does not hide the refusal.
func (s *Service) recordCrossScopeConflict(ctx context.Context, request PublishRequest, err error) {
	var conflict *CrossScopeConflictError
	if !errors.As(err, &conflict) {
		return
	}
	_ = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		actor := request.Actor.UserID
		var actorID *uuid.UUID
		if actor != uuid.Nil {
			actorID = &actor
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: request.ConfigurationScopeID, ActorUserID: actorID,
			Action: CrossScopeConflictAction, ResourceType: "node", ResourceID: conflict.NodeID.String(),
			RequestID: request.RequestID, Result: "denied",
			Payload: map[string]any{"reason": conflict.Reason, "node_id": conflict.NodeID.String(),
				"configuration_scope_id": request.ConfigurationScopeID.String(),
				"idempotency_key":        request.IdempotencyKey},
		})
	})
}
