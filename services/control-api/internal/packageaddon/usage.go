package packageaddon

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrInUse = errors.New("package addon resources still in use")

// CheckSiteSecurityUsage prevents changing a site's subscription underneath an
// active or outstanding immutable security publication. The caller holds the
// site and subscription locks; this query deliberately acquires no binding lock.
func CheckSiteSecurityUsage(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, limits RuntimeLimits) error {
	var cc, waf bool
	err := tx.QueryRow(ctx, `SELECT
		coalesce(bool_or(b.policy_kind='cc'),false),coalesce(bool_or(b.policy_kind='waf'),false)
		FROM security_policy_site_bindings b
		WHERE b.tenant_scope_id=$1 AND b.site_id=$2 AND b.policy_kind IN ('cc','waf') AND (
		 EXISTS(SELECT 1 FROM security_policy_versions v WHERE v.policy_id=b.policy_id
		  AND v.revision=b.active_policy_version AND (v.document->>'enabled')::boolean)
		 OR EXISTS(SELECT 1 FROM security_policy_publications p
		  JOIN security_policy_versions v ON v.policy_id=p.policy_id AND v.revision=p.policy_version
		  WHERE p.binding_id=b.id AND (v.document->>'enabled')::boolean AND (
		   EXISTS(SELECT 1 FROM security_policy_publication_targets t
		    WHERE t.publication_id=p.id AND t.released_at IS NULL)
		   OR EXISTS(SELECT 1 FROM security_policy_activation_candidates c
		    WHERE c.last_bundle_id=p.id AND (c.candidate_status IN ('claimed','canary','expanding','healthy')
		     OR (c.candidate_status IN ('failed','cancelled','expired') AND c.recovered_at IS NULL)))
		 )
		))`, scopeID, siteID).Scan(&cc, &waf)
	if err != nil {
		return err
	}
	if waf && !limits.WAF {
		return ErrWAFInUse
	}
	if cc && !limits.CustomCC {
		return ErrInUse
	}
	return nil
}

// checkReducedAssignment runs after the tentative assignment write, while the
// subscription row is locked. Any failure rolls back the write and its audit.
func checkReducedAssignment(ctx context.Context, tx pgx.Tx, scopeID, subscriptionID uuid.UUID, kind string, at time.Time) error {
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT package_addon_effective_limits($1,$2)`, subscriptionID, at).Scan(&raw); err != nil {
		return err
	}
	var limits RuntimeLimits
	if err := json.Unmarshal(raw, &limits); err != nil {
		return ErrUnavailable
	}
	switch kind {
	case "domains", "root_domains", "http_ports":
		usage, err := SiteUsage(ctx, tx, scopeID, subscriptionID)
		if err != nil {
			return err
		}
		used, limit := usage.Domains, limits.Domains
		if kind == "root_domains" {
			used, limit = usage.RootDomains, limits.RootDomains
		} else if kind == "http_ports" {
			used, limit = usage.HTTPPorts, limits.HTTPPorts
		}
		if limit != -1 && used > limit {
			return ErrInUse
		}
	case "stream_ports":
		var used int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(COALESCE(listener.port_end, listener.port)-listener.port+1),0)
		 FROM l4_forward_listeners listener
		 JOIN l4_forwards forward ON forward.id=listener.stream_id
		 WHERE forward.scope_id=$1 AND forward.package_subscription_id=$2
		 AND forward.deleted_at IS NULL AND listener.retired_at IS NULL`, scopeID, subscriptionID).Scan(&used); err != nil {
			return err
		}
		if limits.StreamPorts != -1 && used > limits.StreamPorts {
			return ErrInUse
		}
	case "custom_cc", "waf":
		if (kind == "custom_cc" && limits.CustomCC) || (kind == "waf" && limits.WAF) {
			return nil
		}
		// Only the feature being reduced is relevant to this operation.
		if kind == "custom_cc" {
			limits.WAF = true
		} else {
			limits.CustomCC = true
		}
		rows, err := tx.Query(ctx, `SELECT id FROM sites WHERE scope_id=$1
		 AND package_subscription_id=$2 AND deleted_at IS NULL ORDER BY id`, scopeID, subscriptionID)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		for _, id := range ids {
			if err := CheckSiteSecurityUsage(ctx, tx, scopeID, id, limits); err != nil {
				return err
			}
		}
	}
	return nil
}
