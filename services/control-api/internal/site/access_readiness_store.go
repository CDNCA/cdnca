package site

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The control plane's node presence cutoff (NODE_PRESENCE_OFFLINE_AFTER,
// default 45s, as nodepresence.Inventory): a node is online when its
// confirmed session's last heartbeat is newer than now minus this.
const defaultNodeOfflineAfter = 45 * time.Second

// WithNodeOfflineAfter sets the presence cutoff the line_group check uses.
func (s *Store) WithNodeOfflineAfter(after time.Duration) *Store {
	if after > 0 {
		s.nodeOfflineAfter = after
	}
	return s
}

func (s *Store) offlineAfter() time.Duration {
	if s.nodeOfflineAfter > 0 {
		return s.nodeOfflineAfter
	}
	return defaultNodeOfflineAfter
}

type accessQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// accessReadinessSQL reads every fact of a page of sites in one statement
// (the list stays a fixed number of queries). The line group is the one
// cnameallocation resolves: the site's own, else (with a package) the
// package's, else the platform default; online nodes are its current
// revision's endpoints published right now (node_line_endpoint_published:
// enabled, node active/draining, primary or a standby taking over) whose
// node is not held and heartbeating; an unpublished standby carries no
// traffic, so it does not make the line usable. The certificate is the
// site's current binding. The publication is the site's latest automatic
// request plus the scope's latest publication: whether its config version
// carries the site (config_version_telemetry_site_bindings) and its node
// deployments.
const accessReadinessSQL = `
SELECT site.id, site.enabled, site.https_enabled,
	line.line_group_id IS NOT NULL,
	COALESCE((SELECT count(DISTINCT endpoint.node_id) FROM node_line_endpoint_published endpoint
		JOIN node_presence presence ON presence.node_id=endpoint.node_id
		WHERE endpoint.tenant_scope_id=line.tenant_scope_id AND endpoint.line_group_id=line.line_group_id
		  AND endpoint.config_revision=line.current_revision AND endpoint.published
		  AND NOT EXISTS (SELECT 1 FROM node_serving_holds hold WHERE hold.node_id=endpoint.node_id AND hold.held)
		  AND presence.confirmed_session_epoch IS NOT NULL AND presence.status='online' AND presence.last_seen_at > $2), 0),
	binding.action='bind', version.not_before, version.not_after,
	COALESCE(active.version_id=binding.version_id, false),
	EXISTS (SELECT 1 FROM certificate_asset_revocation_facts revoked WHERE revoked.tenant_scope_id=binding.tenant_scope_id
		AND revoked.asset_id=binding.asset_id AND revoked.version_id=binding.version_id),
	COALESCE(request.state, ''), publication.rollout_id IS NOT NULL,
	COALESCE(EXISTS (SELECT 1 FROM config_version_telemetry_site_bindings carried
		WHERE carried.config_version_id=publication.config_version_id AND carried.site_id=site.id), false),
	COALESCE(deployment.total, 0), COALESCE(deployment.healthy, 0), COALESCE(deployment.failed, 0),
	check_row.ok, check_row.detail, check_row.cname, check_row.domains, check_row.checked_at, check_row.manual_requested_at
FROM sites site
LEFT JOIN package_subscriptions subscription
  ON subscription.tenant_scope_id=site.scope_id AND subscription.id=site.package_subscription_id
LEFT JOIN LATERAL (
	SELECT line_group.tenant_scope_id, line_group.id AS line_group_id, line_group.current_revision
	FROM node_line_groups line_group
	JOIN node_line_group_revisions revision ON revision.tenant_scope_id=line_group.tenant_scope_id
	 AND revision.line_group_id=line_group.id AND revision.revision=line_group.current_revision AND revision.sealed_at IS NOT NULL
	WHERE line_group.deleted_at IS NULL
	  AND (line_group.tenant_scope_id=site.scope_id OR line_group.tenant_scope_id=(
	      SELECT platform.id FROM access_scopes platform WHERE platform.kind='platform'))
	  AND CASE WHEN site.node_group_id IS NOT NULL THEN line_group.id=site.node_group_id
	           WHEN site.package_subscription_id IS NOT NULL THEN line_group.id=(subscription.product_snapshot->'spec'->>'node_group_id')::uuid
	           ELSE line_group.is_platform_default END
	ORDER BY (line_group.tenant_scope_id=site.scope_id) DESC LIMIT 1
) line ON true
LEFT JOIN LATERAL (
	SELECT fact.tenant_scope_id, fact.action, fact.asset_id, fact.version_id FROM certificate_site_binding_facts fact
	WHERE fact.tenant_scope_id=site.scope_id AND fact.site_id=site.id ORDER BY fact.sequence DESC LIMIT 1
) binding ON true
LEFT JOIN certificate_asset_versions version
  ON binding.action='bind' AND version.tenant_scope_id=binding.tenant_scope_id AND version.asset_id=binding.asset_id
 AND version.id=binding.version_id
LEFT JOIN LATERAL (
	SELECT activation.version_id FROM certificate_asset_activation_facts activation
	WHERE binding.action='bind' AND activation.tenant_scope_id=binding.tenant_scope_id AND activation.asset_id=binding.asset_id
	ORDER BY activation.sequence DESC LIMIT 1
) active ON true
LEFT JOIN LATERAL (
	SELECT state.state FROM edge_automatic_publication_requests request_row
	JOIN LATERAL (SELECT state FROM edge_automatic_publication_request_state_facts
		WHERE request_id=request_row.id ORDER BY sequence DESC LIMIT 1) state ON true
	WHERE request_row.target_scope_id=site.scope_id AND request_row.source_kind='site' AND request_row.source_resource_id=site.id
	ORDER BY request_row.created_at DESC, request_row.id DESC LIMIT 1
) request ON true
LEFT JOIN LATERAL (
	SELECT published.rollout_id, published.config_version_id FROM edge_config_publications published
	WHERE published.configuration_scope_id=site.scope_id
	ORDER BY published.created_at DESC, published.id DESC LIMIT 1
) publication ON true
LEFT JOIN LATERAL (
	SELECT count(*) AS total, count(*) FILTER (WHERE latest.state='healthy') AS healthy,
		count(*) FILTER (WHERE latest.state IN ('failed','reverted','rollback_failed')) AS failed
	FROM (SELECT DISTINCT ON (node_deployment.id) node_deployment.state FROM node_deployments node_deployment
		WHERE node_deployment.rollout_id=publication.rollout_id
		ORDER BY node_deployment.id, node_deployment.attempt DESC) latest
) deployment ON publication.rollout_id IS NOT NULL
LEFT JOIN site_dns_resolution_checks check_row ON check_row.site_id=site.id
WHERE site.id=ANY($1)`

// loadAccessReadiness: site ID → its readiness facts (with the site
// fields the caller already has filled in by fill).
func loadAccessFacts(ctx context.Context, db accessQuerier, ids []uuid.UUID, onlineSince time.Time) (map[uuid.UUID]*accessFacts, error) {
	facts := make(map[uuid.UUID]*accessFacts, len(ids))
	if len(ids) == 0 {
		return facts, nil
	}
	rows, err := db.Query(ctx, accessReadinessSQL, ids, onlineSince)
	if err != nil {
		return nil, fmt.Errorf("load site access readiness: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var item accessFacts
		var bound *bool
		var checkOK *bool
		var checkDetail, checkCNAME *string
		var checkDomains []string
		var checkedAt, manualAt *time.Time
		if err := rows.Scan(&id, &item.Enabled, &item.HTTPSEnabled, &item.LineGroupFound, &item.OnlineNodes,
			&bound, &item.CertNotBefore, &item.CertNotAfter, &item.CertActive, &item.CertRevoked,
			&item.PublishState, &item.publication, &item.includesSite, &item.deployments, &item.healthy, &item.failed,
			&checkOK, &checkDetail, &checkCNAME, &checkDomains, &checkedAt, &manualAt); err != nil {
			return nil, err
		}
		item.CertBound = bound != nil && *bound
		item.PublishState = publishState(item.PublishState, item.publication, item.includesSite, item.deployments, item.healthy, item.failed)
		if checkOK != nil {
			item.DNS = &dnsCheckRow{OK: *checkOK, Domains: checkDomains, CheckedAt: checkedAt, ManualRequestedAt: manualAt}
			if checkDetail != nil {
				item.DNS.Detail = *checkDetail
			}
			if checkCNAME != nil {
				item.DNS.CNAME = *checkCNAME
			}
		}
		facts[id] = &item
	}
	return facts, rows.Err()
}

// projectListAccessReadiness fills access_readiness of a page of sites.
func (s *Store) projectListAccessReadiness(ctx context.Context, db accessQuerier, items []ListItem) error {
	ids := make([]uuid.UUID, len(items))
	for index := range items {
		ids[index] = items[index].ID
	}
	now := s.now().UTC()
	facts, err := loadAccessFacts(ctx, db, ids, now.Add(-s.offlineAfter()))
	if err != nil {
		return err
	}
	for index := range items {
		item := &items[index]
		fact := facts[item.ID]
		if fact == nil {
			continue
		}
		fact.CNAME, fact.CNAMEState, fact.CNAMEFailureCode, fact.Domains = item.CNAME, item.CNAMEState, item.CNAMEFailureCode, item.Domains
		fact.PackageUnavailable = item.PackageUnavailableReason
		readiness := buildAccessReadiness(*fact, now)
		item.AccessReadiness = &readiness
	}
	return nil
}

func (s *Store) projectAccessReadiness(ctx context.Context, db accessQuerier, item *Site) error {
	now := s.now().UTC()
	facts, err := loadAccessFacts(ctx, db, []uuid.UUID{item.ID}, now.Add(-s.offlineAfter()))
	if err != nil {
		return err
	}
	fact := facts[item.ID]
	if fact == nil {
		return nil
	}
	fact.CNAME, fact.CNAMEState, fact.CNAMEFailureCode, fact.Domains = item.CNAME, item.CNAMEState, item.CNAMEFailureCode, item.Domains
	fact.PackageUnavailable = item.PackageUnavailableReason
	readiness := buildAccessReadiness(*fact, now)
	item.AccessReadiness = &readiness
	return nil
}

// DNSCheckClaim is one due resolution check handed to the worker.
type DNSCheckClaim struct {
	SiteID, ScopeID uuid.UUID
	Generation      int64
	Failures        int
	Target          dnsTarget
}

// dnsTargetSQL: a site's CNAME, active domains and the addresses its line
// group publishes right now (node_line_endpoint_published; an unpublished
// standby address is not in DNS, so a domain pointing at it is not ours yet).
const dnsTargetSQL = `
SELECT site.cname, ` + "%s" + `,
	COALESCE((SELECT array_agg(DISTINCT host(endpoint.address)) FROM node_line_endpoint_published endpoint
		JOIN node_line_groups line_group ON line_group.tenant_scope_id=endpoint.tenant_scope_id AND line_group.id=endpoint.line_group_id
		 AND line_group.current_revision=endpoint.config_revision AND line_group.deleted_at IS NULL
		WHERE endpoint.published AND (line_group.tenant_scope_id=site.scope_id OR line_group.tenant_scope_id=(
		      SELECT platform.id FROM access_scopes platform WHERE platform.kind='platform'))
		  AND CASE WHEN site.node_group_id IS NOT NULL THEN line_group.id=site.node_group_id
		           WHEN site.package_subscription_id IS NOT NULL THEN line_group.id=(
		               SELECT (subscription.product_snapshot->'spec'->>'node_group_id')::uuid FROM package_subscriptions subscription
		               WHERE subscription.tenant_scope_id=site.scope_id AND subscription.id=site.package_subscription_id)
		           ELSE line_group.is_platform_default END), '{}'::text[])
FROM sites site WHERE site.id=$1 AND site.deleted_at IS NULL`

func (s *Store) loadDNSTarget(ctx context.Context, db pgx.Tx, siteID uuid.UUID) (dnsTarget, bool, error) {
	var target dnsTarget
	err := db.QueryRow(ctx, fmt.Sprintf(dnsTargetSQL, activeDomainsExpression("site")), siteID).
		Scan(&target.CNAME, &target.Domains, &target.Expected)
	if errors.Is(err, pgx.ErrNoRows) {
		return dnsTarget{}, false, nil
	}
	return target, err == nil, err
}

// ClaimDNSChecks enrolls sites without a check row (due now) and leases up
// to limit due checks for lease (a crashed worker's check comes back).
func (s *Store) ClaimDNSChecks(ctx context.Context, limit int, lease time.Duration) ([]DNSCheckClaim, error) {
	now := s.now().UTC()
	var claims []DNSCheckClaim
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO site_dns_resolution_checks (site_id, scope_id, next_check_at, created_at, updated_at)
			SELECT site.id, site.scope_id, $1, $1, $1 FROM sites site
			WHERE site.deleted_at IS NULL AND NOT EXISTS (SELECT 1 FROM site_dns_resolution_checks existing WHERE existing.site_id=site.id)
			ORDER BY site.created_at LIMIT $2
			ON CONFLICT (site_id) DO NOTHING`, now, limit); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `WITH due AS (
				SELECT check_row.site_id FROM site_dns_resolution_checks check_row
				JOIN sites site ON site.id=check_row.site_id AND site.deleted_at IS NULL
				WHERE check_row.next_check_at <= $1
				ORDER BY check_row.next_check_at LIMIT $2 FOR UPDATE OF check_row SKIP LOCKED)
			UPDATE site_dns_resolution_checks check_row SET next_check_at=$3, updated_at=$1
			FROM due WHERE check_row.site_id=due.site_id
			RETURNING check_row.site_id, check_row.scope_id, check_row.generation, check_row.consecutive_failures`,
			now, limit, now.Add(lease))
		if err != nil {
			return err
		}
		for rows.Next() {
			var claim DNSCheckClaim
			if err := rows.Scan(&claim.SiteID, &claim.ScopeID, &claim.Generation, &claim.Failures); err != nil {
				rows.Close()
				return err
			}
			claims = append(claims, claim)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		kept := claims[:0]
		for _, claim := range claims {
			target, found, err := s.loadDNSTarget(ctx, tx, claim.SiteID)
			if err != nil {
				return err
			}
			if found {
				claim.Target = target
				kept = append(kept, claim)
			}
		}
		claims = kept
		return nil
	})
	return claims, err
}

// CompleteDNSCheck stores the outcome unless 立即检查 replaced the claim,
// and schedules the next check (10 minutes, failures backing off to 1 hour).
func (s *Store) CompleteDNSCheck(ctx context.Context, claim DNSCheckClaim, outcome dnsOutcome) error {
	now := s.now().UTC()
	failures := 0
	if !outcome.OK {
		failures = claim.Failures + 1
	}
	_, err := s.pool.Exec(ctx, storeDNSCheckSQL, claim.SiteID, claim.Generation, outcome.OK, nullableDetail(outcome),
		claim.Target.CNAME, nonNilDomains(claim.Target.Domains), resultsJSON(outcome), failures,
		now.Add(dnsCheckDelay(failures, dnsCheckInterval, dnsCheckMaxBackoff)), now)
	return err
}

const storeDNSCheckSQL = `UPDATE site_dns_resolution_checks SET ok=$3, detail=$4, cname=$5, domains=$6, results=$7,
	consecutive_failures=$8, next_check_at=$9, checked_at=$10, updated_at=$10
	WHERE site_id=$1 AND generation=$2`

func nullableDetail(outcome dnsOutcome) *string {
	if outcome.OK {
		return nil
	}
	detail := outcome.Detail
	if detail == "" {
		detail = DNSLookupFailed
	}
	return &detail
}

func nonNilDomains(domains []string) []string {
	if domains == nil {
		return []string{}
	}
	return domains
}

func resultsJSON(outcome dnsOutcome) string {
	results := outcome.Results
	if results == nil {
		results = []DNSDomainResult{}
	}
	raw, _ := json.Marshal(results)
	return string(raw)
}

// CheckAccessNow is 立即检查: once a minute per site, it resolves the
// site's domains now (bounded by the per-lookup timeout) and stores the
// result like the background check, then returns the site's readiness.
func (s *Store) CheckAccessNow(ctx context.Context, actor Actor, siteID uuid.UUID, resolver DNSResolver) (AccessReadiness, error) {
	now := s.now().UTC()
	var claim DNSCheckClaim
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var scopeID uuid.UUID
		err := tx.QueryRow(ctx, `SELECT site.scope_id FROM sites site
			WHERE site.id=$1 AND site.deleted_at IS NULL AND ($2='platform' OR site.scope_id=$3)`,
			siteID, actor.ScopeKind, actor.ScopeID).Scan(&scopeID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_dns_resolution_checks (site_id, scope_id, next_check_at, created_at, updated_at)
			VALUES ($1, $2, $3, $3, $3) ON CONFLICT (site_id) DO NOTHING`, siteID, scopeID, now); err != nil {
			return err
		}
		var last *time.Time
		if err := tx.QueryRow(ctx, `SELECT manual_requested_at FROM site_dns_resolution_checks WHERE site_id=$1 FOR UPDATE`,
			siteID).Scan(&last); err != nil {
			return err
		}
		if wait := manualAccessCheckWait(last, now); wait > 0 {
			return &AccessCheckThrottledError{Wait: wait}
		}
		// A new generation: a background claim in flight can no longer store
		// its older answer over this one.
		if err := tx.QueryRow(ctx, `UPDATE site_dns_resolution_checks SET manual_requested_at=$2, generation=generation+1,
				next_check_at=$3, updated_at=$2 WHERE site_id=$1 RETURNING generation, consecutive_failures`,
			siteID, now, now.Add(5*time.Minute)).Scan(&claim.Generation, &claim.Failures); err != nil {
			return err
		}
		target, found, err := s.loadDNSTarget(ctx, tx, siteID)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		claim.SiteID, claim.ScopeID, claim.Target = siteID, scopeID, target
		return nil
	})
	if err != nil {
		return AccessReadiness{}, err
	}
	if err := s.CompleteDNSCheck(ctx, claim, resolveSiteDNS(ctx, resolver, claim.Target)); err != nil {
		return AccessReadiness{}, err
	}
	item, err := s.Get(ctx, actor, siteID)
	if err != nil {
		return AccessReadiness{}, err
	}
	if item.AccessReadiness == nil {
		return AccessReadiness{}, ErrNotFound
	}
	return *item.AccessReadiness, nil
}
