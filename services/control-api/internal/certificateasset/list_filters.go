package certificateasset

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxListFilterDomains bounds the exact multi-domain filter.
const MaxListFilterDomains = 100

func validListFilterText(value string, maximum int) bool {
	return value == "" || len(value) <= maximum && strings.TrimSpace(value) == value &&
		utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

// validRemark: an asset or order 备注, up to 256 characters, trimmed, no
// control characters (migration 517).
func validRemark(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= 256 &&
		strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

func validListFilters(filters ListFilters) bool {
	for _, value := range []string{filters.Domain, filters.User, filters.CertificateID, filters.Name, filters.Remark} {
		if !validListFilterText(value, 128) {
			return false
		}
	}
	if len(filters.Domains) > MaxListFilterDomains {
		return false
	}
	for _, domain := range filters.Domains {
		if domain == "" || !validListFilterText(domain, 253) {
			return false
		}
	}
	return (filters.Source == "" || filters.Source == SourceUploaded || filters.Source == SourceACME) &&
		(filters.DNSProviderID == nil || *filters.DNSProviderID != [16]byte{}) &&
		(filters.Expiry == "" || slices.Contains(ListExpiries, filters.Expiry)) &&
		(filters.Issue == "" || slices.Contains(ListIssueStates, filters.Issue)) &&
		(filters.Sync == "" || slices.Contains(ListSyncStates, filters.Sync))
}

// currentBindingPublications is, per site currently bound to asset, the
// latest publication state of that binding revision and whether its rollout
// is fully applied: an apply rollout with deployments whose latest attempts
// are all healthy (as edgedeployment reports a succeeded rollout).
const currentBindingPublications = `SELECT latest.state, rollout_done.applied
	FROM (SELECT DISTINCT ON (binding.site_id) binding.site_id,binding.sequence,binding.action,binding.asset_id
		FROM certificate_site_binding_facts binding
		WHERE binding.tenant_scope_id=asset.tenant_scope_id AND binding.site_id IN (
			SELECT ever.site_id FROM certificate_site_binding_facts ever
			WHERE ever.tenant_scope_id=asset.tenant_scope_id AND ever.asset_id=asset.id)
		ORDER BY binding.site_id,binding.sequence DESC) current_binding
	LEFT JOIN LATERAL (SELECT state.state,state.rollout_id FROM certificate_publication_intent_state_facts state
		WHERE state.tenant_scope_id=asset.tenant_scope_id AND state.site_id=current_binding.site_id
		  AND state.binding_revision=current_binding.sequence
		ORDER BY state.sequence DESC LIMIT 1) latest ON true
	LEFT JOIN LATERAL (SELECT rollout.action='apply' AND rollout.status NOT IN ('paused','failed','cancelled') AND
			EXISTS (SELECT 1 FROM node_deployments deployment WHERE deployment.rollout_id=rollout.id) AND
			NOT EXISTS (SELECT 1 FROM (SELECT DISTINCT ON (deployment.id) deployment.state FROM node_deployments deployment
				WHERE deployment.rollout_id=rollout.id ORDER BY deployment.id,deployment.attempt DESC) attempt
				WHERE attempt.state<>'healthy') AS applied
		FROM rollouts rollout WHERE rollout.id=latest.rollout_id) rollout_done ON true
	WHERE current_binding.action='bind' AND current_binding.asset_id=asset.id`

// listFilterSQL is the WHERE conjunction of the advanced search (CERT-05).
// It may reference the fact lateral of ListPage (latest version facts);
// nowPosition is the placeholder of the list's clock.
func listFilterSQL(filters ListFilters, arguments *[]any, nowPosition int) string {
	var clauses []string
	bind := func(value any) int {
		*arguments = append(*arguments, value)
		return len(*arguments)
	}
	if filters.Domain != "" {
		clauses = append(clauses, fmt.Sprintf(`EXISTS (SELECT 1 FROM certificate_asset_versions version
			CROSS JOIN LATERAL unnest(version.sans) domain
			WHERE version.tenant_scope_id=asset.tenant_scope_id AND version.asset_id=asset.id
			  AND strpos(lower(domain),lower($%d))>0)`, bind(filters.Domain)))
	}
	if len(filters.Domains) > 0 {
		domains := make([]string, len(filters.Domains))
		for index, domain := range filters.Domains {
			domains[index] = strings.ToLower(domain)
		}
		clauses = append(clauses, fmt.Sprintf(`fact.latest_sans @> $%d::text[]`, bind(domains)))
	}
	if filters.User != "" {
		clauses = append(clauses, fmt.Sprintf(`EXISTS (SELECT 1 FROM users owner WHERE owner.id=asset.owner_user_id AND (
			strpos(owner.display_id::text,$%[1]d)>0 OR strpos(lower(owner.username),lower($%[1]d))>0 OR
			strpos(COALESCE(owner.email,''),lower($%[1]d))>0 OR strpos(COALESCE(owner.phone,''),$%[1]d)>0))`, bind(filters.User)))
	}
	if filters.CertificateID != "" {
		clauses = append(clauses, fmt.Sprintf(`strpos(asset.display_id::text,$%d)>0`, bind(filters.CertificateID)))
	}
	if filters.Name != "" {
		clauses = append(clauses, fmt.Sprintf(`strpos(lower(asset.name),lower($%d))>0`, bind(filters.Name)))
	}
	if filters.Remark != "" {
		clauses = append(clauses, fmt.Sprintf(`strpos(lower(asset.remark),lower($%d))>0`, bind(filters.Remark)))
	}
	if filters.Source != "" {
		clauses = append(clauses, fmt.Sprintf(`asset.source=$%d`, bind(filters.Source)))
	}
	if filters.DNSProviderID != nil {
		clauses = append(clauses, fmt.Sprintf(`EXISTS (SELECT 1 FROM certificate_orders cert_order
			WHERE cert_order.scope_id=asset.tenant_scope_id AND cert_order.issued_asset_id=asset.id
			  AND cert_order.dns_provider_id=$%d)`, bind(*filters.DNSProviderID)))
	}
	switch filters.Expiry {
	case "within30", "within90":
		days := map[string]string{"within30": "30 days", "within90": "90 days"}[filters.Expiry]
		clauses = append(clauses, fmt.Sprintf(`fact.expiry IN ('normal','expiring') AND
			fact.latest_not_after - $%d <= interval '%s'`, nowPosition, days))
	case "expired":
		clauses = append(clauses, `fact.expiry='expired'`)
	}
	if filters.AutoRenew != nil {
		if *filters.AutoRenew {
			clauses = append(clauses, `renew.auto_renew`)
		} else {
			clauses = append(clauses, `NOT renew.auto_renew`)
		}
	}
	switch filters.Issue {
	case "issued":
		clauses = append(clauses, `EXISTS (SELECT 1 FROM certificate_orders cert_order
			WHERE cert_order.scope_id=asset.tenant_scope_id AND cert_order.issued_asset_id=asset.id)`)
	case "failed":
		clauses = append(clauses, `EXISTS (SELECT 1 FROM certificate_orders source
			WHERE source.scope_id=asset.tenant_scope_id AND source.issued_asset_id=asset.id AND (source.status='failed' OR
			EXISTS (SELECT 1 FROM certificate_orders renewal WHERE renewal.scope_id=source.scope_id
				AND renewal.renewal_of_order_id=source.id AND renewal.status='failed')))`)
	}
	switch filters.Sync {
	case "failed":
		clauses = append(clauses, `EXISTS (`+currentBindingPublications+` AND latest.state='permanent_failed')`)
	case "complete":
		clauses = append(clauses, `EXISTS (`+currentBindingPublications+`) AND NOT EXISTS (`+currentBindingPublications+
			` AND NOT COALESCE(latest.state='succeeded' AND rollout_done.applied,false))`)
	case "pending":
		clauses = append(clauses, `EXISTS (`+currentBindingPublications+
			` AND NOT COALESCE(latest.state='succeeded' AND rollout_done.applied,false)) AND NOT EXISTS (`+
			currentBindingPublications+` AND latest.state='permanent_failed')`)
	}
	if len(clauses) == 0 {
		return ""
	}
	return " AND " + strings.Join(clauses, " AND ")
}
