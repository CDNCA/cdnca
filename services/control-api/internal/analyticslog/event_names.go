package analyticslog

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Security event names (P14): a block event row names its site by domain and
// its rule by the rule name of the deciding policy, looked up when the page
// is served (ClickHouse rows keep the IDs). A managed WAF event's OWASP CRS
// rule is named "OWASP CRS #<id> · <msg>".
//
// fix-wafname: a rule pack rule runs on the node under
// rulepack.NodeRuleID(pack_id, rule_id) in a segment whose policy is
// NodeRuleID(pack_id, "@pack") (libs/rulepack MountRulePlan), so it is named
// "<pack name> · <rule name>" from the stored pack artifacts; a policy
// default ("<policy_id>:default"), system-managed rules (quick block, JA4,
// cccoord) and the node's auto defense / managed WAF IDs get Chinese names;
// any other UUID is "未命名规则（<first 8>）". A name is "" only for a rule
// ID that is not a UUID and not known (shown as it is).
type EventNames struct {
	// Sites maps site ID to domain.
	Sites map[string]string
	// Rules maps policy ID (or pack segment policy ID), then rule ID, to the
	// rule name.
	Rules map[string]map[string]string
	// Policies maps policy ID (or pack segment policy ID) to the policy /
	// pack name.
	Policies map[string]string
}

// EventNameRef is one row's site, deciding policy and rule.
type EventNameRef struct {
	SiteID, PolicyID, RuleID string
}

// EventNameLookup resolves the names of one page of rows, all of one tenant
// (tenantID "": the platform view across tenants).
type EventNameLookup interface {
	Lookup(ctx context.Context, tenantID string, refs []EventNameRef) EventNames
}

// SetEventNameLookup makes block event rows carry site_domain and rule_name.
func (handler *Handler) SetEventNameLookup(lookup EventNameLookup) { handler.eventNames = lookup }

func (handler *Handler) lookupEventNames(ctx context.Context, tenantID string, items []BlockEvent) EventNames {
	if handler.eventNames == nil || len(items) == 0 {
		return EventNames{}
	}
	refs := make([]EventNameRef, len(items))
	for index, item := range items {
		refs[index] = EventNameRef{SiteID: item.SiteID, PolicyID: item.PolicyID, RuleID: item.RuleID}
	}
	return handler.eventNames.Lookup(ctx, tenantID, refs)
}

// rule: the name of ruleID in policyID; a row without a policy finds the
// rule in any of the looked-up policies and packs (rule IDs are UUIDs); then
// the CRS, node-written and fallback names (event_rule_names.go).
func (names EventNames) rule(policyID, ruleID string) string {
	ruleID, policyID = strings.ToLower(ruleID), strings.ToLower(policyID)
	if owner, ok := strings.CutSuffix(ruleID, ":default"); ok && validUUID(owner) {
		return defaultRuleName(names.Policies[owner], owner)
	}
	if policyID != "" {
		if name := names.Rules[policyID][ruleID]; name != "" {
			return displayRuleName(name)
		}
	} else {
		for _, policy := range names.Rules {
			if name := policy[ruleID]; name != "" {
				return displayRuleName(name)
			}
		}
	}
	if name := crsRuleName(ruleID); name != "" {
		return name
	}
	if name := fixedRuleName(ruleID); name != "" {
		return name
	}
	return unnamedRuleName(names.Policies[policyID], ruleID)
}

// RuleName is rule for other packages (the WAF overview's attack types).
func (names EventNames) RuleName(policyID, ruleID string) string { return names.rule(policyID, ruleID) }

// PostgresEventNameLookup reads site domains and rule names of the tenant's
// own sites and policies. The rule names come from every stored version of
// the policy (security_policy_versions), newest first, so an event decided
// by an older published revision still finds the name its rule had then
// unless a newer revision renamed it. Rule pack names come from the stored
// pack artifacts the tenant's sites can mount (event_pack_names.go).
type PostgresEventNameLookup struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	packs  *packNameCache
}

func NewPostgresEventNameLookup(pool *pgxpool.Pool, logger *slog.Logger) *PostgresEventNameLookup {
	if logger == nil {
		logger = slog.Default()
	}
	return &PostgresEventNameLookup{pool: pool, logger: logger, packs: &packNameCache{}}
}

const eventSiteNamesSQL = `SELECT site.id::text, site.domain
	FROM sites site
	JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
	WHERE ($1::uuid IS NULL OR scope.tenant_id=$1::uuid) AND site.id=ANY($2::uuid[])`

// eventRuleNamesSQL: the versions of the rows' policies, and of the
// tenant's policies holding a rule a row names without a policy (CC v2
// events carry the rule's UUID only), with the policy name.
const eventRuleNamesSQL = `SELECT version.policy_id::text, version.document->'rules', policy.name
	FROM security_policy_versions version
	JOIN security_policies policy ON policy.id=version.policy_id
	WHERE ($1::uuid IS NULL OR policy.tenant_id=$1::uuid) AND (version.policy_id=ANY($2::uuid[]) OR EXISTS (
		SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(version.document->'rules')='array'
			THEN version.document->'rules' ELSE '[]'::jsonb END) rule
		WHERE rule->>'id'=ANY($3::text[])))
	ORDER BY version.policy_id, version.revision DESC`

// eventNameRule is the part of a stored policy rule the lookup reads.
type eventNameRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (lookup *PostgresEventNameLookup) Lookup(ctx context.Context, tenantID string, refs []EventNameRef) EventNames {
	names := EventNames{Sites: map[string]string{}, Rules: map[string]map[string]string{}, Policies: map[string]string{}}
	if lookup == nil || lookup.pool == nil || tenantID != "" && !validUUID(tenantID) {
		return names
	}
	// tenantID "" is the platform view of every tenant's rows.
	var tenant any
	if tenantID != "" {
		tenant = tenantID
	}
	sites, policies, orphanRules := eventNameIDs(refs)
	if len(sites) > 0 {
		rows, err := lookup.pool.Query(ctx, eventSiteNamesSQL, tenant, sites)
		if err != nil {
			lookup.logger.WarnContext(ctx, "security event site names failed", "error", err)
		} else {
			for rows.Next() {
				var id, domain string
				if rows.Scan(&id, &domain) == nil {
					names.Sites[id] = domain
				}
			}
			rows.Close()
		}
	}
	if len(policies) > 0 || len(orphanRules) > 0 {
		rows, err := lookup.pool.Query(ctx, eventRuleNamesSQL, tenant, policies, orphanRules)
		if err != nil {
			lookup.logger.WarnContext(ctx, "security event rule names failed", "error", err)
		} else {
			for rows.Next() {
				var policyID, policyName string
				var raw []byte
				if rows.Scan(&policyID, &raw, &policyName) != nil {
					continue
				}
				mergeRuleNames(names.Rules, policyID, raw)
				names.Policies[policyID] = policyName
			}
			rows.Close()
		}
	}
	if len(refs) > 0 {
		lookup.lookupPacks(ctx, tenant, refs, &names)
	}
	return names
}

// mergeRuleNames adds one version's rule names; versions come newest first,
// so a name already known for a rule is kept.
func mergeRuleNames(rules map[string]map[string]string, policyID string, raw []byte) {
	var decoded []eventNameRule
	if json.Unmarshal(raw, &decoded) != nil {
		return
	}
	policy := rules[policyID]
	if policy == nil {
		policy = map[string]string{}
		rules[policyID] = policy
	}
	for _, rule := range decoded {
		id := strings.ToLower(rule.ID)
		if _, known := policy[id]; !known && id != "" && rule.Name != "" {
			policy[id] = rule.Name
		}
	}
}

// eventNameIDs: the distinct canonical site and policy UUIDs of the rows,
// and the rule UUIDs of rows without a policy.
func eventNameIDs(refs []EventNameRef) (sites, policies, orphanRules []string) {
	seenSites, seenPolicies, seenRules := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, ref := range refs {
		if id, err := uuid.Parse(ref.SiteID); err == nil && !seenSites[id.String()] {
			seenSites[id.String()] = true
			sites = append(sites, id.String())
		}
		policyID := ref.PolicyID
		if owner, ok := strings.CutSuffix(ref.RuleID, ":default"); ok && policyID == "" {
			policyID = owner // a policy default names its policy (attack types carry no policy)
		}
		if id, err := uuid.Parse(policyID); err == nil && !seenPolicies[id.String()] {
			seenPolicies[id.String()] = true
			policies = append(policies, id.String())
		} else if policyID == "" {
			if id, err := uuid.Parse(ref.RuleID); err == nil && len(ref.RuleID) == 36 && !seenRules[id.String()] {
				seenRules[id.String()] = true
				orphanRules = append(orphanRules, id.String())
			}
		}
	}
	return sites, policies, orphanRules
}
