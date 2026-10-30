// Package securityrulereport uploads every tenant-created CC rule group,
// matcher, filter and WAF policy to the license service
// (cdnca.security-custom-rule-report/v2). The upload is mandatory: there is
// no installation or tenant switch. Owners leave only as an
// installation-salted hash; display names, usernames and system rules are
// never included.
package securityrulereport

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrReportTooLarge means the tenant rules exceed the v2 limits (256 items
// per section, 64 KiB per item, 1 MiB per report); the upload is deferred and
// the condition is surfaced in the state row instead of silently truncating.
var ErrReportTooLarge = errors.New("security custom rule report exceeds v2 limits")

type PolicySource interface {
	ListCustomPoliciesForReport(context.Context, string) ([]securitypolicy.CustomPolicyReportItem, error)
}

type Collector struct {
	pool     *pgxpool.Pool
	policies PolicySource
}

func NewCollector(pool *pgxpool.Pool, policies PolicySource) *Collector {
	return &Collector{pool: pool, policies: policies}
}

// Collect builds the canonical report and its digest.
func (collector *Collector) Collect(ctx context.Context, installationID uuid.UUID) (rulecatalog.Report, [32]byte, error) {
	var zero [32]byte
	if collector == nil || collector.pool == nil || collector.policies == nil || installationID == uuid.Nil {
		return rulecatalog.Report{}, zero, errors.New("invalid security custom rule collector")
	}
	owner := func(id uuid.UUID) string { return rulecatalog.OwnerHash(installationID.String(), id.String()) }
	report := rulecatalog.Report{}
	for _, section := range []struct {
		kind   string
		target *[]json.RawMessage
	}{{securitypolicy.KindWAF, &report.WAFPolicies}, {securitypolicy.KindCC, &report.CCRuleGroups}} {
		items, err := collector.policies.ListCustomPoliciesForReport(ctx, section.kind)
		if err != nil {
			return rulecatalog.Report{}, zero, err
		}
		*section.target = make([]json.RawMessage, 0, len(items))
		for _, item := range items {
			encoded, err := json.Marshal(map[string]any{"id": item.ID, "scope_id": item.ScopeID, "owner_hash": owner(item.OwnerID),
				"name": item.Name, "description": item.Description, "enabled": item.Enabled,
				"default_action": item.DefaultAction, "rules": item.Rules, "version": item.Version})
			if err != nil {
				return rulecatalog.Report{}, zero, err
			}
			*section.target = append(*section.target, encoded)
		}
	}
	var err error
	if report.CCMatchers, err = collector.references(ctx, `SELECT id,scope_id,owner_user_id,name,description,enabled,
		jsonb_build_object('field',field,'operator',operator,'key',condition_key,'values',values),revision
		FROM cc_reference_matchers WHERE deleted_at IS NULL AND NOT system_rule ORDER BY id`, owner); err != nil {
		return rulecatalog.Report{}, zero, err
	}
	if report.CCFilters, err = collector.references(ctx, `SELECT id,scope_id,owner_user_id,name,description,enabled,
		jsonb_build_object('type',filter_type,'parameters',parameters),revision
		FROM cc_reference_filters WHERE deleted_at IS NULL AND NOT system_rule ORDER BY id`, owner); err != nil {
		return rulecatalog.Report{}, zero, err
	}
	canonical, digest, err := rulecatalog.CanonicalReport(report)
	if err != nil {
		return rulecatalog.Report{}, zero, ErrReportTooLarge
	}
	return canonical, digest, nil
}

func (collector *Collector) references(ctx context.Context, query string, owner func(uuid.UUID) string) ([]json.RawMessage, error) {
	rows, err := collector.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (json.RawMessage, error) {
		var id, scopeID, ownerID uuid.UUID
		var name, description string
		var enabled bool
		var fields map[string]any
		var revision int64
		if err := row.Scan(&id, &scopeID, &ownerID, &name, &description, &enabled, &fields, &revision); err != nil {
			return nil, err
		}
		fields["id"], fields["scope_id"], fields["owner_hash"] = id, scopeID, owner(ownerID)
		fields["name"], fields["description"], fields["enabled"], fields["version"] = name, description, enabled, revision
		return json.Marshal(fields)
	})
	if err != nil {
		return nil, err
	}
	if items == nil {
		items = []json.RawMessage{}
	}
	return items, nil
}
