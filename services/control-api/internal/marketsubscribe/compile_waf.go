package marketsubscribe

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecrs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The site's WAF (fix-mktsiteconf2 ②) carried as siteconf's waf block: the
// leaf is a cdnca 1.0.35 controller, so the block is the bound policy's own
// fields. The managed OWASP CRS rule carries what the site runs (its WAF
// rule library's profile and exclusions with the site override applied);
// the leaf validates the profile against the CRS packs it has downloaded.

// WAF is siteconf's waf block.
type WAF struct {
	DefaultAction string                      `json:"default_action"`
	Rules         []securitypolicy.Rule       `json:"rules"`
	WAFSettings   *securitypolicy.WAFSettings `json:"waf_settings,omitempty"`
	QuickBlock    *securitypolicy.QuickBlock  `json:"quick_block,omitempty"`
	// IPLists (fix-mktsiteconf3) are the published contents of the IP lists
	// the rules' ip_list conditions name, by this platform's list ID; the
	// leaf writes them as its own lists and points the rules at those.
	IPLists map[string]WAFIPList `json:"ip_lists,omitempty"`
	// CRSApps are the site's CRS application types (system/app-* pack IDs);
	// the leaf applies them when it downloaded every pack.
	CRSApps []string `json:"crs_apps,omitempty"`
}

// WAFIPList is one carried IP list: its name and CIDRs.
type WAFIPList struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

// compileWAF is an enabled WAF policy as the waf block; profile and
// exclusions, when the site runs a managed WAF, are the effective ones; the
// IP lists its rules name are expanded from lists. A rule naming a list that
// is not in lists (deleted, not usable) cannot be carried (the reason is
// returned).
func compileWAF(p securitypolicy.Policy, crs *sitecrs.Library, apps []string, lists map[uuid.UUID]WAFIPList) (*WAF, string) {
	if !p.Enabled {
		return nil, ""
	}
	waf := &WAF{DefaultAction: p.DefaultAction, WAFSettings: p.WAFSettings, QuickBlock: p.QuickBlock,
		CRSApps: slices.Clone(apps)}
	if waf.QuickBlock != nil && !waf.QuickBlock.Active() {
		waf.QuickBlock = nil
	}
	for _, r := range p.Rules {
		if securitypolicy.IsQuickBlockRuleID(r.ID) {
			continue // the leaf's SetQuickBlock rebuilds them
		}
		for _, id := range securitypolicy.IPListReferences([]securitypolicy.Rule{r}) {
			list, ok := lists[id]
			if !ok {
				return nil, "waf_ip_list"
			}
			if waf.IPLists == nil {
				waf.IPLists = map[string]WAFIPList{}
			}
			waf.IPLists[id.String()] = list
		}
		r.ID = uuid.Nil
		if m := r.ActionConfig.ManagedWAF; m != nil && crs != nil {
			managed := *m
			managed.Profile, managed.Exclusions = crs.Profile, slices.Clone(crs.Exclusions)
			r.ActionConfig.ManagedWAF = &managed
		}
		waf.Rules = append(waf.Rules, r)
	}
	if waf.Rules == nil {
		waf.Rules = []securitypolicy.Rule{}
	}
	return waf, ""
}

// siteCRS reads the site's CRS override and its effective managed WAF.
func (s *Service) siteCRS(ctx context.Context, siteID uuid.UUID) (*sitecrs.Library, []string, error) {
	var library *sitecrs.Library
	var apps []string
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var scopeID uuid.UUID
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT site.scope_id, crs.override FROM sites site
			LEFT JOIN site_crs_overrides crs ON crs.site_id=site.id WHERE site.id=$1`, siteID).Scan(&scopeID, &raw); err != nil {
			return err
		}
		if raw != nil {
			override, err := securitypolicy.DecodeCRSOverride(raw)
			if err != nil {
				return err
			}
			apps = override.Apps
		}
		var err error
		library, err = sitecrs.EffectiveLibraryTx(ctx, tx, scopeID, siteID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	return library, apps, err
}

// policyIPLists reads the published contents of the IP lists p's rules
// name, as the policy's scope may use them (LoadIPListsTx), with their names.
func (s *Service) policyIPLists(ctx context.Context, p securitypolicy.Policy) (map[uuid.UUID]WAFIPList, error) {
	ids := securitypolicy.IPListReferences(p.Rules)
	if len(ids) == 0 {
		return nil, nil
	}
	out := map[uuid.UUID]WAFIPList{}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		resolved, err := securitypolicy.LoadIPListsTx(ctx, tx, p.ScopeID, ids)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id, name FROM security_ip_lists WHERE id=ANY($1::uuid[])`, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var name string
			if err := rows.Scan(&id, &name); err != nil {
				return err
			}
			if list, ok := resolved[id]; ok {
				out[id] = WAFIPList{Name: name, CIDRs: list.CIDRs}
			}
		}
		return rows.Err()
	})
	return out, err
}

// compileWAFPolicy writes the site's WAF block or the reason it cannot.
func (s *Service) compileWAFPolicy(ctx context.Context, siteID uuid.UUID, p securitypolicy.Policy, cfg *siteconf.Config) (string, error) {
	crs, apps, err := s.siteCRS(ctx, siteID)
	if err != nil {
		return "", err
	}
	lists, err := s.policyIPLists(ctx, p)
	if err != nil {
		return "", err
	}
	waf, reason := compileWAF(p, crs, apps, lists)
	if waf != nil {
		cfg.WAF, err = json.Marshal(waf)
	}
	return reason, err
}
