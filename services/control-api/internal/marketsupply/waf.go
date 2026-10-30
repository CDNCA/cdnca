package marketsupply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/securityiplist"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// siteWAF is siteconf's waf block (marketsubscribe.WAF): the subscriber's
// WAF policy fields without rule IDs, the IP lists its rules name and the
// site's CRS application types.
type siteWAF struct {
	DefaultAction string                      `json:"default_action"`
	Rules         []securitypolicy.Rule       `json:"rules"`
	WAFSettings   *securitypolicy.WAFSettings `json:"waf_settings,omitempty"`
	QuickBlock    *securitypolicy.QuickBlock  `json:"quick_block,omitempty"`
	IPLists       map[string]siteIPList       `json:"ip_lists,omitempty"`
	CRSApps       []string                    `json:"crs_apps,omitempty"`
}

type siteIPList struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

func decodeSiteWAF(c siteconf.Config) (*siteWAF, error) {
	if len(c.WAF) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(c.WAF))
	decoder.DisallowUnknownFields()
	var waf siteWAF
	if err := decoder.Decode(&waf); err != nil {
		return nil, err
	}
	return &waf, nil
}

// checkIPLists: every ip_list condition names a carried list, and every
// carried list is named and holds what a local list may.
func (waf *siteWAF) checkIPLists() error {
	for _, id := range securitypolicy.IPListReferences(waf.Rules) {
		if _, ok := waf.IPLists[id.String()]; !ok {
			return errors.New("ip list condition without its list")
		}
	}
	for key, list := range waf.IPLists {
		if _, err := uuid.Parse(key); err != nil {
			return err
		}
		if _, err := securityiplist.Normalize(securityiplist.Input{Name: leafIPListName(list.Name, key), Entries: list.CIDRs}); err != nil {
			return err
		}
	}
	return nil
}

// leafIPListName is the leaf's own list for a subscriber list: unique per
// subscriber list ID, within the local 64 character name limit.
func leafIPListName(name, subscriberID string) string {
	name = strings.TrimSpace(name)
	if runes := []rune(name); len(runes) > 40 {
		name = string(runes[:40])
	}
	return "market " + strings.ReplaceAll(subscriberID, "-", "")[:16] + " " + name
}

// wafFields maps the block onto a local WAF policy, checked as the policy
// store would publish it. ip_list conditions still name the subscriber's
// lists; applySecurity points them at the leaf's (withLeafIPLists).
func wafFields(waf *siteWAF) (securitypolicy.PolicyFields, error) {
	fields := securitypolicy.PolicyFields{Kind: securitypolicy.KindWAF, Name: "market waf", Enabled: true,
		DefaultAction: waf.DefaultAction, Rules: waf.Rules, WAFSettings: waf.WAFSettings}
	if fields.Rules == nil {
		fields.Rules = []securitypolicy.Rule{}
	}
	if err := waf.checkIPLists(); err != nil {
		return securitypolicy.PolicyFields{}, err
	}
	if len(waf.CRSApps) > edgeconfig.MaxManagedWAFApps {
		return securitypolicy.PolicyFields{}, errors.New("too many CRS application types")
	}
	if waf.QuickBlock != nil {
		block := *waf.QuickBlock
		if err := securitypolicy.NormalizeQuickBlock(&block); err != nil {
			return securitypolicy.PolicyFields{}, err
		}
	}
	policy := securitypolicy.Policy{Kind: fields.Kind, Name: fields.Name, Enabled: true,
		DefaultAction: fields.DefaultAction, Rules: fields.Rules, WAFSettings: fields.WAFSettings}
	if err := securitypolicy.ValidatePublishablePolicy(policy); err != nil {
		return securitypolicy.PolicyFields{}, err
	}
	return fields, nil
}

// withLeafIPLists is fields with every ip_list condition naming the leaf
// list mapped[subscriber list ID].
func withLeafIPLists(fields securitypolicy.PolicyFields, mapped map[string]uuid.UUID) securitypolicy.PolicyFields {
	if len(mapped) == 0 {
		return fields
	}
	rules := slices.Clone(fields.Rules)
	for i := range rules {
		conditions := slices.Clone(rules[i].Conditions)
		for j := range conditions {
			if conditions[j].Field == "ip_list" && len(conditions[j].Values) == 1 {
				if id, ok := mapped[conditions[j].Values[0]]; ok {
					conditions[j].Values = []string{id.String()}
				}
			}
		}
		rules[i].Conditions = conditions
	}
	fields.Rules = rules
	return fields
}

// managedWAFProfiles are the CRS profile packs the block's managed WAF rules
// run.
func managedWAFProfiles(waf *siteWAF) []string {
	var out []string
	for _, rule := range waf.Rules {
		if m := rule.ActionConfig.ManagedWAF; m != nil && m.Profile != "" {
			out = append(out, m.Profile)
		}
	}
	return out
}

// wafBlockers: a malformed waf block (waf_invalid), one on a leaf without
// security activation, or a managed WAF profile pack / CRS application
// pack this controller has not downloaded (unsupported_waf, detail the pack).
func (s *Service) wafBlockers(ctx context.Context, c siteconf.Config, wired bool) []siteconf.Blocker {
	waf, err := decodeSiteWAF(c)
	if err != nil {
		return []siteconf.Blocker{{Code: "waf_invalid"}}
	}
	if waf == nil {
		return nil
	}
	if _, err := wafFields(waf); err != nil {
		return []siteconf.Blocker{{Code: "waf_invalid"}}
	}
	if !wired || len(waf.CRSApps) > 0 && s.crs == nil || len(waf.IPLists) > 0 && s.ipLists == nil {
		return []siteconf.Blocker{{Code: "unsupported_waf", Detail: activationPending}}
	}
	if len(managedWAFProfiles(waf)) == 0 && len(waf.CRSApps) == 0 {
		return nil
	}
	var profiles securitypolicy.CRSProfiles
	var apps securitypolicy.CRSApps
	if err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		if profiles, err = securitypolicy.LoadCRSProfilesTx(ctx, tx, nil); err != nil {
			return err
		}
		apps, err = securitypolicy.LoadCRSAppsTx(ctx, tx)
		return err
	}); err != nil {
		return []siteconf.Blocker{{Code: "leaf_unavailable"}}
	}
	var out []siteconf.Blocker
	for _, rule := range waf.Rules {
		if m := rule.ActionConfig.ManagedWAF; m != nil && profiles.Check(*m) != nil {
			out = append(out, siteconf.Blocker{Code: "unsupported_waf", Detail: m.Profile})
		}
	}
	for _, app := range waf.CRSApps {
		if _, ok := apps[app]; !ok {
			out = append(out, siteconf.Blocker{Code: "unsupported_waf", Detail: app})
		}
	}
	return out
}
