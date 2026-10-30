package securitypolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CCSystemDefaults is what system-mode CC settings follow: the tenant's
// global CC config (防火墙配置 → CC全局配置, openresty_security_configs scope
// global; region/node overrides do not apply to a site's policy).
type CCSystemDefaults struct {
	BlockSeconds int
	WhiteSeconds int
	AutoSwitch   CCSystemAutoSwitch
	// Layers (fix-fwregion) are the platform's auto switch layers; AutoSwitch
	// is Layers.Global once loaded.
	Layers AutoSwitchLayers
}

// CCSystemAutoSwitch is the global auto_switch: Rule is the catalog rule
// group, by legacy ID ("10003") or system key ("cc_rule:10003").
type CCSystemAutoSwitch struct {
	Enable   bool   `json:"enable"`
	QPS5xx   int    `json:"qps_50x"`
	QPSTotal int    `json:"qps_total"`
	Rule     string `json:"rule"`
	Seconds  int    `json:"seconds"`
}

// Global config defaults (openrestysecurity.DefaultGlobalConfig): blacklist
// 3600 s, temporary whitelist 21600 s, no auto switch.
const (
	ccSystemDefaultBlockSeconds = 3600
	ccSystemDefaultWhiteSeconds = 21600
)

// OwnerCCDefaults reads the owner's enabled global 默认设置 > 黑名单时间 /
// 白名单时间 (site_user_defaults cc_ban_seconds / cc_pass_seconds, migration
// 511; values validated when saved); 0 is none.
func (s *Store) OwnerCCDefaults(ctx context.Context, scopeID, ownerID uuid.UUID) (ban, pass int, err error) {
	rows, err := s.pool.Query(ctx, `SELECT setting_name, setting_value::int FROM site_user_defaults
		WHERE scope_id=$1 AND owner_user_id=$2 AND group_id IS NULL AND enabled
		AND setting_name IN ('cc_ban_seconds', 'cc_pass_seconds')`, scopeID, ownerID)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var seconds int
		if err := rows.Scan(&name, &seconds); err != nil {
			return 0, 0, err
		}
		if name == "cc_ban_seconds" {
			ban = seconds
		} else {
			pass = seconds
		}
	}
	return ban, pass, rows.Err()
}

// CCSystemDefaults reads scopeID's global CC config (blacklist / whitelist
// time) and the platform's auto switch layers (fix-fwregion), the tenant's
// own auto_switch (the license's cc_protection) being the default of an
// unset platform global one.
func (s *Store) CCSystemDefaults(ctx context.Context, scopeID uuid.UUID) (CCSystemDefaults, error) {
	result, raw, err := s.tenantCCSystemDefaults(ctx, scopeID)
	if err != nil {
		return CCSystemDefaults{}, err
	}
	layers, err := LoadAutoSwitchLayers(ctx, s.pool, raw)
	if err != nil {
		return CCSystemDefaults{}, err
	}
	result.AutoSwitch, result.Layers = layers.Global, layers
	return result, nil
}

func (s *Store) tenantCCSystemDefaults(ctx context.Context, scopeID uuid.UUID) (CCSystemDefaults, []byte, error) {
	result := CCSystemDefaults{BlockSeconds: ccSystemDefaultBlockSeconds, WhiteSeconds: ccSystemDefaultWhiteSeconds}
	var available bool
	if err := s.pool.QueryRow(ctx, `SELECT to_regclass('openresty_security_configs') IS NOT NULL`).Scan(&available); err != nil {
		return CCSystemDefaults{}, nil, err
	}
	if !available {
		return result, nil, nil
	}
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT document FROM openresty_security_configs
		WHERE tenant_scope_id=$1 AND scope_type='global' AND scope_id='0' AND deleted_at IS NULL`, scopeID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, nil, nil
	}
	if err != nil {
		return CCSystemDefaults{}, nil, err
	}
	result, err = decodeCCSystemDefaults(raw, result)
	return result, raw, err
}

func decodeCCSystemDefaults(raw []byte, result CCSystemDefaults) (CCSystemDefaults, error) {
	var document struct {
		BlockTime  *int                `json:"block_time"`
		WhiteTime  *int                `json:"white_time"`
		AutoSwitch *CCSystemAutoSwitch `json:"auto_switch"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&document); err != nil {
		return CCSystemDefaults{}, err
	}
	if document.BlockTime != nil {
		result.BlockSeconds = *document.BlockTime
	}
	if document.WhiteTime != nil {
		result.WhiteSeconds = *document.WhiteTime
	}
	if document.AutoSwitch != nil {
		result.AutoSwitch = *document.AutoSwitch
	}
	return result, nil
}

func clampInt(value, minimum, maximum int) int {
	return max(minimum, min(maximum, value))
}

// ResolveCCSettings fills every system-mode value of settings from
// defaults; custom values are left as they are. The global auto switch
// expands its catalog rule group like an import; a disabled or unusable global auto switch
// (no threshold, unknown or empty rule group) resolves to off. Rule IDs of
// the expansion are left empty (assignCCSettingsRuleIDs derives them).
func ResolveCCSettings(settings *CCSettings, defaults CCSystemDefaults, catalog []rulecatalog.Item) {
	if settings == nil {
		return
	}
	if settings.BanSeconds != nil && settings.BanSeconds.Mode == CCSettingSystem {
		// The global blacklist time may be 0 or beyond a day; the node bans
		// for 1 s .. 1 day.
		seconds := defaults.BlockSeconds
		if seconds <= 0 {
			seconds = ccSystemDefaultBlockSeconds
		}
		settings.BanSeconds.Seconds = clampInt(seconds, 1, 86_400)
	}
	if settings.PassSeconds != nil && settings.PassSeconds.Mode == CCSettingSystem {
		settings.PassSeconds.Seconds = clampInt(defaults.WhiteSeconds, 60, 7*86_400)
	}
	value := settings.AutoSwitch
	if value == nil || value.Mode != CCSettingSystem {
		return
	}
	*value = resolveGlobalAutoSwitch(defaults.AutoSwitch, catalog)
	// Platform nodes whose region / node override differs (Q2: only platform
	// nodes; Q3: a custom site switch is never overridden).
	resolveAutoSwitchOverrides(value, defaults.Layers, catalog)
}

func resolveGlobalAutoSwitch(global CCSystemAutoSwitch, catalog []rulecatalog.Item) CCAutoSwitch {
	off := CCAutoSwitch{Mode: CCSettingSystem, RuleGroups: []string{}, Rules: []Rule{}}
	if !global.Enable || global.QPSTotal <= 0 && global.QPS5xx <= 0 {
		return off
	}
	key, found := catalogRuleGroupKey(catalog, global.Rule)
	if !found {
		return off
	}
	index := make(map[string]rulecatalog.Item, len(catalog))
	for _, item := range catalog {
		index[item.SystemKey] = item
	}
	rules, err := ExpandCCRuleGroup(index, key)
	if err != nil || len(rules) == 0 {
		return off
	}
	return CCAutoSwitch{Mode: CCSettingSystem, QPSTotal: clampInt(global.QPSTotal, 0, ccAutoSwitchMaxQPS),
		QPS5xx: clampInt(global.QPS5xx, 0, ccAutoSwitchMaxQPS), RecoverSeconds: recoverSeconds(global),
		RuleGroups: []string{key}, Rules: rules}
}

// AutoSwitchNeedsCatalog: some layer would expand a rule group.
func AutoSwitchNeedsCatalog(defaults CCSystemDefaults) bool {
	if defaults.AutoSwitch.Enable {
		return true
	}
	for _, item := range defaults.Layers.Nodes {
		if item.Value.Enable {
			return true
		}
	}
	return false
}

// catalogRuleGroupKey finds a CC rule group by legacy ID or system key.
func catalogRuleGroupKey(catalog []rulecatalog.Item, reference string) (string, bool) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return "", false
	}
	for _, item := range catalog {
		if item.Kind == rulecatalog.KindCCRuleGroup && (item.SystemKey == reference || item.LegacyID == reference) {
			return item.SystemKey, true
		}
	}
	return "", false
}

// UsesSystemCCSettings reports settings with a value that follows the global
// CC config.
func UsesSystemCCSettings(settings *CCSettings) bool {
	return settings != nil && (settings.BanSeconds != nil && settings.BanSeconds.Mode == CCSettingSystem ||
		settings.PassSeconds != nil && settings.PassSeconds.Mode == CCSettingSystem ||
		settings.AutoSwitch != nil && settings.AutoSwitch.Mode == CCSettingSystem)
}

// resolveSystemCCSettings resolves fields' system-mode CC settings for a
// policy of scopeID (no queries unless something follows the global config).
func (s *Service) resolveSystemCCSettings(ctx context.Context, scopeID uuid.UUID, fields *PolicyFields) error {
	settings := fields.CCSettings
	if !UsesSystemCCSettings(settings) {
		return nil
	}
	defaults, err := s.store.CCSystemDefaults(ctx, scopeID)
	if err != nil {
		return err
	}
	var catalog []rulecatalog.Item
	if settings.AutoSwitch != nil && settings.AutoSwitch.Mode == CCSettingSystem && AutoSwitchNeedsCatalog(defaults) {
		if catalog, err = s.store.SystemCatalog(ctx); err != nil {
			return err
		}
	}
	ResolveCCSettings(settings, defaults, catalog)
	return nil
}

// CanonicalCCSettings is settings of policyID as the store would save them:
// switch rules without an ID get the derived one, everything normalized. Two
// resolutions that are equal after it compile to the same policy.
func CanonicalCCSettings(policyID uuid.UUID, settings *CCSettings) (*CCSettings, error) {
	value := cloneCCSettings(settings)
	if value == nil {
		return nil, nil
	}
	if value.AutoSwitch != nil {
		for index := range value.AutoSwitch.Rules {
			if value.AutoSwitch.Rules[index].ID == uuid.Nil {
				value.AutoSwitch.Rules[index].ID = ccAutoSwitchRuleID(policyID, index)
			}
		}
		assignCCAutoSwitchRuleSetIDs(policyID, value.AutoSwitch)
	}
	if err := normalizeCCSettings(KindCC, value, false); err != nil {
		return nil, unlocated(err)
	}
	return value, nil
}
