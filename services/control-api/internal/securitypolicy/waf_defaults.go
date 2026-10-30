package securitypolicy

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/jackc/pgx/v5"
)

// System default WAF (系统设置 > 网站默认 > 安全设置), ge-waf logic 1 / 2:
// the waf_enabled switch, the ten built-in module modes (off / detect = log
// only / on = block) and waf_auto_block were stored and shown but read by
// nothing. CatalogDefaultWAF turns them into a WAF policy draft the editor
// creates a site's WAF from:
//
//   - each module's self-developed rule set (waf_set:<suffix>) expanded with
//     action log (detect) or block (on); off modules are left out;
//   - waf_settings.auto_block from waf_auto_block when it is enabled;
//   - enabled = waf_enabled.
//
// The OWASP CRS sets are a separately licensed engine and stay the editor's
// choice.

// SystemDefaultWAFKey is the catalog-rules key that asks for the system
// default WAF (GET /v1/security-policies/catalog-rules?kind=waf&keys=@system-default).
const SystemDefaultWAFKey = "@system-default"

// systemWAFModuleSets maps the system setting module names to the catalog
// rule sets.
var systemWAFModuleSets = []struct{ name, key string }{
	{"sqli", "waf_set:sqli"}, {"xss", "waf_set:xss"}, {"upload", "waf_set:file_upload"}, {"fi", "waf_set:file_include"},
	{"cmdi", "waf_set:cmd_injection"}, {"java", "waf_set:java_code_injection"}, {"jdeser", "waf_set:java_deserialization"},
	{"php", "waf_set:php_code_injection"}, {"phpdeser", "waf_set:php_deserialization"}, {"ssti", "waf_set:ssti"},
}

func systemWAFModuleMode(modules systemconfig.DefaultWAFModules, name string) string {
	switch name {
	case "sqli":
		return modules.SQLI
	case "xss":
		return modules.XSS
	case "upload":
		return modules.Upload
	case "fi":
		return modules.FI
	case "cmdi":
		return modules.CMDI
	case "java":
		return modules.Java
	case "jdeser":
		return modules.JDeser
	case "php":
		return modules.PHP
	case "phpdeser":
		return modules.PHPDeser
	case "ssti":
		return modules.SSTI
	}
	return "off"
}

// DefaultWAFPolicy is the system default WAF policy draft.
type DefaultWAFPolicy struct {
	Enabled     bool         `json:"enabled"`
	Rules       []Rule       `json:"rules"`
	WAFSettings *WAFSettings `json:"waf_settings,omitempty"`
}

// BuildDefaultWAFPolicy derives the draft from the system defaults and the
// synced catalog (pure, for tests and the service).
func BuildDefaultWAFPolicy(defaults systemconfig.DefaultSecuritySettings, index map[string]rulecatalog.Item) (DefaultWAFPolicy, error) {
	result := DefaultWAFPolicy{Enabled: defaults.WAFEnabled, Rules: []Rule{}}
	for _, module := range systemWAFModuleSets {
		action := ""
		switch systemWAFModuleMode(defaults.WAFModules, module.name) {
		case "detect":
			action = ActionLog
		case "on":
			action = ActionBlock
		default:
			continue
		}
		if _, ok := index[module.key]; !ok {
			return DefaultWAFPolicy{}, fmt.Errorf("%w: %s", ErrCatalogUnsupported, module.key)
		}
		rules, err := ExpandWAFRuleSets(index, []string{module.key}, action)
		if err != nil {
			return DefaultWAFPolicy{}, err
		}
		for _, rule := range rules {
			rule.Priority = len(result.Rules) + 1
			result.Rules = append(result.Rules, rule)
		}
	}
	if block := defaults.WAFAutoBlock; block.Enabled {
		result.WAFSettings = &WAFSettings{AutoBlock: &WAFAutoBlock{WindowSeconds: block.WindowSeconds,
			HitThreshold: block.HitThreshold, BlockSeconds: block.BlockSeconds}}
	}
	return result, nil
}

// CatalogDefaultWAF reads the platform defaults and builds the draft.
func (s *Service) CatalogDefaultWAF(ctx context.Context) (DefaultWAFPolicy, error) {
	items, err := s.store.SystemCatalog(ctx)
	if err != nil {
		return DefaultWAFPolicy{}, err
	}
	defaults, err := s.store.DefaultWAFSecurity(ctx)
	if err != nil {
		return DefaultWAFPolicy{}, err
	}
	index := make(map[string]rulecatalog.Item, len(items))
	for _, item := range items {
		index[item.SystemKey] = item
	}
	return BuildDefaultWAFPolicy(defaults, index)
}

// DefaultWAFSecurity reads the active platform defaults.
func (s *Store) DefaultWAFSecurity(ctx context.Context) (systemconfig.DefaultSecuritySettings, error) {
	var defaults systemconfig.DefaultSecuritySettings
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		defaults, err = systemconfig.LoadDefaultWAFSecurity(ctx, tx)
		return err
	})
	return defaults, err
}
