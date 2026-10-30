package audit

// Event catalog (unified-log). Every action production code writes must have
// one Entry here: TestEventCatalogCoversProductionActions scans the source
// tree and fails on unregistered actions. See docs/architecture/unified-log.md.

import (
	"regexp"
	"sort"
	"strings"
)

// Category groups events for the log center tabs and for retention.
type Category string

const (
	CategoryAdmin    Category = "admin"    // platform administration: users, roles, impersonation
	CategoryUser     Category = "user"     // a user's own account: profile, MFA, API keys, verification
	CategoryAuth     Category = "auth"     // login, logout, sessions, credential denials
	CategorySite     Category = "site"     // site, origin, cache, L4 stream configuration
	CategorySecurity Category = "security" // CC/WAF/firewall/challenge policies and their activation
	CategoryRule     Category = "rule"     // rule libraries, subscriptions, quick blocks, error pages
	CategoryFinance  Category = "finance"  // balance, recharge, orders, payment channels, billing
	CategoryPackage  Category = "package"  // packages, subscriptions, traffic packages, enforcement
	CategoryPlugin   Category = "plugin"   // plugin installation, publication, webhooks
	CategoryNode     Category = "node"     // nodes, scheduling, line groups, edge publication
	CategoryDNS      Category = "dns"      // DNS providers, zones, records, CNAME, domain ownership
	CategoryCert     Category = "cert"     // certificates, ACME, node certificates
	CategorySystem   Category = "system"   // system settings, upgrades, backups, jobs, retention
	CategoryOther    Category = "other"    // fallback for an action missing from the catalog
)

// CategoryInfo describes one category for the log center and retention.
type CategoryInfo struct {
	Category      Category `json:"category"`
	LabelZH       string   `json:"label_zh"`
	LabelEN       string   `json:"label_en"`
	RetentionDays int      `json:"default_retention_days"` // 0 = keep forever
}

var categories = []CategoryInfo{
	{CategoryAdmin, "管理员操作", "Administration", 365},
	{CategoryUser, "用户操作", "User account", 180},
	{CategoryAuth, "登录与安全", "Sign-in & security", 90},
	{CategorySite, "网站配置", "Site configuration", 180},
	{CategorySecurity, "防御策略", "Protection policies", 180},
	{CategoryRule, "规则", "Rules", 180},
	{CategoryFinance, "财务", "Finance", 1095},
	{CategoryPackage, "套餐", "Packages", 365},
	{CategoryPlugin, "插件", "Plugins", 180},
	{CategoryNode, "节点", "Nodes", 90},
	{CategoryDNS, "DNS", "DNS", 180},
	{CategoryCert, "证书", "Certificates", 180},
	{CategorySystem, "系统", "System", 365},
	{CategoryOther, "其它", "Other", 180},
}

// Categories returns every category in display order.
func Categories() []CategoryInfo {
	return append([]CategoryInfo(nil), categories...)
}

// ValidCategory reports whether category is one of Categories().
func ValidCategory(category Category) bool {
	for _, info := range categories {
		if info.Category == category {
			return true
		}
	}
	return false
}

// Entry is one catalogued action.
//
// TemplateZH / TemplateEN describe what happened, without the actor, time
// and IP (Render prefixes those). Placeholders are {name}; allowed names are
// the common ones ({resource}, {resource_type}, {resource_id}, {reason},
// {changes}) plus the payload keys listed in Fields.
type Entry struct {
	Action     string   `json:"action"`
	Category   Category `json:"category"`
	TemplateZH string   `json:"template_zh"`
	TemplateEN string   `json:"template_en"`
	// Fields are payload keys safe to show in the detail view and usable in templates.
	Fields []string `json:"fields,omitempty"`
	// Masked are payload/change keys shown masked (for example an email or phone).
	Masked []string `json:"masked,omitempty"`
}

var catalogIndex = map[string]Entry{}

// register adds entries; duplicates are reported by TestEventCatalogIntegrity.
func register(entries ...Entry) {
	for _, entry := range entries {
		if _, exists := catalogIndex[entry.Action]; exists {
			duplicateActions = append(duplicateActions, entry.Action)
			continue
		}
		catalogIndex[entry.Action] = entry
	}
}

var duplicateActions []string

// e builds an Entry; f/m attach Fields and Masked.
func e(action string, category Category, zh, en string) Entry {
	return Entry{Action: action, Category: category, TemplateZH: zh, TemplateEN: en}
}

func (entry Entry) f(fields ...string) Entry {
	entry.Fields = append(entry.Fields, fields...)
	return entry
}
func (entry Entry) m(fields ...string) Entry {
	entry.Masked = append(entry.Masked, fields...)
	return entry
}

// Lookup returns the catalog entry for action.
func Lookup(action string) (Entry, bool) {
	entry, ok := catalogIndex[action]
	return entry, ok
}

// CategoryOf returns the category of action, CategoryOther when uncatalogued.
func CategoryOf(action string) Category {
	if entry, ok := catalogIndex[action]; ok {
		return entry.Category
	}
	return CategoryOther
}

// Entries returns every entry sorted by action.
func Entries() []Entry {
	out := make([]Entry, 0, len(catalogIndex))
	for _, entry := range catalogIndex {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Action < out[j].Action })
	return out
}

// ActionsIn returns the catalogued actions of category, sorted.
func ActionsIn(category Category) []string {
	var out []string
	for action, entry := range catalogIndex {
		if entry.Category == category {
			out = append(out, action)
		}
	}
	sort.Strings(out)
	return out
}

var (
	placeholderPattern = regexp.MustCompile(`\{([a-z0-9_]+)\}`)
	// New actions use <category>.<object>.<verb>; older actions keep their
	// names because database triggers match them (see the design doc).
	actionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`)
)

// commonPlaceholders are always available to templates.
var commonPlaceholders = map[string]bool{
	"resource": true, "resource_type": true, "resource_id": true, "reason": true, "changes": true,
}

func templatePlaceholders(template string) []string {
	var out []string
	for _, match := range placeholderPattern.FindAllStringSubmatch(template, -1) {
		out = append(out, match[1])
	}
	return out
}

// validateEntry returns the problems with entry (empty when valid).
func validateEntry(entry Entry) []string {
	var problems []string
	if !actionPattern.MatchString(entry.Action) {
		problems = append(problems, "action name is not <a>.<b>[.<c>] lower snake case")
	}
	if !ValidCategory(entry.Category) || entry.Category == CategoryOther {
		problems = append(problems, "category must be one of Categories() except other")
	}
	if strings.TrimSpace(entry.TemplateZH) == "" || strings.TrimSpace(entry.TemplateEN) == "" {
		problems = append(problems, "both templates are required")
	}
	allowed := map[string]bool{}
	for key := range commonPlaceholders {
		allowed[key] = true
	}
	for _, field := range entry.Fields {
		allowed[field] = true
		if sensitivePayloadKey(field) {
			problems = append(problems, "field "+field+" is a secret key and is always redacted")
		}
	}
	for _, field := range entry.Masked {
		allowed[field] = true
	}
	for _, template := range []string{entry.TemplateZH, entry.TemplateEN} {
		for _, name := range templatePlaceholders(template) {
			if !allowed[name] {
				problems = append(problems, "template placeholder {"+name+"} is not a common placeholder or a declared field")
			}
		}
		if strings.Contains(template, "{actor}") || strings.Contains(template, "{time}") || strings.Contains(template, "{ip}") {
			problems = append(problems, "templates must not repeat {actor}/{time}/{ip}; Render adds them")
		}
	}
	return problems
}
