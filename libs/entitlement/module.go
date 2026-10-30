package entitlement

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Module feature codes (ADR 0007 §3.1): module.<id> for official built-in
// modules (A), pack.<id> for official signed package families (B) and
// theme.<id> for official themes (D). They are ordinary lease features, so
// the 256-code lease limit (maxEntitlements) applies to them as well.
type ModuleKind string

const (
	ModuleKindModule ModuleKind = "module"
	ModuleKindPack   ModuleKind = "pack"
	ModuleKindTheme  ModuleKind = "theme"
)

// RevokeBehavior is what a module does to existing state once the lease no
// longer grants it. Both behaviors stop new use (API entry, menu, publication
// gate); they differ only in what happens to state that already exists.
type RevokeBehavior string

const (
	// RevokeKeepExisting freezes: existing resources and published state stay
	// as they are until the module is granted again.
	RevokeKeepExisting RevokeBehavior = "keep_existing"
	// RevokeRemoveExisting withdraws: the next node set/publication generated
	// without the grant drops the module's artifacts (bytes stay on the
	// control plane, so a renewed grant can re-enable them directly).
	RevokeRemoveExisting RevokeBehavior = "remove_existing"
	// RevokeDrainExisting steps down: state already in force (automatic
	// mitigations) is withdrawn gradually within DrainSeconds instead of all
	// at once, so revoking during an attack does not expose the origin; data
	// the module learned is kept RetainDays so a renewed grant resumes it
	// directly (ADR 0010 section 9.1). Executed by the module (AD-05 node
	// stepping, AD-08 retention), not by the licence code.
	RevokeDrainExisting RevokeBehavior = "drain_existing"
)

// Automatic defense feature codes (ADR 0010 section 9.1): API CheckFeature,
// menu requiredModule and the AutoDefenseCommand publication gate use these.
const (
	ModuleAutoDefense     = "module.autodefense"
	ModuleAutoDefenseAuto = "module.autodefense.auto"
)

// ModuleEscalate is attack auto-escalation (official and free, user 10-22):
// once automatic defense has judged a site under attack, it moves the site
// A → B → C → D (normal / high-defense / unlimited line group or the
// owner's Cloudflare / blackhole) and back automatically. The control API
// gates its write endpoints and worker on this code.
const ModuleEscalate = "module.escalate"

// ModuleBillingBridge is the billing system bridge (ADR 0019, official and
// free, Q1 a): WHMCS / ZJMF provision CDN accounts and packages through
// signed bridge keys, either as a reseller on this platform (A) or against a
// self-hosted control plane (B). The control API gates the key management
// endpoints and every bridge route on this code.
const ModuleBillingBridge = "module.billing.bridge"

// RevokePhase is where a drain_existing module is after its grant ended.
type RevokePhase string

const (
	// RevokePhaseDraining: new use stopped; existing state is being stepped
	// down (before revoked_at + DrainSeconds).
	RevokePhaseDraining RevokePhase = "draining"
	// RevokePhaseRetained: nothing is in force any more; learned data is kept
	// (before revoked_at + RetainDays).
	RevokePhaseRetained RevokePhase = "retained"
	// RevokePhaseExpired: the retention ended; the module may purge its data.
	RevokePhaseExpired RevokePhase = "expired"
)

var (
	ErrInvalidModuleCode = errors.New("invalid module feature code")

	moduleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$`)
)

// ModuleDescriptor is the catalog entry every module declares. Every catalog
// entry is official (ADR 0007 §3.1); Free marks the ones every new install's
// default plans grant without a purchase.
type ModuleDescriptor struct {
	Code   string         `json:"code"`
	NameZH string         `json:"name_zh"`
	NameEN string         `json:"name_en"`
	Revoke RevokeBehavior `json:"revoke_behavior"`
	Free   bool           `json:"free"`
	// DrainSeconds and RetainDays are set exactly for drain_existing.
	DrainSeconds int64 `json:"drain_seconds,omitempty"`
	RetainDays   int64 `json:"retain_days,omitempty"`
}

func (descriptor ModuleDescriptor) Kind() ModuleKind {
	kind, _, _ := ParseModuleFeatureCode(descriptor.Code)
	return kind
}

func (descriptor ModuleDescriptor) Validate() error {
	if _, _, ok := ParseModuleFeatureCode(descriptor.Code); !ok ||
		strings.TrimSpace(descriptor.NameZH) == "" || strings.TrimSpace(descriptor.NameEN) == "" {
		return ErrInvalidModuleCode
	}
	switch descriptor.Revoke {
	case RevokeKeepExisting, RevokeRemoveExisting:
		if descriptor.DrainSeconds != 0 || descriptor.RetainDays != 0 {
			return ErrInvalidModuleCode
		}
		return nil
	case RevokeDrainExisting:
		if descriptor.DrainSeconds <= 0 || descriptor.RetainDays <= 0 ||
			descriptor.DrainSeconds > descriptor.RetainDays*24*3600 {
			return ErrInvalidModuleCode
		}
		return nil
	default:
		return ErrInvalidModuleCode
	}
}

// RevokePhaseAt reports the phase of a drain_existing module whose grant
// ended at revokedAt; ok is false for the other behaviors, which have no
// phases (keep and remove act at once).
func (descriptor ModuleDescriptor) RevokePhaseAt(revokedAt, now time.Time) (RevokePhase, bool) {
	if descriptor.Revoke != RevokeDrainExisting {
		return "", false
	}
	elapsed := now.Sub(revokedAt)
	switch {
	case elapsed < time.Duration(descriptor.DrainSeconds)*time.Second:
		return RevokePhaseDraining, true
	case elapsed < time.Duration(descriptor.RetainDays)*24*time.Hour:
		return RevokePhaseRetained, true
	default:
		return RevokePhaseExpired, true
	}
}

// ModuleFeatureCode builds the lease feature code of a module.
func ModuleFeatureCode(kind ModuleKind, id string) (string, error) {
	switch kind {
	case ModuleKindModule, ModuleKindPack, ModuleKindTheme:
	default:
		return "", ErrInvalidModuleCode
	}
	code := string(kind) + "." + id
	if !moduleIDPattern.MatchString(id) || len(code) > maxCodeLength {
		return "", ErrInvalidModuleCode
	}
	return code, nil
}

// ParseModuleFeatureCode reports whether code is a well-formed module, pack or
// theme feature code and returns its kind and id.
func ParseModuleFeatureCode(code string) (ModuleKind, string, bool) {
	prefix, id, found := strings.Cut(code, ".")
	if !found {
		return "", "", false
	}
	kind := ModuleKind(prefix)
	if normalized, err := ModuleFeatureCode(kind, id); err != nil || normalized != code {
		return "", "", false
	}
	return kind, id, true
}

// hasModulePrefix reports whether code uses a reserved module prefix, whether
// or not the rest of it is well formed.
func hasModulePrefix(code string) bool {
	for _, kind := range []ModuleKind{ModuleKindModule, ModuleKindPack, ModuleKindTheme} {
		if strings.HasPrefix(code, string(kind)+".") {
			return true
		}
	}
	return false
}

// ModuleCodes returns the module, pack and theme codes the lease grants, in
// lease (sorted) order.
func (lease Lease) ModuleCodes() []string {
	codes := []string{}
	for _, feature := range lease.Features {
		if _, _, ok := ParseModuleFeatureCode(feature.Code); ok {
			codes = append(codes, feature.Code)
		}
	}
	return codes
}

// moduleCatalog lists the official modules a plan or license can grant (ADR
// 0007 plugin table). The default theme and the IP base library are free and
// therefore have no code; a coded entry the official seller gives away sets
// Free, and new installs' default plans then grant it.
var moduleCatalog = []ModuleDescriptor{
	// Official and free: every new install's default plans carry
	// these. Official is the publisher, free the price; a module can be both,
	// and official paid modules leave Free unset.
	{Code: "module.aggregated_edge", NameZH: "聚合边缘（第三方 CDN）", NameEN: "Aggregated edge (third-party CDN)", Revoke: RevokeKeepExisting, Free: true},
	// Intelligent automatic defense (ADR 0010 section 9.1, Q1/Q2): learning,
	// observing and alerting are official and free; automatic mitigation is
	// official and paid. Revoking either stops new learning/verdicts/mining,
	// steps mitigations in force down within 10 minutes and keeps baselines
	// 30 days.
	{Code: "module.autodefense", NameZH: "智能自动防御（学习、观察、告警）", NameEN: "Automatic defense (learn, observe, alert)",
		Revoke: RevokeDrainExisting, Free: true, DrainSeconds: 600, RetainDays: 30},
	{Code: "module.autodefense.auto", NameZH: "智能自动防御（自动处置）", NameEN: "Automatic defense (automatic mitigation)",
		Revoke: RevokeDrainExisting, DrainSeconds: 600, RetainDays: 30},
	// Billing system bridge (ADR 0019): revoking it makes every bridge route
	// answer entitlement_feature_denied; customers and subscriptions already
	// opened through it stay.
	{Code: "module.billing.bridge", NameZH: "财务系统对接", NameEN: "Billing system bridge", Revoke: RevokeKeepExisting, Free: true},
	// Attack auto-escalation: official and free. Revoking it
	// stops new escalations and steps a site that is above A back down level
	// by level within 10 minutes instead of jumping straight to A during an
	// attack; policies and history are kept 30 days. (Revoke semantics are
	// provisional, pending the user's decision.)
	{Code: "module.escalate", NameZH: "攻击自动升级", NameEN: "Attack auto-escalation",
		Revoke: RevokeDrainExisting, Free: true, DrainSeconds: 600, RetainDays: 30},
	{Code: "module.icp", NameZH: "备案查询", NameEN: "ICP filing lookup", Revoke: RevokeKeepExisting, Free: true},
	{Code: "module.ipintel.dnspup", NameZH: "IP 库实时更新（dnspup）", NameEN: "IP intelligence live updates (dnspup)", Revoke: RevokeRemoveExisting, Free: true},
	// Official mail services (libs/mail): the system mail sender may be one of
	// them instead of the built-in SMTP. The control plane gates it: choosing
	// or testing a service needs its module (systemmailsettings
	// checkMailModule), every send asks the lease (officialMailTransport),
	// and the settings page offers only granted services. Keep existing: a
	// saved choice stays saved; its sends fail until the module is granted.
	{Code: "module.mail.aliyun", NameZH: "阿里云邮件推送", NameEN: "Alibaba Cloud DirectMail", Revoke: RevokeKeepExisting, Free: true},
	{Code: "module.mail.sendgrid", NameZH: "SendGrid 邮件", NameEN: "SendGrid email", Revoke: RevokeKeepExisting, Free: true},
	// Migration import (ADR 0016): import users, packages, sites,
	// certificates and balances from third-party CDN panels / Cloudflare /
	// Bunny / CSV. Revoking it stops new imports and pauses running ones; imported
	// data stays.
	{Code: "module.migrate.import", NameZH: "迁移导入", NameEN: "Migration import", Revoke: RevokeKeepExisting, Free: true},
	{Code: "module.payment.alipay", NameZH: "支付宝支付", NameEN: "Alipay payments", Revoke: RevokeKeepExisting, Free: true},
	{Code: "module.payment.codepay", NameZH: "码支付", NameEN: "Codepay payments", Revoke: RevokeKeepExisting, Free: true},
	{Code: "module.payment.epay", NameZH: "易支付", NameEN: "Epay payments", Revoke: RevokeKeepExisting, Free: true},
	{Code: "module.payment.wechat", NameZH: "微信支付", NameEN: "WeChat Pay payments", Revoke: RevokeKeepExisting, Free: true},
	// dnspup probing: the platform's own dnspup key pair probes
	// origins and supplies as a probe source next to nodes; revoking it stops
	// new dnspup probes at once (the other sources take over).
	{Code: "module.probe.dnspup", NameZH: "dnspup 拨测", NameEN: "dnspup probing", Revoke: RevokeRemoveExisting, Free: true},
	{Code: "module.sms.aliyun", NameZH: "阿里云短信", NameEN: "Alibaba Cloud SMS", Revoke: RevokeKeepExisting, Free: true},
	{Code: "module.sms.submail", NameZH: "SUBMAIL 短信", NameEN: "SUBMAIL SMS", Revoke: RevokeKeepExisting, Free: true},
	{Code: "pack.cc.advanced", NameZH: "高级 CC 规则组", NameEN: "Advanced CC rule groups", Revoke: RevokeRemoveExisting},
	{Code: "pack.crs", NameZH: "OWASP CRS 档位", NameEN: "OWASP CRS levels", Revoke: RevokeRemoveExisting},
	{Code: "pack.selfwaf", NameZH: "自研检测规则集", NameEN: "In-house detection rules", Revoke: RevokeRemoveExisting},
}

// ModuleCatalog returns a copy of the official module catalog sorted by code.
func ModuleCatalog() []ModuleDescriptor {
	return append([]ModuleDescriptor(nil), moduleCatalog...)
}

// FreeModuleCodes returns the sorted codes of the catalog's free entries.
func FreeModuleCodes(catalog []ModuleDescriptor) []string {
	codes := []string{}
	for _, module := range catalog {
		if module.Free {
			codes = append(codes, module.Code)
		}
	}
	slices.Sort(codes)
	return slices.Compact(codes)
}

func LookupModule(code string) (ModuleDescriptor, bool) {
	for _, module := range moduleCatalog {
		if module.Code == code {
			return module, true
		}
	}
	return ModuleDescriptor{}, false
}
