package rulepackprecheck

import (
	"fmt"
	"slices"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/rulepack"
)

// Compiled is what a site's mounts run on the node: the WAF/ACL rule plan
// the dynamic routing interpreter runs after the site's own policies, and
// the CC v2 policy of its cc_v2 / challenge pack rules (nil without any),
// which the CC engine runs after the site's own CC binding.
type Compiled struct {
	Rules edgeconfig.RulePlan
	CC    *edgeconfig.CCV2Policy
	// ModSecurity are the rules (CRS sets) of the site's modsecurity pack:
	// they narrow the site's managed WAF, which the control plane already
	// turned into managed_waf.exclusions (CheckModSecurity verifies it).
	ModSecurity []rulepack.NodeRule
	// ModSecurityMount / ModSecurityPack are that mount and its (opened)
	// pack, for the crs_rule_ids check (CheckModSecurity).
	ModSecurityMount *rulepack.Mount
	ModSecurityPack  *rulepack.CompiledPack
	// Tuning are the entries of the site's system/crs-tuning pack (ADR 0011
	// RI-13, rulepack.TuningOf; nil without that mount) and TuningVersion its
	// version: the node renders one tuning pack into its node rules.
	Tuning        []edgeconfig.CRSTuningEntry
	TuningVersion string
}

// Identity is the site a CC pack policy belongs to: the engine keys its
// counters, bans and challenge passes by it (scoped like the site's own CC
// binding, so one site's pack state is never another's).
type Identity struct {
	ScopeID string
	SiteID  string
	// TrustedCrawlers are the site's own CC trusted crawlers (FX47): a
	// verified crawler skips the pack rules too, as it skips the site's.
	TrustedCrawlers []edgeconfig.CCV2TrustedCrawler
}

// Plan prechecks a site's security mounts (CheckWith) and compiles the
// mounted WAF/ACL pack rules into the layered rule plan: one segment per
// mount, in the published order, default allow (a pack only adds
// decisions). It refuses CC and modsecurity mounts (Compile runs those).
func Plan(document []byte, objects Objects, load Loader, overflowBlocks bool) (edgeconfig.RulePlan, error) {
	compiled, err := Compile(document, objects, load, Identity{}, overflowBlocks)
	if err != nil {
		return edgeconfig.RulePlan{}, err
	}
	if compiled.CC != nil {
		return edgeconfig.RulePlan{}, fmt.Errorf("%w: CC pack mounts need the site identity", ErrRejected)
	}
	if len(compiled.ModSecurity) != 0 {
		return edgeconfig.RulePlan{}, fmt.Errorf("%w: modsecurity pack mounts need the site's managed WAF", ErrRejected)
	}
	return compiled.Rules, nil
}

// Compile prechecks a site's security mounts and compiles every engine the
// node runs from them:
//
//   - waf_v2 / acl: the layered rule plan (see Plan);
//
//   - cc_v2 / challenge: one CC v2 policy whose rules are the pack rules in
//     the published order (user -> developer -> system; rule IDs and
//     priorities as the compiler assigned them), enabled, without trusted
//     proxies, allowlist or auto switch (those are the site policy's), with
//     the site's trusted crawlers (Identity.TrustedCrawlers: a crawler the
//     site trusts is exempt from the packs too; the engine also skips the
//     packs after the site policy passed it, but a site without a CC
//     binding on the port runs only the packs). Its envelope is derived
//     from the site (Identity) so that counters and passes survive pack
//     upgrades.
//
//   - modsecurity: the pack's CRS sets (Compiled.ModSecurity), enforced as
//     the site's managed WAF exclusions (方案 A, CheckModSecurity).
func Compile(document []byte, objects Objects, load Loader, site Identity, overflowBlocks bool) (Compiled, error) {
	rules, security, packs, err := checkWithPacks(document, objects, load)
	if err != nil {
		return Compiled{}, err
	}
	var cc []edgeconfig.CCV2Rule
	var modSecurity []rulepack.NodeRule
	for _, rule := range rules {
		switch rule.Engine {
		case rulepack.EngineWAFV2, rulepack.EngineACL:
		case rulepack.EngineCCV2, rulepack.EngineChallenge:
			if rule.CC == nil {
				return Compiled{}, fmt.Errorf("%w: pack %s rule %s", ErrRejected, rule.PackID, rule.RuleID)
			}
			cc = append(cc, *rule.CC)
		case rulepack.EngineModSecurity:
			if rule.CRS == nil {
				return Compiled{}, fmt.Errorf("%w: pack %s rule %s", ErrRejected, rule.PackID, rule.RuleID)
			}
			modSecurity = append(modSecurity, rule)
		default:
			return Compiled{}, fmt.Errorf("%w: pack %s engine %s is not run by this node", ErrRejected, rule.PackID, rule.Engine)
		}
	}
	// The interpreter runs the plan through its match index (ADR 0011
	// §6.5); a plan over the compiled cost budget is refused here, as the
	// control plane refuses to publish it (rulepack.Resolve).
	plan, err := rulepack.MountRulePlan(rules, func(packID string) string { return packDigest(document, packID) }, overflowBlocks)
	if err != nil {
		return Compiled{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	compiled := Compiled{Rules: plan, ModSecurity: modSecurity}
	tuning, _, mounted, err := rulepack.TuningOf(security.Mounts, packs)
	if err != nil {
		return Compiled{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	if mounted {
		compiled.Tuning = tuning
		for _, mount := range security.Mounts {
			if rulepack.IsCRSTuningPack(mount.PackID) {
				compiled.TuningVersion = mount.Version
			}
		}
	}
	for index, mount := range security.Mounts {
		// the CRS tuning pack is no CRS selection (rulepack.TuningOf)
		if mount.Engine == rulepack.EngineModSecurity && !rulepack.IsCRSTuningPack(mount.PackID) {
			compiled.ModSecurityMount, compiled.ModSecurityPack = &security.Mounts[index], packs[mount.SHA256]
		}
	}
	if len(cc) == 0 {
		return compiled, nil
	}
	policy, err := ccPolicy(site, security.ResolvedSHA256, cc)
	if err != nil {
		return Compiled{}, err
	}
	compiled.CC = &policy
	return compiled, nil
}

// ccPolicyNamespace names the derived CC policy envelope IDs.
const ccPolicyNamespace = "@rule-packs/cc"

func ccPolicy(site Identity, resolved string, rules []edgeconfig.CCV2Rule) (edgeconfig.CCV2Policy, error) {
	id := rulepack.NodeRuleID(ccPolicyNamespace, site.SiteID)
	policy := edgeconfig.CCV2Policy{SchemaVersion: edgeconfig.CCV2SchemaVersion, TenantScopeID: site.ScopeID,
		SiteID: site.SiteID, PolicyID: id, PolicyVersion: 1, BindingID: id, BindingRevision: 1,
		PublicationID: rulepack.NodeRuleID(ccPolicyNamespace, resolved), Enabled: true,
		TrustedProxies: []string{}, Allowlist: []string{}, Rules: rules, TrustedCrawlers: site.TrustedCrawlers}
	if _, err := edgeconfig.CanonicalCCV2Policy(policy); err != nil {
		return edgeconfig.CCV2Policy{}, fmt.Errorf("%w: CC pack policy of site %s: %v", ErrRejected, site.SiteID, err)
	}
	return policy, nil
}

// packDigest is the mounted object digest of packID (segment provenance).
func packDigest(document []byte, packID string) string {
	security, err := decodeSecurity(document)
	if err != nil {
		return ""
	}
	for _, mount := range security.Mounts {
		if mount.PackID == packID {
			return mount.SHA256
		}
	}
	return ""
}

// CheckModSecurity verifies a site's modsecurity pack against its managed
// WAF: the exclusions the pack implies on the site's CRS profile
// (rulepack.NarrowCRSProfile, the control plane's computation) must all be
// in the site's managed_waf.exclusions. The node never widens CRS for a
// pack; a site that would run rules its pack switches off is refused.
//
// A pack listing crs_rule_ids (a sealed pack the control plane checked by
// the list alone) must evaluate exactly those IDs once opened
// (rulepack.CheckCRSRuleIDs); otherwise the site is refused and the apply
// failure is reported like any other.
func CheckModSecurity(site edgesite.Site, compiled Compiled, manifest *edgeconfig.CRSManifest,
	profiles map[string]edgeconfig.CRSProfile) error {
	rules := compiled.ModSecurity
	if len(rules) == 0 {
		return nil
	}
	if compiled.ModSecurityMount != nil {
		if err := rulepack.CheckCRSRuleIDs(manifest, *compiled.ModSecurityMount, compiled.ModSecurityPack, rules); err != nil {
			return fmt.Errorf("%w: %v", ErrRejected, err)
		}
	}
	waf := site.Security.ManagedWAF
	if waf == nil {
		return fmt.Errorf("%w: modsecurity pack %s needs the site's managed WAF", ErrRejected, rules[0].PackID)
	}
	profile, ok := profiles[waf.CRSProfile.SHA256]
	if !ok || profile.Ref != waf.CRSProfile {
		return fmt.Errorf("%w: CRS profile %s is not on this node", ErrRejected, waf.CRSProfile.PackID)
	}
	needed, err := rulepack.NarrowCRSProfile(manifest, profile, nil, rules)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRejected, err)
	}
	for _, id := range needed {
		if !slices.Contains(waf.Exclusions, id) {
			return fmt.Errorf("%w: managed WAF does not exclude rule %d the modsecurity pack %s switches off",
				ErrRejected, id, rules[0].PackID)
		}
	}
	return nil
}
