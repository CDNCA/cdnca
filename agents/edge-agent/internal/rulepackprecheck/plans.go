package rulepackprecheck

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/rulepack"
	"golang.org/x/mod/semver"
)

// Vault is what Plans needs of rulepackvault.Vault.
type Vault interface {
	Object(sha256 string) ([]byte, error)
	Load(content []byte, sha256 string) (*rulepack.CompiledPack, error)
	PlanDir() string
	WritePlan(resolved string, plan []byte) error
	WriteCCPlan(resolved, siteID string, policy []byte) error
	RetainPlans(keep map[string]bool) error
}

// Plans is the dynamic routing runtime's rule pack mounts (dynroute.RulePlans):
// every mounting site's mounts are prechecked against the packs in the
// object store and their plans written: <PlanDir>/<resolved_sha256>.json
// (WAF/ACL rule plan, shared by the sites with the same mounts) and, for CC
// pack rules, <PlanDir>/<resolved_sha256>.<site_id>.cc.json (the site's CC
// v2 pack policy, canonical bytes).
type Plans struct{ Vault Vault }

func (plans Plans) Root() string { return plans.Vault.PlanDir() }

// Prepare returns the official CRS tuning entries the node renders (ADR 0011
// RI-13): the system/crs-tuning pack of the highest version any site mounts
// (official packs update automatically, so sites converge on the current one;
// a site still on an older version gets the newer entries, its u= list names
// entry numbers, which a version keeps). nil: no site mounts it. referenced
// holds the objects the sites reference by digest (their CC policies).
func (plans Plans) Prepare(sites []edgesite.Site, referenced map[string][]byte, crsText *edgeconfig.CRSRuleText,
	profiles map[string]edgeconfig.CRSProfile) ([]edgeconfig.CRSTuningEntry, error) {
	done := map[string]bool{}
	var tuning []edgeconfig.CRSTuningEntry
	tuningVersion := ""
	var manifest *edgeconfig.CRSManifest
	for _, site := range sites {
		if len(site.Security.Mounts) == 0 {
			continue
		}
		resolved := site.Security.ResolvedSHA256
		document, err := json.Marshal(struct {
			Mounts         []edgesite.RuleMount `json:"mounts"`
			ResolvedSHA256 string               `json:"resolved_sha256"`
		}{site.Security.Mounts, resolved})
		if err != nil {
			return nil, err
		}
		overflowBlocks := site.Security.Rules.HeaderOverflow == edgesite.HeaderOverflowBlock
		crawlers, err := siteTrustedCrawlers(site, referenced)
		if err != nil {
			return nil, fmt.Errorf("site %s: %w", site.SiteID, err)
		}
		compiled, err := Compile(document, plans.Vault.Object, plans.Vault.Load,
			Identity{ScopeID: site.ConfigurationScopeID, SiteID: site.SiteID, TrustedCrawlers: crawlers}, overflowBlocks)
		if err != nil {
			return nil, fmt.Errorf("site %s: %w", site.SiteID, err)
		}
		if len(compiled.ModSecurity) != 0 && manifest == nil {
			if manifest, err = edgeconfig.DeriveCRSManifest(crsText); err != nil {
				return nil, fmt.Errorf("site %s: %w: CRS rule text: %v", site.SiteID, ErrRejected, err)
			}
		}
		if err := CheckModSecurity(site, compiled, manifest, profiles); err != nil {
			return nil, fmt.Errorf("site %s: %w", site.SiteID, err)
		}
		if compiled.Tuning != nil && (tuningVersion == "" ||
			semver.Compare("v"+compiled.TuningVersion, "v"+tuningVersion) > 0) {
			tuning, tuningVersion = compiled.Tuning, compiled.TuningVersion
		}
		if !done[resolved] {
			encoded, err := edgeconfig.EncodeRulePlan(compiled.Rules)
			if err != nil {
				return nil, err
			}
			if err := plans.Vault.WritePlan(resolved, encoded); err != nil {
				return nil, fmt.Errorf("site %s: write rule plan: %w", site.SiteID, err)
			}
			done[resolved] = true
		}
		if compiled.CC != nil {
			canonical, err := edgeconfig.CanonicalCCV2Policy(*compiled.CC)
			if err != nil {
				return nil, fmt.Errorf("site %s: CC pack policy: %w", site.SiteID, err)
			}
			if err := plans.Vault.WriteCCPlan(resolved, site.SiteID, canonical); err != nil {
				return nil, fmt.Errorf("site %s: write CC pack policy: %w", site.SiteID, err)
			}
		}
	}
	return tuning, nil
}

// Retain keeps the plans of the kept resolved digests (rule plans and every
// site's CC pack policy of them).
func (plans Plans) Retain(resolved map[string]bool) error { return plans.Vault.RetainPlans(resolved) }

// siteTrustedCrawlers are the trusted crawlers of the site's own CC
// policies (every bound port's policy, merged by name: the same crawler on
// two ports is the same list entry since a site's CC settings are the
// site's): a crawler the site trusts skips the CC pack rules as well. A CC
// policy the node cannot read is refused (it would run the packs without
// the site's exemptions).
func siteTrustedCrawlers(site edgesite.Site, referenced map[string][]byte) ([]edgeconfig.CCV2TrustedCrawler, error) {
	byName := map[string]edgeconfig.CCV2TrustedCrawler{}
	for _, binding := range site.Security.CC {
		content, ok := referenced[binding.Policy.SHA256]
		if !ok {
			return nil, fmt.Errorf("%w: CC policy %s is not available", ErrRejected, binding.Policy.SHA256)
		}
		policy, err := edgeconfig.DecodeCCV2Policy(content)
		if err != nil {
			return nil, fmt.Errorf("%w: CC policy %s: %v", ErrRejected, binding.Policy.SHA256, err)
		}
		for _, crawler := range policy.TrustedCrawlers {
			if _, seen := byName[crawler.Name]; !seen {
				byName[crawler.Name] = crawler
			}
		}
	}
	if len(byName) == 0 {
		return nil, nil
	}
	crawlers := make([]edgeconfig.CCV2TrustedCrawler, 0, len(byName))
	for _, crawler := range byName {
		crawlers = append(crawlers, crawler)
	}
	slices.SortFunc(crawlers, func(a, b edgeconfig.CCV2TrustedCrawler) int { return strings.Compare(a.Name, b.Name) })
	return crawlers, nil
}
