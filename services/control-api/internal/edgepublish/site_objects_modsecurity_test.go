package edgepublish

import (
	"errors"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
)

// modSecurityFactsForTest is the crs_sqli set of crs-pl1 as a modsecurity
// pack rule (paranoia, action and threshold as given) with 942100 excluded.
func modSecurityFactsForTest(t *testing.T, paranoia int) (*siteModSecurityFacts, edgeconfig.CRSProfile) {
	t.Helper()
	inputs := crsInputsForEdgeTest(t)
	manifest, err := edgeconfig.DeriveCRSManifest(inputs.RuleText)
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[string]edgeconfig.CRSProfile{}
	for _, profile := range inputs.Profiles {
		profiles[profile.Profile.Ref.SHA256] = profile.Profile
	}
	rule := rulepack.NodeRule{PackID: "system/sqli-narrow", RuleID: "crs_sqli", Engine: rulepack.EngineModSecurity,
		CRS: &rulecatalog.WAFEngineSet{Engine: rulecatalog.WAFEngineCRS, Files: []string{"REQUEST-942"}, ExcludeIDs: []int{942100},
			Action: "block", Paranoia: paranoia, Threshold: 5}}
	return &siteModSecurityFacts{PackID: rule.PackID, Rules: []rulepack.NodeRule{rule}, Manifest: manifest, Profiles: profiles},
		inputs.Profiles["system/crs-pl1"].Profile
}

func TestApplySiteModSecurityNarrowsTheSiteProfile(t *testing.T) {
	facts, profile := modSecurityFactsForTest(t, 1)
	site := edgesite.Site{SiteID: "s1", Security: edgesite.Security{ManagedWAF: &edgesite.ManagedWAF{
		CRSProfile: profile.Ref, Exclusions: []int{941100}}}}
	if err := applySiteModSecurity(&site, facts); err != nil {
		t.Fatal(err)
	}
	got := site.Security.ManagedWAF.Exclusions
	if !slices.Contains(got, 941100) || !slices.Contains(got, 942100) || !slices.Contains(got, 932160) ||
		slices.Contains(got, 942140) || !slices.IsSorted(got) {
		t.Fatalf("exclusions = %v", got)
	}
	if err := applySiteModSecurity(&site, nil); err != nil {
		t.Fatal(err)
	}
}

func TestApplySiteModSecurityRefusesOutOfProfile(t *testing.T) {
	facts, profile := modSecurityFactsForTest(t, 2)
	site := edgesite.Site{SiteID: "s1", Security: edgesite.Security{ManagedWAF: &edgesite.ManagedWAF{CRSProfile: profile.Ref}}}
	var refusal *CRSOutOfProfileError
	if err := applySiteModSecurity(&site, facts); !errors.As(err, &refusal) || refusal.PackID != "system/sqli-narrow" ||
		!errors.Is(err, ErrUnsupportedSecurityPolicy) {
		t.Fatalf("paranoia 2 on PL1: %v", err)
	}
	inProfile, _ := modSecurityFactsForTest(t, 1)
	if err := applySiteModSecurity(&edgesite.Site{SiteID: "s2"}, inProfile); !errors.As(err, &refusal) {
		t.Fatalf("no managed WAF: %v", err)
	}
	inProfile.Rules = nil
	if err := applySiteModSecurity(&site, inProfile); !errors.As(err, &refusal) {
		t.Fatalf("unreadable pack: %v", err)
	}
}

// A sealed pack known only by its crs_rule_ids narrows the profile the same
// way as its rules would.
func TestApplySiteModSecurityNarrowsBySealedRuleIDs(t *testing.T) {
	facts, profile := modSecurityFactsForTest(t, 1)
	byRules := edgesite.Site{SiteID: "s1", Security: edgesite.Security{ManagedWAF: &edgesite.ManagedWAF{CRSProfile: profile.Ref}}}
	if err := applySiteModSecurity(&byRules, facts); err != nil {
		t.Fatal(err)
	}
	sealed := *facts
	sealed.Runs, sealed.Rules = rulepack.CRSRuns(facts.Manifest, facts.Rules), nil
	byIDs := edgesite.Site{SiteID: "s1", Security: edgesite.Security{ManagedWAF: &edgesite.ManagedWAF{CRSProfile: profile.Ref}}}
	if err := applySiteModSecurity(&byIDs, &sealed); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(byIDs.Security.ManagedWAF.Exclusions, byRules.Security.ManagedWAF.Exclusions) {
		t.Fatalf("by IDs %v, by rules %v", byIDs.Security.ManagedWAF.Exclusions, byRules.Security.ManagedWAF.Exclusions)
	}
	sealed.Runs = append(slices.Clone(sealed.Runs), 942200) // paranoia 2: not evaluated by crs-pl1
	var refusal *CRSOutOfProfileError
	if err := applySiteModSecurity(&edgesite.Site{SiteID: "s1", Security: edgesite.Security{ManagedWAF: &edgesite.ManagedWAF{
		CRSProfile: profile.Ref}}}, &sealed); !errors.As(err, &refusal) {
		t.Fatalf("IDs beyond the profile: %v", err)
	}
}
