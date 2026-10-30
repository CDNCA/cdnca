package edgepublish

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func crsCatalogBody(t *testing.T, change func(*rulecatalog.WAFEngineBundle)) []byte {
	t.Helper()
	bundle := *rulecatalog.CRSRulesBundle()
	bundle.Files = slices.Clone(bundle.Files)
	if change != nil {
		change(&bundle)
	}
	body, err := json.Marshal(rulecatalog.ItemBody{WAFRuleSet: &rulecatalog.WAFRuleSetBody{Bundle: &bundle}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestChangedCRSRuleFilesComparesFileDigests(t *testing.T) {
	current := crsCatalogBody(t, nil)
	if changed := ChangedCRSRuleFiles(current, current); len(changed) != 0 {
		t.Fatalf("same body changed %v", changed)
	}
	var sqli string
	edited := crsCatalogBody(t, func(bundle *rulecatalog.WAFEngineBundle) {
		for index, file := range bundle.Files {
			if file.Name == "REQUEST-942-APPLICATION-ATTACK-SQLI.conf" {
				sqli = file.Name
				bundle.Files[index].SHA256 = "00" + file.SHA256[2:]
			}
		}
	})
	if changed := ChangedCRSRuleFiles(current, edited); !slices.Equal(changed, []string{sqli}) || sqli == "" {
		t.Fatalf("edited SQLi file: changed %v", changed)
	}
	dropped := crsCatalogBody(t, func(bundle *rulecatalog.WAFEngineBundle) { bundle.Files = bundle.Files[1:] })
	if changed := ChangedCRSRuleFiles(current, dropped); len(changed) != 1 {
		t.Fatalf("dropped file: changed %v", changed)
	}
	all := ChangedCRSRuleFiles(nil, current)
	if len(all) != len(rulecatalog.CRSRulesBundle().Files) {
		t.Fatalf("first delivery changes %d of %d files", len(all), len(rulecatalog.CRSRulesBundle().Files))
	}
	// Withdrawn or undecodable: no release could be built from it.
	if changed := ChangedCRSRuleFiles(current, nil); changed != nil {
		t.Fatalf("withdrawn body changed %v", changed)
	}
	if changed := ChangedCRSRuleFiles(current, []byte(`{"waf_rule_set":{}}`)); changed != nil {
		t.Fatalf("bodiless set changed %v", changed)
	}
}

func TestPublishedCRSRuleFilesFromSiteRuntime(t *testing.T) {
	siteID := uuid.MustParse("01990000-0000-7000-8000-000000000011")
	policy := managedWAFPolicyForEdgeTest(siteID)
	crs := crsInputsForEdgeTest(t)
	profile := crs.Profiles[securitypolicy.DefaultCRSProfile].Profile
	config := *policy.Rules[0].ActionConfig.ManagedWAF
	// One CRS set only: exactly its files (and the base, data and license files).
	sqli := []edgeconfig.ManagedWAFSet{}
	for _, set := range profile.Sets {
		if set.Key == "waf_set:crs_sqli" {
			sqli = append(sqli, set)
		}
	}
	profile.Sets, profile.Exports = sqli, []int{942100}
	profile.Ref.SHA256 = strings.Repeat("e", 64)
	crs.Profiles = securitypolicy.CRSProfiles{"system/crs-sqli": {Profile: profile}}
	managed := securitypolicy.EdgeManagedWAF(config, profile.Ref, policy.ID.String(), 1, nil)
	listenerManaged, err := edgeconfig.CanonicalListenerManagedWAF(managed)
	if err != nil {
		t.Fatal(err)
	}
	document := siteRuntimeV2Document{Schema: siteRuntimeV2Schema, Sites: []siteRuntimeV2Site{{ID: siteID.String(),
		Domains: []string{"waf.example"}, Listeners: []siteRuntimeV2Listener{{Port: 80,
			Security: &edgeconfig.ListenerSecurity{ManagedWAF: listenerManaged}}}}}}
	canonical, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	v2, known := publishedCRSRuleFiles(canonical, crs.RuleText, crs.Profiles)
	if !known || !slices.Contains(v2, "REQUEST-942-APPLICATION-ATTACK-SQLI.conf") ||
		slices.Contains(v2, "REQUEST-941-APPLICATION-ATTACK-XSS.conf") {
		t.Fatalf("v2 files = %v known=%v", v2, known)
	}
	if _, known := publishedCRSRuleFiles([]byte(`{"schema":"cdnca.edge.config-source/v1"}`), crs.RuleText, crs.Profiles); known {
		t.Fatal("a release that is not site runtime v2 reported as known")
	}
	// A release selecting a pack this control plane no longer has is unknown
	// (republished on any rule text change).
	if _, known := publishedCRSRuleFiles(canonical, crs.RuleText, securitypolicy.CRSProfiles{}); known {
		t.Fatal("release with an unknown profile pack reported as known")
	}
}
