package securitypublication

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cdnca/cdnca/libs/edgeconfig/crawlerdefaults"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

var (
	ErrInvalidBinding     = errors.New("invalid security publication binding")
	ErrUnsupportedRuntime = errors.New("security publication cannot be represented by the edge runtime")
)

type ActiveBinding struct {
	BindingID             uuid.UUID
	PublicationID         uuid.UUID
	BindingRevision       int64
	RuntimeSnapshotSHA256 [sha256.Size]byte
	Snapshot              securitypolicy.RuntimeSnapshot
	// CRS (WAF bindings whose policy runs a managed WAF): the downloaded CRS
	// profile packs, the CRS rule text and the site's own CRS override.
	CRS *CRSInputs
	// TrustedCrawlers (CC bindings): the downloaded official crawler IP
	// ranges dataset (dataset/trusted-crawlers), merged by crawler name into
	// the policy's trusted crawlers; nil when none was downloaded.
	TrustedCrawlers *crawlerdefaults.Dataset
	// IPLists (WAF bindings whose rules name IP lists):
	// the lists' current contents; an unresolved list refuses the binding.
	IPLists securitypolicy.ResolvedIPLists
}

// CRSInputs is what a managed WAF compiles against (PA-12): the CRS profile
// packs the control plane may use (securitypolicy.LoadCRSProfilesTx), the
// synced CRS rule text (waf_set:crs_rules; nil: the compiler seed) and the
// site's override of the library's profile / exclusions.
type CRSInputs struct {
	Profiles securitypolicy.CRSProfiles
	RuleText *edgeconfig.CRSRuleText
	Override securitypolicy.CRSOverride
	// Apps are the downloaded application exclusion packs (the override's
	// application types select from them).
	Apps securitypolicy.CRSApps
}

type BindingIdentity struct {
	PublicationID         uuid.UUID
	BindingRevision       int64
	PolicyID              uuid.UUID
	PolicyVersion         int64
	Kind                  string
	RuntimeSnapshotSHA256 [sha256.Size]byte
}

type CompiledSiteSecurity struct {
	Site     edgeconfig.Site
	Bindings []BindingIdentity
}

// CompileSiteSecurityBindings converts active immutable publication snapshots
// into the narrower security contract currently understood by edgeconfig.
func CompileSiteSecurityBindings(site edgeconfig.Site, targetScopeID, siteID uuid.UUID,
	bindings []ActiveBinding) (CompiledSiteSecurity, error) {
	return CompileSiteSecurityBindingsFor(site, nil, targetScopeID, siteID, bindings)
}

// CompileSiteSecurityBindingsFor is CompileSiteSecurityBindings for a server
// whose server_name is domains (site runtime v2: every live domain): a CC
// host condition may name any of them. nil is the site's primary only.
func CompileSiteSecurityBindingsFor(site edgeconfig.Site, domains []string, targetScopeID, siteID uuid.UUID,
	bindings []ActiveBinding) (CompiledSiteSecurity, error) {
	if targetScopeID == uuid.Nil || siteID == uuid.Nil || site.ID != siteID.String() ||
		len(bindings) > 3 || len(site.WAF.Rules) != 0 || len(site.ACL.Rules) != 0 ||
		site.ACL.DefaultAction != edgeconfig.ACLAllow {
		return CompiledSiteSecurity{}, ErrInvalidBinding
	}

	result := CompiledSiteSecurity{
		Site: site, Bindings: make([]BindingIdentity, 0, len(bindings)),
	}
	seen := make(map[string]struct{}, len(bindings))
	var managed *securitypolicy.ManagedWAFConfig
	var managedSnapshot securitypolicy.RuntimeSnapshot
	var managedCRS *CRSInputs
	allowCIDRs := make([]string, 0)
	for _, binding := range bindings {
		snapshot := binding.Snapshot
		if binding.BindingID == uuid.Nil || binding.PublicationID == uuid.Nil || binding.BindingRevision < 1 ||
			snapshot.TenantScopeID != targetScopeID || snapshot.SiteID != siteID ||
			snapshot.PolicyID == uuid.Nil || snapshot.PolicyVersion < 1 {
			return CompiledSiteSecurity{}, ErrInvalidBinding
		}
		if _, duplicate := seen[snapshot.Kind]; duplicate {
			return CompiledSiteSecurity{}, ErrInvalidBinding
		}
		seen[snapshot.Kind] = struct{}{}
		if err := securitypolicy.ValidateRuntimeSnapshot(snapshot); err != nil {
			return CompiledSiteSecurity{}, ErrInvalidBinding
		}
		encoded, err := json.Marshal(snapshot)
		if err != nil || sha256.Sum256(encoded) != binding.RuntimeSnapshotSHA256 {
			return CompiledSiteSecurity{}, ErrInvalidBinding
		}

		switch snapshot.Kind {
		case securitypolicy.KindACL:
			var policy edgeconfig.SecurityPolicy
			policy, err = compileACL(snapshot, binding.BindingRevision, binding.RuntimeSnapshotSHA256)
			result.Site.SecurityPolicies = append(result.Site.SecurityPolicies, policy)
		case securitypolicy.KindWAF:
			var policy edgeconfig.SecurityPolicy
			policy, managed, err = compileWAF(snapshot, binding.BindingRevision, binding.RuntimeSnapshotSHA256, binding.IPLists)
			result.Site.SecurityPolicies = append(result.Site.SecurityPolicies, policy)
		case securitypolicy.KindCC:
			result.Site.CCV2, err = compileCCV2(result.Site, domains, binding)
		default:
			err = ErrInvalidBinding
		}
		if err != nil {
			return CompiledSiteSecurity{}, err
		}
		if managed != nil && managedSnapshot.PolicyID == uuid.Nil {
			managedSnapshot, managedCRS = snapshot, binding.CRS
		}
		if snapshot.Kind != securitypolicy.KindCC && snapshot.Enabled {
			allowCIDRs = append(allowCIDRs, unconditionalAllowCIDRs(snapshot)...)
		}
		result.Bindings = append(result.Bindings, BindingIdentity{
			PublicationID: binding.PublicationID, BindingRevision: binding.BindingRevision,
			PolicyID:      snapshot.PolicyID,
			PolicyVersion: snapshot.PolicyVersion, Kind: snapshot.Kind,
			RuntimeSnapshotSHA256: binding.RuntimeSnapshotSHA256,
		})
	}
	sort.Slice(result.Bindings, func(left, right int) bool {
		return result.Bindings[left].Kind < result.Bindings[right].Kind
	})
	sort.Slice(result.Site.SecurityPolicies, func(left, right int) bool {
		return result.Site.SecurityPolicies[left].Kind < result.Site.SecurityPolicies[right].Kind
	})
	var profile *edgeconfig.CRSProfile
	var apps []edgeconfig.CRSApp
	if managed != nil {
		if managedCRS == nil {
			return CompiledSiteSecurity{}, ErrUnsupportedRuntime
		}
		effective := securitypolicy.EffectiveManagedWAF(*managed, managedCRS.Override)
		selected, ok := managedCRS.Profiles[effective.Profile]
		if !ok || managedCRS.Profiles.Check(effective) != nil {
			return CompiledSiteSecurity{}, ErrUnsupportedRuntime
		}
		profile = &selected.Profile
		sort.Strings(allowCIDRs)
		allowCIDRs = slices.Compact(allowCIDRs)
		edge := securitypolicy.EdgeManagedWAF(effective, selected.Profile.Ref, managedSnapshot.PolicyID.String(),
			managedSnapshot.PolicyVersion, allowCIDRs)
		if len(managedCRS.Override.Apps) != 0 {
			refs, selectedApps, ok := managedCRS.Apps.Refs(managedCRS.Override.Apps)
			if !ok {
				return CompiledSiteSecurity{}, ErrUnsupportedRuntime
			}
			edge.Apps, apps = refs, selectedApps
		}
		result.Site.ManagedWAF = &edge
	}
	var rules *edgeconfig.CRSRuleText
	if profile != nil {
		// The site is checked against the CRS rule text and profile pack the
		// release loads (the compiler seed when the caller has none).
		rules = managedCRS.RuleText
		if rules == nil {
			var err error
			if rules, err = securitypolicy.EdgeCRSRuleText(*rulecatalog.CRSRulesBundle()); err != nil {
				return CompiledSiteSecurity{}, ErrUnsupportedRuntime
			}
		}
	}
	if err := validateSiteRuntimeSecurity(targetScopeID, result.Site, rules, profile, apps...); err != nil {
		return CompiledSiteSecurity{}, err
	}
	return result, nil
}

// validateSiteRuntimeSecurity renders the compiled security as the site
// runtime release does (one listener: rules, CC, managed WAF): what the
// node cannot render is refused before it is published.
func validateSiteRuntimeSecurity(targetScopeID uuid.UUID, site edgeconfig.Site, rules *edgeconfig.CRSRuleText,
	profile *edgeconfig.CRSProfile, apps ...edgeconfig.CRSApp) error {
	protocol := site.Protocol
	if protocol == "" {
		protocol = edgeconfig.ProtocolHTTP
	}
	listener := edgeconfig.SecurityListener{SiteID: site.ID, Domain: site.Domain, Port: site.ListenPort, Protocol: protocol,
		Security: edgeconfig.ListenerSecurity{Policies: site.SecurityPolicies, CC: site.CCV2}}
	if site.ManagedWAF != nil {
		managed, err := edgeconfig.CanonicalListenerManagedWAF(*site.ManagedWAF)
		if err != nil {
			return ErrUnsupportedRuntime
		}
		listener.Security.ManagedWAF = managed
	}
	listeners := []edgeconfig.SecurityListener{listener}
	if _, err := edgeconfig.RenderSecurityFragments(targetScopeID.String(), "security-binding-validation", listeners); err != nil {
		return ErrUnsupportedRuntime
	}
	if listener.Security.ManagedWAF != nil {
		if rules == nil || profile == nil {
			return ErrUnsupportedRuntime
		}
		if _, err := edgeconfig.ListenerCRSReleaseFiles(listeners, rules, []edgeconfig.CRSProfile{*profile}, apps...); err != nil {
			return ErrUnsupportedRuntime
		}
	}
	return nil
}

func compileACL(snapshot securitypolicy.RuntimeSnapshot, bindingRevision int64,
	runtimeSHA256 [sha256.Size]byte) (edgeconfig.SecurityPolicy, error) {
	policy := edgeconfig.SecurityPolicy{
		Kind: edgeconfig.SecurityACL, PolicyID: snapshot.PolicyID.String(),
		PolicyVersion: snapshot.PolicyVersion, BindingRevision: bindingRevision,
		RuntimeSHA256: fmt.Sprintf("%x", runtimeSHA256[:]), Enabled: snapshot.Enabled,
	}
	switch snapshot.DefaultAction {
	case securitypolicy.ActionAllow:
		policy.DefaultAction = edgeconfig.WAFAllow
	case securitypolicy.ActionBlock:
		policy.DefaultAction = edgeconfig.WAFBlock
	default:
		return edgeconfig.SecurityPolicy{}, ErrUnsupportedRuntime
	}
	if !snapshot.Enabled {
		return policy, nil
	}

	for _, rule := range snapshot.Rules {
		if !rule.Enabled {
			continue
		}
		if len(rule.Conditions) != 1 {
			return edgeconfig.SecurityPolicy{}, ErrUnsupportedRuntime
		}
		condition := rule.Conditions[0]
		if condition.Field != "client_ip" || condition.Operator != "ip_in_cidr" ||
			condition.Key != "" || len(condition.Values) != 1 {
			return edgeconfig.SecurityPolicy{}, ErrUnsupportedRuntime
		}
		action, control, err := edgeWAFAction(rule)
		if err != nil {
			return edgeconfig.SecurityPolicy{}, err
		}
		match := edgeconfig.WAFMatch{SourceCIDR: condition.Values[0]}
		if terminalSecurityRuleShadows(policy.Rules, match) {
			return edgeconfig.SecurityPolicy{}, ErrUnsupportedRuntime
		}
		policy.Rules = append(policy.Rules, edgeconfig.WAFRule{
			RuleID: rule.ID.String(), Comment: rule.Comment, ExpiresAt: rule.ExpiresAt, Match: match,
			Action: action, Control: control,
		})
	}
	return policy, nil
}

// unconditionalAllowCIDRs lists the networks an enabled ACL/WAF policy allows
// with a permanent client_ip-only rule; the managed WAF engine is off for
// them so the allow keeps precedence over CRS (ModSecurity runs before the
// Lua policies). A rule with expires_at is not here (SF-E01: the list has no
// expiry): the node derives its CRS exemption from the rule plan, which
// keeps the expiry, and checks it per request (cdnca_managed_waf.lua).
func unconditionalAllowCIDRs(snapshot securitypolicy.RuntimeSnapshot) []string {
	result := make([]string, 0)
	for _, rule := range snapshot.Rules {
		if !rule.Enabled || rule.Action != securitypolicy.ActionAllow || len(rule.Conditions) != 1 || rule.ExpiresAt != "" {
			continue
		}
		condition := rule.Conditions[0]
		if condition.Field != "client_ip" || condition.Operator != "ip_in_cidr" {
			continue
		}
		for _, value := range condition.Values {
			if prefix, err := netip.ParsePrefix(value); err == nil {
				result = append(result, prefix.Masked().String())
			}
		}
	}
	return result
}

func compileWAF(snapshot securitypolicy.RuntimeSnapshot, bindingRevision int64,
	runtimeSHA256 [sha256.Size]byte, ipLists securitypolicy.ResolvedIPLists) (edgeconfig.SecurityPolicy, *securitypolicy.ManagedWAFConfig, error) {
	defaultAction := edgeconfig.WAFAction("")
	switch snapshot.DefaultAction {
	case securitypolicy.ActionAllow:
		defaultAction = edgeconfig.WAFAllow
	case securitypolicy.ActionBlock:
		defaultAction = edgeconfig.WAFBlock
	default:
		return edgeconfig.SecurityPolicy{}, nil, ErrUnsupportedRuntime
	}
	policy := edgeconfig.SecurityPolicy{
		Kind: edgeconfig.SecurityWAF, PolicyID: snapshot.PolicyID.String(),
		PolicyVersion: snapshot.PolicyVersion, BindingRevision: bindingRevision,
		RuntimeSHA256: fmt.Sprintf("%x", runtimeSHA256[:]), Enabled: snapshot.Enabled,
		DefaultAction: defaultAction, Rules: make([]edgeconfig.WAFRule, 0, len(snapshot.Rules)),
	}
	if settings := snapshot.WAFSettings; settings != nil {
		if settings.Mode == securitypolicy.WAFModeObserve {
			policy.Mode = edgeconfig.WAFModeObserve
		}
		if value := settings.AutoBlock; value != nil {
			policy.AutoBlock = &edgeconfig.WAFAutoBlock{WindowSeconds: value.WindowSeconds, HitThreshold: value.HitThreshold,
				BlockSeconds: value.BlockSeconds}
		}
	}
	if !snapshot.Enabled {
		return policy, nil, nil
	}
	var managed *securitypolicy.ManagedWAFConfig
	for _, rule := range snapshot.Rules {
		if !rule.Enabled {
			continue
		}
		if rule.Action == securitypolicy.ActionManagedWAF {
			if managed != nil || rule.ActionConfig.ManagedWAF == nil || len(rule.Conditions) != 0 {
				return edgeconfig.SecurityPolicy{}, nil, ErrUnsupportedRuntime
			}
			config := *rule.ActionConfig.ManagedWAF
			managed = &config
			continue
		}
		action, control, err := edgeWAFAction(rule)
		if err != nil {
			return edgeconfig.SecurityPolicy{}, nil, err
		}
		match, err := edgeWAFMatchWith(rule.Conditions, ipLists)
		if err != nil {
			return edgeconfig.SecurityPolicy{}, nil, err
		}
		if terminalSecurityRuleShadows(policy.Rules, match) {
			return edgeconfig.SecurityPolicy{}, nil, ErrUnsupportedRuntime
		}
		compiled := edgeconfig.WAFRule{
			RuleID: rule.ID.String(), Comment: rule.Comment, ExpiresAt: rule.ExpiresAt,
			Match: match, Action: action, Control: control,
		}
		switch {
		case rule.ActionConfig.WAFBan != nil:
			compiled.ActionConfig = &edgeconfig.WAFActionConfig{BanSeconds: rule.ActionConfig.WAFBan.BanSeconds}
		case rule.ActionConfig.WAFChallenge != nil:
			compiled.ActionConfig = &edgeconfig.WAFActionConfig{PassSeconds: rule.ActionConfig.WAFChallenge.PassSeconds,
				PowBits: rule.ActionConfig.WAFChallenge.PowBits}
		}
		policy.Rules = append(policy.Rules, compiled)
	}
	return policy, managed, nil
}

// WAFRuleShadowed reports whether an earlier terminal rule matches every
// request current matches (a policy with such a rule is not published).
func WAFRuleShadowed(earlier []edgeconfig.WAFRule, current edgeconfig.WAFMatch) bool {
	return terminalSecurityRuleShadows(earlier, current)
}

func terminalSecurityRuleShadows(rules []edgeconfig.WAFRule, current edgeconfig.WAFMatch) bool {
	for _, previous := range rules {
		if previous.Control == edgeconfig.WAFStop && securityMatchCovers(previous.Match, current) {
			return true
		}
	}
	return false
}

func securityMatchCovers(previous, current edgeconfig.WAFMatch) bool {
	// An IP list condition (ge36-waf) is not compared: never a cover.
	// Nor a negated JA4 set: compared conservatively, never a cover.
	if len(previous.Inspect) != 0 || len(previous.IPLists) != 0 || previous.NotJA4 != nil {
		return false
	}
	if previous.Host != "" && (current.Host == "" || previous.Host != current.Host) ||
		previous.Port != 0 && (current.Port == 0 || previous.Port != current.Port) ||
		previous.Method != "" && (current.Method == "" || previous.Method != current.Method) ||
		!securityPathCovers(previous.Path, current.Path) ||
		!securityHeaderCovers(previous.Header, current.Header) ||
		!edgeconfig.WAFJA4Covers(previous.JA4, current.JA4) ||
		!edgeconfig.WAFIPIntelCovers(previous.IPIntel, current.IPIntel) {
		return false
	}
	if previous.SourceCIDR == "" {
		return true
	}
	if current.SourceCIDR == "" {
		return false
	}
	previousPrefix, previousErr := netip.ParsePrefix(previous.SourceCIDR)
	currentPrefix, currentErr := netip.ParsePrefix(current.SourceCIDR)
	return previousErr == nil && currentErr == nil &&
		previousPrefix.Addr().BitLen() == currentPrefix.Addr().BitLen() &&
		previousPrefix.Bits() <= currentPrefix.Bits() && previousPrefix.Contains(currentPrefix.Addr())
}

func securityPathCovers(previous, current *edgeconfig.WAFPathMatch) bool {
	if previous == nil {
		return true
	}
	if current == nil {
		return false
	}
	if previous.Kind == edgeconfig.WAFPathExact {
		return current.Kind == edgeconfig.WAFPathExact && previous.Value == current.Value
	}
	return current.Value == previous.Value || strings.HasPrefix(current.Value, previous.Value+"/")
}

func securityHeaderCovers(previous, current *edgeconfig.WAFHeaderMatch) bool {
	if previous == nil {
		return true
	}
	if current == nil || previous.Name != current.Name {
		return false
	}
	return previous.Kind == edgeconfig.WAFHeaderExists ||
		previous.Kind == edgeconfig.WAFHeaderExact && current.Kind == edgeconfig.WAFHeaderExact && previous.Value == current.Value
}

// CompileWAFRule maps one allow / block / log WAF policy rule to the node
// rule model, exactly as a bound WAF policy is compiled (no rule ID; the
// caller assigns it). WAF rule subscriptions use it to build their rule
// pack rules.
func CompileWAFRule(action, flow string, conditions []securitypolicy.Condition) (edgeconfig.WAFRule, error) {
	edgeAction, control, err := edgeWAFAction(securitypolicy.RuntimeRule{Action: action, Flow: flow})
	if err != nil {
		return edgeconfig.WAFRule{}, err
	}
	match, err := edgeWAFMatch(conditions)
	if err != nil {
		return edgeconfig.WAFRule{}, err
	}
	return edgeconfig.WAFRule{Match: match, Action: edgeAction, Control: control}, nil
}

func edgeWAFAction(rule securitypolicy.RuntimeRule) (edgeconfig.WAFAction, edgeconfig.WAFControl, error) {
	control := edgeconfig.WAFControl("")
	switch rule.Flow {
	case securitypolicy.FlowContinue:
		control = edgeconfig.WAFContinue
	case securitypolicy.FlowStop:
		control = edgeconfig.WAFStop
	default:
		return "", "", ErrUnsupportedRuntime
	}
	switch rule.Action {
	case securitypolicy.ActionAllow:
		return edgeconfig.WAFAllow, control, nil
	case securitypolicy.ActionBlock:
		return edgeconfig.WAFBlock, control, nil
	case securitypolicy.ActionLog:
		return edgeconfig.WAFLog, control, nil
	case securitypolicy.ActionChallenge:
		if rule.ActionConfig.WAFChallenge == nil {
			return "", "", ErrUnsupportedRuntime
		}
		return edgeconfig.WAFChallenge, control, nil
	case securitypolicy.ActionBan:
		return edgeconfig.WAFBan, control, nil
	default:
		return "", "", ErrUnsupportedRuntime
	}
}

func edgeWAFMatch(conditions []securitypolicy.Condition) (edgeconfig.WAFMatch, error) {
	return edgeWAFMatchWith(conditions, nil)
}

// edgeWAFMatchWith is edgeWAFMatch with the bound policy's resolved IP lists.
func edgeWAFMatchWith(conditions []securitypolicy.Condition, ipLists securitypolicy.ResolvedIPLists) (edgeconfig.WAFMatch, error) {
	if len(conditions) == 0 || len(conditions) > securitypolicy.MaxWAFRuleConditions {
		return edgeconfig.WAFMatch{}, ErrUnsupportedRuntime
	}
	match := edgeconfig.WAFMatch{}
	seen := make(map[string]struct{}, len(conditions))
	for _, condition := range conditions {
		inspect, ok, err := edgeWAFInspect(condition)
		if !ok {
			if _, duplicate := seen[condition.Field]; duplicate {
				return edgeconfig.WAFMatch{}, ErrUnsupportedRuntime
			}
			seen[condition.Field] = struct{}{}
		}
		if ok {
			if err != nil {
				return edgeconfig.WAFMatch{}, ErrUnsupportedRuntime
			}
			match.Inspect = append(match.Inspect, inspect)
			continue
		}
		if condition.Field == "ip_list" {
			list, ok := ipLists.Condition(condition)
			if !ok {
				return edgeconfig.WAFMatch{}, ErrUnsupportedRuntime
			}
			match.IPLists = append(match.IPLists, list)
			continue
		}
		if condition.Field == "ja4" {
			// equals / in: the request's $cdnca_ja4 is one of the values;
			// not_in: it has one and it is none of them (WAF_JA4_NEGATION).
			values, err := edgeconfig.NormalizeWAFJA4(append([]string(nil), condition.Values...))
			if err != nil || condition.Key != "" || condition.Operator != "equals" && condition.Operator != "in" && condition.Operator != "not_in" ||
				condition.Operator == "equals" && len(values) != 1 {
				return edgeconfig.WAFMatch{}, ErrUnsupportedRuntime
			}
			if condition.Operator == "not_in" {
				match.NotJA4 = values
			} else {
				match.JA4 = values
			}
			continue
		}
		// carrier / ip_tag / asn / country / province / city: looked up in
		// the node's IP intelligence library (needs IP_INTEL v2).
		if ipIntel, ok, err := edgeconfig.IPIntelPolicyCondition(condition.Field, condition.Operator, condition.Key, condition.Values); ok {
			if err != nil {
				return edgeconfig.WAFMatch{}, ErrUnsupportedRuntime
			}
			match.IPIntel = append(match.IPIntel, ipIntel)
			continue
		}
		if len(condition.Values) != 1 {
			return edgeconfig.WAFMatch{}, ErrUnsupportedRuntime
		}
		value := condition.Values[0]
		switch {
		case condition.Field == "method" && condition.Operator == "equals" && condition.Key == "":
			match.Method = value
		case condition.Field == "path" && (condition.Operator == "equals" || condition.Operator == "prefix") && condition.Key == "":
			kind := edgeconfig.WAFPathExact
			if condition.Operator == "prefix" {
				kind = edgeconfig.WAFPathPrefix
			}
			match.Path = &edgeconfig.WAFPathMatch{Kind: kind, Value: value}
		case condition.Field == "header" && condition.Operator == "equals":
			match.Header = &edgeconfig.WAFHeaderMatch{Name: condition.Key, Kind: edgeconfig.WAFHeaderExact, Value: value}
		case condition.Field == "port" && condition.Operator == "number_eq" && condition.Key == "":
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil || port == 0 || strconv.FormatUint(port, 10) != value {
				return edgeconfig.WAFMatch{}, ErrUnsupportedRuntime
			}
			match.Port = uint16(port)
		case condition.Field == "client_ip" && condition.Operator == "ip_in_cidr" && condition.Key == "":
			match.SourceCIDR = value
		default:
			return edgeconfig.WAFMatch{}, ErrUnsupportedRuntime
		}
	}
	if match.IPIntel != nil {
		// carrier and ip_tag both become tag conditions; canonical order.
		normalized, err := edgeconfig.NormalizeWAFIPIntel(match.IPIntel)
		if err != nil {
			return edgeconfig.WAFMatch{}, ErrUnsupportedRuntime
		}
		match.IPIntel = normalized
	}
	return match, nil
}

// edgeWAFInspect maps request-content conditions (content operators on the
// content fields, edgeconfig.WAFInspectPolicyCondition) to node inspect
// clauses. Path equals/prefix and header equals stay native matches.
func edgeWAFInspect(condition securitypolicy.Condition) (edgeconfig.WAFInspect, bool, error) {
	return edgeconfig.WAFInspectPolicyCondition(condition.Field, condition.Operator, condition.Key, condition.Values,
		condition.Filters, condition.BodyOverflow)
}
