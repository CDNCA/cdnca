package edgeconfig

import (
	"fmt"
	"strings"
)

// ListenerSecurity carries the same compiled, provenance-bound policies used by
// the legacy site renderer. The runtime schema selects capability version 4.
type ListenerSecurity struct {
	Policies []SecurityPolicy `json:"policies,omitempty"`
	CC       *CCV2SiteBinding `json:"cc,omitempty"`
	// ManagedWAF and Challenge are the site's OWASP CRS managed WAF and JS
	// challenge binding (site runtime v6, listener_runtime_security.go); every
	// listener of a site carries the same values.
	ManagedWAF *ManagedWAF        `json:"managed_waf,omitempty"`
	Challenge  *ListenerChallenge `json:"challenge,omitempty"`
}

type SecurityListener struct {
	SiteID   string
	Domain   string
	Port     uint16
	Protocol Protocol
	Security ListenerSecurity
	// Telemetry: the server sets the security telemetry variables
	// (RenderTelemetryServer), so blocking rules record security events as the
	// legacy renderer does.
	Telemetry bool
	// Identity is the server's signed telemetry identity: a CC v2 hook
	// assigns it before deciding (ccV2IdentityPrelude). nil without telemetry.
	Identity *ServerTelemetryIdentity
}

type SecurityFragments struct {
	HTTP     string
	Server   []string
	Location []string
	// Log is per listener the Lua the server's one log_by_lua_block runs
	// (the CC v2 log hook), "" for none; the renderer joins it with the
	// capture's log Lua (RenderTelemetryCaptureHooks).
	Log     []string
	Files   map[string][]byte
	NeedsCC bool
	// NeedsWAFState: some listener's policies use WAF v2 actions; the http
	// block must declare WAFStateDictionary once (WAFStateHTTP), however
	// many scopes a composition joins.
	NeedsWAFState bool
	// CCV2Registry is the scope's CC v2 registry and HTTPWithoutCC is HTTP
	// without its CC v2 dictionary and init block, for a composition that
	// renders one merged registry for every scope (RenderComposedCCV2).
	CCV2Registry  *CCV2Registry
	HTTPWithoutCC string
}

// composedCCV2DictionaryLimit caps the merged CC v2 dictionary.
const composedCCV2DictionaryLimit = 256

// RenderComposedCCV2 renders the one CC v2 dictionary and init block of a
// composition: every scope's registry merged under versionID. The engine runs
// with scoped_state, so counters, bans, challenge state and the challenge
// cookie secret are kept per tenant scope. The dictionary is the scopes'
// single-scope size summed, capped at composedCCV2DictionaryLimit MiB.
func RenderComposedCCV2(versionID string, registries []CCV2Registry) (string, error) {
	if len(registries) == 0 {
		return "", nil
	}
	merged := CCV2Registry{SchemaVersion: CCV2RegistrySchemaVersion, ConfigVersionID: versionID}
	for _, registry := range registries {
		merged.Entries = append(merged.Entries, registry.Entries...)
	}
	merged = sortedCCV2Registry(merged)
	encoded, err := CanonicalCCV2Registry(merged)
	if err != nil {
		return "", err
	}
	size := min(16*len(registries), composedCCV2DictionaryLimit)
	var http strings.Builder
	fmt.Fprintf(&http, "  lua_shared_dict %s %dm;\n  %s\n", CCV2StateDictionary, size, CCV2RegistryBeginMarker)
	fmt.Fprintf(&http, "  init_by_lua_block { require(%q).init({ state_dict = %q, release_root = ngx.config.prefix(), scoped_state = true, registry_json = %s }) }\n",
		CCV2LuaModule, CCV2StateDictionary, ccV2RegistryLua(encoded))
	http.WriteString("  " + CCV2RegistryEndMarker + "\n")
	return http.String(), nil
}

func RenderSecurityFragments(scopeID, versionID string, listeners []SecurityListener) (SecurityFragments, error) {
	return RenderSecurityFragmentsAt(scopeID, versionID, listeners, 0)
}

// RenderSecurityFragmentsAt numbers listener-derived http-level names from
// listenerOffset, so several scopes composed into one nginx.conf do not
// redefine each other's geo variables. Offset 0 is the single-scope output.
func RenderSecurityFragmentsAt(scopeID, versionID string, listeners []SecurityListener, listenerOffset int) (SecurityFragments, error) {
	result := SecurityFragments{Server: make([]string, len(listeners)), Location: make([]string, len(listeners)), Log: make([]string, len(listeners)), Files: make(map[string][]byte)}
	if !uuidPattern.MatchString(scopeID) || !versionPattern.MatchString(versionID) || len(listeners) > 32000 ||
		listenerOffset < 0 || listenerOffset > 32000-len(listeners) {
		return result, ErrInvalidConfig
	}
	spec := normalizedSpec{TenantID: scopeID, ConfigVersionID: versionID}
	managedWAF, err := normalizeListenerRuntimeSecurity(listeners)
	if err != nil {
		return result, err
	}
	telemetry := make([]bool, len(listeners))
	for index, listener := range listeners {
		telemetry[index] = listener.Telemetry
		if !uuidPattern.MatchString(listener.SiteID) || listener.Port == 0 || (listener.Protocol != ProtocolHTTP && listener.Protocol != ProtocolHTTPS) {
			return result, ErrInvalidConfig
		}
		domain, err := normalizeSiteDomainName(listener.Domain)
		if err != nil || domain != listener.Domain {
			return result, ErrInvalidConfig
		}
		policies, err := normalizeSecurityPolicies(listener.Security.Policies)
		if err != nil {
			return result, err
		}
		site := Site{ID: listener.SiteID, Domain: domain, ListenPort: listener.Port, Protocol: listener.Protocol, SecurityPolicies: policies, CCV2: listener.Security.CC,
			ManagedWAF: managedWAF[listener.SiteID]}
		site.CCV2, err = normalizeCCV2SiteBinding(scopeID, site)
		if err != nil {
			return result, err
		}
		spec.Sites = append(spec.Sites, site)
	}
	var http, withoutCC strings.Builder
	// NeedsCC adds the security Lua directory (cdnca_waf inspect, cdnca_iplib).
	result.NeedsCC = hasWAFInspect(spec.Sites) || SpecUsesIPIntel(spec.Sites)
	for _, site := range spec.Sites {
		// IP list conditions run cdnca_waf.ip_list (security Lua directory).
		result.NeedsCC = result.NeedsCC || SecurityPoliciesUseIPLists(site.SecurityPolicies)
	}
	// A bound policy of a telemetry listener records its attack evidence
	// (cdnca_waf.evidence) on every block / log decision.
	for index, site := range spec.Sites {
		if telemetry[index] && len(site.SecurityPolicies) != 0 {
			result.NeedsCC = true
		}
	}
	if specUsesWAFActions(spec.Sites) {
		result.NeedsCC, result.NeedsWAFState = true, true
	}
	if hasCCV2(spec.Sites) {
		result.NeedsCC = true
		registry, err := ccV2RegistryForSpec(spec)
		if err != nil {
			return result, err
		}
		encoded, err := CanonicalCCV2Registry(registry)
		if err != nil {
			return result, err
		}
		http.WriteString("  lua_shared_dict " + CCV2StateDictionary + " 16m;\n  " + CCV2RegistryBeginMarker + "\n")
		fmt.Fprintf(&http, "  init_by_lua_block { require(%q).init({ state_dict = %q, release_root = ngx.config.prefix(), registry_json = %s }) }\n", CCV2LuaModule, CCV2StateDictionary, ccV2RegistryLua(encoded))
		http.WriteString("  " + CCV2RegistryEndMarker + "\n")
		result.CCV2Registry = &registry
	}
	for siteIndex, site := range spec.Sites {
		for policyIndex, policy := range site.SecurityPolicies {
			for ruleIndex, rule := range policy.Rules {
				if rule.Match.SourceCIDR != "" {
					fmt.Fprintf(&withoutCC, "  geo $%s {\n    default 0;\n    %s 1;\n  }\n", securitySourceVariable(listenerOffset+siteIndex, policyIndex, ruleIndex), rule.Match.SourceCIDR)
				}
			}
		}
		var location strings.Builder
		renderWAF(&location, listenerOffset+siteIndex, site.ID, WAFPolicy{}, site.SecurityPolicies, headerOverflowBlocks(site), telemetry[siteIndex])
		result.Location[siteIndex] = location.String()
		if site.CCV2 != nil {
			registry, err := ccV2RegistryForSpec(normalizedSpec{ConfigVersionID: versionID, Sites: []Site{site}})
			if err != nil {
				return result, err
			}
			hook := fmt.Sprintf("return require(%q).access(%q)", CCV2LuaModule, registry.Entries[0].EntryID)
			if prelude := ccV2IdentityPrelude(listeners[siteIndex].Identity); prelude != "" {
				hook = prelude + " " + hook
			}
			result.Server[siteIndex] = "    server_rewrite_by_lua_block { " + hook + " }\n"
			result.Log[siteIndex] = fmt.Sprintf("require(%q).log()", CCV2LuaModule)
			content, err := CanonicalCCV2Policy(site.CCV2.Policy)
			if err != nil {
				return result, err
			}
			result.Files[ccV2CompiledPath(site.ID)] = content
		}
	}
	result.HTTPWithoutCC = withoutCC.String()
	result.HTTP = http.String() + result.HTTPWithoutCC
	return result, nil
}
