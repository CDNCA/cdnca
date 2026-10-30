package edgeconfig

import (
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// ListenerRuntimeSecuritySiteRuntimeVersion is the site runtime API version
// that serves a listener's managed WAF (OWASP CRS) and JS challenge.
const ListenerRuntimeSecuritySiteRuntimeVersion uint32 = 6

// ListenerChallenge binds a site runtime listener to one version of a JS
// challenge policy, exactly like the legacy renderer's ChallengeBinding: the
// node loads <StateRoot>/challenge/policies/<PolicyID>/versions/<PolicyVersion>.json
// (installed by the challenge secret rollout) and the engine matches the
// request by TenantID (tenants.id) and the site ID.
type ListenerChallenge struct {
	TenantID      string `json:"tenant_id"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion uint64 `json:"policy_version"`
}

// ListenerSecuritySiteRuntimeVersion is the lowest site runtime API version
// that serves security (4 for policies and CC, 6 with a managed WAF or a
// challenge); 0 without security.
func ListenerSecuritySiteRuntimeVersion(security *ListenerSecurity) uint32 {
	switch {
	case security == nil:
		return 0
	case security.ManagedWAF != nil || security.Challenge != nil:
		return ListenerRuntimeSecuritySiteRuntimeVersion
	default:
		return 4
	}
}

// CanonicalListenerManagedWAF is a managed WAF as a signed site runtime
// document must carry it: normalized (sorted exclusions and CIDRs, the
// default inspection limit action spelled out).
func CanonicalListenerManagedWAF(value ManagedWAF) (*ManagedWAF, error) {
	return normalizeManagedWAF(&value)
}

// normalizeListenerRuntimeSecurity checks every listener's managed WAF and
// challenge and returns each site's normalized managed WAF. A site's
// listeners carry the same values (both are per site, as in the legacy
// renderer), and a managed WAF must already be canonical, so what is signed
// is what the node renders.
func normalizeListenerRuntimeSecurity(listeners []SecurityListener) (map[string]*ManagedWAF, error) {
	type siteSecurity struct {
		managed, challenge []byte
	}
	seen := make(map[string]siteSecurity, len(listeners))
	result := make(map[string]*ManagedWAF)
	for _, listener := range listeners {
		security := listener.Security
		var current siteSecurity
		if security.ManagedWAF != nil {
			canonical, err := CanonicalListenerManagedWAF(*security.ManagedWAF)
			if err != nil {
				return nil, ErrInvalidConfig
			}
			encoded, _ := json.Marshal(security.ManagedWAF)
			expected, _ := json.Marshal(canonical)
			if string(encoded) != string(expected) {
				return nil, ErrInvalidConfig
			}
			current.managed = encoded
			if _, exists := result[listener.SiteID]; !exists {
				result[listener.SiteID] = canonical
			}
		}
		if challenge := security.Challenge; challenge != nil {
			if !uuidPattern.MatchString(challenge.TenantID) || !uuidPattern.MatchString(challenge.PolicyID) ||
				challenge.PolicyVersion == 0 || challenge.PolicyVersion > 1<<53-1 {
				return nil, ErrInvalidConfig
			}
			current.challenge, _ = json.Marshal(challenge)
		}
		if previous, exists := seen[listener.SiteID]; exists &&
			(string(previous.managed) != string(current.managed) || string(previous.challenge) != string(current.challenge)) {
			return nil, ErrInvalidConfig
		}
		seen[listener.SiteID] = current
	}
	return result, nil
}

// ListenerSecurityRuntime is the node side of rendering listener security:
//   - StateRoot: the edge deployment root, where the challenge rollout
//     installs policies and the WAF engine gate lives (the legacy Spec.StateRoot);
//   - LuaRoot: the node's Lua root (<LuaRoot>/challenge/engine.lua);
//   - CRSFiles: every CRS file of the signed release (security/modsecurity/crs/<name>,
//     by name); the managed WAF requires exactly the files it loads;
//   - CRSProfile: the CRS profile pack a listener selects, verified by the
//     node (bytes with the ref's digest, rulepack.Load, rulepack.CRSProfileOf).
type ListenerSecurityRuntime struct {
	StateRoot  string
	LuaRoot    string
	CRSFiles   func() (map[string][]byte, error)
	CRSProfile func(ref CRSProfileRef) (CRSProfile, error)
	// CRSApp: an application exclusion pack a listener selects, verified by
	// the node (rulepack.LoadCRSApp); nil when the release selects none.
	CRSApp func(ref CRSAppRef) (CRSApp, error)
}

// RuntimeSecurity is the node-rendered part of listener security that the
// security fragments do not carry:
//   - Main: main-context lines (before events{}); HTTP: http-level lines of
//     this scope (an http{} with any Challenge also needs ChallengeHTTP once);
//   - Init: Lua statements the http init_by_lua_block runs (MergeSecurityInitLua);
//   - Server / Access: per listener, server-level lines and access_by_lua statements;
//   - Files: release files (managed WAF main/site configuration and engine manifest).
type RuntimeSecurity struct {
	Main, HTTP, Init string
	Server, Access   []string
	Files            map[string][]byte
	Challenge        bool
	ManagedWAF       bool
}

const (
	challengeStateDictionary = "cdnca_challenge_state"
	challengeInitIndent      = "    "
	// ChallengeHTTP is the http-level state every challenge engine shares
	// (written once per http{}, as the legacy renderer does).
	ChallengeHTTP = "  lua_shared_dict " + challengeStateDictionary + " 16m;\n"
)

// RenderListenerRuntimeSecurity renders the managed WAF gate and the JS
// challenge of listeners exactly as the legacy renderer does for the same
// sites: the same engine gate includes and ModSecurity files, the same
// challenge policy file, request context and phase (access, after the WAF
// policies in rewrite and CC in server rewrite).
func RenderListenerRuntimeSecurity(scopeID, versionID string, listeners []SecurityListener, runtime ListenerSecurityRuntime) (RuntimeSecurity, error) {
	result := RuntimeSecurity{Server: make([]string, len(listeners)), Access: make([]string, len(listeners)), Files: map[string][]byte{}}
	if !uuidPattern.MatchString(scopeID) || !versionPattern.MatchString(versionID) {
		return result, ErrInvalidConfig
	}
	managed, err := normalizeListenerRuntimeSecurity(listeners)
	if err != nil {
		return result, err
	}
	used := len(managed) != 0
	for _, listener := range listeners {
		used = used || listener.Security.Challenge != nil
	}
	if !used {
		return result, nil
	}
	// The roots end up in nginx and Lua string literals.
	if !runtimeSecurityPath(runtime.StateRoot) || !runtimeSecurityPath(runtime.LuaRoot) {
		return result, ErrInvalidConfig
	}
	challenges := map[string]ListenerChallenge{}
	var challengeSites, managedSites []string
	for index, listener := range listeners {
		if !uuidPattern.MatchString(listener.SiteID) {
			return result, ErrInvalidConfig
		}
		if challenge := listener.Security.Challenge; challenge != nil {
			if _, exists := challenges[listener.SiteID]; !exists {
				challenges[listener.SiteID] = *challenge
				challengeSites = append(challengeSites, listener.SiteID)
			}
			result.Access[index] = listenerChallengeAccessLua(*challenge, listener.SiteID)
		}
		if managed[listener.SiteID] != nil {
			if !containsString(managedSites, listener.SiteID) {
				managedSites = append(managedSites, listener.SiteID)
			}
			result.Server[index] = "    " + wafEngineIncludeLine(runtime.StateRoot, versionID, "site-"+listener.SiteID) + "\n"
		}
	}
	if len(challengeSites) != 0 {
		sort.Strings(challengeSites)
		result.Challenge = true
		result.Init = listenerChallengeInitLua(runtime, challengeSites, challenges)
	}
	if len(managedSites) != 0 {
		sort.Strings(managedSites)
		if err := renderListenerManagedWAF(&result, runtime, versionID, managedSites, managed); err != nil {
			return result, err
		}
	}
	return result, nil
}

func runtimeSecurityPath(value string) bool {
	return safeAbsolutePath(value) && filepath.ToSlash(value) == value && !strings.ContainsAny(value, "\"'\\ \t{};$")
}

func listenerChallengeModule(siteID string) string { return "cdnca_challenge_site_" + siteID }

func listenerChallengeInitLua(runtime ListenerSecurityRuntime, sites []string, challenges map[string]ListenerChallenge) string {
	var output strings.Builder
	indent := challengeInitIndent
	// Every site gets its own engine instance (state and policy), loaded once
	// in the master like the legacy renderer's init: the policy and its keys
	// are read as root, and a missing policy fails nginx -t.
	output.WriteString(indent + "do\n")
	fmt.Fprintf(&output, "%s  package.path = %q .. \";\" .. package.path\n", indent, path.Join(runtime.LuaRoot, "challenge", "?.lua"))
	fmt.Fprintf(&output, "%s  local engine = %q\n", indent, path.Join(runtime.LuaRoot, "challenge", "engine.lua"))
	output.WriteString(indent + "  for _, binding in ipairs({\n")
	for _, siteID := range sites {
		challenge := challenges[siteID]
		policyPath := path.Join(runtime.StateRoot, "challenge", "policies", challenge.PolicyID, "versions",
			fmt.Sprintf("%020d.json", challenge.PolicyVersion))
		fmt.Fprintf(&output, "%s    { module = %q, policy_path = %q, state_dict = %q },\n",
			indent, listenerChallengeModule(siteID), policyPath, challengeStateDictionary)
	}
	output.WriteString(indent + "  }) do\n")
	fmt.Fprintf(&output, "%s    local chunk, load_error = loadfile(engine)\n", indent)
	fmt.Fprintf(&output, "%s    if not chunk then error(load_error) end\n", indent)
	fmt.Fprintf(&output, "%s    local module = chunk()\n", indent)
	fmt.Fprintf(&output, "%s    if type(module) ~= \"table\" or type(module.init) ~= \"function\" then error(\"invalid challenge module\") end\n", indent)
	fmt.Fprintf(&output, "%s    module.init({ policy_path = binding.policy_path, state_dict = binding.state_dict })\n", indent)
	fmt.Fprintf(&output, "%s    package.loaded[binding.module] = module\n", indent)
	output.WriteString(indent + "  end\n" + indent + "end\n")
	return output.String()
}

// listenerChallengeAccessLua is the legacy challenge access prefix
// (challengeCachePolicyPrefixLua) for one site.
func listenerChallengeAccessLua(challenge ListenerChallenge, siteID string) string {
	var output strings.Builder
	fmt.Fprintf(&output, "        local cdnca_challenge_result = require(%q).access({ tenant_id = ", listenerChallengeModule(siteID))
	fmt.Fprintf(&output, "%q, site_id = %q })\n", challenge.TenantID, siteID)
	output.WriteString("        if cdnca_challenge_result ~= nil then\n")
	output.WriteString("          return cdnca_challenge_result\n")
	output.WriteString("        end\n")
	return output.String()
}

func renderListenerManagedWAF(result *RuntimeSecurity, runtime ListenerSecurityRuntime, versionID string,
	sites []string, managed map[string]*ManagedWAF) error {
	if runtime.CRSFiles == nil || runtime.CRSProfile == nil {
		return ErrInvalidConfig
	}
	edgeSites := make([]Site, len(sites))
	for index, siteID := range sites {
		edgeSites[index] = Site{ID: siteID, ManagedWAF: managed[siteID]}
	}
	refs := managedWAFProfileRefs(edgeSites)
	profiles := make([]CRSProfile, 0, len(refs))
	for _, ref := range refs {
		profile, err := runtime.CRSProfile(ref)
		if err != nil || profile.Ref != ref {
			return ErrInvalidConfig
		}
		profiles = append(profiles, profile)
	}
	var apps []CRSApp
	for _, ref := range managedWAFAppRefs(edgeSites) {
		if runtime.CRSApp == nil {
			return ErrInvalidConfig
		}
		app, err := runtime.CRSApp(ref)
		if err != nil || app.Ref != ref {
			return ErrInvalidConfig
		}
		apps = append(apps, app)
	}
	files, err := runtime.CRSFiles()
	if err != nil {
		return ErrInvalidConfig
	}
	release, err := resolveManagedWAFRelease(edgeSites, &CRSRuleText{Files: files}, profiles, true, apps...)
	if err != nil {
		return ErrInvalidConfig
	}
	main, err := renderManagedWAFMain(release, runtime.StateRoot)
	if err != nil {
		return ErrInvalidConfig
	}
	result.ManagedWAF = true
	result.Main = wafEngineIncludeLine(runtime.StateRoot, versionID, "load") + "\n"
	result.HTTP += "  " + wafEngineIncludeLine(runtime.StateRoot, versionID, "http") + "\n"
	result.Files[managedWAFMainPath] = main
	result.Files[WAFEngineManifestPath] = renderWAFEngineManifest(release)
	for _, site := range release.sites {
		result.Files[managedWAFSitePath(site.ID)] = renderManagedWAFSite(release, site)
	}
	return nil
}

// managedWAFProfileRefs is the distinct profiles the sites select, by digest.
func managedWAFProfileRefs(sites []Site) []CRSProfileRef {
	seen := map[string]bool{}
	refs := []CRSProfileRef{}
	for _, site := range sites {
		if site.ManagedWAF != nil && !seen[site.ManagedWAF.Profile.SHA256] {
			seen[site.ManagedWAF.Profile.SHA256] = true
			refs = append(refs, site.ManagedWAF.Profile)
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].SHA256 < refs[j].SHA256 })
	return refs
}

func listenerManagedSites(listeners []SecurityListener) ([]Site, error) {
	managed, err := normalizeListenerRuntimeSecurity(listeners)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(managed))
	for siteID := range managed {
		ids = append(ids, siteID)
	}
	sort.Strings(ids)
	sites := make([]Site, len(ids))
	for index, siteID := range ids {
		sites[index] = Site{ID: siteID, ManagedWAF: managed[siteID]}
	}
	return sites, nil
}

// ListenerCRSProfiles is the distinct CRS profiles the listeners' managed
// WAF selects (sorted by digest); none without a managed WAF. The control
// plane ships these packs with the release (ListenerCRSProfilePath), the node
// loads them (ListenerSecurityRuntime.CRSProfile).
func ListenerCRSProfiles(listeners []SecurityListener) ([]CRSProfileRef, error) {
	sites, err := listenerManagedSites(listeners)
	if err != nil {
		return nil, err
	}
	return managedWAFProfileRefs(sites), nil
}

// ListenerCRSApps is the distinct application exclusion packs the
// listeners' managed WAF selects (sorted by digest). The control plane ships
// them with the release (ListenerCRSAppPath).
func ListenerCRSApps(listeners []SecurityListener) ([]CRSAppRef, error) {
	sites, err := listenerManagedSites(listeners)
	if err != nil {
		return nil, err
	}
	return managedWAFAppRefs(sites), nil
}

func managedWAFAppRefs(sites []Site) []CRSAppRef {
	seen := map[string]CRSAppRef{}
	for _, site := range sites {
		if site.ManagedWAF == nil {
			continue
		}
		for _, ref := range site.ManagedWAF.Apps {
			seen[ref.SHA256] = ref
		}
	}
	refs := make([]CRSAppRef, 0, len(seen))
	for _, ref := range seen {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].SHA256 < refs[j].SHA256 })
	return refs
}

const crsAppReleaseDir = "security/modsecurity/crs-apps"

// ListenerCRSAppPath is where a release carries an application exclusion
// pack (its canonical cdnca.rule-pack/v1 document).
func ListenerCRSAppPath(sha256 string) string { return crsAppReleaseDir + "/" + sha256 + ".json" }

// ListenerCRSAppDigest returns the digest a release path names when it is an
// application exclusion pack path.
func ListenerCRSAppDigest(path string) (string, bool) {
	name, ok := strings.CutPrefix(path, crsAppReleaseDir+"/")
	digest, json := strings.CutSuffix(name, ".json")
	return digest, ok && json && crsProfileSHA256.MatchString(digest)
}

// ListenerCRSReleaseFiles is the signed release files (path -> content) of
// the CRS rule text these listeners load, from the catalog's whole CRS rule
// package text and the profiles they select (exactly what the node then
// requires); none without a managed WAF.
func ListenerCRSReleaseFiles(listeners []SecurityListener, text *CRSRuleText, profiles []CRSProfile, apps ...CRSApp) (map[string][]byte, error) {
	sites, err := listenerManagedSites(listeners)
	if err != nil {
		return nil, err
	}
	return CRSReleaseFiles(sites, text, profiles, apps...)
}

// CRSReleaseFiles is ListenerCRSReleaseFiles for sites (a Spec's). The
// application exclusion packs are checked against the sites but are not
// rule text: the caller ships their bytes (ListenerCRSAppPath).
func CRSReleaseFiles(sites []Site, text *CRSRuleText, profiles []CRSProfile, apps ...CRSApp) (map[string][]byte, error) {
	result := map[string][]byte{}
	release, err := resolveManagedWAFRelease(sites, text, profiles, false, apps...)
	if err != nil || release == nil {
		return result, err
	}
	for _, name := range release.fileNames() {
		result[ListenerCRSReleasePath(name)] = release.text.Files[name]
	}
	return result, nil
}

// ListenerCRSReleasePath is where a release carries one CRS file.
func ListenerCRSReleasePath(name string) string { return crsReleaseDir + "/" + name }

const crsProfileReleaseDir = "security/modsecurity/crs-profiles"

// ListenerCRSProfilePath is where a site runtime release carries the bytes
// of a CRS profile pack (its canonical cdnca.rule-pack/v1 document). PA-01
// moves the packs into the node artifact set (object store by the same
// digest); the release then carries none.
func ListenerCRSProfilePath(sha256 string) string {
	return crsProfileReleaseDir + "/" + sha256 + ".json"
}

// ListenerCRSProfileDigest returns the digest a release path names when it is
// a CRS profile pack path.
func ListenerCRSProfileDigest(path string) (string, bool) {
	name, ok := strings.CutPrefix(path, crsProfileReleaseDir+"/")
	digest, json := strings.CutSuffix(name, ".json")
	return digest, ok && json && crsProfileSHA256.MatchString(digest)
}

// ListenerRuntimeSecurityReleasePath reports whether a release path is
// reserved for files the node renders (a signed release must not carry it).
func ListenerRuntimeSecurityReleasePath(name string) bool {
	return name == managedWAFMainPath || name == WAFEngineManifestPath ||
		strings.HasPrefix(name, "security/") && strings.HasSuffix(name, "/modsecurity.conf")
}

// MergeSecurityInitLua adds statements to the one init_by_lua_block of an
// http-level fragment (the CC v2 registry init), or appends a block when the
// fragment has none: nginx accepts one init_by_lua_block per http{}.
func MergeSecurityInitLua(http, statements string) (string, error) {
	if statements == "" {
		return http, nil
	}
	const opener = "init_by_lua_block {"
	count := strings.Count(http, opener)
	if count > 1 {
		return "", ErrInvalidConfig
	}
	if count == 0 {
		return http + "  " + opener + "\n" + statements + "  }\n", nil
	}
	start := strings.Index(http, opener)
	lineEnd := strings.Index(http[start:], "\n")
	if lineEnd < 0 {
		return "", ErrInvalidConfig
	}
	line := http[start : start+lineEnd]
	if !strings.HasSuffix(line, " }") {
		return "", ErrInvalidConfig
	}
	closing := start + len(line) - len(" }")
	return http[:closing] + "\n" + statements + "  }" + http[start+lineEnd:], nil
}
