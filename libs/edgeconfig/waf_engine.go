package edgeconfig

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// CRSRuleText is the OWASP CRS rule text of one release: file name ->
// content, taken from the signed catalog's CRS rule package
// (crs_profile/crs_rules). Build requires it when a site runs a managed WAF;
// the CRS manifest is derived from it (DeriveCRSManifest). Version, when
// set, must be the version the rule files carry.
type CRSRuleText struct {
	Version string
	Files   map[string][]byte
}

// The OWASP CRS engine (libmodsecurity + ModSecurity-nginx) is an optional
// node extension: node packages do not contain it. A release that uses it
// carries WAFEngineManifestPath; the agent downloads, verifies and installs
// the extension, then writes the gate (RenderWAFEngineGate) into
// WAFEngineGateDir(StateRoot, ConfigVersionID). nginx.conf includes the gate
// files through globs that match nothing while the gate is absent, so a node
// without the extension starts normally and the managed WAF sites run their
// Lua policies (self-developed detection) only.
const (
	WAFEngineManifestPath   = "security/modsecurity/engine.json"
	WAFEngineManifestSchema = "cdnca.edge.waf-engine/v2"
	WAFEngineModSecurity    = "modsecurity"
	wafEngineGateRoot       = "waf-engine"
	// wafEngineControlVariable carries a site's request-time exclusions into
	// ModSecurity (the transaction ID).
	wafEngineControlVariable = "cdnca_modsecurity_ctl"
)

// WAFEngineManifest tells the agent which engine a release needs, which
// sites use it and the CRS rules each site excludes per request (sorted,
// from the site's profile exports).
type WAFEngineManifest struct {
	Schema     string              `json:"schema"`
	Engine     string              `json:"engine"`
	CRSVersion string              `json:"crs_version"`
	Sites      []WAFEngineSiteGate `json:"sites"`
}

type WAFEngineSiteGate struct {
	SiteID     string `json:"site_id"`
	Exclusions []int  `json:"exclusions"`
	// Apps are the keys of the site's application types (sorted).
	Apps []string `json:"apps,omitempty"`
}

// WAFEngineGateDir is the agent-owned directory nginx.conf of one release
// includes the gate from.
func WAFEngineGateDir(stateRoot, configVersionID string) string {
	return path.Join(stateRoot, wafEngineGateRoot, configVersionID)
}

// WAFEngineGateRoot is the parent of every release's gate directory.
func WAFEngineGateRoot(stateRoot string) string { return path.Join(stateRoot, wafEngineGateRoot) }

// wafEngineInclude matches the only include directives a release may carry:
// the three gate globs (the "[.]" makes nginx treat a missing file as an
// empty match instead of an error).
var wafEngineInclude = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,512}/` + wafEngineGateRoot +
	`/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/(load|http|site-[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\[\.\]conf$`)

// IsWAFEngineInclude reports whether an nginx include argument is a gate glob.
func IsWAFEngineInclude(argument string) bool {
	return wafEngineInclude.MatchString(argument) && !strings.Contains(argument, "/../") &&
		!strings.Contains(argument, "/./") && !strings.Contains(argument, "//")
}

func wafEngineIncludeLine(stateRoot, configVersionID, name string) string {
	return fmt.Sprintf("include %s/%s[.]conf;", WAFEngineGateDir(stateRoot, configVersionID), name)
}

func renderWAFEngineManifest(release *managedWAFRelease) []byte {
	manifest := WAFEngineManifest{Schema: WAFEngineManifestSchema, Engine: WAFEngineModSecurity,
		CRSVersion: release.manifest.Version, Sites: make([]WAFEngineSiteGate, 0, len(release.sites))}
	for _, site := range release.sites {
		exclusions := append([]int{}, site.ManagedWAF.Exclusions...)
		var apps []string
		for _, ref := range site.ManagedWAF.Apps {
			apps = append(apps, crsAppKey(ref.PackID))
		}
		sort.Strings(apps)
		manifest.Sites = append(manifest.Sites, WAFEngineSiteGate{SiteID: site.ID, Exclusions: exclusions, Apps: apps})
	}
	encoded, _ := json.Marshal(manifest)
	return append(encoded, '\n')
}

var crsVersionPattern = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)

func validWAFEngineManifest(manifest WAFEngineManifest) bool {
	if manifest.Schema != WAFEngineManifestSchema || manifest.Engine != WAFEngineModSecurity ||
		!crsVersionPattern.MatchString(manifest.CRSVersion) || len(manifest.Sites) == 0 || len(manifest.Sites) > 4096 {
		return false
	}
	for index, site := range manifest.Sites {
		if !uuidPattern.MatchString(site.SiteID) || index > 0 && manifest.Sites[index-1].SiteID >= site.SiteID ||
			site.Exclusions == nil || len(site.Exclusions) > MaxManagedWAFExclusions {
			return false
		}
		for position, id := range site.Exclusions {
			if !validCRSRuleID(id) || position > 0 && site.Exclusions[position-1] >= id {
				return false
			}
		}
		if len(site.Apps) > MaxManagedWAFApps {
			return false
		}
		for position, key := range site.Apps {
			if crsAppKey("system/app-"+key) != key || position > 0 && site.Apps[position-1] >= key {
				return false
			}
		}
	}
	return true
}

// ParseWAFEngineManifest validates a release's engine manifest.
func ParseWAFEngineManifest(content []byte) (WAFEngineManifest, error) {
	var manifest WAFEngineManifest
	if len(content) == 0 || len(content) > 16<<20 || json.Unmarshal(content, &manifest) != nil ||
		!validWAFEngineManifest(manifest) {
		return WAFEngineManifest{}, ErrInvalidConfig
	}
	return manifest, nil
}

// WAFEngineGate locates an installed, verified engine extension.
//   - ReleasePath: the resolved release directory (not the "current" link,
//     so a precheck and the reload that follows render identical files);
//   - ModulePath: ngx_http_modsecurity_module.so of the installed version;
//   - UnicodeMapPath: libmodsecurity's unicode.mapping of that version.
type WAFEngineGate struct {
	ReleasePath    string
	ModulePath     string
	UnicodeMapPath string
}

var gatePathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,512}$`)

// RenderWAFEngineGate returns the gate files (name -> content) for a release
// whose engine manifest is manifest. The agent writes them into
// WAFEngineGateDir only after the extension verified; nothing else is ever
// written there. A site that excludes rules gets its exclusions as the
// ModSecurity transaction ID, produced by set_by_lua (server rewrite phase,
// before ModSecurity creates the transaction): request ID, then "|x<id>|"
// per excluded rule, which the node-wide hooks match (renderManagedWAFMain).
func RenderWAFEngineGate(manifest WAFEngineManifest, gate WAFEngineGate) (map[string][]byte, error) {
	if !validWAFEngineManifest(manifest) {
		return nil, ErrInvalidConfig
	}
	for _, value := range []string{gate.ReleasePath, gate.ModulePath, gate.UnicodeMapPath} {
		if !gatePathPattern.MatchString(value) || path.Clean(value) != value || strings.Contains(value, "/../") {
			return nil, ErrInvalidConfig
		}
	}
	files := map[string][]byte{
		"load.conf": []byte(fmt.Sprintf("load_module %s;\n", gate.ModulePath)),
		"http.conf": []byte(fmt.Sprintf("modsecurity_rules 'SecUnicodeMapFile %s 20127';\nmodsecurity_rules_file %s/%s;\n",
			gate.UnicodeMapPath, gate.ReleasePath, managedWAFMainPath)),
	}
	for _, site := range manifest.Sites {
		content := fmt.Sprintf("modsecurity on;\nmodsecurity_rules_file %s/%s;\n", gate.ReleasePath, managedWAFSitePath(site.SiteID))
		if len(site.Exclusions) != 0 || len(site.Apps) != 0 {
			var marker strings.Builder
			marker.WriteString("|")
			for _, id := range site.Exclusions {
				fmt.Fprintf(&marker, "x%d|", id)
			}
			for _, key := range site.Apps {
				fmt.Fprintf(&marker, "a%s|", key)
			}
			content += fmt.Sprintf("set_by_lua_block $%s { return ngx.var.request_id .. %q }\nmodsecurity_transaction_id $%s;\n",
				wafEngineControlVariable, marker.String(), wafEngineControlVariable)
		}
		files["site-"+site.SiteID+".conf"] = []byte(content)
	}
	return files, nil
}
