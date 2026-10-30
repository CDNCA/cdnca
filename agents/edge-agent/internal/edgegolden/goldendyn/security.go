package goldendyn

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldenrelease"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// Dynamic routing D7 security (docs/edge/dynroute-security.md): scenarios
// whose sites carry listener security or an HTTP policy run on site objects
// the control plane's own conversion builds (services/control-api
// cmd/cdnca-site-objects-v2 = edgepublish.BuildSiteObjectsV2FromBundle) from
// the scenario's signed release (goldenrelease.Build). That conversion lives in control-api,
// which the agent module does not import: the run passes its binary in
// CDNCA_EDGE_GOLDEN_SITE_OBJECTS (tests/edge-golden/run.sh builds it).

// SecurityTenant is the scope tenant handed to the conversion. The corpus'
// challenge policies name it (v7 takes a challenge's tenant from its
// binding), so the site objects carry it.
const SecurityTenant = "0a1b9999-0000-4000-8000-000000000002"

// securityScenario: a scenario with listener security, an HTTP policy or
// certificates (TLS listeners: the conversion carries the site TLS fields).
func securityScenario(scenario *edgegolden.Scenario) bool {
	if len(scenario.Facts.HTTPPolicy) != 0 || len(scenario.Facts.Node.Challenges) != 0 ||
		len(scenario.Facts.Node.Certificates) != 0 {
		return true
	}
	var document struct {
		Sites []struct {
			Listeners []struct {
				Security json.RawMessage `json:"security"`
			} `json:"listeners"`
		} `json:"sites"`
	}
	if json.Unmarshal(scenario.Facts.Document, &document) != nil {
		return false
	}
	for _, site := range document.Sites {
		for _, listener := range site.Listeners {
			if len(listener.Security) != 0 && string(listener.Security) != "null" {
				return true
			}
		}
	}
	return false
}

// productionSites converts the scenario's signed release (goldenrelease) with
// the production conversion and publishes the scenario's challenge policies
// under <root>/challenge, where the skeleton's configure() preloads them.
func productionSites(ctx context.Context, env edgegolden.Env, scenario *edgegolden.Scenario, root string) ([]edgesite.Site, map[string][]byte, error) {
	converter := os.Getenv("CDNCA_EDGE_GOLDEN_SITE_OBJECTS")
	if converter == "" {
		return nil, nil, ErrUnsupported{"listener security without CDNCA_EDGE_GOLDEN_SITE_OBJECTS (control-api cdnca-site-objects-v2)"}
	}
	// telemetry identity is accepted (access logs are D12's); error pages
	// are merged after the conversion (withErrorPages, D9)
	// the release's state root is where v7 would publish it; the challenge
	// rollout writes <root>/challenge, the skeleton's challenge_root
	built, err := goldenrelease.Build(env, scenario, root)
	if err != nil {
		return nil, nil, err
	}
	bundle := built.Bundle
	bundleDir := filepath.Join(root, "bundle")
	for path, content := range bundle.Files {
		target := filepath.Join(bundleDir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(target, content, 0o600); err != nil {
			return nil, nil, err
		}
	}
	converted := filepath.Join(root, "converted")
	// v7 logs the telemetry identity's tenant; on a node it is the scope
	// tenant (one per scope). The challenge corpus names SecurityTenant.
	tenant := SecurityTenant
	if scenario.Facts.Telemetry != nil && len(scenario.Facts.Node.Challenges) == 0 {
		tenant = scenario.Facts.Telemetry.TenantID
	}
	if output, err := exec.CommandContext(ctx, converter, "-bundle", bundleDir, "-tenant", tenant, "-out", converted).CombinedOutput(); err != nil {
		return nil, nil, fmt.Errorf("site objects v2: %v: %s", err, output)
	}
	raw, err := os.ReadFile(filepath.Join(converted, "sites.json"))
	if err != nil {
		return nil, nil, err
	}
	var index map[string]string
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, nil, err
	}
	read := func(digest string) ([]byte, error) {
		return os.ReadFile(filepath.Join(converted, "sha256", digest[:2], digest[2:4], digest))
	}
	ids := make([]string, 0, len(index))
	for id := range index {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	sites := make([]edgesite.Site, 0, len(ids))
	referenced := map[string][]byte{}
	for _, id := range ids {
		content, err := read(index[id])
		if err != nil {
			return nil, nil, err
		}
		site, err := edgesite.Decode(content)
		if err != nil {
			return nil, nil, fmt.Errorf("site %s: %w", id, err)
		}
		if site.Cache != nil || len(site.Origin.Auth) != 0 {
			return nil, nil, ErrUnsupported{"cache or origin authentication together with security"}
		}
		for _, digest := range site.ReferencedDigests() {
			if referenced[digest], err = read(digest); err != nil {
				return nil, nil, err
			}
		}
		sites = append(sites, site)
	}
	for _, policy := range scenario.Facts.Node.Challenges {
		if err := goldenrelease.PublishChallenge(root, policy); err != nil {
			return nil, nil, fmt.Errorf("challenge %s: %w", policy.PolicyID, err)
		}
	}
	return sites, referenced, nil
}
