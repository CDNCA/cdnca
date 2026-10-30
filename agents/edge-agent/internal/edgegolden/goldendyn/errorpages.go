package goldendyn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/errorpage"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
	"github.com/google/uuid"
)

// D9: the scenario's error page policy (the node policy cdnca.error-pages/v1
// the v7 renderer publishes) as site object error pages, merged per site as
// the control plane's siteErrorPageFacts does (edgesite.ErrorPagesFor), the
// bodies as referenced objects. Inline bodies only (what the corpus uses).
type scenarioPages struct {
	global []edgesite.ErrorPageRule
	sites  map[string][]edgesite.ErrorPageRule
	assets map[string][]byte // digest -> body
}

var assetNamespace = uuid.MustParse("6f1d7c62-3b0e-4f9a-9d55-2b0d8d3f9a11")

func pageRules(rules []errorpage.Rule, assets map[string][]byte) ([]edgesite.ErrorPageRule, error) {
	result := make([]edgesite.ErrorPageRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Category == errorpage.CategoryNoHost || rule.Category == errorpage.CategoryUnknownSite {
			continue // node pages, not a site's (D2 skeleton)
		}
		if rule.Resource.Inline == nil {
			return nil, ErrUnsupported{"error page resources from files"}
		}
		body := []byte(*rule.Resource.Inline)
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])
		assets[digest] = body
		converted := edgesite.ErrorPageRule{ID: rule.ID, Category: string(rule.Category), Codes: rule.Match.Codes,
			MIMEType: rule.Resource.MIMEType, Asset: edgesite.Ref{Kind: edgesite.RefErrorPageAsset,
				ID: uuid.NewSHA1(assetNamespace, []byte(digest)).String(), Revision: 1, SHA256: digest}}
		for _, span := range rule.Match.Ranges {
			converted.Ranges = append(converted.Ranges, [2]int{span.From, span.To})
		}
		result = append(result, converted)
	}
	return result, nil
}

func errorPages(scenario *edgegolden.Scenario) (*scenarioPages, error) {
	if len(scenario.Facts.Node.ErrorPages) == 0 {
		return nil, nil
	}
	var policy errorpage.Policy
	if err := json.Unmarshal(scenario.Facts.Node.ErrorPages, &policy); err != nil {
		return nil, fmt.Errorf("error pages: %w", err)
	}
	pages := &scenarioPages{sites: map[string][]edgesite.ErrorPageRule{}, assets: map[string][]byte{}}
	var err error
	if pages.global, err = pageRules(policy.Global.Rules, pages.assets); err != nil {
		return nil, err
	}
	for _, site := range policy.Sites {
		if pages.sites[site.SiteKey], err = pageRules(site.Rules, pages.assets); err != nil {
			return nil, err
		}
	}
	return pages, nil
}

// withErrorPages gives every site its effective error pages from the
// scenario's node policy and adds their bodies to the referenced objects
// (where the agent puts every site object reference).
func withErrorPages(scenario *edgegolden.Scenario, sites []edgesite.Site, referenced map[string][]byte) ([]edgesite.Site, map[string][]byte, error) {
	pages, err := errorPages(scenario)
	if err != nil || pages == nil {
		return sites, referenced, err
	}
	if referenced == nil {
		referenced = map[string][]byte{}
	}
	for digest, body := range pages.assets {
		referenced[digest] = body
	}
	for index := range sites {
		if sites[index].Errors, err = edgesite.ErrorPagesFor(pages.global, pages.sites[sites[index].SiteID]); err != nil {
			return nil, nil, fmt.Errorf("site %s error pages: %w", sites[index].SiteID, err)
		}
		if err := edgesite.Validate(sites[index]); err != nil {
			return nil, nil, fmt.Errorf("site %s: %w", sites[index].SiteID, err)
		}
	}
	return sites, referenced, nil
}

// unknownSitePage is the node's domain mismatch page (the global
// unknown_site rule, one status) written under root for the skeleton; nil
// when the scenario publishes none (the node answers 421).
func unknownSitePage(scenario *edgegolden.Scenario, root string) (*edgeskeleton.NodePage, error) {
	if len(scenario.Facts.Node.ErrorPages) == 0 {
		return nil, nil
	}
	var policy errorpage.Policy
	if err := json.Unmarshal(scenario.Facts.Node.ErrorPages, &policy); err != nil {
		return nil, fmt.Errorf("error pages: %w", err)
	}
	for _, rule := range policy.Global.Rules {
		if rule.Category != errorpage.CategoryUnknownSite {
			continue
		}
		if rule.Resource.Inline == nil || len(rule.Match.Codes) != 1 || len(rule.Match.Ranges) != 0 {
			return nil, ErrUnsupported{"unknown_site page from a file or with more than one status"}
		}
		path := filepath.Join(root, "unknown-site-page")
		if err := os.WriteFile(path, []byte(*rule.Resource.Inline), 0o644); err != nil {
			return nil, err
		}
		return &edgeskeleton.NodePage{Status: rule.Match.Codes[0], MIMEType: rule.Resource.MIMEType, BodyFile: path}, nil
	}
	return nil, nil
}
