package edgesite

import (
	"fmt"
	"sort"
)

// ErrorPageRule is one error page rule as the error page policy publishes
// it (errorpagecontrol production snapshot, cdnca.error-pages/v1): a
// category, the statuses it covers (single codes and ranges) and the page.
type ErrorPageRule struct {
	ID        string
	Category  string
	Codes     []int
	Ranges    [][2]int
	MIMEType  string
	StyleHash string
	Asset     Ref
}

// ErrorPagesFor is the site's effective error page list (Site.Errors) from
// the policy's global rules and the site's own rules, with the precedence of
// the v7 runtime (agents/edge-agent/internal/errorpage Compile/Lookup):
//
//   - per scope, a status matched by a single code beats one matched by a
//     range, and a narrower range beats a wider one; two rules of one scope
//     with equal precedence for the same (category, status) are refused;
//   - a site rule for (category, status) replaces the global one;
//   - categories no_host / unknown_site are node pages (global only), not
//     site pages, and are not accepted here.
func ErrorPagesFor(global, site []ErrorPageRule) ([]ErrorPage, error) {
	// Node pages (no Host, unknown site) are the node's, not a site's. v7
	// also counted their statuses (400, 404) into every site's intercepted
	// set, which replaced every origin 400/404 with the built-in text page as
	// soon as a theme published node pages; site objects do not repeat that
	// (tests/edge-golden/cdnca-v7/compare.json, dynroute-filters.md §6).
	siteGlobal := make([]ErrorPageRule, 0, len(global))
	for _, rule := range global {
		if rule.Category != CategoryNoHost && rule.Category != CategoryUnknownSite {
			siteGlobal = append(siteGlobal, rule)
		}
	}
	globalPages, err := scopePages(siteGlobal)
	if err != nil {
		return nil, fmt.Errorf("global: %w", err)
	}
	sitePages, err := scopePages(site)
	if err != nil {
		return nil, fmt.Errorf("site: %w", err)
	}
	for key, page := range sitePages {
		globalPages[key] = page
	}
	result := make([]ErrorPage, 0, len(globalPages))
	for _, page := range globalPages {
		result = append(result, page.page)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Category != result[j].Category {
			return result[i].Category < result[j].Category
		}
		return result[i].Status < result[j].Status
	})
	if len(result) > MaxErrorPages {
		return nil, fmt.Errorf("%w: %d error pages exceed %d", ErrInvalid, len(result), MaxErrorPages)
	}
	return result, validateErrorPages(result)
}

type pageKey struct {
	category string
	status   int
}

type scopedPage struct {
	page        ErrorPage
	ruleID      string
	specificity int // 1 = single code, else the range width
}

func scopePages(rules []ErrorPageRule) (map[pageKey]scopedPage, error) {
	selected := make(map[pageKey]scopedPage)
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if seen[rule.ID] {
			return nil, fmt.Errorf("%w: error page rule %q twice", ErrInvalid, rule.ID)
		}
		seen[rule.ID] = true
		if len(rule.Codes) == 0 && len(rule.Ranges) == 0 {
			return nil, fmt.Errorf("%w: error page rule %q has no status", ErrInvalid, rule.ID)
		}
		matches := make(map[int]int)
		for _, code := range rule.Codes {
			if !ErrorCategoryAllows(rule.Category, code) {
				return nil, fmt.Errorf("%w: error page rule %q: status %d in %q", ErrInvalid, rule.ID, code, rule.Category)
			}
			matches[code] = 1
		}
		for _, span := range rule.Ranges {
			if span[0] > span[1] || !ErrorCategoryAllows(rule.Category, span[0]) || !ErrorCategoryAllows(rule.Category, span[1]) {
				return nil, fmt.Errorf("%w: error page rule %q: range %d-%d in %q", ErrInvalid, rule.ID, span[0], span[1], rule.Category)
			}
			width := span[1] - span[0] + 1
			for status := span[0]; status <= span[1]; status++ {
				if previous, exists := matches[status]; !exists || width < previous {
					matches[status] = width
				}
			}
		}
		for status, specificity := range matches {
			key := pageKey{rule.Category, status}
			previous, exists := selected[key]
			if exists && previous.ruleID != rule.ID && previous.specificity == specificity {
				return nil, fmt.Errorf("%w: error page rules %q and %q have equal precedence for %s %d",
					ErrInvalid, previous.ruleID, rule.ID, rule.Category, status)
			}
			if !exists || specificity < previous.specificity {
				selected[key] = scopedPage{ruleID: rule.ID, specificity: specificity, page: ErrorPage{
					Category: rule.Category, Status: status, RuleID: rule.ID, MIMEType: rule.MIMEType,
					StyleHash: rule.StyleHash, Asset: rule.Asset,
				}}
			}
		}
	}
	return selected, nil
}
