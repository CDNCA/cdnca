package edgepublish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/cdnca/cdnca/libs/themepack"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Dynamic routing D9: a scope's error page snapshot (the production snapshot
// errorpagecontrol builds for a tenant scope: global rules, the active
// theme's default pages, the sites' own rules) as site object error pages.
// Each site gets its effective pages (edgesite.ErrorPagesFor: v7 precedence,
// site over global), every page body becomes a referenced object
// (error_page_asset, content addressed), a theme page carries the CSP hash
// of its <style>. Node pages (no_host, unknown_site) stay out of site
// objects (they are the node skeleton's, D2).

// errorPageAssetID is the Ref identity of a page body: stable per content,
// so the same page shared by many sites or rules is one object.
var errorPageAssetNamespace = uuid.MustParse("6f1d7c62-3b0e-4f9a-9d55-2b0d8d3f9a11")

func errorPageAssetRef(digest string) edgesite.Ref {
	return edgesite.Ref{Kind: edgesite.RefErrorPageAsset, ID: uuid.NewSHA1(errorPageAssetNamespace, []byte(digest)).String(),
		Revision: 1, SHA256: digest}
}

func snapshotPageRules(rules []errorpagecontrol.ProductionSnapshotRule, referenced map[string][]byte) ([]edgesite.ErrorPageRule, error) {
	result := make([]edgesite.ErrorPageRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Category == edgesite.CategoryNoHost || rule.Category == edgesite.CategoryUnknownSite {
			continue
		}
		body := rule.Resource.Body
		digest, err := addReferencedObject(referenced, body)
		if err != nil {
			return nil, fmt.Errorf("error page rule %s: %w", rule.ID, err)
		}
		if digest != rule.Resource.SHA256 || int64(len(body)) != rule.Resource.Size {
			return nil, fmt.Errorf("error page rule %s: resource does not match its digest", rule.ID)
		}
		converted := edgesite.ErrorPageRule{ID: rule.ID, Category: rule.Category, Codes: rule.Match.Codes,
			MIMEType: rule.Resource.MIMEType, Asset: errorPageAssetRef(digest)}
		for _, span := range rule.Match.Ranges {
			converted.Ranges = append(converted.Ranges, [2]int{span.From, span.To})
		}
		if rule.Resource.MIMEType == "text/html" {
			converted.StyleHash = themepack.ThemeStyleHash(body)
		}
		result = append(result, converted)
	}
	return result, nil
}

// siteErrorPageFacts converts a scope's snapshot into each site's error
// pages (keyed by site ID) for siteObjectV2Facts. Every site of the scope
// gets the global pages, sites without own rules included. The second map
// is each site's error page variants (errpage-ovr, siteErrorPageVariants).
func siteErrorPageFacts(snapshot errorpagecontrol.ProductionSnapshotDocument, siteIDs []string,
	referenced map[string][]byte) (map[string][]edgesite.ErrorPage, map[string][]edgesite.ErrorPageVariant, error) {
	if snapshot.Schema != errorpagecontrol.ProductionSnapshotSchema {
		return nil, nil, fmt.Errorf("%w: error page snapshot schema %q", ErrInvalidInput, snapshot.Schema)
	}
	global, err := snapshotPageRules(snapshot.Global.Rules, referenced)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	own := make(map[string][]edgesite.ErrorPageRule, len(snapshot.Sites))
	for _, site := range snapshot.Sites {
		rules, err := snapshotPageRules(site.Rules, referenced)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: site %s: %v", ErrInvalidInput, site.SiteKey, err)
		}
		own[site.SiteKey] = rules
	}
	variants, err := snapshotPageVariants(snapshot.Slots, referenced)
	if err != nil {
		return nil, nil, err
	}
	result := make(map[string][]edgesite.ErrorPage, len(siteIDs))
	byVariant := make(map[string][]edgesite.ErrorPageVariant)
	for _, siteID := range siteIDs {
		pages, err := edgesite.ErrorPagesFor(global, own[siteID])
		if err != nil {
			return nil, nil, fmt.Errorf("%w: site %s error pages: %v", ErrInvalidInput, siteID, err)
		}
		result[siteID] = pages
		if len(variants) == 0 {
			continue
		}
		ownPages, err := edgesite.ErrorPagesFor(nil, own[siteID])
		if err != nil {
			return nil, nil, fmt.Errorf("%w: site %s error pages: %v", ErrInvalidInput, siteID, err)
		}
		if list := siteErrorPageVariants(variants, ownPages); len(list) > 0 {
			byVariant[siteID] = list
		}
	}
	return result, byVariant, nil
}

// snapshotPageVariants are the snapshot's region / node overrides of the
// edge_connect pages (http_502 / http_504, errpage-ovr), sorted
// (edgesite.ErrorPageVariantKey), bodies added to referenced.
func snapshotPageVariants(slots []errorpagecontrol.ProductionSnapshotSlot, referenced map[string][]byte) ([]edgesite.ErrorPageVariant, error) {
	var variants []edgesite.ErrorPageVariant
	for _, slot := range slots {
		if slot.Category != edgesite.ErrorEdgeConnect {
			continue
		}
		if slot.Region == "" && slot.NodeID == "" {
			return nil, fmt.Errorf("%w: edge_connect slot %s without a region or node", ErrInvalidInput, slot.Key)
		}
		body := slot.Resource.Body
		digest, err := addReferencedObject(referenced, body)
		if err != nil || digest != slot.Resource.SHA256 || int64(len(body)) != slot.Resource.Size {
			return nil, fmt.Errorf("%w: slot page variant %s: resource does not match its digest", ErrInvalidInput, slot.Key)
		}
		target := "region." + slot.Region
		if slot.NodeID != "" {
			target = "node." + slot.NodeID
		}
		variant := edgesite.ErrorPageVariant{Category: slot.Category, Status: slot.Status, Region: slot.Region, NodeID: slot.NodeID,
			RuleID: "slot." + slot.Key + "." + target, MIMEType: slot.Resource.MIMEType, Asset: errorPageAssetRef(digest)}
		if variant.MIMEType == "text/html" {
			variant.StyleHash = themepack.ThemeStyleHash(body)
		}
		variants = append(variants, variant)
	}
	sort.Slice(variants, func(i, j int) bool {
		return edgesite.ErrorPageVariantKey(variants[i]) < edgesite.ErrorPageVariantKey(variants[j])
	})
	for index := 1; index < len(variants); index++ {
		if edgesite.ErrorPageVariantKey(variants[index-1]) == edgesite.ErrorPageVariantKey(variants[index]) {
			return nil, fmt.Errorf("%w: slot page variant %s published twice", ErrInvalidInput, variants[index].RuleID)
		}
	}
	return variants, nil
}

// siteErrorPageVariants: the variants a site carries. A site's own rule for
// (edge_connect, status) beats the platform's overrides (site over global,
// as ErrorPagesFor), so those variants stay out.
func siteErrorPageVariants(variants []edgesite.ErrorPageVariant, ownPages []edgesite.ErrorPage) []edgesite.ErrorPageVariant {
	owned := make(map[int]bool, len(ownPages))
	for _, page := range ownPages {
		if page.Category == edgesite.ErrorEdgeConnect {
			owned[page.Status] = true
		}
	}
	var result []edgesite.ErrorPageVariant
	for _, variant := range variants {
		if !owned[variant.Status] {
			result = append(result, variant)
		}
	}
	return result
}

// nodePageFacts are the snapshot's node pages (global no_host and
// unknown_site rules, D13-b2; the slot node pages, errpage-3) for the v2
// scope, their bodies added to
// referenced. A category's rule has one status (errorpagecontrol validates
// no_host as 400 and unknown_site as one of 403/404/410/421).
func nodePageFacts(snapshot errorpagecontrol.ProductionSnapshotDocument, referenced map[string][]byte) ([]siteobject.NodePageV2, error) {
	var pages []siteobject.NodePageV2
	for _, rule := range snapshot.Global.Rules {
		if rule.Category != edgesite.CategoryNoHost && rule.Category != edgesite.CategoryUnknownSite {
			continue
		}
		status := 0
		if len(rule.Match.Codes) == 1 && len(rule.Match.Ranges) == 0 {
			status = rule.Match.Codes[0]
		} else if len(rule.Match.Codes) == 0 && len(rule.Match.Ranges) == 1 && rule.Match.Ranges[0].From == rule.Match.Ranges[0].To {
			status = rule.Match.Ranges[0].From
		} else {
			return nil, fmt.Errorf("%w: node page rule %s has more than one status", ErrInvalidInput, rule.ID)
		}
		body := rule.Resource.Body
		digest, err := addReferencedObject(referenced, body)
		if err != nil || digest != rule.Resource.SHA256 || int64(len(body)) != rule.Resource.Size {
			return nil, fmt.Errorf("%w: node page rule %s: resource does not match its digest", ErrInvalidInput, rule.ID)
		}
		page := siteobject.NodePageV2{Category: rule.Category, Status: status, MIMEType: rule.Resource.MIMEType, SHA256: digest}
		if page.MIMEType == "text/html" {
			page.StyleHash = themepack.ThemeStyleHash(body)
		}
		for _, existing := range pages {
			if existing.Category == page.Category {
				return nil, fmt.Errorf("%w: node page %s published twice", ErrInvalidInput, page.Category)
			}
		}
		pages = append(pages, page)
	}
	// errpage-3: the platform's slot node pages and region / node overrides
	// (ERROR_PAGE_SLOTS; BuildV2 refuses them without the capability).
	for _, slot := range snapshot.Slots {
		if slot.Category == edgesite.ErrorEdgeConnect {
			continue // http_502/504 overrides: site page variants (siteErrorPageFacts)
		}
		body := slot.Resource.Body
		digest, err := addReferencedObject(referenced, body)
		if err != nil || digest != slot.Resource.SHA256 || int64(len(body)) != slot.Resource.Size {
			return nil, fmt.Errorf("%w: slot node page %s: resource does not match its digest", ErrInvalidInput, slot.Key)
		}
		page := siteobject.NodePageV2{Category: slot.Category, Status: slot.Status, MIMEType: slot.Resource.MIMEType,
			SHA256: digest, Region: slot.Region, NodeID: slot.NodeID}
		if page.MIMEType == "text/html" {
			page.StyleHash = themepack.ThemeStyleHash(body)
		}
		pages = append(pages, page)
	}
	return pages, nil
}

// scopeErrorPagesNeedSlots: the scope's latest published error page
// snapshot carries slot node pages, so its dynamic routing releases need
// ERROR_PAGE_SLOTS. Only the slots field is decoded.
func scopeErrorPagesNeedSlots(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (bool, error) {
	var wire []byte
	err := tx.QueryRow(ctx, `SELECT artifact.wire_bytes FROM rollouts rollout
		JOIN configuration_artifacts artifact ON artifact.config_version_id=rollout.config_version_id
		 AND artifact.ordinal=1 AND artifact.kind='configuration' AND artifact.media_type=$2
		WHERE rollout.configuration_scope_id=$1 ORDER BY rollout.created_at DESC, rollout.id DESC LIMIT 1`,
		scopeID, errorpagecontrol.ProductionSnapshotMediaType).Scan(&wire)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: load error page snapshot", ErrPersistence)
	}
	var slots struct {
		Slots []json.RawMessage `json:"slots"`
	}
	if err := json.Unmarshal(wire, &slots); err != nil {
		return false, fmt.Errorf("%w: error page snapshot: %v", ErrInvalidInput, err)
	}
	return len(slots.Slots) > 0, nil
}
