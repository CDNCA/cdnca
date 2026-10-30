package edgepublish

import (
	"context"
	"sort"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// bindSiteRuntimeV2Schedule302 gives every site with HTTP 302 scheduling
// (site_schedule302_settings, migration 377) its settings and requires
// sched302 v1. The signing key is not in the document: it reaches the
// site's nodes only in their signed scheduling table (sched302table).
func bindSiteRuntimeV2Schedule302(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, document *siteRuntimeV2Document) error {
	if len(document.Sites) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT site_id,target,keep_path,keep_query,signature_ttl_seconds,https_to_http,
			extensions,path_prefixes,min_size_bytes
		FROM site_schedule302_settings WHERE scope_id=$1`, scopeID)
	if err != nil {
		return ErrPersistence
	}
	settings, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (struct {
		siteID uuid.UUID
		site   sched302.Site
	}, error) {
		var value struct {
			siteID uuid.UUID
			site   sched302.Site
		}
		return value, row.Scan(&value.siteID, &value.site.Target, &value.site.KeepPath, &value.site.KeepQuery,
			&value.site.SignatureTTLSeconds, &value.site.HTTPSToHTTP, &value.site.Extensions, &value.site.PathPrefixes,
			&value.site.MinSizeBytes)
	})
	if err != nil {
		return ErrPersistence
	}
	bySite := make(map[string]sched302.Site, len(settings))
	for _, value := range settings {
		bySite[value.siteID.String()] = value.site
	}
	scheduled := false
	for index := range document.Sites {
		site := &document.Sites[index]
		value, exists := bySite[site.ID]
		if !exists || !siteRuntimeV2HasPlainListener(*site) {
			// A site with only HTTPS listeners has nowhere to land (nodes have
			// no certificate for their address): the setting waits.
			continue
		}
		if value.Extensions == nil {
			value.Extensions = []string{}
		}
		if value.PathPrefixes == nil {
			value.PathPrefixes = []string{}
		}
		if err := sched302.NormalizeSite(&value); err != nil {
			return ErrInvalidInput
		}
		site.Schedule302 = &value
		scheduled = true
	}
	if scheduled {
		requireSiteRuntimeV2Capability(document, "sched302", sched302.APIVersion)
	}
	return nil
}

func siteRuntimeV2HasPlainListener(site siteRuntimeV2Site) bool {
	for _, listener := range site.Listeners {
		if listener.TLS == nil {
			return true
		}
	}
	return false
}

// requireSiteRuntimeV2Capability raises (never lowers) a required capability.
func requireSiteRuntimeV2Capability(document *siteRuntimeV2Document, name string, version uint32) {
	for index := range document.RequiredCapabilities {
		if document.RequiredCapabilities[index].Name == name {
			document.RequiredCapabilities[index].APIVersion = max(document.RequiredCapabilities[index].APIVersion, version)
			return
		}
	}
	document.RequiredCapabilities = append(document.RequiredCapabilities, siteRuntimeV2Capability{Name: name, APIVersion: version})
	sort.Slice(document.RequiredCapabilities, func(i, j int) bool {
		return document.RequiredCapabilities[i].Name < document.RequiredCapabilities[j].Name
	})
}

func validateSiteRuntimeV2Schedule302(site siteRuntimeV2Site, inferred map[string]uint32) error {
	if site.Schedule302 == nil {
		return nil
	}
	if !sched302.ValidSite(*site.Schedule302) || !siteRuntimeV2HasPlainListener(site) {
		return ErrInvalidInput
	}
	inferred["sched302"] = sched302.APIVersion
	return nil
}
