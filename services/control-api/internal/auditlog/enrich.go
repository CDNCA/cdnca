package auditlog

import (
	"context"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/observabilitylog"
	"github.com/google/uuid"
)

var countryCode = regexp.MustCompile(`^[A-Z]{2}$`)

// attachRegions replaces each row's stored geo with the IP library's answer
// for its source IP (B6 semantics: unloaded / no answer keeps the stored
// value; answers with a bad country code or control characters are ignored).
func (store *Store) attachRegions(ctx context.Context, rows []audit.RenderInput) {
	for index := range rows {
		if !countryCode.MatchString(rows[index].GeoCode) {
			rows[index].GeoCode, rows[index].GeoRegion, rows[index].GeoCity = "", "", ""
		}
	}
	if store.ipIntel == nil {
		return
	}
	addresses := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.SourceIP != "" && row.SourceIP != "unknown" {
			addresses = append(addresses, row.SourceIP)
		}
	}
	if len(addresses) == 0 {
		return
	}
	answers := store.ipIntel.Lookup(ctx, addresses)
	for index := range rows {
		info := answers[rows[index].SourceIP]
		if info == nil || !countryCode.MatchString(info.Country) || !plainText(info.ProvinceName, 128) || !plainText(info.CityName, 128) {
			continue
		}
		rows[index].GeoCode, rows[index].GeoRegion, rows[index].GeoCity = info.Country, info.ProvinceName, info.CityName
	}
}

// attachNames resolves object names with the B6b lookup, one query per scope
// on the page, and only inside the row's own scope: a row that references
// another tenant's object shows it as deleted, never that tenant's name. A
// lookup failure leaves the scope's rows showing resource_id. A platform-scope
// row keeps its platform-wide name (selectSQL) when the scoped lookup misses.
func (store *Store) attachNames(ctx context.Context, rows []audit.RenderInput) {
	if store.names == nil {
		return
	}
	byScope := map[uuid.UUID][]observabilitylog.ResourceRef{}
	seen := map[uuid.UUID]map[observabilitylog.ResourceRef]bool{}
	for _, row := range rows {
		ref, ok := nameRef(row)
		if !ok {
			continue
		}
		if seen[row.ScopeID] == nil {
			seen[row.ScopeID] = map[observabilitylog.ResourceRef]bool{}
		}
		if !seen[row.ScopeID][ref] {
			seen[row.ScopeID][ref] = true
			byScope[row.ScopeID] = append(byScope[row.ScopeID], ref)
		}
	}
	for scopeID, refs := range byScope {
		names, err := store.names.ResourceNames(ctx, scopeID, refs)
		if err != nil {
			continue
		}
		for index := range rows {
			ref, ok := nameRef(rows[index])
			if !ok || rows[index].ScopeID != scopeID {
				continue
			}
			switch name := names[ref]; {
			case name != "" && plainText(name, 256):
				rows[index].ResourceName = name
			case name == "" && rows[index].ResourceName == "":
				rows[index].ResourceDeleted = true
			}
		}
	}
}

func nameRef(row audit.RenderInput) (observabilitylog.ResourceRef, bool) {
	if !observabilitylog.Nameable(row.ResourceType) {
		return observabilitylog.ResourceRef{}, false
	}
	id, err := uuid.Parse(row.ResourceID)
	if err != nil || id == uuid.Nil {
		return observabilitylog.ResourceRef{}, false
	}
	return observabilitylog.ResourceRef{Type: row.ResourceType, ID: id}, true
}

func plainText(value string, maxBytes int) bool {
	return len(value) <= maxBytes && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}
