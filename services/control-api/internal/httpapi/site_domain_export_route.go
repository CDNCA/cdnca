package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const maxSiteDomainExportRows = 1_000_000

type siteDomainExportRequest struct {
	TargetScopeID uuid.UUID
	Filter        site.ListFilter
	FilterSHA256  [sha256.Size]byte
}

func (s *Server) handleExportSiteDomains(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.export")
	if !ok {
		return
	}
	request, err := parseSiteDomainExportRequest(r, principal)
	if err != nil {
		s.writeSiteError(w, r, err)
		return
	}
	snapshot, rows, err := s.captureSiteDomainExport(r.Context(), principal, request)
	if err != nil {
		s.writeSiteError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", siteDomainCSVContentType)
	w.Header().Set("Content-Disposition", `attachment; filename="site-domains.csv"`)
	w.Header().Set("X-Site-Domain-Export-Snapshot-ID", snapshot.ID.String())
	if err := writeSiteDomainExportCSV(w, rows); err != nil {
		s.logger.Error("write site domain export", "error", err, "snapshot_id", snapshot.ID)
	}
}

func parseSiteDomainExportRequest(r *http.Request, principal identity.Principal) (siteDomainExportRequest, error) {
	query := r.URL.Query()
	allowed := map[string]bool{
		"target_scope_id": true, "domain": true, "domains": true, "origin_ip": true,
		"site_ids": true, "owner": true, "package_id": true, "group_id": true,
		"region_id": true, "node_group_id": true, "cname_domain": true,
		"cname_hostname": true, "http_port": true, "https_port": true,
		"https_enabled": true, "enabled": true, "status": true, "is_default": true,
		"sync_status": true,
	}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 {
			return siteDomainExportRequest{}, site.ErrInvalidInput
		}
	}

	targetScopeID := principal.ScopeID
	rawTargetScopeID := strings.TrimSpace(query.Get("target_scope_id"))
	switch principal.ScopeKind {
	case "tenant":
		if rawTargetScopeID != "" {
			requested, err := uuid.Parse(rawTargetScopeID)
			if err != nil {
				return siteDomainExportRequest{}, site.ErrInvalidInput
			}
			if requested != principal.ScopeID {
				return siteDomainExportRequest{}, site.ErrPermissionDenied
			}
		}
	case "platform":
		requested, err := uuid.Parse(rawTargetScopeID)
		if err != nil || requested == uuid.Nil {
			return siteDomainExportRequest{}, site.ErrInvalidInput
		}
		targetScopeID = requested
	default:
		return siteDomainExportRequest{}, site.ErrPermissionDenied
	}

	filterRequest := r.Clone(r.Context())
	filterURL := *r.URL
	filterQuery := filterURL.Query()
	filterQuery.Del("target_scope_id")
	filterURL.RawQuery = filterQuery.Encode()
	filterRequest.URL = &filterURL
	filter, err := parseSiteListFilter(filterRequest)
	if err != nil {
		return siteDomainExportRequest{}, site.ErrInvalidInput
	}
	filter.Page = 1
	filter.Limit = 100
	filter, err = site.NormalizeListFilter(siteActor(principal), filter)
	if err != nil {
		return siteDomainExportRequest{}, err
	}
	encodedFilter, err := json.Marshal(filter)
	if err != nil || !utf8.Valid(encodedFilter) {
		return siteDomainExportRequest{}, site.ErrInvalidInput
	}
	filterSHA256 := sha256.Sum256([]byte("cdnca/site-domain-export-filter/v2\x00" + targetScopeID.String() + "\x00" + string(encodedFilter)))
	return siteDomainExportRequest{TargetScopeID: targetScopeID, Filter: filter, FilterSHA256: filterSHA256}, nil
}

func siteDomainExportWhere(targetScopeID uuid.UUID, filter site.ListFilter) (string, []any) {
	conditions := []string{"site.scope_id = $1", "site.deleted_at IS NULL", "latest.action = 'activate'"}
	args := []any{targetScopeID}
	add := func(format string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(format, len(args)))
	}
	if filter.Domain != "" {
		add("position($%d in lower(site.domain)) > 0", filter.Domain)
	}
	if len(filter.Domains) > 0 {
		add("site.domain = ANY($%d::text[])", filter.Domains)
	}
	if filter.OriginIP != "" {
		add("$%d = ANY(site.origin_hosts)", filter.OriginIP)
	}
	if len(filter.SiteIDs) > 0 {
		add("site.id = ANY($%d::uuid[])", filter.SiteIDs)
	}
	if filter.Owner != "" {
		args = append(args, strings.ToLower(filter.Owner))
		position := len(args)
		conditions = append(conditions, fmt.Sprintf(
			"(lower(site_owner.display_name) LIKE '%%' || $%d || '%%' OR lower(site_owner.username) LIKE '%%' || $%d || '%%' OR site_owner.id::text = $%d)",
			position, position, position,
		))
	}
	for _, item := range []struct {
		format string
		value  *uuid.UUID
	}{
		{"site.package_id = $%d", filter.PackageID},
		{"site.group_id = $%d", filter.GroupID},
		{"site.region_id = $%d", filter.RegionID},
		{"site.node_group_id = $%d", filter.NodeGroupID},
	} {
		if item.value != nil {
			add(item.format, *item.value)
		}
	}
	if filter.CNAMEDomain != "" {
		add("position($%d in lower(site.cname)) > 0", filter.CNAMEDomain)
	}
	if filter.CNAMEHostname != "" {
		add("split_part(lower(site.cname), '.', 1) = $%d", filter.CNAMEHostname)
	}
	if filter.HTTPPort != "" {
		add("$%d = ANY(site.http_ports)", filter.HTTPPort)
	}
	if filter.HTTPSPort != "" {
		add("$%d = ANY(site.https_ports)", filter.HTTPSPort)
	}
	for _, item := range []struct {
		format string
		value  *bool
	}{
		{"site.https_enabled = $%d", filter.HTTPSEnabled},
		{"site.enabled = $%d", filter.Enabled},
		{"site.is_default = $%d", filter.IsDefault},
	} {
		if item.value != nil {
			add(item.format, *item.value)
		}
	}
	if filter.Status == site.StatusLocked {
		conditions = append(conditions, "site.locked_at IS NOT NULL")
	} else if filter.Status != "" {
		add("site.status = $%d", filter.Status)
	}
	if filter.SyncStatus != "" {
		add("site_sync_status_503(site.scope_id, site.id) = $%d", filter.SyncStatus)
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (s *Server) captureSiteDomainExport(
	ctx context.Context,
	principal identity.Principal,
	request siteDomainExportRequest,
) (SiteDomainExportSnapshot, []siteDomainExportRow, error) {
	if s.pool == nil {
		return SiteDomainExportSnapshot{}, nil, errors.New("site domain export database is unavailable")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return SiteDomainExportSnapshot{}, nil, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var scopeKind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM access_scopes WHERE id=$1`, request.TargetScopeID).Scan(&scopeKind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SiteDomainExportSnapshot{}, nil, site.ErrPermissionDenied
		}
		return SiteDomainExportSnapshot{}, nil, err
	}
	if scopeKind != "tenant" || (principal.ScopeKind == "tenant" && principal.ScopeID != request.TargetScopeID) {
		return SiteDomainExportSnapshot{}, nil, site.ErrPermissionDenied
	}

	where, args := siteDomainExportWhere(request.TargetScopeID, request.Filter)
	limitPosition := len(args) + 1
	args = append(args, maxSiteDomainExportRows+1)
	rows, err := tx.Query(ctx, `WITH latest AS (
		SELECT DISTINCT ON (site_id,canonical_domain)
			site_id,canonical_domain,action
		FROM site_domain_facts
		WHERE scope_id=$1
		ORDER BY site_id,canonical_domain,global_sequence DESC
	)
	SELECT site.id,latest.canonical_domain,site.revision,site.enabled
	FROM latest
	JOIN sites site ON site.id=latest.site_id
	JOIN users site_owner ON site_owner.id=site.owner_user_id
	`+where+`
	ORDER BY latest.canonical_domain,site.id
	LIMIT $`+fmt.Sprint(limitPosition), args...)
	if err != nil {
		return SiteDomainExportSnapshot{}, nil, err
	}
	exportRows := make([]siteDomainExportRow, 0)
	for rows.Next() {
		var row siteDomainExportRow
		if err := rows.Scan(&row.SiteID, &row.Domain, &row.Revision, &row.Enabled); err != nil {
			rows.Close()
			return SiteDomainExportSnapshot{}, nil, err
		}
		exportRows = append(exportRows, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return SiteDomainExportSnapshot{}, nil, err
	}
	rows.Close()
	if len(exportRows) > maxSiteDomainExportRows {
		return SiteDomainExportSnapshot{}, nil, site.ErrInvalidInput
	}

	snapshotID, err := uuid.NewV7()
	if err != nil {
		return SiteDomainExportSnapshot{}, nil, err
	}
	var createdAt time.Time
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&createdAt); err != nil {
		return SiteDomainExportSnapshot{}, nil, err
	}
	snapshot := SiteDomainExportSnapshot{
		ID: snapshotID, ActorUserID: principal.UserID, ActorScopeID: principal.ScopeID,
		TargetScopeID: request.TargetScopeID, FilterSHA256: request.FilterSHA256,
	}
	if _, err := tx.Exec(ctx, `INSERT INTO site_domain_export_snapshots(
		id,actor_user_id,actor_scope_id,target_scope_id,filter_sha256,row_count,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, snapshot.ID, snapshot.ActorUserID, snapshot.ActorScopeID,
		snapshot.TargetScopeID, snapshot.FilterSHA256[:], len(exportRows), createdAt, createdAt.Add(24*time.Hour)); err != nil {
		return SiteDomainExportSnapshot{}, nil, err
	}
	copyRows := make([][]any, len(exportRows))
	for index, row := range exportRows {
		copyRows[index] = []any{snapshot.ID, index + 1, row.SiteID, row.Domain, row.Revision, row.Enabled, createdAt}
	}
	if len(copyRows) != 0 {
		copied, err := tx.CopyFrom(ctx, pgx.Identifier{"site_domain_export_rows"},
			[]string{"snapshot_id", "row_sequence", "site_id", "canonical_domain", "site_revision", "enabled", "created_at"},
			pgx.CopyFromRows(copyRows))
		if err != nil {
			return SiteDomainExportSnapshot{}, nil, err
		}
		if copied != int64(len(exportRows)) {
			return SiteDomainExportSnapshot{}, nil, errors.New("site domain export snapshot is incomplete")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return SiteDomainExportSnapshot{}, nil, err
	}
	return snapshot, exportRows, nil
}
