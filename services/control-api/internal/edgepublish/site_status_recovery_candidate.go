package edgepublish

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const siteStatusRecoveryCandidateQuery = `
	SELECT scope.tenant_id,job.tenant_id,job.id,job.state,job.subject,
	       item.item_id,item.state,site.id,site.revision,site.status
	FROM sites site
	JOIN access_scopes scope ON scope.id=site.scope_id
	JOIN background_jobs job ON scope.tenant_id=job.tenant_id
	  AND job.kind='site.status_recovery' AND job.state IN ('queued','running')
	JOIN background_job_items item ON item.tenant_id=job.tenant_id AND item.job_id=job.id
	  AND item.item_id=site.id::text AND item.state='pending'
	WHERE site.scope_id=$1 AND site.deleted_at IS NULL AND site.enabled=true
	  AND site.status IN ('package_expired','traffic_exceeded')
	ORDER BY site.id,job.created_at,job.id
	FOR SHARE OF scope,job,item,site`

type siteStatusRecoveryCandidate struct {
	tenantID           uuid.UUID
	jobID              uuid.UUID
	siteID             uuid.UUID
	trigger            string
	siteRevision       int64
	edgeSourceRevision int64
}

func siteStatusRecoveryCandidateIDs(candidates map[uuid.UUID]siteStatusRecoveryCandidate) []uuid.UUID {
	result := make([]uuid.UUID, 0, len(candidates))
	for siteID := range candidates {
		result = append(result, siteID)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].String() < result[right].String()
	})
	return result
}

func optionalSiteStatusRecoveryCandidateIDs(values [][]uuid.UUID) []uuid.UUID {
	if len(values) == 0 {
		return nil
	}
	return values[0]
}

type siteStatusRecoveryCandidateRow struct {
	scopeTenantID uuid.UUID
	jobTenantID   uuid.UUID
	jobID         uuid.UUID
	jobState      string
	subject       string
	itemID        string
	itemState     string
	siteID        uuid.UUID
	siteRevision  int64
	siteStatus    string
}

func loadSiteStatusRecoveryCandidates(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	edgeSourceRevision int64,
) (map[uuid.UUID]siteStatusRecoveryCandidate, error) {
	if ctx == nil || tx == nil || scopeID == uuid.Nil || edgeSourceRevision < 1 {
		return nil, ErrInvalidInput
	}
	rows, err := tx.Query(ctx, siteStatusRecoveryCandidateQuery, scopeID)
	if err != nil {
		return nil, fmt.Errorf("%w: read site status recovery candidates", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]siteStatusRecoveryCandidate)
	for rows.Next() {
		var row siteStatusRecoveryCandidateRow
		if err := rows.Scan(
			&row.scopeTenantID, &row.jobTenantID, &row.jobID, &row.jobState, &row.subject,
			&row.itemID, &row.itemState, &row.siteID, &row.siteRevision, &row.siteStatus,
		); err != nil {
			return nil, fmt.Errorf("%w: scan site status recovery candidate", ErrPersistence)
		}
		candidate, eligible := validateSiteStatusRecoveryCandidate(row, edgeSourceRevision)
		if !eligible {
			continue
		}
		if _, duplicate := result[candidate.siteID]; duplicate {
			return nil, fmt.Errorf("%w: ambiguous site status recovery candidate", ErrPersistence)
		}
		result[candidate.siteID] = candidate
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate site status recovery candidates", ErrPersistence)
	}
	return result, nil
}

func validateSiteStatusRecoveryCandidate(
	row siteStatusRecoveryCandidateRow,
	edgeSourceRevision int64,
) (siteStatusRecoveryCandidate, bool) {
	if row.scopeTenantID == uuid.Nil || row.scopeTenantID != row.jobTenantID || row.jobID == uuid.Nil ||
		(row.jobState != "queued" && row.jobState != "running") || row.itemState != "pending" ||
		row.siteID == uuid.Nil || row.itemID != row.siteID.String() || row.siteRevision < 1 || edgeSourceRevision < 1 {
		return siteStatusRecoveryCandidate{}, false
	}
	siteID, trigger, siteRevision, requestedEdgeRevision, ok := parseSiteStatusRecoveryCandidateSubject(row.subject)
	if !ok || siteID != row.siteID || siteRevision != row.siteRevision || requestedEdgeRevision != edgeSourceRevision ||
		trigger == "renewal" && row.siteStatus != "package_expired" ||
		trigger == "traffic_top_up" && row.siteStatus != "traffic_exceeded" ||
		trigger != "renewal" && trigger != "traffic_top_up" {
		return siteStatusRecoveryCandidate{}, false
	}
	return siteStatusRecoveryCandidate{
		tenantID: row.jobTenantID, jobID: row.jobID, siteID: row.siteID, trigger: trigger,
		siteRevision: siteRevision, edgeSourceRevision: requestedEdgeRevision,
	}, true
}

func parseSiteStatusRecoveryCandidateSubject(subject string) (uuid.UUID, string, int64, int64, bool) {
	parts := strings.Split(subject, "/")
	if len(parts) != 6 || parts[0] != "site" || parts[1] != "status-recovery" {
		return uuid.Nil, "", 0, 0, false
	}
	siteID, err := uuid.Parse(parts[2])
	if err != nil || siteID == uuid.Nil || siteID.String() != parts[2] {
		return uuid.Nil, "", 0, 0, false
	}
	if parts[3] != "renewal" && parts[3] != "traffic_top_up" && parts[3] != "unlock" {
		return uuid.Nil, "", 0, 0, false
	}
	siteRevision, err := parseCanonicalPositiveInt64(parts[4])
	if err != nil {
		return uuid.Nil, "", 0, 0, false
	}
	edgeRevision, err := parseCanonicalPositiveInt64(parts[5])
	if err != nil {
		return uuid.Nil, "", 0, 0, false
	}
	return siteID, parts[3], siteRevision, edgeRevision, true
}

func parseCanonicalPositiveInt64(value string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 1 || strconv.FormatInt(parsed, 10) != value {
		return 0, ErrInvalidInput
	}
	return parsed, nil
}
