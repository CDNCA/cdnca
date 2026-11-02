package site

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/google/uuid"
)

const BatchActionRegenerateCNAME = "regenerate_cname"

func batchCNAMERegenerationFields(current Site) (SiteFields, string) {
	if current.CNAMEMode == nil ||
		current.CNAMEDomain == nil || current.CNAMEHostname == nil || current.CNAMEState == nil {
		return SiteFields{}, "cname_not_configured"
	}
	if !cnameRegenerable(*current.CNAMEState) {
		return SiteFields{}, "cname_not_failed"
	}
	fields := SiteFields{
		CNAMEMode:       *current.CNAMEMode,
		CNAMEDomain:     *current.CNAMEDomain,
		CNAMEHostname:   *current.CNAMEHostname,
		CNAMERegenerate: true,
	}
	if current.PackageSubscriptionID != nil {
		subscriptionID := *current.PackageSubscriptionID
		fields.PackageSubscriptionID = &subscriptionID
	}
	if current.PackageID != nil {
		packageID := *current.PackageID
		fields.PackageID = &packageID
	}
	return fields, ""
}

// cnameRegenerable: a failed CNAME, or one stuck "pending" (the
// intent or allocation job never settles, e.g. no worker, a provider that keeps
// answering unavailable). A new intent moves sites.cname_task_id to itself, so
// the old intent settles intent_superseded (412) the same way a site edit does.
func cnameRegenerable(state string) bool {
	return state == "failed" || state == "pending"
}

// Pending CNAME codes: why a site's CNAME is still "pending".
// The worker only records a code when it fails the job, so while it retries a
// provider that keeps answering "unavailable" (or no worker runs at all) the
// list showed 生成中 with no reason for hours. These are derived from the
// site's current CNAME job (sites.cname_task_id) at read time.
const (
	CNAMEPendingJobMissing = "cname_job_missing" // the job row does not exist
	CNAMEPendingJobEnded   = "cname_job_ended"   // the job ended, the site was not settled
	CNAMEPendingWorkerIdle = "cname_worker_idle" // queued 5+ minutes, never claimed
	CNAMEPendingStalled    = "cname_stalled"     // claimed, unsettled for 15+ minutes
)

// cnamePendingCodeColumn: NULL unless the site's CNAME is pending and its job
// shows one of the codes above.
func cnamePendingCodeColumn(alias string) string {
	return strings.NewReplacer("{s}", alias).Replace(`(SELECT CASE
		WHEN pending_job.id IS NULL THEN '` + CNAMEPendingJobMissing + `'
		WHEN pending_job.state IN ('succeeded','failed','partial_failed','cancelled') THEN '` + CNAMEPendingJobEnded + `'
		WHEN pending_job.state='queued' AND pending_job.attempt=0
		  AND pending_job.created_at < clock_timestamp() - interval '5 minutes' THEN '` + CNAMEPendingWorkerIdle + `'
		WHEN pending_job.created_at < clock_timestamp() - interval '15 minutes' THEN '` + CNAMEPendingStalled + `'
		END
		FROM access_scopes pending_scope
		LEFT JOIN background_jobs pending_job ON pending_job.tenant_id = pending_scope.tenant_id AND pending_job.id = {s}.cname_task_id
		WHERE {s}.cname_state = 'pending' AND {s}.cname_task_id IS NOT NULL AND pending_scope.id = {s}.scope_id)`)
}

func cnameBatchIntentKey(batchKey string, siteID uuid.UUID) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("cdnca.site.cname-batch-intent/v1\x00"))
	_, _ = digest.Write([]byte(batchKey))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(siteID[:])
	return hex.EncodeToString(digest.Sum(nil))
}
