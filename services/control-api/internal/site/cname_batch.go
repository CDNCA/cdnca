package site

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/google/uuid"
)

const BatchActionRegenerateCNAME = "regenerate_cname"

func batchCNAMERegenerationFields(current Site) (SiteFields, string) {
	if current.CNAMEMode == nil ||
		current.CNAMEDomain == nil || current.CNAMEHostname == nil || current.CNAMEState == nil {
		return SiteFields{}, "cname_not_configured"
	}
	if *current.CNAMEState != "failed" {
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

func cnameBatchIntentKey(batchKey string, siteID uuid.UUID) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("cdnca.site.cname-batch-intent/v1\x00"))
	_, _ = digest.Write([]byte(batchKey))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(siteID[:])
	return hex.EncodeToString(digest.Sum(nil))
}
