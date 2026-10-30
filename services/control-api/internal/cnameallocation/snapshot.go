package cnameallocation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

// ProviderSnapshotSource lists the A/AAAA/CNAME records a CNAME owner holds
// at its zone's DNS provider now. With it, a publication plans deletes and
// replacements for values that are no longer served (a paused node, a standby
// IP back offline); without it the plan can only create missing values.
type ProviderSnapshotSource interface {
	OwnerRecords(ctx context.Context, tenantID, siteID, zoneID uuid.UUID, owner string) ([]dnscheck.ProviderRecord, error)
}

// withProviderSnapshot fills check.Provider.Records from the provider and
// returns the idempotency key bound to that snapshot (a later attempt that
// sees other records is a different reconcile request).
func (worker *Worker) withProviderSnapshot(ctx context.Context, check dnscheck.CheckRequest, key string,
	tenantID, siteID, zoneID uuid.UUID) (dnscheck.CheckRequest, string, error) {
	source := worker.dependencies.Snapshots
	if source == nil {
		return check, key, nil
	}
	records, err := source.OwnerRecords(ctx, tenantID, siteID, zoneID, check.Name)
	if err != nil {
		return check, key, err
	}
	owner := strings.ToLower(strings.TrimSuffix(check.Name, ".")) + "."
	kept := make([]dnscheck.ProviderRecord, 0, len(records))
	for _, record := range records {
		if strings.ToLower(strings.TrimSuffix(record.Name, "."))+"." != owner ||
			record.Type != dnscheck.RecordA && record.Type != dnscheck.RecordAAAA && record.Type != dnscheck.RecordCNAME {
			continue
		}
		record.Name = owner
		// Records on other lines are not this request's: the aggregated
		// edge writes the site CNAME per line (ADR 0008 §6.1).
		if !SameLine(record.Line, check.Line) {
			continue
		}
		// The provider's default line is the request's default line.
		if defaultLine(record.Line) && defaultLine(check.Line) {
			record.Line = check.Line
		}
		kept = append(kept, record)
	}
	if len(kept) == 0 {
		return check, key, nil
	}
	sort.Slice(kept, func(left, right int) bool { return kept[left].RecordID < kept[right].RecordID })
	check.Provider.Records = kept
	payload, _ := json.Marshal(kept)
	digest := sha256.Sum256(append([]byte(key+"\x00"), payload...))
	prefix, _, _ := strings.Cut(key, "-")
	return check, prefix + "-s" + hex.EncodeToString(digest[:24]), nil
}

func defaultLine(line string) bool {
	return line == "" || line == "默认" || line == "default"
}

// SameLine compares a provider record's line with a request line; every
// spelling of the default line is the same line.
func SameLine(left, right string) bool {
	return left == right || defaultLine(left) && defaultLine(right)
}
