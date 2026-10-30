// Package dnsmaintenance runs 节点管理 > DNS配置 记录修复 (dns.repair.v1) and
// 清除CDN无关解析 (dns.cleanup.v1) background jobs.
//
// Background job items are fixed when the job is created and their item_id is
// the only per-item text that is stored and shown under 系统管理 > 后台任务, so
// each item is one human readable result line (like the competitor's
// "[success] 添加记录..." lines) that also identifies the work: a CNAME owner
// for a repair, one provider record for a cleanup.
package dnsmaintenance

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	RepairJobKind  = "dns.repair.v1"
	CleanupJobKind = "dns.cleanup.v1"

	repairPrefix  = "修复记录 "
	cleanupPrefix = "删除记录 "
	// NothingToRepair / NothingToClean are the single item of a job without
	// work, so the job still appears and settles under 后台任务.
	NothingToRepair = "没有需要修复的记录"
	NothingToClean  = "没有CDN无关解析"

	maxItemRunes = 256
)

var (
	ErrInvalidInput   = errors.New("invalid DNS maintenance input")
	ErrNotConfigured  = errors.New("DNS configuration is incomplete")
	ErrNoTenant       = errors.New("no tenant holds the DNS configuration")
	ErrProviderListed = errors.New("DNS provider records could not be listed")
)

// Failure codes reported on items (background_job_items.error_code).
const (
	CodeNoServingEndpoint   = "dns_no_serving_endpoint"
	CodeAllocationMissing   = "dns_allocation_missing"
	CodeProviderUnavailable = "dns_provider_unavailable"
	CodeReconcileFailed     = "dns_reconcile_failed"
	CodeReconcileTimeout    = "dns_reconcile_timeout"
	CodeRecordChanged       = "dns_record_changed"
	CodeDeleteFailed        = "dns_record_delete_failed"
)

// RepairItem formats the item of one CNAME owner: "修复记录 <owner> A <v,..>
// AAAA <v,..>" (values as planned, truncated to the item limit).
func RepairItem(owner string, a, aaaa []string) string {
	line := repairPrefix + strings.TrimSuffix(owner, ".")
	if len(a) > 0 {
		line += " A " + strings.Join(a, ",")
	}
	if len(aaaa) > 0 {
		line += " AAAA " + strings.Join(aaaa, ",")
	}
	return truncate(line)
}

// RepairOwner returns the CNAME owner of a repair item.
func RepairOwner(item string) (string, bool) {
	rest, ok := strings.CutPrefix(item, repairPrefix)
	if !ok {
		return "", false
	}
	owner, _, _ := strings.Cut(rest, " ")
	return strings.ToLower(owner), owner != ""
}

// CleanupRecord identifies one provider record a cleanup deletes.
type CleanupRecord struct {
	ZoneID   uuid.UUID
	Name     string
	Type     string
	Value    string
	RecordID string
}

// CleanupItem formats "删除记录 <name> <type> <value> #<zone>/<record id>".
// The identity suffix is kept intact when the value is truncated.
func CleanupItem(record CleanupRecord) string {
	suffix := fmt.Sprintf(" #%s/%s", record.ZoneID, record.RecordID)
	head := cleanupPrefix + strings.TrimSuffix(record.Name, ".") + " " + record.Type + " " + strings.TrimSuffix(record.Value, ".")
	budget := maxItemRunes - utf8.RuneCountInString(suffix)
	if utf8.RuneCountInString(head) > budget {
		head = string([]rune(head)[:budget-1]) + "…"
	}
	return head + suffix
}

// ParseCleanupItem returns the record a cleanup item deletes.
func ParseCleanupItem(item string) (CleanupRecord, bool) {
	rest, ok := strings.CutPrefix(item, cleanupPrefix)
	index := strings.LastIndex(rest, " #")
	if !ok || index < 0 {
		return CleanupRecord{}, false
	}
	zone, recordID, ok := strings.Cut(rest[index+2:], "/")
	zoneID, err := uuid.Parse(zone)
	fields := strings.Fields(rest[:index])
	if !ok || err != nil || recordID == "" || len(fields) < 3 {
		return CleanupRecord{}, false
	}
	return CleanupRecord{ZoneID: zoneID, Name: strings.ToLower(fields[0]) + ".", Type: fields[1],
		Value: strings.Join(fields[2:], " "), RecordID: recordID}, true
}

func truncate(line string) string {
	if utf8.RuneCountInString(line) <= maxItemRunes {
		return line
	}
	return string([]rune(line)[:maxItemRunes-1]) + "…"
}
