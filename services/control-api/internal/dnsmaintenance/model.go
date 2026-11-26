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
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
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
	// CodeProxyUnavailable: the platform http代理 (系统设置 › 其它配置) could
	// not be used, so the provider was not reached.
	CodeProxyUnavailable = "dns_proxy_unavailable"
	CodeReconcileFailed  = "dns_reconcile_failed"
	CodeReconcileTimeout = "dns_reconcile_timeout"
	CodeRecordChanged    = "dns_record_changed"
	CodeDeleteFailed     = "dns_record_delete_failed"
	// CodeCleanupPlanStale: a 清除CDN无关解析 item planned before migration 686
	// has no stored full record, so it is skipped; plan the cleanup again.
	CodeCleanupPlanStale = "dns_cleanup_plan_stale"
	// CodeNotConfigured: the platform has no DNS provider (断开 DNS 服务商
	// while the job was queued).
	CodeNotConfigured = "dns_not_configured"
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

// CleanupRecord identifies one provider record a cleanup deletes: its
// canonical owner (lower case, trailing dot), type, full value and provider
// record ID. It is stored with the plan (dns_cleanup_plan_records, migration
// 696) because the item text may truncate the value.
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

// sameRecord reports whether the provider record read back now is the planned
// one: same record ID, owner, type and full value. Owners and CNAME targets
// compare without case and trailing dot, addresses by their parsed form.
func sameRecord(planned CleanupRecord, found dnsproviderremote.ZoneRecord) bool {
	recordType := recordTypeName(found.Type)
	return found.ID == planned.RecordID && canonicalOwner(found.Name) == canonicalOwner(planned.Name) &&
		recordType == strings.ToUpper(strings.TrimSpace(planned.Type)) &&
		canonicalValue(recordType, found.Value) == canonicalValue(recordType, planned.Value)
}

func canonicalValue(recordType, value string) string {
	value = strings.TrimSpace(value)
	if recordType == "CNAME" {
		return canonicalOwner(value)
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.String()
	}
	return value
}

func truncate(line string) string {
	if utf8.RuneCountInString(line) <= maxItemRunes {
		return line
	}
	return string([]rune(line)[:maxItemRunes-1]) + "…"
}
