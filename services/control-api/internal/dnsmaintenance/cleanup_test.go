package dnsmaintenance

import (
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
)

// planCleanup runs 清除CDN无关解析 planning and stores its records the way
// dnssettings does (dns_cleanup_plan_records).
func (fixture *maintenanceFixture) planCleanup(t *testing.T) []string {
	t.Helper()
	planner, err := NewPlanner(fixture.targets, fixture.platform, fixture.provider)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := planner.PlanCleanup(t.Context())
	if err != nil || len(jobs) != 1 {
		t.Fatalf("PlanCleanup() = %+v, %v", jobs, err)
	}
	for _, item := range jobs[0].Items {
		if _, ok := jobs[0].Records[item]; !ok {
			t.Fatalf("item %q has no planned record", item)
		}
		fixture.targets.plans[item] = jobs[0].Records[item]
	}
	return jobs[0].Items
}

func codesByRecord(reports []jobstate.Report) map[string]string {
	codes := map[string]string{}
	for _, report := range reports {
		codes[report.ItemID[strings.LastIndex(report.ItemID, "/")+1:]] = report.Code
	}
	return codes
}

// the provider changes a planned record under the
// same ID before the job runs (value, type or owner). The record is kept and
// reported changed; an unchanged record is still deleted.
func TestCleanupKeepsRecordsChangedUnderTheSameID(t *testing.T) {
	fixture := newMaintenanceFixture(t,
		zoneRecord("value", "old.cdn.example.com.", dnscheck.RecordA, "198.51.100.7", 600),
		zoneRecord("target", "www.cdn.example.com.", dnscheck.RecordCNAME, "elsewhere.example.net.", 600),
		zoneRecord("type", "typ.cdn.example.com.", dnscheck.RecordA, "198.51.100.8", 600),
		zoneRecord("owner", "own.cdn.example.com.", dnscheck.RecordA, "198.51.100.9", 600),
		zoneRecord("same", "same.cdn.example.com.", dnscheck.RecordA, "198.51.100.10", 600))
	items := fixture.planCleanup(t)
	change := func(id string, edit func(*dnsproviderremote.ZoneRecord)) {
		record := fixture.provider.records[id]
		edit(&record)
		fixture.provider.records[id] = record
	}
	change("value", func(record *dnsproviderremote.ZoneRecord) { record.Value = "198.51.100.70" })
	change("target", func(record *dnsproviderremote.ZoneRecord) { record.Value = "new-home.example.net." })
	change("type", func(record *dnsproviderremote.ZoneRecord) {
		record.Type, record.Value = dnscheck.RecordAAAA, "2001:db8::8"
	})
	change("owner", func(record *dnsproviderremote.ZoneRecord) { record.Name = "moved.cdn.example.com." })
	codes := codesByRecord(fixture.run(t, CleanupJobKind, items...))
	want := map[string]string{"value": CodeRecordChanged, "target": CodeRecordChanged, "type": CodeRecordChanged,
		"owner": CodeRecordChanged, "same": ""}
	for id, code := range want {
		if codes[id] != code {
			t.Fatalf("codes = %v, want %v", codes, want)
		}
	}
	if !slices.Equal(fixture.provider.deletes, []string{"same"}) {
		t.Fatalf("deleted = %v", fixture.provider.deletes)
	}
	if got := fixture.provider.records["value"].Value; got != "198.51.100.70" {
		t.Fatalf("changed record value = %q", got)
	}
}

// The item text truncates a long value; the stored full value decides. A
// change past the truncation point keeps the record.
func TestCleanupComparesTheFullValueNotTheItemText(t *testing.T) {
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." +
		strings.Repeat("d", 50) + ".example.net."
	fixture := newMaintenanceFixture(t,
		zoneRecord("tail", "tail.cdn.example.com.", dnscheck.RecordCNAME, long, 600),
		zoneRecord("kept", "kept.cdn.example.com.", dnscheck.RecordCNAME, long, 600))
	items := fixture.planCleanup(t)
	for _, item := range items {
		if !strings.Contains(item, "…") {
			t.Fatalf("item %q is not truncated", item)
		}
	}
	record := fixture.provider.records["tail"]
	record.Value = strings.TrimSuffix(long, "example.net.") + "example.org."
	fixture.provider.records["tail"] = record
	codes := codesByRecord(fixture.run(t, CleanupJobKind, items...))
	if codes["tail"] != CodeRecordChanged || codes["kept"] != "" || !slices.Equal(fixture.provider.deletes, []string{"kept"}) {
		t.Fatalf("codes = %v, deleted = %v", codes, fixture.provider.deletes)
	}
}

// A cleanup job planned before migration 686 has items but no stored records:
// nothing is deleted, each item asks for a new plan.
func TestCleanupSkipsItemsPlannedWithoutRecords(t *testing.T) {
	fixture := newMaintenanceFixture(t, zoneRecord("old", "old.cdn.example.com.", dnscheck.RecordA, "198.51.100.7", 600))
	item := CleanupItem(CleanupRecord{ZoneID: fixture.zoneID, Name: "old.cdn.example.com.", Type: "A",
		Value: "198.51.100.7", RecordID: "old"})
	reports := fixture.run(t, CleanupJobKind, item)
	if len(reports) != 1 || reports[0].Code != CodeCleanupPlanStale || reports[0].State != jobstate.ItemFailed {
		t.Fatalf("reports = %+v", reports)
	}
	if len(fixture.provider.deletes) != 0 {
		t.Fatalf("deleted = %v", fixture.provider.deletes)
	}
}

// Owners and CNAME targets compare without case and trailing dot, types
// without case, addresses by their parsed form; the apex and allocated CNAME
// hostnames stay protected whatever case the plan holds.
func TestCleanupNormalizesOwnerTypeAndValue(t *testing.T) {
	fixture := newMaintenanceFixture(t,
		zoneRecord("cname", "mixed.cdn.example.com.", dnscheck.RecordCNAME, "target.example.net.", 600),
		zoneRecord("upper", "UPPER.CDN.Example.com", dnscheck.RecordA, "198.51.100.7", 600),
		zoneRecord("v6", "six.cdn.example.com.", dnscheck.RecordAAAA, "2001:db8::1", 600),
		zoneRecord("apex", "cdn.example.com.", dnscheck.RecordA, "198.51.100.1", 600),
		zoneRecord("ours", "abc.cdn.example.com.", dnscheck.RecordA, "192.0.2.1", 600))
	fixture.targets.claimed["abc.cdn.example.com."] = true
	plans := map[string]CleanupRecord{
		"cname": {Name: "Mixed.CDN.example.com", Type: "cname", Value: "Target.Example.NET"},
		"upper": {Name: "upper.cdn.example.com.", Type: "A", Value: " 198.51.100.7 "},
		"v6":    {Name: "six.cdn.example.com.", Type: "aaaa", Value: "2001:DB8:0::1"},
		"apex":  {Name: "CDN.example.com", Type: "A", Value: "198.51.100.1"},
		"ours":  {Name: "ABC.cdn.example.com", Type: "A", Value: "192.0.2.1"},
	}
	items := make([]string, 0, len(plans))
	for id, record := range plans {
		record.ZoneID, record.RecordID = fixture.zoneID, id
		item := CleanupItem(record)
		fixture.targets.plans[item] = record
		items = append(items, item)
	}
	codes := codesByRecord(fixture.run(t, CleanupJobKind, items...))
	want := map[string]string{"cname": "", "upper": "", "v6": "", "apex": CodeRecordChanged, "ours": CodeRecordChanged}
	for id, code := range want {
		if codes[id] != code {
			t.Fatalf("codes = %v, want %v", codes, want)
		}
	}
	deleted := slices.Sorted(slices.Values(fixture.provider.deletes))
	if !slices.Equal(deleted, []string{"cname", "upper", "v6"}) {
		t.Fatalf("deleted = %v", deleted)
	}
}
