package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
)

const (
	ccStatsNode   = "018f1000-0000-7000-8000-0000000000aa"
	ccStatsTenant = "018f1000-0000-7000-8000-000000000001"
	ccStatsSite   = "018f1000-0000-7000-8000-000000000002"
	ccStatsPolicy = "018f1000-0000-7000-8000-000000000003"
	ccStatsRule   = "018f1000-0000-7000-8000-000000000004"
)

func ccStatsFrame(rows ...string) string {
	return `{"schema":"cdnca.edge.cc-stats-frame/v1","pid":7,"rows":[` + strings.Join(rows, ",") + `]}`
}

func ccStatsTestRow(site, rule string, minute int64, matched, triggered, blocked int64, clients, paths string) string {
	return fmt.Sprintf(`{"tenant_scope_id":%q,"site_id":%q,"policy_id":%q,"policy_version":"9007199254740991","rule_id":%q,`+
		`"minute":%d,"matched":%d,"triggered":%d,"challenged":0,"blocked":%d,"passed":0,"ja4_unavailable":0,`+
		`"top_clients":%s,"top_paths":%s}`, ccStatsTenant, site, ccStatsPolicy, rule, minute, matched, triggered, blocked, clients, paths)
}

func drainCCStats(t *testing.T, stats *ccStats) []autodefense.Report {
	t.Helper()
	var reports []autodefense.Report
	for {
		select {
		case encoded := <-stats.Reports():
			report, err := autodefense.DecodeReport(encoded)
			if err != nil {
				t.Fatalf("report rejected by the contract: %v", err)
			}
			reports = append(reports, report)
		default:
			return reports
		}
	}
}

func TestCCStatsSumsFramesPerInterval(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	stats := newCCStats(ccStatsNode, func() time.Time { return now })
	minute := now.Unix() - now.Unix()%60
	// Two workers' frames of the same rule and minute, one site level row.
	stats.add([]byte(ccStatsFrame(ccStatsTestRow(ccStatsSite, ccStatsRule, minute, 5, 3, 2, `{"198.51.100.7":2,"2001:db8::1":1}`, `{"/a":3}`)) + "\n" +
		ccStatsFrame(ccStatsTestRow(ccStatsSite, ccStatsRule, minute, 2, 2, 2, `{"198.51.100.7":2}`, `{"/b":2}`),
			ccStatsTestRow(ccStatsSite, "", minute, 0, 1, 1, `{"192.0.2.6":1}`, `{}`)) + "\n" + `{"dropped":4}` + "\n"))
	if reports := drainCCStats(t, stats); len(reports) != 0 {
		t.Fatalf("sent before the interval: %d", len(reports))
	}
	now = now.Add(ccStatsInterval)
	stats.add(nil)
	reports := drainCCStats(t, stats)
	if len(reports) != 1 || reports[0].Kind != autodefense.ReportCCStats || reports[0].NodeID != ccStatsNode ||
		reports[0].Seq != uint64(now.UnixMilli()) || len(reports[0].CCStats) != 2 {
		t.Fatalf("reports = %+v", reports)
	}
	site, rule := reports[0].CCStats[0], reports[0].CCStats[1]
	if site.RuleID != "" || site.Triggered != 1 || site.Blocked != 1 || len(site.TopClients) != 1 || len(site.TopPaths) != 0 {
		t.Errorf("site level row = %+v", site)
	}
	if rule.RuleID != ccStatsRule || rule.PolicyVersion != 9007199254740991 || rule.Matched != 7 || rule.Triggered != 5 ||
		rule.Blocked != 4 || rule.Minute != minute {
		t.Errorf("rule row = %+v", rule)
	}
	wantClients := []autodefense.Count{{Value: "198.51.100.7", Count: 4}, {Value: "2001:db8::1", Count: 1}}
	wantPaths := []autodefense.Count{{Value: "/a", Count: 3}, {Value: "/b", Count: 2}}
	if fmt.Sprint(rule.TopClients) != fmt.Sprint(wantClients) || fmt.Sprint(rule.TopPaths) != fmt.Sprint(wantPaths) {
		t.Errorf("tops = %v %v", rule.TopClients, rule.TopPaths)
	}
	// The pending set is cleared; an empty interval sends nothing; seq grows.
	now = now.Add(ccStatsInterval)
	stats.add(nil)
	if reports := drainCCStats(t, stats); len(reports) != 0 {
		t.Fatalf("empty interval sent %d", len(reports))
	}
	stats.add([]byte(ccStatsFrame(ccStatsTestRow(ccStatsSite, ccStatsRule, minute, 1, 0, 0, `{}`, `{}`))))
	stats.lastSeq = uint64(now.Add(time.Hour).UnixMilli())
	now = now.Add(ccStatsInterval)
	stats.add(nil)
	if reports := drainCCStats(t, stats); len(reports) != 1 || reports[0].Seq != uint64(now.Add(time.Hour-ccStatsInterval).UnixMilli())+1 {
		t.Fatalf("seq after a clock step back: %+v", reports)
	}
}

func TestCCStatsSplitsAndDropsInvalid(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	stats := newCCStats(ccStatsNode, func() time.Time { return now })
	minute := now.Unix() - now.Unix()%60
	var rows []string
	for index := 0; index < autodefense.MaxCCStats+3; index++ {
		rows = append(rows, ccStatsTestRow(fmt.Sprintf("018f1000-0000-7000-8000-%012d", 1000+index), ccStatsRule, minute, 1, 0, 0, `{}`, `{}`))
	}
	body := ccStatsFrame(rows...) + "\n" +
		// A corrupt row (bad site id) is dropped alone; a bad frame and a foreign schema are dropped.
		ccStatsFrame(ccStatsTestRow("not-a-uuid", ccStatsRule, minute, 1, 0, 0, `{}`, `{}`)) + "\nnot json\n" +
		`{"schema":"other/v1","rows":[]}` + "\n" +
		// A non decimal policy version and an over-long top list.
		ccStatsFrame(strings.Replace(ccStatsTestRow(ccStatsSite, ccStatsRule, minute, 1, 0, 0, `{}`, `{}`), `"9007199254740991"`, `"1e3"`, 1)) + "\n" +
		ccStatsFrame(ccStatsTestRow(ccStatsSite, ccStatsRule, minute, 1, 11, 0,
			`{"192.0.2.1":1,"192.0.2.2":1,"192.0.2.3":1,"192.0.2.4":1,"192.0.2.5":1,"192.0.2.6":1,"192.0.2.7":1,"192.0.2.8":1,"192.0.2.9":1,"192.0.2.10":1,"192.0.2.11":1}`, `{}`))
	now = now.Add(ccStatsInterval)
	stats.add([]byte(body))
	reports := drainCCStats(t, stats)
	if len(reports) != 2 || len(reports[0].CCStats) != autodefense.MaxCCStats || len(reports[1].CCStats) != 3 ||
		reports[1].Seq != reports[0].Seq+1 {
		t.Fatalf("reports = %d", len(reports))
	}
	if stats.dropped != 0 || len(stats.pending) != 0 {
		t.Errorf("state after flush: dropped=%d pending=%d", stats.dropped, len(stats.pending))
	}
}

func TestCCStatsQueueFullDrops(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	stats := newCCStats(ccStatsNode, func() time.Time { return now })
	minute := now.Unix() - now.Unix()%60
	for index := 0; index < ccStatsQueue+2; index++ {
		now = now.Add(ccStatsInterval)
		stats.add([]byte(ccStatsFrame(ccStatsTestRow(ccStatsSite, ccStatsRule, minute, 1, 0, 0, `{}`, `{}`))))
	}
	if reports := drainCCStats(t, stats); len(reports) != ccStatsQueue {
		t.Fatalf("queued %d", len(reports))
	}
}

func TestCCStatsUpstreamMergesReports(t *testing.T) {
	keys := newAutoDefenseKeys(t)
	local := &autoDefenseLocalStub{}
	receiver := newAutoDefenseReceiver(ccStatsNode, keys.trusted, local, nil)
	if withCCStatsReports(receiver, nil) != gatewayclient.AutoDefenseRuntime(receiver) {
		t.Fatal("without CC statistics the receiver is used as is")
	}
	now := time.Unix(1_700_000_000, 0)
	stats := newCCStats(ccStatsNode, func() time.Time { return now })
	upstream := withCCStatsReports(receiver, stats)
	if result := upstream.ApplyAutoDefense([]byte("{}")); result.Applied || result.ErrorCode != autodefense.ErrorInvalid {
		t.Errorf("snapshot parts must reach the receiver: %+v", result)
	}
	if upstream.Reports() != upstream.Reports() {
		t.Error("reports must be merged once")
	}
	minute := now.Truncate(time.Minute).Unix()
	stats.add([]byte(ccStatsFrame(ccStatsTestRow(ccStatsSite, ccStatsRule, minute, 1, 0, 0, `{}`, `{}`))))
	now = now.Add(ccStatsInterval)
	stats.add(nil)
	select {
	case encoded := <-upstream.Reports():
		if report, err := autodefense.DecodeReport(encoded); err != nil || report.Kind != autodefense.ReportCCStats {
			t.Errorf("merged report = %+v, %v", report, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CC statistics did not reach the merged upstream")
	}
}
