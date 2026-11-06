package dnspupprobe

import (
	"context"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe/dnspuptest"
)

func TestDNSRowsAndTracesAreRead(t *testing.T) {
	fake, server := newFakeDNSPup(t)
	fake.AllowedTools = []string{"dns", "mtr", "tcping"}
	fake.AnswerDNS = func(request dnspuptest.ProbeRequest) []dnspuptest.DNSRow {
		if request.Record != "CNAME" || request.Server != "" {
			t.Errorf("dns body = %+v", request)
		}
		return []dnspuptest.DNSRow{
			{NodeID: "gd-ct", Region: "广东", ISP: "电信", Results: []string{"a.cdn.example."}, ElapsedMS: 9, Status: "ok"},
			{NodeID: "bj-cu", Region: "北京", ISP: "联通", Status: "bad", ErrorCode: "dns_timeout"},
		}
	}
	fake.AnswerTraces = func(dnspuptest.ProbeRequest) []map[string]any {
		return []map[string]any{{"nodeId": "gd-ct", "status": "ok", "trace": map[string]any{"hops": []any{map[string]any{"hop": 1}}}}}
	}
	prober, _ := newTestProber(t, fake, server.URL)
	results, err := prober.Run(context.Background(), ConsumerPlugin, "s", "dns", 1,
		ProbeRequest{Type: "dns", Target: "www.example.com", Record: "CNAME"})
	if err != nil || len(results) != 2 {
		t.Fatalf("dns run = %v %v", results, err)
	}
	if voted, ok, _ := Judge("dns", results[0], []string{"a.cdn.example"}); !voted || !ok || Latency(results[0]) != 9 {
		t.Fatalf("dns row 0 = %+v", results[0])
	}
	if _, ok, failure := Judge("dns", results[1], nil); ok || failure != FailureTimeout {
		t.Fatalf("dns row 1 = %+v → %s", results[1], failure)
	}
	if place := PlaceOf(results[1].Region, results[1].Location, results[1].ISP); place.Carrier != CarrierUnicom {
		t.Fatalf("dns row place = %+v", place)
	}
	job, err := prober.client.CreateProbe(context.Background(), "k-mtr", ProbeRequest{Type: "mtr", Target: "1.2.3.4", Count: 100})
	for err == nil && job.Pending() {
		job, err = prober.client.GetProbe(context.Background(), job.RequestID)
	}
	if err != nil || !strings.Contains(string(job.Traces()), `"hops"`) || len(job.Results()) != 0 {
		t.Fatalf("mtr traces = %s %v", job.Traces(), err)
	}
}
