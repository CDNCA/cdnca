package l4analytics

import (
	"net/http/httptest"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// 事实写入 CH 时带上节点上报的套餐（CH 027 package_subscription_id）；
// 无套餐的转发写零 UUID。
func TestFactWriterWritesThePackageSubscription(t *testing.T) {
	fake := &fakeClickHouse{exists: true}
	server := httptest.NewServer(fake.handler(t))
	defer server.Close()
	source, err := NewClickHouseSource(ClickHouseConfig{Endpoint: server.URL, Database: "facts", QueryTimeout: time.Second, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewClickHouseFactWriterWithSessionLogs(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	packaged := sessionEvent("packaged", nil)
	packaged.PackageSubscriptionId = "66666666-6666-4666-8666-666666666666"
	if err := writer.Write(t.Context(), []*agentv1.L4SessionEventV1{packaged, sessionEvent("plain", nil)}, 3); err != nil {
		t.Fatal(err)
	}
	facts := fake.inserts["l4_session_facts_v1"]
	if len(facts) != 2 || facts[0]["package_subscription_id"] != "66666666-6666-4666-8666-666666666666" ||
		facts[1]["package_subscription_id"] != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("facts = %v", facts)
	}
}
