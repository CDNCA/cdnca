package eventspool

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

// 四层事实带上发布时转发的套餐（L4_PACKAGE_ATTRIBUTION）；
// 同一转发换套餐前后的事实不进同一个信封；非规范的套餐 ID 拒绝。
func TestL4SessionCarriesThePackageSubscription(t *testing.T) {
	const before, after = "88888888-8888-4888-8888-888888888881", "88888888-8888-4888-8888-888888888882"
	identity := TrustedIdentity{
		EnrollmentNodeID: nodeOne, TenantID: tenantOne, SiteID: siteOne,
		ConfigVersionID: "55555555-5555-4555-8555-555555555555",
		StreamID:        "66666666-6666-4666-8666-666666666666",
		ListenerID:      "66666666-6666-4666-8666-666666666666", ConfigRevision: 9, PackageSubscriptionID: before,
	}
	line := func(connection string) []byte {
		return []byte("{\"time\":\"2026-08-08T12:00:05Z\",\"connection\":\"" + connection +
			"\",\"protocol\":\"TCP\",\"server_port\":\"18080\",\"status\":\"200\",\"bytes_sent\":10,\"bytes_received\":5,\"session_time\":1}")
	}
	first, err := ParseL4SourceLineBound(line("1"), identity)
	if err != nil || first.PackageSubscriptionID != before {
		t.Fatalf("event = %#v, %v", first, err)
	}
	identity.PackageSubscriptionID = after
	second, err := ParseL4SourceLineBound(line("2"), identity)
	if err != nil {
		t.Fatal(err)
	}
	identity.PackageSubscriptionID = ""
	third, err := ParseL4SourceLineBound(line("3"), identity)
	if err != nil || third.PackageSubscriptionID != "" {
		t.Fatalf("forward without a package = %#v, %v", third, err)
	}
	for _, bad := range []string{"88888888-8888-4888-8888-88888888888A", "00000000-0000-0000-0000-000000000000", "x"} {
		identity.PackageSubscriptionID = bad
		if _, err := ParseL4SourceLineBound(line("4"), identity); err == nil {
			t.Errorf("package %q accepted", bad)
		}
	}
	first.EventID, second.EventID, third.EventID = "l4evt_one", "l4evt_two", "l4evt_three"

	config := testConfig(t.TempDir())
	config.Now = func() time.Time { return time.Date(2026, 8, 8, 12, 1, 0, 0, time.UTC) }
	spool := newTestSpool(t, config)
	if _, err := spool.AppendBatch(context.Background(), []Envelope{first, second, third}); err != nil {
		t.Fatal(err)
	}
	records, err := spool.nextBatch(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	publications, err := buildPublications(records)
	if err != nil || len(publications) != 3 {
		t.Fatalf("publications = %d, %v; want one per package", len(publications), err)
	}
	for index, want := range []string{before, after, ""} {
		var envelope agentv1.L4SessionEnvelopeV1
		if err := proto.Unmarshal(publications[index].Payload, &envelope); err != nil {
			t.Fatal(err)
		}
		if len(envelope.GetEvents()) != 1 || envelope.GetEvents()[0].GetPackageSubscriptionId() != want {
			t.Fatalf("publication %d events = %#v, want package %q", index, envelope.GetEvents(), want)
		}
	}
}
