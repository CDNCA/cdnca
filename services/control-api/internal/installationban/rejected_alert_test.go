package installationban

import (
	"context"
	"log/slog"
	"regexp"
	"slices"
	"testing"
	"time"

	transport "github.com/cdnca/cdnca/libs/edgeconfig/installationban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// fz-x13: the permanent refusal event is registered in the notification
// center and its template variables are exactly what enqueueRejected fills.
func TestRejectedAlertRegistrationAndTemplates(t *testing.T) {
	if EventTypeRejected != "installation_ban.rejected" || !notification.PlatformEventType(EventTypeRejected) ||
		!notificationcontrol.SupportedEventType(EventTypeRejected) {
		t.Fatalf("%s is not registered as a platform notification event", EventTypeRejected)
	}
	raw, err := controlmigrations.FS.ReadFile("530_installation_ban_rejected_notice.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	contexts := rejectedContexts(RejectedAlert{NodeID: uuid.New(), Revision: 7, Reason: "notice_signature_invalid",
		At: time.Date(2026, 10, 26, 1, 2, 3, 0, time.UTC)}, "edge-a", "203.0.113.7")
	declared := regexp.MustCompile(`\('installation_ban\.rejected\.zh-cn', 1, '(sms|email)',[\s\S]*?ARRAY\[([^\]]*)\]`).
		FindAllStringSubmatch(string(raw), -1)
	if len(declared) != 2 {
		t.Fatalf("templates in migration = %d", len(declared))
	}
	for _, template := range declared {
		channel := notification.Channel(template[1])
		var want []string
		for _, quoted := range regexp.MustCompile(`'([a-z_]+)'`).FindAllStringSubmatch(template[2], -1) {
			want = append(want, quoted[1])
		}
		var got []string
		for key := range contexts[channel] {
			got = append(got, key)
		}
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(want, got) {
			t.Errorf("%s variables: template %v, context %v", channel, want, got)
		}
		for _, name := range want {
			if !regexp.MustCompile(`\{\{\.` + name + `\}\}`).MatchString(string(raw)) {
				t.Errorf("%s variable %s unused in the body", channel, name)
			}
		}
	}
	if contexts[notification.ChannelEmail]["revision"] != notification.PublicValue("7") {
		t.Fatalf("revision context = %#v", contexts[notification.ChannelEmail]["revision"])
	}
	node := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b717f")
	if got := RejectedSourceEventID(node, 7); got != "installation-ban-rejected/v1/"+node.String()+"/7" ||
		RejectedSourceEventID(node, 8) == got {
		t.Fatalf("source event ID = %q", got)
	}
	// Without the notification store (tests, or no pool) nothing is enqueued.
	if err := AlertRejected(context.Background(), nil, nil, RejectedAlert{}); err != nil {
		t.Fatal(err)
	}
}

// Only a permanent refusal raises the notification; applied receipts and
// retryable refusals do not.
func TestHandleReceiptAlertsOnlyPermanentRefusals(t *testing.T) {
	nodeID := uuid.New()
	for _, test := range []struct {
		name    string
		receipt *agentv1.InstallationBanReceipt
		alerted bool
	}{
		{"permanent", &agentv1.InstallationBanReceipt{NodeId: nodeID.String(), Revision: 3, Status: "serving",
			Reason: transport.ReasonInvalid}, true},
		{"retryable", &agentv1.InstallationBanReceipt{NodeId: nodeID.String(), Revision: 3, Status: "serving",
			Reason: transport.ReasonPersistence}, false},
		{"applied", &agentv1.InstallationBanReceipt{NodeId: nodeID.String(), Revision: 3, Status: "serving",
			Applied: true}, false},
	} {
		var alerts []RejectedAlert
		distributor := &Distributor{Store: &fakeDeliveryStore{deliveries: map[string]NodeDelivery{}},
			Now: func() time.Time { return testNow }, Logger: slog.New(slog.DiscardHandler)}
		distributor.alertRejected = func(_ context.Context, alert RejectedAlert) error {
			alerts = append(alerts, alert)
			return nil
		}
		receipt := &fakeReceipt{receipt: test.receipt}
		distributor.HandleReceipt(t.Context(), receipt)
		if !receipt.acked || (len(alerts) == 1) != test.alerted {
			t.Fatalf("%s: acked=%v alerts=%+v", test.name, receipt.acked, alerts)
		}
		if test.alerted && (alerts[0].NodeID != nodeID || alerts[0].Revision != 3 || alerts[0].Reason != transport.ReasonInvalid ||
			!alerts[0].At.Equal(testNow)) {
			t.Fatalf("alert = %+v", alerts[0])
		}
	}
}
