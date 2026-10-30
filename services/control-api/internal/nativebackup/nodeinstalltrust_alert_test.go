package nativebackup

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// fix-btenv5: the failure event is a registered platform notification, its
// template variables are exactly what the alert fills, and one failure
// streak has one merge key.
func TestNodeInstallTrustFailedRegistrationAndTemplates(t *testing.T) {
	if EventTypeNodeInstallTrustFailed != "node.install_trust.failed" || !notification.PlatformEventType(EventTypeNodeInstallTrustFailed) ||
		!notificationcontrol.SupportedEventType(EventTypeNodeInstallTrustFailed) {
		t.Fatalf("%s is not registered as a platform notification event", EventTypeNodeInstallTrustFailed)
	}
	raw, err := controlmigrations.FS.ReadFile("575_node_install_trust_alerts.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, 10, 28, 5, 0, 0, 0, time.UTC)
	reason := "cannot resolve cdnca.com for node upgrade downloads: " + strings.Repeat("x", 400)
	contexts := nodeInstallTrustFailedContexts(NodeInstallTrustAlert{Since: since, At: since.Add(20 * time.Minute), Failures: 3,
		Host: "cdnca.com", Port: 19445, Reason: reason})
	declared := regexp.MustCompile(`\('node\.install_trust\.failed\.zh-cn', 1, '(sms|email)',[\s\S]*?ARRAY\[([^\]]*)\]`).
		FindAllStringSubmatch(string(raw), -1)
	if len(declared) != 2 {
		t.Fatalf("templates in migration = %d", len(declared))
	}
	for _, template := range declared {
		channel := notification.Channel(template[1])
		var want, got []string
		for _, quoted := range regexp.MustCompile(`'([a-z_]+)'`).FindAllStringSubmatch(template[2], -1) {
			want = append(want, quoted[1])
		}
		for key := range contexts[channel] {
			got = append(got, key)
		}
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(want, got) {
			t.Errorf("%s variables: template %v, context %v", channel, want, got)
		}
		for _, name := range want {
			if !strings.Contains(string(raw), "{{."+name+"}}") {
				t.Errorf("%s variable %s unused in the body", channel, name)
			}
		}
	}
	email := contexts[notification.ChannelEmail]
	if email["download"] != notification.PublicValue("cdnca.com:19445") || email["since"] != notification.PublicValue("2026-10-28T05:00:00Z") ||
		email["reason"] != notification.PublicValue(reason[:300]) {
		t.Fatalf("email context = %#v", email)
	}
	first := NodeInstallTrustFailedSourceEventID(since)
	if first != "node-install-trust-failed/v1/1793163600" || NodeInstallTrustFailedSourceEventID(since) != first ||
		NodeInstallTrustFailedSourceEventID(since.Add(time.Hour)) == first {
		t.Fatalf("source event ID = %q", first)
	}
	if err := AlertNodeInstallTrustFailed(context.Background(), nil, nil, NodeInstallTrustAlert{}); err != nil {
		t.Fatal(err)
	}
}

// The republication audit event is a cataloged system action with the old
// and new download endpoints; private root CA content is not written.
func TestNodeInstallTrustRepublishAuditEvent(t *testing.T) {
	platform := uuid.New()
	event := nodeInstallTrustRepublishEvent(platform, NodeInstallTrustChange{
		Before:         &entitlement.UpgradeDownloadPolicy{Host: "cdnca.com", Port: 443, Addresses: []string{"198.51.100.7"}, RootCA: "system"},
		After:          entitlement.UpgradeDownloadPolicy{Host: "cdnca.com", Port: 19445, Addresses: []string{"203.0.113.20"}, RootCA: testRootPEM},
		PreviousSHA256: oldTrustSHA, SHA256: strings.Repeat("ab", 32)})
	if _, ok := audit.Lookup(event.Action); !ok {
		t.Fatalf("%s is not in the audit catalog", event.Action)
	}
	if event.ScopeID != platform || event.ActorKind != "system" || event.ActorUserID != nil || event.Result != "success" ||
		len(event.Changes) != 1 || event.Changes[0].Before != "cdnca.com:443 → 198.51.100.7 (root system)" ||
		event.Changes[0].After != "cdnca.com:19445 → 203.0.113.20 (root private)" || event.Payload["previous_sha256"] != oldTrustSHA {
		t.Fatalf("audit event = %+v", event)
	}
	for _, value := range event.Payload {
		if text, _ := value.(string); strings.Contains(text, "BEGIN CERTIFICATE") {
			t.Fatal("the audit event carries the root CA")
		}
	}
}
