package notificationcontrol

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func deliveryPolicyRequestWithEvents(count int) UpdateDeliveryPolicyRequest {
	events := make([]DeliveryPolicyEvent, count)
	for index := range events {
		events[index] = DeliveryPolicyEvent{EventType: fmt.Sprintf("test.event_%d", index), RepeatCount: 1, IntervalHours: 24, Supported: true}
	}
	return UpdateDeliveryPolicyRequest{WindowMode: "all_day", WindowStart: "00:00", WindowEnd: "23:59", Timezone: "Asia/Shanghai", Events: events}
}

// live-click-B E1: 事件目录 75 条时旧上限 64 拒绝整份策略。
func TestDeliveryPolicyAcceptsCatalogBeyondOldLimit(t *testing.T) {
	if err := validateDeliveryPolicyRequest(deliveryPolicyRequestWithEvents(75)); err != nil {
		t.Fatalf("75 events = %v, want accepted", err)
	}
	if err := validateDeliveryPolicyRequest(deliveryPolicyRequestWithEvents(maxDeliveryPolicyEvents)); err != nil {
		t.Fatalf("%d events = %v, want accepted", maxDeliveryPolicyEvents, err)
	}
	if err := validateDeliveryPolicyRequest(deliveryPolicyRequestWithEvents(maxDeliveryPolicyEvents + 1)); err == nil {
		t.Fatalf("%d events accepted, want ErrInvalidInput", maxDeliveryPolicyEvents+1)
	}
}

var (
	policyInsertPattern = regexp.MustCompile(`(?s)INSERT INTO notification_event_policies\s*\(.*?;`)
	policyTuplePattern  = regexp.MustCompile(`\(\s*'([a-z][a-z0-9._-]*)'\s*,`)
)

// 事件目录 = 各迁移写入 notification_event_policies 的事件 ∪ supportedEventTypes。
// 策略接口整表读出、整表写回，目录条数必须留在上限之内，否则通知配置页整体不可用。
func TestNotificationEventCatalogStaysBelowPolicyLimit(t *testing.T) {
	catalog := map[string]bool{}
	for _, eventType := range supportedEventTypes {
		catalog[eventType] = true
	}
	files, err := fs.Glob(controlmigrations.FS, "*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		contents, err := controlmigrations.FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range policyInsertPattern.FindAllString(string(contents), -1) {
			for _, match := range policyTuplePattern.FindAllStringSubmatch(statement, -1) {
				catalog[match[1]] = true
			}
		}
	}
	// 当前目录 75 条（10-22）；读不到时说明解析失效，不能当作通过。
	if len(catalog) < 75 {
		t.Fatalf("event catalog = %d entries, parser lost migrations", len(catalog))
	}
	if len(catalog) >= maxDeliveryPolicyEvents {
		t.Fatalf("event catalog = %d entries, must stay below maxDeliveryPolicyEvents %d", len(catalog), maxDeliveryPolicyEvents)
	}
}

func TestDeliveryPolicyLimitMatchesOpenAPI(t *testing.T) {
	contents, err := os.ReadFile("../../../../api/control-notifications.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	start := strings.Index(text, "    DeliveryPolicyWrite:")
	if start < 0 {
		t.Fatal("DeliveryPolicyWrite schema missing")
	}
	match := regexp.MustCompile(`\n {8}events: \{[^\n]*maxItems: (\d+)`).FindStringSubmatch(text[start:])
	if match == nil {
		t.Fatal("DeliveryPolicyWrite.events maxItems missing")
	}
	if value, _ := strconv.Atoi(match[1]); value != maxDeliveryPolicyEvents {
		t.Fatalf("OpenAPI maxItems = %d, want %d", value, maxDeliveryPolicyEvents)
	}
}
