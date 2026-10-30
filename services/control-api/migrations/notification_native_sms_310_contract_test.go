package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// G9c-④ 原生短信（阿里云/submail）迁移，占位号 310（守卫指向 309 节点告警）。
// 合入时如改号，只改这里的常量和两个 SQL 文件头部。
const (
	notificationNativeSMSVersion    = 310
	notificationNativeSMSPreviousID = "309_node_availability_alerts"
	notificationNativeSMSUpSHA256   = "806aed64663a810fb3040f78582215f1a58baca11ddf7f5698617f4bf3cdae9c"
	notificationNativeSMSDownSHA256 = "5fe79fcecbdc45214ec6931c86778f6a5ca55f88e7f2b0db004bea6652d9e512"
)

func TestNotificationNativeSMSMigrationContract(t *testing.T) {
	previous := fmt.Sprint(notificationNativeSMSVersion - 1)
	current := fmt.Sprint(notificationNativeSMSVersion)
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{current + "_notification_native_sms.up.sql", notificationNativeSMSUpSHA256, []string{
			"(SELECT count(*) FROM schema_migrations) <> " + previous, notificationNativeSMSPreviousID,
			"ADD COLUMN template_params jsonb", "template_params IS NULL OR channel = 'sms'",
			"notification outbox template params are immutable",
			"ADD COLUMN sms_secret_ciphertext bytea", "sms_secret_fingerprint ~ '^[0-9a-f]{16}$'",
		}},
		{current + "_notification_native_sms.down.sql", notificationNativeSMSDownSHA256, []string{
			"(SELECT count(*) FROM schema_migrations) <> " + current, current + "_notification_native_sms",
			"would discard native SMS credentials or pending template SMS",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
		if strings.Contains(string(raw), "CASCADE") {
			t.Errorf("%s uses CASCADE", script.name)
		}
	}
}
