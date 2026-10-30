//go:build integration

package migrations_test

import "testing"

// TestEscalateCNAMENotice469: 468→469 连号重放，469 up/down/up 往返；up 后事件策略一行、
// zh-cn 短信/邮件模板各一行，down 后全部清掉（合线 merge-b3 补）。
func TestEscalateCNAMENotice469(t *testing.T) {
	pool := migrationPoolAt(t, 467)
	ctx := t.Context()
	if err := migrateVersionIsolated(ctx, pool, "up", 468); err != nil {
		t.Fatalf("up 468: %v", err)
	}
	counts := func() (policies, templates int) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM notification_event_policies WHERE event_type='security.escalate.cname_change_required'),
			(SELECT count(*) FROM notification_templates WHERE template_id='security.escalate.cname_change_required.zh-cn')`).
			Scan(&policies, &templates); err != nil {
			t.Fatal(err)
		}
		return policies, templates
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, 469); err != nil {
			t.Fatalf("%s 469: %v", step, err)
		}
		policies, templates := counts()
		want := [2]int{1, 2}
		if step == "down" {
			want = [2]int{0, 0}
		}
		if [2]int{policies, templates} != want {
			t.Fatalf("after %s 469: policies=%d templates=%d, want %v", step, policies, templates, want)
		}
	}
	var channels []string
	if err := pool.QueryRow(ctx, `SELECT array_agg(channel ORDER BY channel) FROM notification_templates
		WHERE template_id='security.escalate.cname_change_required.zh-cn' AND version=1`).Scan(&channels); err != nil {
		t.Fatal(err)
	}
	if len(channels) != 2 || channels[0] != "email" || channels[1] != "sms" {
		t.Fatalf("469 template channels = %v", channels)
	}
}
