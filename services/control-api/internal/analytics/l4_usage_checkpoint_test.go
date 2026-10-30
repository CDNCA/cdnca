package analytics

import (
	"strings"
	"testing"
)

// L4-USAGE-01：四层计费按增量累计。结束事实只计未被检查点计过的余量
// （bytes - least(bytes, checkpointed)，按 finalized_at），进行中的检查点按
// checkpoint_at 计增量；套餐流量限额、授权端用量、套餐用量概览/曲线、用量
// 查询四处同口径。
func TestL4BilledTrafficCountsCheckpointsAndTheFinalDelta(t *testing.T) {
	for name, query := range map[string]string{
		"package traffic":      packageL4TrafficSQL,
		"installation traffic": installationTrafficSQL,
		"package usage":        packageUsageL4FactsSQL,
		"usage search":         l4UsageRowsSQL("finalized_at>={from:DateTime64(3,'UTC')} AND finalized_at<{to:DateTime64(3,'UTC')}", "tenant_id={tenant:UUID}"),
	} {
		for _, token := range []string{
			"l4_session_facts_v1 FINAL", "l4_usage_checkpoints_v1 FINAL",
			"bytes_up-least(bytes_up,checkpointed_bytes_up)", "bytes_down-least(bytes_down,checkpointed_bytes_down)",
			"checkpoint_at", "UNION ALL",
		} {
			if !strings.Contains(query, token) {
				t.Errorf("%s query lacks %q:\n%s", name, token, query)
			}
		}
	}
}

// 检查点与结束事实用同一条件：时间窗口换成各自的时间列，其它条件原样。
func TestL4UsageRowsBindTheWindowToEachTimeColumn(t *testing.T) {
	query := l4UsageRowsSQL("finalized_at>={from:DateTime64(3,'UTC')} AND finalized_at<{to:DateTime64(3,'UTC')}", "tenant_id={tenant:UUID}")
	facts, checkpoints, ok := strings.Cut(query, "UNION ALL")
	if !ok {
		t.Fatal(query)
	}
	if !strings.Contains(facts, "finalized_at>={from:DateTime64(3,'UTC')} AND finalized_at<{to:DateTime64(3,'UTC')} AND tenant_id={tenant:UUID}") ||
		strings.Contains(facts, "checkpoint_at>=") {
		t.Fatalf("facts = %s", facts)
	}
	if !strings.Contains(checkpoints, "checkpoint_at>={from:DateTime64(3,'UTC')} AND checkpoint_at<{to:DateTime64(3,'UTC')} AND tenant_id={tenant:UUID}") ||
		strings.Contains(checkpoints, "finalized_at") {
		t.Fatalf("checkpoints = %s", checkpoints)
	}
}
