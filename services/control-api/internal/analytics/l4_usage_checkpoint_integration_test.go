package analytics

import (
	"net/http"
	"testing"
	"time"
)

type l4CheckpointRow struct {
	TenantID              string    `json:"tenant_id"`
	StreamID              string    `json:"stream_id"`
	PackageSubscriptionID string    `json:"package_subscription_id"`
	SessionID             string    `json:"session_id"`
	StartedAt             time.Time `json:"started_at"`
	CheckpointAt          time.Time `json:"checkpoint_at"`
	Sequence              uint32    `json:"sequence"`
	BytesUp               uint64    `json:"bytes_up"`
	BytesDown             uint64    `json:"bytes_down"`
	EventID               string    `json:"event_id"`
	SourceWatermark       uint64    `json:"source_watermark"`
}

type l4CheckpointedFactRow struct {
	TenantID              string    `json:"tenant_id"`
	StreamID              string    `json:"stream_id"`
	PackageSubscriptionID string    `json:"package_subscription_id"`
	EventID               string    `json:"event_id"`
	FinalizedAt           time.Time `json:"finalized_at"`
	BytesUp               uint64    `json:"bytes_up"`
	BytesDown             uint64    `json:"bytes_down"`
	CheckpointedBytesUp   uint64    `json:"checkpointed_bytes_up"`
	CheckpointedBytesDown uint64    `json:"checkpointed_bytes_down"`
	SourceWatermark       uint64    `json:"source_watermark"`
}

// TestL4UsageCheckpointsClickHouseIntegration（待出包前全量跑，需 TEST_CLICKHOUSE_URL/
// TEST_CLICKHOUSE_DATABASE）：真 ClickHouse 全量迁移（含 029）下，一条跨月长连接
// 1 月有两个检查点、2 月有一个检查点，2 月结束时事实带已检查点字节：
// 1 月计两个检查点之和，2 月计第三个检查点+结束余量，两月合计等于会话总字节；
// 同一检查点重复上报（同会话+序号）只计一次；授权端用量同口径。
func TestL4UsageCheckpointsClickHouseIntegration(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyAllClickHouseMigrations(t, database)
	const (
		tenantID       = "10000000-0000-4000-8000-0000000005a2"
		subscriptionID = "20000000-0000-4000-8000-0000000005a1"
		streamID       = "50000000-0000-4000-8000-0000000005a1"
	)
	january := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	february := january.AddDate(0, 1, 0)
	march := february.AddDate(0, 1, 0)
	started := february.Add(-3 * time.Minute)
	checkpoint := func(sequence uint32, at time.Time, up, down, watermark uint64) l4CheckpointRow {
		return l4CheckpointRow{TenantID: tenantID, StreamID: streamID, PackageSubscriptionID: subscriptionID, SessionID: "17",
			StartedAt: started, CheckpointAt: at, Sequence: sequence, BytesUp: up, BytesDown: down,
			EventID: "ckpt", SourceWatermark: watermark}
	}
	insertRankRows(t, database, `INSERT INTO l4_usage_checkpoints_v1
		(tenant_id,stream_id,package_subscription_id,session_id,started_at,checkpoint_at,sequence,bytes_up,bytes_down,event_id,source_watermark)
		FORMAT JSONEachRow`, []l4CheckpointRow{
		checkpoint(1, february.Add(-2*time.Minute), 10, 100, 1),
		checkpoint(2, february.Add(-time.Minute), 20, 200, 2),
		checkpoint(2, february.Add(-time.Minute), 20, 200, 5), // 重复上报：去重
		checkpoint(3, february.Add(time.Minute), 30, 300, 3),
	})
	insertRankRows(t, database, `INSERT INTO l4_session_facts_v1
		(tenant_id,stream_id,package_subscription_id,event_id,finalized_at,bytes_up,bytes_down,checkpointed_bytes_up,checkpointed_bytes_down,source_watermark)
		FORMAT JSONEachRow`, []l4CheckpointedFactRow{{TenantID: tenantID, StreamID: streamID, PackageSubscriptionID: subscriptionID,
		EventID: "end", FinalizedAt: february.Add(90 * time.Second), BytesUp: 65, BytesDown: 650,
		CheckpointedBytesUp: 60, CheckpointedBytesDown: 600, SourceWatermark: 4}})
	client, err := NewClient(Config{
		Endpoint: database.endpoint, Database: database.name, Username: database.username, Password: database.password,
		QueryTimeout: 5 * time.Second,
	}, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	inJanuary, err := client.PackageL4Traffic(t.Context(), tenantID, subscriptionID, january, february)
	if err != nil || inJanuary != 330 {
		t.Fatalf("January = %d, %v; want 330 (two checkpoints)", inJanuary, err)
	}
	inFebruary, err := client.PackageL4Traffic(t.Context(), tenantID, subscriptionID, february, march)
	if err != nil || inFebruary != 330+55 {
		t.Fatalf("February = %d, %v; want 385 (third checkpoint + final delta)", inFebruary, err)
	}
	if inJanuary+inFebruary != 65+650 {
		t.Fatalf("months sum %d, session %d", inJanuary+inFebruary, 65+650)
	}
	installation, err := client.InstallationTrafficBytes(t.Context(), january, march, false)
	if err != nil || installation != 715 {
		t.Fatalf("installation = %d, %v; want 715", installation, err)
	}
}
