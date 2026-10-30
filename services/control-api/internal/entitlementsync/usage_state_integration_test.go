//go:build integration

package entitlementsync

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
)

// L08（迁移 554）：真实 PostgreSQL 上的持久投递状态。

func usageStateReporter(t *testing.T, state UsageReportState, id uuid.UUID, key ed25519.PrivateKey, server *usageServer,
	now *time.Time, used *int64,
) *UsageReporter {
	t.Helper()
	client, err := NewClient("https://license.example.test", &http.Client{Transport: server})
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := NewUsageReporter(UsageReporterConfig{
		Client: client, Store: &fakeLeaseStore{serial: 9}, State: state, InstallationID: id, PrivateKey: key,
		Collect: func(context.Context) (time.Time, []UsageValue, error) { return *now, usageValues(*used), nil },
		Now:     func() time.Time { return *now },
		Wait:    func(ctx context.Context, delay time.Duration) error { *now = now.Add(delay); return ctx.Err() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return reporter
}

// 同秒重启与回拨一小时后重启（新 Store 对象、同一库）：序号严格递增，observed_at 保留真实采集时间。
func TestUsageSequenceDBAllocationSurvivesRestartAndClockRollback(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	id := uuid.New()
	_, key, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_900_000_000, 0).UTC()
	used := int64(3)
	server := &usageServer{}
	if err := usageStateReporter(t, NewPostgresUsageState(pool), id, key, server, &now, &used).ReportOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	used = 4
	if err := usageStateReporter(t, NewPostgresUsageState(pool), id, key, server, &now, &used).ReportOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(-time.Hour)
	if err := usageStateReporter(t, NewPostgresUsageState(pool), id, key, server, &now, &used).ReportOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	var sequences []float64
	for _, body := range server.bodies {
		sequences = append(sequences, body["sequence"].(float64))
	}
	if len(sequences) != 3 || !(sequences[0] < sequences[1] && sequences[1] < sequences[2]) ||
		server.bodies[2]["observed_at"].(float64) != float64(now.Unix()) {
		t.Fatalf("sequences=%v bodies=%v", sequences, server.bodies)
	}
	var pending bool
	if err := pool.QueryRow(t.Context(), `SELECT pending_sequence IS NOT NULL FROM control_usage_report_state WHERE installation_id=$1`,
		id).Scan(&pending); err != nil || pending {
		t.Fatalf("pending=%v err=%v", pending, err)
	}
}

// 两个连接并发首轮：库里只有一份 pending，双方拿到同序号、同幂等键、同字节。
func TestUsagePendingReservationIsAtomicAcrossWorkers(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	id := uuid.New()
	_, key, _ := ed25519.GenerateKey(nil)
	at := time.Unix(1_900_000_000, 0).UTC()
	results := make([]usageReport, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for index := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[index], errs[index] = NewPostgresUsageState(pool).Reserve(t.Context(), id, func(previous uint64) (usageReport, error) {
				return prepareUsageReport(id, 9, at, previous, usageValues(int64(index)), key)
			}, at)
		}()
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || results[0].requestID != results[1].requestID ||
		string(results[0].body) != string(results[1].body) || results[0].sequence != results[1].sequence {
		t.Fatalf("results=%+v errs=%v", results, errs)
	}
}

// 预留落盘后发送前退出：重建后固定 body/key/serial 字节一致；迟到的旧确认不清新 pending。
func TestUsagePendingRestoresExactBytesAndLateSettleIsConditional(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	id := uuid.New()
	_, key, _ := ed25519.GenerateKey(nil)
	at := time.Unix(1_900_000_000, 0).UTC()
	reserved, err := NewPostgresUsageState(pool).Reserve(t.Context(), id, func(previous uint64) (usageReport, error) {
		return prepareUsageReport(id, 9, at, previous, usageValues(3), key)
	}, at)
	if err != nil {
		t.Fatal(err)
	}
	restored, found, err := NewPostgresUsageState(pool).Pending(t.Context(), id)
	if err != nil || !found || restored.requestID != reserved.requestID || string(restored.body) != string(reserved.body) ||
		restored.leaseSerial != 9 || restored.path != reserved.path {
		t.Fatalf("restored=%+v found=%v err=%v", restored, found, err)
	}
	state := NewPostgresUsageState(pool)
	if err := state.Settle(t.Context(), id, reserved); err != nil {
		t.Fatal(err)
	}
	newer, err := state.Reserve(t.Context(), id, func(previous uint64) (usageReport, error) {
		return prepareUsageReport(id, 9, at, previous, usageValues(4), key)
	}, at)
	if err != nil || newer.sequence <= reserved.sequence {
		t.Fatalf("newer=%+v err=%v", newer, err)
	}
	if err := state.Settle(t.Context(), id, reserved); err != nil {
		t.Fatal(err)
	}
	if still, found, _ := state.Pending(t.Context(), id); !found || still.requestID != newer.requestID {
		t.Fatalf("late settle cleared the newer pending: %+v %v", still, found)
	}
}

// 不同安装互不影响。
func TestUsageSequenceIsolationByInstallation(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	_, key, _ := ed25519.GenerateKey(nil)
	at := time.Unix(1_900_000_000, 0).UTC()
	state := NewPostgresUsageState(pool)
	a, b := uuid.New(), uuid.New()
	ra, _ := state.Reserve(t.Context(), a, func(p uint64) (usageReport, error) { return prepareUsageReport(a, 9, at, p, usageValues(1), key) }, at)
	_ = state.Settle(t.Context(), b, ra)
	if _, found, _ := state.Pending(t.Context(), a); !found {
		t.Fatal("settling another installation cleared this pending")
	}
}
