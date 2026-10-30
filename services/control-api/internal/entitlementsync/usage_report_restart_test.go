package entitlementsync

import (
	"context"
	"errors"
	"testing"
	"time"
)

// L08 主审反例：以同一配置（同一安装、同一持久状态）重建 Reporter，不复制上一进程内存。
// 同秒重启与时钟回拨后重启，新序号都必须严格大于上一份已发出的序号。
func TestUsageReporterRestartPreservesSequenceFence(t *testing.T) {
	for _, item := range []struct {
		name       string
		clockDelta time.Duration
	}{{"same_second_restart", 0}, {"restart_after_clock_rollback", -time.Hour}} {
		t.Run(item.name, func(t *testing.T) {
			now := time.Unix(1_900_000_000, 0).UTC()
			server := &usageServer{}
			var waits []time.Duration
			used := int64(3)
			collect := func(context.Context) (time.Time, []UsageValue, error) {
				return now, usageValues(used), nil
			}
			first := newTestUsageReporter(t, server, &fakeLeaseStore{serial: 9}, &now, collect, &waits)
			if err := first.ReportOnce(t.Context()); err != nil {
				t.Fatal(err)
			}
			config := first.config
			now = now.Add(item.clockDelta)
			used = 4
			restarted, err := NewUsageReporter(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := restarted.ReportOnce(t.Context()); err != nil {
				t.Fatal(err)
			}
			prior := uint64(server.bodies[0]["sequence"].(float64))
			next := uint64(server.bodies[1]["sequence"].(float64))
			if next <= prior || server.keys[0] == server.keys[1] {
				t.Fatalf("sequence fence lost across restart: next %d must exceed prior %d (keys %q %q)", next, prior, server.keys[0], server.keys[1])
			}
		})
	}
}

// 未确认的报文跨重启按原字节、原幂等键重发，不重新采集、不重签变化的正文；确认后下一轮才分配新序号。
func TestUsageReporterPendingResentVerbatimAfterRestart(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	server := &usageServer{statuses: []int{503}}
	var waits []time.Duration
	used := int64(3)
	collects := 0
	collect := func(context.Context) (time.Time, []UsageValue, error) { collects++; return now, usageValues(used), nil }
	first := newTestUsageReporter(t, server, &fakeLeaseStore{serial: 9}, &now, collect, &waits)
	first.config.Wait = func(context.Context, time.Duration) error { return context.Canceled } // 进程在重试前退出
	if err := first.ReportOnce(t.Context()); err == nil {
		t.Fatal("first round must not succeed")
	}
	config := first.config
	config.Wait = func(ctx context.Context, delay time.Duration) error { now = now.Add(delay); return ctx.Err() }
	used = 4
	restarted, err := NewUsageReporter(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ReportOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if collects != 1 || len(server.bodies) != 2 || server.keys[0] != server.keys[1] ||
		server.bodies[1]["values"].([]any)[0].(map[string]any)["used"].(float64) != 3 {
		t.Fatalf("pending not resent verbatim: collects=%d keys=%v bodies=%v", collects, server.keys, server.bodies)
	}
	if err := restarted.ReportOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if collects != 2 || len(server.bodies) != 3 || server.bodies[2]["sequence"].(float64) <= server.bodies[1]["sequence"].(float64) {
		t.Fatalf("next round after ack: collects=%d bodies=%v", collects, server.bodies)
	}
}

// 租约已换且旧报文明确 usage_lease_unknown：终结旧 pending，下一轮用新租约和更大序号。
func TestUsageReporterLeaseUnknownAbandonsPending(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	server := &usageServer{statuses: []int{409}, codes: []string{"usage_lease_unknown"}}
	var waits []time.Duration
	leases := &fakeLeaseStore{serial: 9}
	collect := func(context.Context) (time.Time, []UsageValue, error) { return now, usageValues(1), nil }
	reporter := newTestUsageReporter(t, server, leases, &now, collect, &waits)
	if err := reporter.ReportOnce(t.Context()); err == nil {
		t.Fatal("lease unknown must fail the round")
	}
	leases.mu.Lock()
	leases.serial = 10
	leases.mu.Unlock()
	if err := reporter.ReportOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(server.bodies) != 2 || server.bodies[1]["lease_serial"].(float64) != 10 ||
		server.bodies[1]["sequence"].(float64) <= server.bodies[0]["sequence"].(float64) || server.keys[0] == server.keys[1] {
		t.Fatalf("bodies=%v keys=%v", server.bodies, server.keys)
	}
}

// 非终结的 4xx（如安装暂时被拒）不清 pending、不越过它发新一轮：下一轮仍重发原报文。
func TestUsageReporterDefinitiveFailureKeepsPending(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	server := &usageServer{statuses: []int{403, 201}, codes: []string{"installation_denied"}}
	var waits []time.Duration
	collects := 0
	collect := func(context.Context) (time.Time, []UsageValue, error) { collects++; return now, usageValues(1), nil }
	reporter := newTestUsageReporter(t, server, &fakeLeaseStore{serial: 9}, &now, collect, &waits)
	if err := reporter.ReportOnce(t.Context()); err == nil {
		t.Fatal("conflict must fail the round")
	}
	if err := reporter.ReportOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if collects != 1 || server.keys[0] != server.keys[1] {
		t.Fatalf("collects=%d keys=%v", collects, server.keys)
	}
}

// 持久状态写不进去时不发送未落盘的报文。
func TestUsageReporterStateUnavailableDoesNotSend(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	server := &usageServer{}
	var waits []time.Duration
	collect := func(context.Context) (time.Time, []UsageValue, error) { return now, usageValues(1), nil }
	reporter := newTestUsageReporter(t, server, &fakeLeaseStore{serial: 9}, &now, collect, &waits)
	reporter.config.State.(*memoryUsageState).err = errors.New("database down")
	if err := reporter.ReportOnce(t.Context()); err == nil || len(server.bodies) != 0 {
		t.Fatalf("err=%v sent=%d", err, len(server.bodies))
	}
}

// 序号已被别的请求占用（如从旧备份恢复的实例）：终结 pending，下一轮分配更大的序号，不放宽接收端栅栏。
func TestUsageReporterSequenceConflictMovesPast(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	server := &usageServer{statuses: []int{409}, codes: []string{"usage_sequence_conflict"}}
	var waits []time.Duration
	collect := func(context.Context) (time.Time, []UsageValue, error) { return now, usageValues(1), nil }
	reporter := newTestUsageReporter(t, server, &fakeLeaseStore{serial: 9}, &now, collect, &waits)
	if err := reporter.ReportOnce(t.Context()); err == nil {
		t.Fatal("conflict must fail the round")
	}
	if err := reporter.ReportOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if server.bodies[1]["sequence"].(float64) <= server.bodies[0]["sequence"].(float64) {
		t.Fatalf("bodies=%v", server.bodies)
	}
}

// 迟到的旧一轮确认不能清掉后来的 pending。
func TestUsageStateLateSettleKeepsNewerPending(t *testing.T) {
	state := &memoryUsageState{}
	first, _ := state.Reserve(t.Context(), [16]byte{}, func(uint64) (usageReport, error) {
		return usageReport{sequence: 5, requestID: "a"}, nil
	}, time.Time{})
	_ = state.Settle(t.Context(), [16]byte{}, first)
	second, _ := state.Reserve(t.Context(), [16]byte{}, func(previous uint64) (usageReport, error) {
		return usageReport{sequence: previous + 1, requestID: "b"}, nil
	}, time.Time{})
	_ = state.Settle(t.Context(), [16]byte{}, first)
	if pending, found, _ := state.Pending(t.Context(), [16]byte{}); !found || pending.requestID != second.requestID {
		t.Fatalf("pending=%v found=%v", pending, found)
	}
}
