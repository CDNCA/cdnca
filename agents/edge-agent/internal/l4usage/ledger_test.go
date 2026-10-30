package l4usage

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4live"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

const (
	tenant   = "11111111-1111-4111-8111-111111111111"
	site     = "22222222-2222-4222-8222-222222222222"
	node     = "33333333-3333-4333-8333-333333333333"
	stream   = "44444444-4444-4444-8444-444444444444"
	version  = "55555555-5555-4555-8555-555555555555"
	pkg      = "66666666-6666-4666-8666-666666666666"
	listener = stream
)

var (
	local = netip.MustParseAddrPort("203.0.113.10:18080")
	peer  = netip.MustParseAddrPort("198.51.100.7:40001")
	start = time.Date(2026, 1, 31, 23, 58, 30, 0, time.UTC)
)

type fakeClock struct{ now time.Time }

func (clock *fakeClock) Now() time.Time { return clock.now }

type fakeSource struct {
	sockets  []l4live.Socket
	registry map[string]string
	err      error
	gets     int
}

func (source *fakeSource) Established(context.Context, []uint16) ([]l4live.Socket, error) {
	return source.sockets, source.err
}

func (source *fakeSource) Get(_ context.Context, keys []string) (map[string]string, error) {
	if len(keys) > registryBatch {
		return nil, errors.New("control socket refuses more than 20000 keys")
	}
	source.gets++
	result := map[string]string{}
	for _, key := range keys {
		if value, ok := source.registry[key]; ok {
			result[key] = value
		}
	}
	return result, nil
}

func (source *fakeSource) set(up, down uint64) {
	source.sockets = []l4live.Socket{{Local: local, Peer: peer, BytesReceived: &up, BytesSent: &down}}
}

type fakeSink struct {
	appended []eventspool.Envelope
	fail     error
}

func (sink *fakeSink) AppendBatch(_ context.Context, envelopes []eventspool.Envelope) ([]eventspool.AppendResult, error) {
	if sink.fail != nil {
		return nil, sink.fail
	}
	results := make([]eventspool.AppendResult, len(envelopes))
	for index, envelope := range envelopes {
		duplicate := false
		for _, existing := range sink.appended {
			if existing.EventID == envelope.EventID {
				duplicate = true
			}
		}
		results[index] = eventspool.AppendResult{EventID: envelope.EventID, Duplicate: duplicate}
		if !duplicate {
			sink.appended = append(sink.appended, envelope)
		}
	}
	return results, nil
}

func sockets() map[string]l4runtime.UsageSocketV2 {
	return map[string]l4runtime.UsageSocketV2{listener: {ListenerID: listener, StreamID: stream, TenantID: tenant, SiteID: site,
		ConfigVersionID: version, ConfigRevision: 9, PackageSubscriptionID: pkg, Port: 18080}}
}

func newLedger(t *testing.T, dir string, clock *fakeClock, source *fakeSource) *Ledger {
	t.Helper()
	ledger, err := New(Config{StatePath: filepath.Join(dir, "l4-usage.json"), NodeID: node, Now: clock.Now,
		Kernel: source, Registry: source, Sockets: func(context.Context) (map[string]l4runtime.UsageSocketV2, error) {
			return sockets(), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

// endEvent is the l4_session.v1 event of the session's end line (nginx
// l4_session_v1 with $pid), as the tailer parses it.
func endEvent(t *testing.T, pid, connection string, up, down uint64) eventspool.Envelope {
	t.Helper()
	line := `{"time":"2026-02-01T00:30:00Z","connection":"` + connection + `"`
	if pid != "" {
		line += `,"pid":"` + pid + `"`
	}
	line += `,"protocol":"TCP","server_port":"18080","status":"200","bytes_sent":` + strconv.FormatUint(down, 10) +
		`,"bytes_received":` + strconv.FormatUint(up, 10) + `,"session_time":1800}`
	envelope, err := eventspool.ParseL4SourceLineBound([]byte(line), eventspool.TrustedIdentity{EnrollmentNodeID: node,
		TenantID: tenant, SiteID: site, ConfigVersionID: version, StreamID: stream, ListenerID: listener, ConfigRevision: 9,
		PackageSubscriptionID: pkg})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

// registry value as cdnca_l4_geo session_track writes it.
func registryValue() string {
	return stream + "|" + listener + "|198.51.100.7|40001|1769903910.000|4242:17|0"
}

// 长会话跨多个检查点、跨月：每 60 秒写一次增量，序号连续，按检查点时间落月；
// 字节不变不写；结束行补最终增量并带已检查点字节；之后迟到的检查点不再写。
func TestLongSessionCheckpointsAcrossMonthsThenFinalDelta(t *testing.T) {
	dir := t.TempDir()
	clock := &fakeClock{now: start.Add(30 * time.Second)} // 2026-01-31 23:59:00
	source := &fakeSource{registry: map[string]string{l4live.SessionKey(local, peer): registryValue()}}
	sink := &fakeSink{}
	ledger := newLedger(t, dir, clock, source)

	source.set(100, 1000)
	if err := ledger.Checkpoint(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(time.Minute) // 2026-02-01 00:00:00
	source.set(150, 5000)
	if err := ledger.Checkpoint(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(time.Minute)
	if err := ledger.Checkpoint(context.Background(), sink); err != nil { // no bytes moved
		t.Fatal(err)
	}
	if len(sink.appended) != 2 {
		t.Fatalf("checkpoints = %d, want 2", len(sink.appended))
	}
	first, second := sink.appended[0], sink.appended[1]
	if first.Type != eventspool.EventL4Checkpoint || first.CheckpointSequence != 1 || first.RequestBytes != 100 ||
		first.ResponseBytes != 1000 || first.OccurredAt.Month() != time.January || first.SessionID != "17" ||
		!first.StartedAt.Equal(time.Unix(1769903910, 0).UTC()) || first.PackageSubscriptionID != pkg || first.ListenPort != 18080 {
		t.Fatalf("first = %+v", first)
	}
	if second.CheckpointSequence != 2 || second.RequestBytes != 50 || second.ResponseBytes != 4000 ||
		second.OccurredAt.Month() != time.February || second.EventID == first.EventID {
		t.Fatalf("second = %+v", second)
	}

	// 会话结束：结束行的 $pid:$connection 对上登记，写已检查点字节，立墓碑。
	session := ledger.Settle(endEvent(t, "4242", "17", 170, 6000))
	if session.CheckpointedRequestBytes != 150 || session.CheckpointedResponseBytes != 5000 {
		t.Fatalf("settled = %d/%d", session.CheckpointedRequestBytes, session.CheckpointedResponseBytes)
	}
	// 最终增量 = 170-150 / 6000-5000；三者之和等于会话总字节（不双计）。
	if total := first.RequestBytes + second.RequestBytes + (session.RequestBytes - session.CheckpointedRequestBytes); total != 170 {
		t.Fatalf("up total = %d", total)
	}
	// 结束后内核还没回收的同一连接：不再写检查点。
	clock.now = clock.now.Add(time.Minute)
	source.set(170, 6000)
	if err := ledger.Checkpoint(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.appended) != 2 {
		t.Fatalf("checkpoint after the end = %d", len(sink.appended))
	}
}

// 重复上报去重：写入 spool 前先把待写检查点落盘（写前日志）；spool 写入失败、
// 进程重启后原样重写同一事件 ID（spool 按事件 ID 去重），序号不跳不重。
func TestCheckpointReplayAfterFailureKeepsTheSameIdentity(t *testing.T) {
	dir := t.TempDir()
	clock := &fakeClock{now: start}
	source := &fakeSource{registry: map[string]string{l4live.SessionKey(local, peer): registryValue()}}
	ledger := newLedger(t, dir, clock, source)
	source.set(10, 20)
	failing := &fakeSink{fail: errors.New("spool full")}
	if err := ledger.Checkpoint(context.Background(), failing); err == nil {
		t.Fatal("spool failure not reported")
	}
	// restart: a new ledger on the same state file, bytes moved meanwhile
	clock.now = clock.now.Add(time.Minute)
	source.set(30, 90)
	restarted := newLedger(t, dir, clock, source)
	sink := &fakeSink{}
	if err := restarted.Checkpoint(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.appended) != 2 || sink.appended[0].CheckpointSequence != 1 || sink.appended[0].RequestBytes != 10 ||
		!sink.appended[0].OccurredAt.Equal(start) || sink.appended[1].CheckpointSequence != 2 || sink.appended[1].RequestBytes != 20 {
		t.Fatalf("after restart = %+v", sink.appended)
	}
	firstID := sink.appended[0].EventID
	// the same pending replayed twice is the same event (spool dedupes it)
	again := newLedger(t, dir, clock, source)
	if err := again.Checkpoint(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.appended) != 2 || sink.appended[0].EventID != firstID {
		t.Fatalf("replay = %+v", sink.appended)
	}
	// the ledger survives a restart: the end of the session settles all of it
	session := again.Settle(endEvent(t, "4242", "17", 40, 100))
	if session.CheckpointedRequestBytes != 30 || session.CheckpointedResponseBytes != 90 {
		t.Fatalf("settled = %d/%d", session.CheckpointedRequestBytes, session.CheckpointedResponseBytes)
	}
}

// 未登记、登记属于别的转发、监听不在当前配置的连接不写检查点；没有 pid 的
// 结束行不认领；内核读不到时整轮不写（不会写错身份）。
func TestCheckpointSkipsUnattributableSessions(t *testing.T) {
	dir := t.TempDir()
	clock := &fakeClock{now: start}
	source := &fakeSource{registry: map[string]string{}}
	ledger := newLedger(t, dir, clock, source)
	sink := &fakeSink{}
	source.set(10, 20)
	for name, value := range map[string]string{
		"untracked":       "",
		"other listener":  stream + "|77777777-7777-4777-8777-777777777777|198.51.100.7|40001|1769903910.000|4242:17|0",
		"malformed":       "x|y",
		"zero start":      stream + "|" + listener + "|198.51.100.7|40001|0|4242:17|0",
		"bad token":       stream + "|" + listener + "|198.51.100.7|40001|1769903910.000|17|0",
		"listener stream": "77777777-7777-4777-8777-777777777777|" + listener + "|198.51.100.7|40001|1769903910.000|4242:17|0",
	} {
		source.registry = map[string]string{}
		if value != "" {
			source.registry[l4live.SessionKey(local, peer)] = value
		}
		if err := ledger.Checkpoint(context.Background(), sink); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(sink.appended) != 0 {
			t.Fatalf("%s: checkpoint written %+v", name, sink.appended)
		}
	}
	source.registry = map[string]string{l4live.SessionKey(local, peer): registryValue()}
	source.err = errors.New("sock_diag")
	if err := ledger.Checkpoint(context.Background(), sink); err == nil || len(sink.appended) != 0 {
		t.Fatalf("kernel failure: err=%v appended=%d", err, len(sink.appended))
	}
	if settled := ledger.Settle(endEvent(t, "", "17", 9, 9)); settled.CheckpointedRequestBytes != 0 {
		t.Fatal("a line without its worker pid was settled")
	}
}

// 内核计数器只增不减；同一元组换了新会话（登记 token 不同）从 0 重新计。
func TestCheckpointNewSessionOnTheSameTuple(t *testing.T) {
	dir := t.TempDir()
	clock := &fakeClock{now: start}
	source := &fakeSource{registry: map[string]string{l4live.SessionKey(local, peer): registryValue()}}
	ledger := newLedger(t, dir, clock, source)
	sink := &fakeSink{}
	source.set(500, 500)
	if err := ledger.Checkpoint(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(time.Minute)
	source.registry[l4live.SessionKey(local, peer)] = stream + "|" + listener + "|198.51.100.7|40001|1769904000.000|4243:3|0"
	source.set(7, 8)
	if err := ledger.Checkpoint(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.appended) != 2 || sink.appended[1].SessionID != "3" || sink.appended[1].CheckpointSequence != 1 ||
		sink.appended[1].RequestBytes != 7 {
		t.Fatalf("new session = %+v", sink.appended)
	}
}

// 连接数超过控制口单次上限时分批读登记表，不整轮失败。
func TestCheckpointReadsTheRegistryInBatches(t *testing.T) {
	dir := t.TempDir()
	clock := &fakeClock{now: start}
	source := &fakeSource{registry: map[string]string{}}
	ledger := newLedger(t, dir, clock, source)
	up, down := uint64(1), uint64(1)
	for index := 0; index < registryBatch+5; index++ {
		client := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(index >> 8), byte(index)}), 40001)
		source.sockets = append(source.sockets, l4live.Socket{Local: local, Peer: client, BytesReceived: &up, BytesSent: &down})
	}
	source.registry[l4live.SessionKey(local, source.sockets[len(source.sockets)-1].Peer)] = registryValue()
	sink := &fakeSink{}
	if err := ledger.Checkpoint(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	if source.gets != 2 || len(sink.appended) != 1 {
		t.Fatalf("gets=%d checkpoints=%d", source.gets, len(sink.appended))
	}
}
