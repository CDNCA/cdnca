package analytics

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// 73 演示站 30 分钟 13 条「analytics terminal evidence recovery stopped ...
// nats: message was already acknowledged」。第一次结算是处理器自己的 NAK：
// isolateOrRetry 里 RecordTerminal 返回可重试错误前已把恢复任务入队，随后
// processor.nak 在同一个 *nats.Msg 上 NAK（客户端 ackd 置 1）；恢复 worker 确认
// 证据后再 Term 同一对象，nats.go 客户端短路返回 ErrMsgAlreadyAckd，TERM 未上线。
// 证据已确认、标记停在 term_pending，NAK 的重投经 TerminalEvidenceConfirmed 补 Term，
// 不重复隔离也不计数，属良性竞争，不应打 Error。
func TestTerminalEvidenceRecoveryAfterProcessorNakFinishesWithoutError(t *testing.T) {
	for _, test := range []struct {
		name         string
		nakFirst     bool
		wantPhase    parkedDeliveryPhase
		wantTermSent bool
		wantSettles  []string
	}{
		{name: "processor NAK settled the delivery first", nakFirst: true,
			wantPhase: parkedPhaseTermPending, wantSettles: []string{`-NAK {"delay": 1000000000}`}},
		{name: "unsettled delivery is terminated by recovery", wantPhase: parkedPhaseSettled,
			wantTermSent: true, wantSettles: []string{"+TERM"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRecoveryAckFixture(t)
			if test.nakFirst {
				if err := fixture.delivery.Nak(context.Background(), time.Second); err != nil {
					t.Fatalf("processor NAK: %v", err)
				}
			}
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			defer slog.SetDefault(previous)

			fixture.sink.startTerminalEvidenceRecovery(fixture.delivery, fixture.intent)
			fixture.waitRecoveryFinished(t)

			if strings.Contains(logs.String(), "recovery stopped") {
				t.Fatalf("benign already-settled delivery logged an error: %s", logs.String())
			}
			state := fixture.parkedState(t)
			if state.Phase != test.wantPhase || state.TermSent != test.wantTermSent || !state.EvidenceConfirmed {
				t.Fatalf("parked state = %+v, want phase %s term_sent %t", state, test.wantPhase, test.wantTermSent)
			}
			if settles := fixture.server.settlements(t); !slicesEqual(settles, test.wantSettles) {
				t.Fatalf("broker settlements = %v, want %v", settles, test.wantSettles)
			}
		})
	}
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type recoveryAckFixture struct {
	consumer *NATSIngestConsumer
	sink     *NATSIsolationSink
	delivery *natsIngestDelivery
	intent   isolationPublishIntent
	state    *memoryKeyValue
	server   *settlementRecordingServer
}

func newRecoveryAckFixture(t *testing.T) *recoveryAckFixture {
	t.Helper()
	const (
		sourceSequence   = 42
		evidenceSequence = 7
		ownerID          = "owner-a"
	)
	config := DefaultJetStreamConfig()
	config.OperationTimeout = 2 * time.Second
	streamCreated := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	isolationCreated := streamCreated.Add(time.Hour)

	server := newSettlementRecordingServer(t)
	connection, err := nats.Connect("nats://in-process", nats.InProcessServer(server), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	subscription, err := connection.SubscribeSync("analytics.ingest.recovery-ack")
	if err != nil {
		t.Fatal(err)
	}
	message := &nats.Msg{
		Subject: IngestSubjectPrefix + ".node", Reply: "$JS.ACK.recovery-ack", Sub: subscription,
		Header: nats.Header{nats.MsgIdHdr: []string{"batch-recovery-ack"}}, Data: []byte("{"),
	}

	payload := []byte(`{"reason_code":"INVALID_JSON"}`)
	intent := isolationPublishIntent{
		Subject: IsolationSubject, Stream: config.IsolationStream,
		MessageID: "analytics-isolation-v1-recovery-ack", Payload: payload, PayloadSHA256: sha256.Sum256(payload),
		ScanStart: 1, StreamCreated: isolationCreated,
	}
	evidence := newMemoryKeyValue()
	blobDigest, err := persistIsolationEvidenceBlob(context.Background(), evidence, intent, streamCreated, sourceSequence)
	if err != nil {
		t.Fatal(err)
	}
	sourceDigest := sha256.Sum256(message.Data)
	filler := strings.Repeat("ab", sha256.Size)
	state := parkedDeliveryState{
		StreamCreated: streamCreated.Format(time.RFC3339Nano), OwnerID: ownerID, Terminal: true,
		Phase: parkedPhaseEvidenceConfirmed, MessageID: "batch-recovery-ack", ReasonCode: "INVALID_JSON",
		PayloadSHA256: hex.EncodeToString(sourceDigest[:]), EvidenceMessageID: intent.MessageID,
		EvidenceConfirmed: true, EvidencePayloadSHA256: hex.EncodeToString(intent.PayloadSHA256[:]),
		EvidenceBlobSHA256: hex.EncodeToString(blobDigest[:]), EvidenceWireSHA256: filler, EvidenceKeySHA256: filler,
		EvidenceNonce:      base64.RawStdEncoding.EncodeToString(make([]byte, 12)),
		EvidenceIsolatedAt: streamCreated.Format(time.RFC3339Nano), EvidenceAttempts: 1,
		EvidenceStreamCreated: isolationCreated.Format(time.RFC3339Nano), EvidenceScanStart: 1,
		EvidenceSequence: evidenceSequence,
	}
	encodedState, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	parked := newMemoryKeyValue()
	if _, err := parked.Create(fmt.Sprintf("parked.%020d", sourceSequence), encodedState); err != nil {
		t.Fatal(err)
	}
	lease := newMemoryKeyValue()
	leaseRevision, err := lease.Create("active", []byte(ownerID))
	if err != nil {
		t.Fatal(err)
	}
	jetstream := &recoveryAckJetStream{
		info: &nats.StreamInfo{Config: *expectedIsolationStream(config), Created: isolationCreated,
			State: nats.StreamState{FirstSeq: 1, LastSeq: evidenceSequence}},
		stored: &nats.RawStreamMsg{
			Subject: IsolationSubject, Sequence: evidenceSequence, Data: payload,
			Header: nats.Header{
				nats.MsgIdHdr: []string{intent.MessageID}, nats.ExpectedStreamHdr: []string{config.IsolationStream},
				nats.ExpectedLastSeqHdr: []string{"6"},
			},
		},
	}
	lifecycleCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	consumer := &NATSIngestConsumer{
		jetstream: jetstream, config: config, stateStore: parked, leaseStore: lease, evidenceStore: evidence,
		streamCreated: streamCreated, leaseRevision: leaseRevision, ownerID: ownerID, lifecycleCtx: lifecycleCtx,
	}
	sink := &NATSIsolationSink{
		jetstream: jetstream, stream: config.IsolationStream, streamCreated: isolationCreated,
		expectedStream: *expectedIsolationStream(config), operationTimeout: config.OperationTimeout,
		scanLimit: isolationEvidenceScanBatch, stateStore: parked, evidenceStore: evidence,
		recovering:   make(map[string]*isolationRecoveryTask),
		recoveryWake: make(chan struct{}, isolationEvidenceRecoveryWorkers),
	}
	sink.recoveryCond = sync.NewCond(&sink.recoveryMu)
	delivery := &natsIngestDelivery{message: message, attempts: 1, streamSequence: sourceSequence, consumer: consumer}
	intent.delivery = delivery
	return &recoveryAckFixture{
		consumer: consumer, sink: sink, delivery: delivery, intent: intent, state: parked, server: server,
	}
}

func (fixture *recoveryAckFixture) waitRecoveryFinished(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fixture.consumer.recoveryWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("terminal evidence recovery did not finish")
	}
}

func (fixture *recoveryAckFixture) parkedState(t *testing.T) parkedDeliveryState {
	t.Helper()
	entry, err := fixture.state.Get(fmt.Sprintf("parked.%020d", fixture.delivery.streamSequence))
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeParkedDeliveryState(entry.Value(), fixture.delivery.streamSequence)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// memoryKeyValue 只实现恢复路径用到的 Get/Create/Update/Delete，按修订号 CAS。
type memoryKeyValue struct {
	nats.KeyValue
	mu       sync.Mutex
	revision uint64
	entries  map[string]memoryKeyValueEntry
}

type memoryKeyValueEntry struct {
	nats.KeyValueEntry
	key      string
	value    []byte
	revision uint64
}

func (entry memoryKeyValueEntry) Key() string      { return entry.key }
func (entry memoryKeyValueEntry) Value() []byte    { return entry.value }
func (entry memoryKeyValueEntry) Revision() uint64 { return entry.revision }

func newMemoryKeyValue() *memoryKeyValue {
	return &memoryKeyValue{entries: make(map[string]memoryKeyValueEntry)}
}

func (store *memoryKeyValue) Get(key string) (nats.KeyValueEntry, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.entries[key]
	if !ok {
		return nil, nats.ErrKeyNotFound
	}
	return entry, nil
}

func (store *memoryKeyValue) put(key string, value []byte) uint64 {
	store.revision++
	store.entries[key] = memoryKeyValueEntry{key: key, value: append([]byte(nil), value...), revision: store.revision}
	return store.revision
}

func (store *memoryKeyValue) Create(key string, value []byte) (uint64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.entries[key]; ok {
		return 0, nats.ErrKeyExists
	}
	return store.put(key, value), nil
}

func (store *memoryKeyValue) Update(key string, value []byte, last uint64) (uint64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if entry, ok := store.entries[key]; !ok || entry.revision != last {
		return 0, nats.ErrKeyExists
	}
	return store.put(key, value), nil
}

func (store *memoryKeyValue) Delete(key string, _ ...nats.DeleteOpt) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.entries, key)
	return nil
}

// recoveryAckJetStream 只回答隔离流信息和已存证据读取。
type recoveryAckJetStream struct {
	nats.JetStreamContext
	info   *nats.StreamInfo
	stored *nats.RawStreamMsg
}

func (jetstream *recoveryAckJetStream) StreamInfo(name string, _ ...nats.JSOpt) (*nats.StreamInfo, error) {
	if name != jetstream.info.Config.Name {
		return nil, nats.ErrStreamNotFound
	}
	return jetstream.info, nil
}

func (jetstream *recoveryAckJetStream) GetMsg(name string, sequence uint64, _ ...nats.JSOpt) (*nats.RawStreamMsg, error) {
	if name != jetstream.info.Config.Name || sequence != jetstream.stored.Sequence {
		return nil, nats.ErrMsgNotFound
	}
	return jetstream.stored, nil
}

// settlementRecordingServer 是进程内最小 NATS 协议端：完成握手，记录发往
// $JS.ACK 回复主题的结算体（+ACK/-NAK/+TERM），并像 JetStream 一样给带 reply 的
// 同步结算回一个空包。用它区分「结算真的发到 broker」与「客户端 ackd 短路」。
type settlementRecordingServer struct {
	mu      sync.Mutex
	subs    map[string]string // sid -> subject
	settles []string
}

func newSettlementRecordingServer(t *testing.T) *settlementRecordingServer {
	t.Helper()
	return &settlementRecordingServer{subs: make(map[string]string)}
}

func (server *settlementRecordingServer) InProcessConn() (net.Conn, error) {
	client, peer := net.Pipe()
	go server.serve(peer)
	return client, nil
}

func (server *settlementRecordingServer) serve(conn net.Conn) {
	defer conn.Close()
	writer := bufio.NewWriter(conn)
	var writeMu sync.Mutex
	send := func(data string) bool {
		writeMu.Lock()
		defer writeMu.Unlock()
		if _, err := writer.WriteString(data); err != nil {
			return false
		}
		return writer.Flush() == nil
	}
	if !send(`INFO {"server_id":"recovery-ack","version":"2.10.0","proto":1,"headers":true,"max_payload":1048576}` + "\r\n") {
		return
	}
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "PING":
			if !send("PONG\r\n") {
				return
			}
		case "SUB":
			if len(fields) >= 3 {
				server.mu.Lock()
				server.subs[fields[len(fields)-1]] = fields[1]
				server.mu.Unlock()
			}
		case "PUB", "HPUB":
			size, err := strconv.Atoi(fields[len(fields)-1])
			if err != nil || len(fields) < 3 {
				return
			}
			body := make([]byte, size+2)
			if _, err := io.ReadFull(reader, body); err != nil {
				return
			}
			subject := fields[1]
			if !strings.HasPrefix(subject, "$JS.ACK.") {
				continue
			}
			server.mu.Lock()
			server.settles = append(server.settles, string(body[:size]))
			replyTo := ""
			if (fields[0] == "PUB" && len(fields) == 4) || (fields[0] == "HPUB" && len(fields) == 5) {
				replyTo = fields[2]
			}
			sid := ""
			for candidate, pattern := range server.subs {
				if subjectMatches(pattern, replyTo) {
					sid = candidate
				}
			}
			server.mu.Unlock()
			if replyTo != "" && sid != "" && !send("MSG "+replyTo+" "+sid+" 0\r\n\r\n") {
				return
			}
		}
	}
}

func subjectMatches(pattern, subject string) bool {
	if subject == "" {
		return false
	}
	patternTokens, subjectTokens := strings.Split(pattern, "."), strings.Split(subject, ".")
	for index, token := range patternTokens {
		if token == ">" {
			return len(subjectTokens) > index
		}
		if index >= len(subjectTokens) || (token != "*" && token != subjectTokens[index]) {
			return false
		}
	}
	return len(patternTokens) == len(subjectTokens)
}

func (server *settlementRecordingServer) settlements(t *testing.T) []string {
	t.Helper()
	server.mu.Lock()
	defer server.mu.Unlock()
	return append([]string(nil), server.settles...)
}
