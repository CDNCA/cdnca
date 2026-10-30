package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
)

type probeEvent struct {
	EventID    string    `json:"event_id"`
	OccurredAt time.Time `json:"occurred_at"`
}

func main() {
	if err := obsJetStreamProbe(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL jetstream-probe:", err)
		os.Exit(1)
	}
}

func obsJetStreamProbe() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: jetstream_probe NATS_URL RECONNECT_URL_FILE")
	}
	disconnected := make(chan struct{}, 1)
	var disconnects atomic.Uint32
	var reconnects atomic.Uint32
	nc, err := nats.Connect(os.Args[1],
		nats.Name("cdnca-analytics-observability-probe"),
		nats.Timeout(2*time.Second),
		nats.MaxReconnects(300),
		nats.ReconnectWait(100*time.Millisecond),
		nats.ReconnectBufSize(1<<20),
		nats.DisconnectErrHandler(func(_ *nats.Conn, _ error) {
			disconnects.Add(1)
			select {
			case disconnected <- struct{}{}:
			default:
			}
		}),
	)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer nc.Close()
	js, err := nc.JetStream(nats.MaxWait(3 * time.Second))
	if err != nil {
		return fmt.Errorf("jetstream context: %w", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	stream := "OBS_ANALYTICS_" + suffix
	durable := "obs_analytics_" + suffix
	defer js.DeleteStream(stream)
	if _, err = js.AddStream(&nats.StreamConfig{
		Name: stream, Subjects: []string{"cdnca.analytics.ingest.v1.*"},
		Storage: nats.FileStorage, Retention: nats.LimitsPolicy,
		Duplicates: 2 * time.Minute,
	}); err != nil {
		return fmt.Errorf("add stream: %w", err)
	}
	if _, err = js.AddConsumer(stream, &nats.ConsumerConfig{
		Durable: durable, AckPolicy: nats.AckExplicitPolicy,
		FilterSubject: "cdnca.analytics.ingest.v1.*", AckWait: 2 * time.Second,
	}); err != nil {
		return fmt.Errorf("add consumer: %w", err)
	}

	nodeID := "30000000-0000-4000-8000-000000000001"
	tenantID := "10000000-0000-4000-8000-000000000001"
	siteID := "20000000-0000-4000-8000-000000000001"
	configID := "40000000-0000-4000-8000-000000000001"
	subject := "cdnca.analytics.ingest.v1." + nodeID
	base := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	publish := func(event probeEvent, messageID string) (*nats.PubAck, error) {
		payload, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			return nil, marshalErr
		}
		message := nats.NewMsg(subject)
		message.Data = payload
		message.Header.Set(nats.MsgIdHdr, messageID)
		message.Header.Set("Cdnca-Node-Id", nodeID)
		message.Header.Set("Cdnca-Tenant-Id", tenantID)
		message.Header.Set("Cdnca-Site-Id", siteID)
		message.Header.Set("Cdnca-Config-Version-Id", configID)
		message.Header.Set("Cdnca-Installation-Id", "installation-probe-v1")
		return js.PublishMsg(message, nats.ExpectStream(stream))
	}

	publicationOrder := []int{3, 1, 2}
	for _, order := range publicationOrder {
		ack, publishErr := publish(probeEvent{
			EventID: fmt.Sprintf("probe-%d", order), OccurredAt: base.Add(time.Duration(order) * time.Second),
		}, fmt.Sprintf("probe-message-%d", order))
		if publishErr != nil || ack.Duplicate {
			return fmt.Errorf("publish out-of-order event %d: ack=%+v err=%v", order, ack, publishErr)
		}
	}
	duplicateAck, err := publish(probeEvent{EventID: "probe-2", OccurredAt: base.Add(2 * time.Second)}, "probe-message-2")
	if err != nil || !duplicateAck.Duplicate {
		return fmt.Errorf("Nats-Msg-Id duplicate was not suppressed: ack=%+v err=%v", duplicateAck, err)
	}

	fmt.Println("OBS_NATS_READY_FOR_RESTART")
	select {
	case <-disconnected:
	case <-time.After(15 * time.Second):
		return fmt.Errorf("server restart did not disconnect the client")
	}
	offlineQueuedAt := time.Now()
	nc.Close()
	reconnectDeadline := time.Now().Add(55 * time.Second)
	var reconnectURL string
	for {
		reconnectURLBytes, readErr := os.ReadFile(os.Args[2])
		reconnectURL = strings.TrimSpace(string(reconnectURLBytes))
		if readErr == nil && reconnectURL != "" {
			nc, err = nats.Connect(reconnectURL, nats.Name("cdnca-analytics-observability-reconnect"),
				nats.Timeout(time.Second), nats.NoReconnect())
			if err == nil {
				reconnects.Add(1)
				break
			}
		} else {
			err = readErr
		}
		if time.Now().After(reconnectDeadline) {
			return fmt.Errorf("explicit reconnect failed within 55s: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer nc.Close()
	js, err = nc.JetStream(nats.MaxWait(3 * time.Second))
	if err != nil {
		return fmt.Errorf("reconnect jetstream context: %w", err)
	}
	if _, err = publish(probeEvent{EventID: "probe-0", OccurredAt: base}, "probe-message-0"); err != nil {
		return fmt.Errorf("retry stable offline event after reconnect: %w", err)
	}

	sub, err := js.PullSubscribe("cdnca.analytics.ingest.v1.*", durable, nats.Bind(stream, durable))
	if err != nil {
		return fmt.Errorf("bind durable: %w", err)
	}
	defer sub.Unsubscribe()
	messages, err := sub.Fetch(4, nats.MaxWait(10*time.Second))
	if err != nil || len(messages) != 4 {
		return fmt.Errorf("fetch durable messages: count=%d err=%v", len(messages), err)
	}
	gotPublicationOrder := make([]string, 0, len(messages))
	chronological := make([]probeEvent, 0, len(messages))
	var previousSequence uint64
	for _, message := range messages {
		if message.Subject != subject {
			return fmt.Errorf("durable delivered unexpected subject %s", message.Subject)
		}
		var event probeEvent
		if err = json.Unmarshal(message.Data, &event); err != nil {
			return fmt.Errorf("decode message: %w", err)
		}
		metadata, metadataErr := message.Metadata()
		if metadataErr != nil || metadata.Sequence.Stream <= previousSequence {
			return fmt.Errorf("stream sequence is not monotonic: metadata=%+v err=%v", metadata, metadataErr)
		}
		previousSequence = metadata.Sequence.Stream
		for header, want := range map[string]string{
			nats.MsgIdHdr: message.Header.Get(nats.MsgIdHdr), "Cdnca-Node-Id": nodeID,
			"Cdnca-Tenant-Id": tenantID, "Cdnca-Site-Id": siteID,
			"Cdnca-Config-Version-Id": configID, "Cdnca-Installation-Id": "installation-probe-v1",
		} {
			if want == "" || message.Header.Get(header) != want {
				return fmt.Errorf("authoritative header %s mismatch", header)
			}
		}
		gotPublicationOrder = append(gotPublicationOrder, event.EventID)
		chronological = append(chronological, event)
	}
	if fmt.Sprint(gotPublicationOrder) != "[probe-3 probe-1 probe-2 probe-0]" {
		return fmt.Errorf("publication order changed: %v", gotPublicationOrder)
	}
	// The ACK reaches the server, but its synchronous response is deliberately
	// sent to an unsubscribed inbox. Disconnecting immediately afterwards makes
	// the other three pending deliveries retry while the committed ACK must not.
	if err = nc.PublishRequest(messages[0].Reply, nats.NewInbox(), []byte("+ACK")); err != nil {
		return fmt.Errorf("publish response-loss ack: %w", err)
	}
	if err = nc.FlushTimeout(3 * time.Second); err != nil {
		return fmt.Errorf("flush response-loss ack: %w", err)
	}
	nc.Close()
	nc, err = nats.Connect(reconnectURL, nats.Name("cdnca-analytics-observability-ack-reconnect"),
		nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		return fmt.Errorf("reconnect after lost ack response: %w", err)
	}
	reconnects.Add(1)
	defer nc.Close()
	js, err = nc.JetStream(nats.MaxWait(3 * time.Second))
	if err != nil {
		return fmt.Errorf("ack reconnect jetstream context: %w", err)
	}
	sub, err = js.PullSubscribe("cdnca.analytics.ingest.v1.*", durable, nats.Bind(stream, durable))
	if err != nil {
		return fmt.Errorf("rebind durable after lost ack response: %w", err)
	}
	defer sub.Unsubscribe()
	redelivered, err := sub.Fetch(3, nats.MaxWait(10*time.Second))
	if err != nil || len(redelivered) != 3 {
		return fmt.Errorf("fetch response-loss retries: count=%d err=%v", len(redelivered), err)
	}
	redeliveredIDs := make([]string, 0, len(redelivered))
	for _, message := range redelivered {
		var event probeEvent
		metadata, metadataErr := message.Metadata()
		if json.Unmarshal(message.Data, &event) != nil || metadataErr != nil || metadata.NumDelivered < 2 || event.EventID == "probe-3" {
			return fmt.Errorf("response-loss retry mismatch: event=%+v metadata=%+v err=%v", event, metadata, metadataErr)
		}
		redeliveredIDs = append(redeliveredIDs, event.EventID)
		if err = message.AckSync(); err != nil {
			return fmt.Errorf("ack retried message: %w", err)
		}
	}
	sort.Strings(redeliveredIDs)
	if fmt.Sprint(redeliveredIDs) != "[probe-0 probe-1 probe-2]" {
		return fmt.Errorf("response-loss retry set changed: %v", redeliveredIDs)
	}
	sort.Slice(chronological, func(i, j int) bool {
		if chronological[i].OccurredAt.Equal(chronological[j].OccurredAt) {
			return chronological[i].EventID < chronological[j].EventID
		}
		return chronological[i].OccurredAt.Before(chronological[j].OccurredAt)
	})
	chronologicalIDs := make([]string, len(chronological))
	for index := range chronological {
		chronologicalIDs[index] = chronological[index].EventID
	}
	if fmt.Sprint(chronologicalIDs) != "[probe-0 probe-1 probe-2 probe-3]" {
		return fmt.Errorf("event-time order cannot be recovered: %v", chronologicalIDs)
	}
	info, err := js.StreamInfo(stream)
	if err != nil || info.State.Msgs != 4 {
		return fmt.Errorf("stream duplicate count: messages=%d err=%v", info.State.Msgs, err)
	}
	lag := time.Since(offlineQueuedAt)
	if lag > 60*time.Second {
		return fmt.Errorf("offline recovery lag %s exceeds 60s", lag)
	}
	consumerInfo, err := js.ConsumerInfo(stream, durable)
	if err != nil {
		return fmt.Errorf("read response-loss ack floor: %w", err)
	}
	if consumerInfo.NumAckPending != 0 {
		return fmt.Errorf("response-loss ack floor did not settle: pending=%d", consumerInfo.NumAckPending)
	}
	fmt.Printf("jetstream-probe passed: unique=4 duplicate_suppressed=1 ack_response_lost=1 redelivered_after_disconnect=3 disconnects=%d reconnects=%d offline_recovery_ms=%d publication_order=%v event_time_order=%v\n",
		disconnects.Load(), reconnects.Load(), lag.Milliseconds(), gotPublicationOrder, chronologicalIDs)
	return nil
}
