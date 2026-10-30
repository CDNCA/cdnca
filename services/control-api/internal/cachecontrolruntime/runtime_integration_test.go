//go:build integration

package cachecontrolruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

func TestNewNATSUsesNoJetStreamManagementWrites(t *testing.T) {
	natsURL := os.Getenv("CACHE_CONTROL_RUNTIME_NATS_URL")
	if natsURL == "" {
		t.Skip("CACHE_CONTROL_RUNTIME_NATS_URL is not set")
	}
	connection, err := nats.Connect(natsURL, nats.Timeout(2*time.Second),
		nats.Name("cache-control-runtime-bind-audit"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	jetstream, err := connection.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	config := productionNATSTestConfig()
	precreateProductionNATSResources(t, jetstream, config, true)
	before := captureNATSBindingSnapshot(t, jetstream, config)
	subscriptionsBefore := connection.NumSubscriptions()

	bus, consumer, bindErr := newNATS(connection, config)
	if bindErr != nil {
		t.Fatal(bindErr)
	}
	if bus == nil || consumer == nil || connection.IsClosed() ||
		connection.NumSubscriptions() != subscriptionsBefore+1 {
		t.Fatalf("bind state bus=%v consumer=%v closed=%t subscriptions=%d want=%d",
			bus != nil, consumer != nil, connection.IsClosed(), connection.NumSubscriptions(), subscriptionsBefore+1)
	}
	afterBind := captureNATSBindingSnapshot(t, jetstream, config)
	assertNATSBindingSnapshotEqual(t, before, afterBind, "bind")
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}
	if connection.IsClosed() || connection.NumSubscriptions() != subscriptionsBefore {
		t.Fatalf("close state closed=%t subscriptions=%d want=%d",
			connection.IsClosed(), connection.NumSubscriptions(), subscriptionsBefore)
	}
	afterClose := captureNATSBindingSnapshot(t, jetstream, config)
	assertNATSBindingSnapshotEqual(t, before, afterClose, "close")

	rebound, err := jetstream.PullSubscribe(config.StatusSubjectPrefix+".*", config.Durable,
		nats.Bind(config.StatusStream, config.Durable))
	if err != nil {
		t.Fatalf("caller-owned connection cannot rebind durable after Close: %v", err)
	}
	t.Cleanup(func() { _ = rebound.Unsubscribe() })
	statusPayload := []byte("status-after-close")
	statusMessage := nats.NewMsg(config.StatusSubjectPrefix + ".close")
	statusMessage.Data = statusPayload
	if _, err := jetstream.PublishMsg(statusMessage, nats.ExpectStream(config.StatusStream)); err != nil {
		t.Fatalf("publish status after Close: %v", err)
	}
	fetchCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	messages, err := rebound.Fetch(1, nats.Context(fetchCtx))
	cancel()
	if err != nil || len(messages) != 1 || !bytes.Equal(messages[0].Data, statusPayload) {
		t.Fatalf("fetch status after Close messages=%d err=%v", len(messages), err)
	}
	ackCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	err = messages[0].AckSync(nats.Context(ackCtx))
	cancel()
	if err != nil {
		t.Fatalf("ack status after Close: %v", err)
	}
	commandPayload := []byte("command-after-close")
	commandAck, err := jetstream.Publish(config.CommandSubjectPrefix+".close", commandPayload,
		nats.ExpectStream(config.CommandStream))
	if err != nil {
		t.Fatalf("publish command after Close: %v", err)
	}
	commandMessage, err := jetstream.GetMsg(config.CommandStream, commandAck.Sequence)
	if err != nil || !bytes.Equal(commandMessage.Data, commandPayload) {
		t.Fatalf("read command after Close err=%v", err)
	}
}

func TestNewNATSRejectsUnsupportedConsumerAPILevel(t *testing.T) {
	natsURL := os.Getenv("CACHE_CONTROL_RUNTIME_NATS_URL")
	if natsURL == "" {
		t.Skip("CACHE_CONTROL_RUNTIME_NATS_URL is not set")
	}
	for _, test := range []struct {
		name      string
		behavior  map[string]any
		wireField string
	}{
		{
			name: "paused",
			behavior: map[string]any{
				"pause_until": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
			},
			wireField: "pause_until",
		},
		{
			name: "priority",
			behavior: map[string]any{
				"priority_policy": "overflow",
				"priority_groups": []string{"cache-control"},
			},
			wireField: "priority_policy",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection, err := nats.Connect(natsURL, nats.Timeout(2*time.Second),
				nats.Name("cache-control-runtime-api-level-"+test.name))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(connection.Close)
			jetstream, err := connection.JetStream(nats.MaxWait(2 * time.Second))
			if err != nil {
				t.Fatal(err)
			}
			config := productionNATSTestConfig()
			precreateProductionNATSResources(t, jetstream, config, false)
			createRawNATSConsumer(t, connection, config, test.behavior, test.wireField)
			info, err := jetstream.ConsumerInfo(config.StatusStream, config.Durable)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Config.Metadata["_nats.req.level"]; got != "1" {
				t.Fatalf("required API level=%q, want 1", got)
			}

			bus, consumer, bindErr := newNATS(connection, config)
			if consumer != nil {
				_ = consumer.Close()
			}
			if bindErr == nil || bus != nil ||
				bindErr.Error() != "cache control JetStream initialization failed: consumer_validation" {
				t.Fatalf("unsupported consumer bind bus=%v consumer=%v err=%v", bus, consumer, bindErr)
			}
		})
	}
}

func TestNewNATSRequiresPrecreatedConsumer(t *testing.T) {
	natsURL := os.Getenv("CACHE_CONTROL_RUNTIME_NATS_URL")
	if natsURL == "" {
		t.Skip("CACHE_CONTROL_RUNTIME_NATS_URL is not set")
	}
	connection, err := nats.Connect(natsURL, nats.Timeout(2*time.Second),
		nats.Name("cache-control-runtime-missing-consumer"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	jetstream, err := connection.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	config := productionNATSTestConfig()
	precreateProductionNATSResources(t, jetstream, config, false)

	_, consumer, bindErr := newNATS(connection, config)
	if consumer != nil {
		_ = consumer.Close()
	}
	if bindErr == nil {
		t.Fatal("newNATS created a missing durable consumer")
	}
	if _, err := jetstream.ConsumerInfo(config.StatusStream, config.Durable); !errors.Is(err, nats.ErrConsumerNotFound) {
		t.Fatalf("durable consumer exists after rejected bind: %v", err)
	}
}

func TestNewNATSRequiresBothPrecreatedStreams(t *testing.T) {
	natsURL := os.Getenv("CACHE_CONTROL_RUNTIME_NATS_URL")
	if natsURL == "" {
		t.Skip("CACHE_CONTROL_RUNTIME_NATS_URL is not set")
	}
	for _, missing := range []string{"command", "status"} {
		t.Run(missing, func(t *testing.T) {
			connection, err := nats.Connect(natsURL, nats.Timeout(2*time.Second),
				nats.Name("cache-control-runtime-missing-stream"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(connection.Close)
			jetstream, err := connection.JetStream(nats.MaxWait(2 * time.Second))
			if err != nil {
				t.Fatal(err)
			}
			config := productionNATSTestConfig()
			precreateProductionNATSResources(t, jetstream, config, true)
			stream := config.CommandStream
			if missing == "status" {
				stream = config.StatusStream
			}
			if err := jetstream.DeleteStream(stream); err != nil {
				t.Fatal(err)
			}
			if _, consumer, err := newNATS(connection, config); err == nil {
				if consumer != nil {
					_ = consumer.Close()
				}
				t.Fatal("newNATS accepted a missing required stream")
			}
		})
	}
}

func TestBindVerifiedNATSRejectsPostBindDriftAndUnsubscribes(t *testing.T) {
	natsURL := os.Getenv("CACHE_CONTROL_RUNTIME_NATS_URL")
	if natsURL == "" {
		t.Skip("CACHE_CONTROL_RUNTIME_NATS_URL is not set")
	}
	connection, err := nats.Connect(natsURL, nats.Timeout(2*time.Second),
		nats.Name("cache-control-runtime-post-bind-drift"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	jetstream, err := connection.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	config := productionNATSTestConfig()
	precreateProductionNATSResources(t, jetstream, config, true)
	subscriptionsBefore := connection.NumSubscriptions()
	drifting := &postBindDriftJetStream{JetStreamContext: jetstream}
	bus, consumer, bindErr := bindVerifiedNATS(drifting, config)
	if bindErr == nil || bus != nil || consumer != nil ||
		bindErr.Error() != "cache control JetStream initialization failed: consumer_post_bind_validation" {
		t.Fatalf("post-bind drift result bus=%v consumer=%v err=%v", bus, consumer, bindErr)
	}
	if drifting.consumerInfoCalls != 2 {
		t.Fatalf("ConsumerInfo calls=%d, want pre/post validation", drifting.consumerInfoCalls)
	}
	if connection.NumSubscriptions() != subscriptionsBefore {
		t.Fatalf("failed bind leaked subscription: got=%d want=%d",
			connection.NumSubscriptions(), subscriptionsBefore)
	}
}

func TestBindVerifiedNATSRejectsPostBindStreamDriftAndUnsubscribes(t *testing.T) {
	natsURL := os.Getenv("CACHE_CONTROL_RUNTIME_NATS_URL")
	if natsURL == "" {
		t.Skip("CACHE_CONTROL_RUNTIME_NATS_URL is not set")
	}
	for _, streamKind := range []string{"command", "status"} {
		t.Run(streamKind, func(t *testing.T) {
			connection, err := nats.Connect(natsURL, nats.Timeout(2*time.Second),
				nats.Name("cache-control-runtime-post-bind-stream-drift-"+streamKind))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(connection.Close)
			jetstream, err := connection.JetStream(nats.MaxWait(2 * time.Second))
			if err != nil {
				t.Fatal(err)
			}
			config := productionNATSTestConfig()
			precreateProductionNATSResources(t, jetstream, config, true)
			driftStream := config.CommandStream
			if streamKind == "status" {
				driftStream = config.StatusStream
			}
			subscriptionsBefore := connection.NumSubscriptions()
			drifting := &postBindStreamDriftJetStream{
				JetStreamContext: jetstream,
				driftStream:      driftStream,
				streamInfoCalls:  make(map[string]int),
			}
			bus, consumer, bindErr := bindVerifiedNATS(drifting, config)
			if bindErr == nil || bus != nil || consumer != nil ||
				bindErr.Error() != "cache control JetStream initialization failed: stream_post_bind_validation" {
				t.Fatalf("post-bind %s stream drift result bus=%v consumer=%v err=%v",
					streamKind, bus, consumer, bindErr)
			}
			if drifting.streamInfoCalls[driftStream] != 2 {
				t.Fatalf("%s StreamInfo calls=%d, want pre/post validation",
					streamKind, drifting.streamInfoCalls[driftStream])
			}
			if connection.NumSubscriptions() != subscriptionsBefore {
				t.Fatalf("failed %s stream bind leaked subscription: got=%d want=%d",
					streamKind, connection.NumSubscriptions(), subscriptionsBefore)
			}
		})
	}
}

func TestBindVerifiedNATSUsesNoManagementMethods(t *testing.T) {
	natsURL := os.Getenv("CACHE_CONTROL_RUNTIME_NATS_URL")
	if natsURL == "" {
		t.Skip("CACHE_CONTROL_RUNTIME_NATS_URL is not set")
	}
	connection, err := nats.Connect(natsURL, nats.Timeout(2*time.Second),
		nats.Name("cache-control-runtime-management-spy"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	jetstream, err := connection.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	config := productionNATSTestConfig()
	precreateProductionNATSResources(t, jetstream, config, true)
	audited := &managementAuditJetStream{JetStreamContext: jetstream}
	_, consumer, bindErr := bindVerifiedNATS(audited, config)
	if bindErr != nil {
		t.Fatal(bindErr)
	}
	if consumer != nil {
		_ = consumer.Close()
	}
	if audited.writes != 0 {
		t.Fatalf("JetStream management method calls=%d, want 0", audited.writes)
	}
	wantCalls := strings.Join([]string{
		"stream:" + config.CommandStream,
		"stream:" + config.StatusStream,
		"consumer:" + config.StatusStream + "/" + config.Durable,
		"bind:" + config.StatusSubjectPrefix + ".*/" + config.Durable,
		"stream:" + config.CommandStream,
		"stream:" + config.StatusStream,
		"consumer:" + config.StatusStream + "/" + config.Durable,
	}, ",")
	if got := strings.Join(audited.calls, ","); got != wantCalls {
		t.Fatalf("verify/bind calls=%q want=%q", got, wantCalls)
	}
}

func TestNewNATSDisconnectedConnectionFailsClosed(t *testing.T) {
	natsURL := os.Getenv("CACHE_CONTROL_RUNTIME_NATS_URL")
	if natsURL == "" {
		t.Skip("CACHE_CONTROL_RUNTIME_NATS_URL is not set")
	}
	connection, err := nats.Connect(natsURL, nats.Timeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if _, _, err := newNATS(connection, productionNATSTestConfig()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("disconnected connection error=%v", err)
	}
}

type postBindDriftJetStream struct {
	nats.JetStreamContext
	consumerInfoCalls int
}

type postBindStreamDriftJetStream struct {
	nats.JetStreamContext
	driftStream     string
	streamInfoCalls map[string]int
}

type managementAuditJetStream struct {
	nats.JetStreamContext
	writes int
	calls  []string
}

func (jetstream *managementAuditJetStream) StreamInfo(
	stream string,
	options ...nats.JSOpt,
) (*nats.StreamInfo, error) {
	jetstream.calls = append(jetstream.calls, "stream:"+stream)
	return jetstream.JetStreamContext.StreamInfo(stream, options...)
}

func (jetstream *postBindStreamDriftJetStream) StreamInfo(
	stream string,
	options ...nats.JSOpt,
) (*nats.StreamInfo, error) {
	info, err := jetstream.JetStreamContext.StreamInfo(stream, options...)
	if err != nil {
		return nil, err
	}
	jetstream.streamInfoCalls[stream]++
	if stream == jetstream.driftStream && jetstream.streamInfoCalls[stream] == 2 {
		drifted := *info
		drifted.Config = info.Config
		// Losing a required subject after bind (e.g. a re-provisioned stream).
		drifted.Config.Subjects = []string{"cdnca.test.cache.post-bind-drift.*"}
		return &drifted, nil
	}
	return info, nil
}

func (jetstream *managementAuditJetStream) ConsumerInfo(
	stream string,
	consumer string,
	options ...nats.JSOpt,
) (*nats.ConsumerInfo, error) {
	jetstream.calls = append(jetstream.calls, "consumer:"+stream+"/"+consumer)
	return jetstream.JetStreamContext.ConsumerInfo(stream, consumer, options...)
}

func (jetstream *managementAuditJetStream) PullSubscribe(
	subject string,
	durable string,
	options ...nats.SubOpt,
) (*nats.Subscription, error) {
	jetstream.calls = append(jetstream.calls, "bind:"+subject+"/"+durable)
	return jetstream.JetStreamContext.PullSubscribe(subject, durable, options...)
}

func (jetstream *managementAuditJetStream) AddStream(
	*nats.StreamConfig,
	...nats.JSOpt,
) (*nats.StreamInfo, error) {
	jetstream.writes++
	return nil, errors.New("management write is forbidden")
}

func (jetstream *managementAuditJetStream) UpdateStream(
	*nats.StreamConfig,
	...nats.JSOpt,
) (*nats.StreamInfo, error) {
	jetstream.writes++
	return nil, errors.New("management write is forbidden")
}

func (jetstream *managementAuditJetStream) DeleteStream(string, ...nats.JSOpt) error {
	jetstream.writes++
	return errors.New("management write is forbidden")
}

func (jetstream *managementAuditJetStream) AddConsumer(
	string,
	*nats.ConsumerConfig,
	...nats.JSOpt,
) (*nats.ConsumerInfo, error) {
	jetstream.writes++
	return nil, errors.New("management write is forbidden")
}

func (jetstream *managementAuditJetStream) UpdateConsumer(
	string,
	*nats.ConsumerConfig,
	...nats.JSOpt,
) (*nats.ConsumerInfo, error) {
	jetstream.writes++
	return nil, errors.New("management write is forbidden")
}

func (jetstream *managementAuditJetStream) DeleteConsumer(string, string, ...nats.JSOpt) error {
	jetstream.writes++
	return errors.New("management write is forbidden")
}

func (jetstream *postBindDriftJetStream) ConsumerInfo(
	stream string,
	consumer string,
	options ...nats.JSOpt,
) (*nats.ConsumerInfo, error) {
	info, err := jetstream.JetStreamContext.ConsumerInfo(stream, consumer, options...)
	if err != nil {
		return nil, err
	}
	jetstream.consumerInfoCalls++
	if jetstream.consumerInfoCalls == 2 {
		drifted := *info
		drifted.Config = info.Config
		drifted.Config.MaxWaiting++
		return &drifted, nil
	}
	return info, nil
}

func productionNATSTestConfig() Config {
	suffix := strings.ToLower(strings.ReplaceAll(uuid.NewString(), "-", "")[:12])
	config := DefaultConfig()
	config.CommandStream = "CC_BIND_COMMAND_" + strings.ToUpper(suffix)
	config.StatusStream = "CC_BIND_STATUS_" + strings.ToUpper(suffix)
	config.CommandSubjectPrefix = "cdnca.test.cache.bind.command." + suffix
	config.StatusSubjectPrefix = "cdnca.test.cache.bind.status." + suffix
	config.DLQSubjectPrefix = "cdnca.test.cache.bind.dlq." + suffix
	config.Durable = "cc_bind_status_" + suffix
	config.WorkerID = "cc_bind_worker_" + suffix
	config.Replicas = 1
	config.FetchTimeout = time.Second
	config.OperationTimeout = 2 * time.Second
	return config
}

func precreateProductionNATSResources(
	t *testing.T,
	jetstream nats.JetStreamContext,
	config Config,
	consumer bool,
) {
	t.Helper()
	for _, stream := range []*nats.StreamConfig{
		{
			Name: config.CommandStream, Subjects: []string{config.CommandSubjectPrefix + ".*"},
			Retention: nats.LimitsPolicy, Storage: nats.FileStorage, Replicas: config.Replicas,
			MaxMsgs: 2_000_000, MaxBytes: 2 << 30, MaxAge: 7 * 24 * time.Hour,
			Duplicates: 10 * time.Minute, MaxMsgSize: int32(config.MaxPayloadBytes),
		},
		{
			Name:      config.StatusStream,
			Subjects:  []string{config.StatusSubjectPrefix + ".*", config.DLQSubjectPrefix + ".*"},
			Retention: nats.LimitsPolicy, Storage: nats.FileStorage, Replicas: config.Replicas,
			MaxMsgs: 2_000_000, MaxBytes: 2 << 30, MaxAge: 7 * 24 * time.Hour,
			Duplicates: 10 * time.Minute, MaxMsgSize: int32(config.MaxPayloadBytes),
		},
	} {
		if _, err := jetstream.AddStream(stream); err != nil {
			t.Fatal(err)
		}
		streamName := stream.Name
		t.Cleanup(func() { _ = jetstream.DeleteStream(streamName) })
	}
	if !consumer {
		return
	}
	if _, err := jetstream.AddConsumer(config.StatusStream, expectedConsumer(config)); err != nil {
		t.Fatal(err)
	}
}

type natsStreamSnapshot struct {
	Config  nats.StreamConfig
	State   nats.StreamState
	Created time.Time
}

type natsConsumerSnapshot struct {
	Config         nats.ConsumerConfig
	Created        time.Time
	Delivered      nats.SequenceInfo
	AckFloor       nats.SequenceInfo
	NumAckPending  int
	NumRedelivered int
	NumWaiting     int
	NumPending     uint64
	PushBound      bool
}

type natsBindingSnapshot struct {
	Command  natsStreamSnapshot
	Status   natsStreamSnapshot
	Consumer natsConsumerSnapshot
}

func captureNATSBindingSnapshot(
	t *testing.T,
	jetstream nats.JetStreamContext,
	config Config,
) natsBindingSnapshot {
	t.Helper()
	streamSnapshot := func(name string) natsStreamSnapshot {
		info, err := jetstream.StreamInfo(name)
		if err != nil {
			t.Fatal(err)
		}
		return natsStreamSnapshot{Config: info.Config, State: info.State, Created: info.Created}
	}
	info, err := jetstream.ConsumerInfo(config.StatusStream, config.Durable)
	if err != nil {
		t.Fatal(err)
	}
	return natsBindingSnapshot{
		Command: streamSnapshot(config.CommandStream),
		Status:  streamSnapshot(config.StatusStream),
		Consumer: natsConsumerSnapshot{
			Config: info.Config, Created: info.Created, Delivered: info.Delivered, AckFloor: info.AckFloor,
			NumAckPending: info.NumAckPending, NumRedelivered: info.NumRedelivered,
			NumWaiting: info.NumWaiting, NumPending: info.NumPending, PushBound: info.PushBound,
		},
	}
}

func assertNATSBindingSnapshotEqual(
	t *testing.T,
	want natsBindingSnapshot,
	got natsBindingSnapshot,
	stage string,
) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("JetStream resources changed during %s\nwant=%#v\ngot=%#v", stage, want, got)
	}
}

func createRawNATSConsumer(
	t *testing.T,
	connection *nats.Conn,
	config Config,
	behavior map[string]any,
	wireField string,
) {
	t.Helper()
	encoded, err := json.Marshal(expectedConsumer(config))
	if err != nil {
		t.Fatal(err)
	}
	consumerConfig := make(map[string]any)
	if err := json.Unmarshal(encoded, &consumerConfig); err != nil {
		t.Fatal(err)
	}
	for name, value := range behavior {
		consumerConfig[name] = value
	}
	request, err := json.Marshal(map[string]any{
		"stream_name": config.StatusStream,
		"config":      consumerConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := connection.Request(
		fmt.Sprintf("$JS.API.CONSUMER.DURABLE.CREATE.%s.%s", config.StatusStream, config.Durable),
		request,
		2*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Error *struct {
			Description string `json:"description"`
		} `json:"error"`
		Config map[string]json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(message.Data, &response); err != nil {
		t.Fatal(err)
	}
	if response.Error != nil {
		t.Fatalf("raw consumer create: %s", response.Error.Description)
	}
	if _, ok := response.Config[wireField]; !ok {
		t.Fatalf("raw consumer response omitted %s", wireField)
	}
}

func TestPostgresJetStreamRecoveryOfflineAndStatusLifecycle(t *testing.T) {
	natsURL := os.Getenv("CACHE_CONTROL_RUNTIME_NATS_URL")
	if natsURL == "" {
		t.Skip("CACHE_CONTROL_RUNTIME_NATS_URL is not set")
	}
	pool := openRuntimeIntegrationDatabase(t)
	fixture := seedRuntimeIntegrationFixture(t, pool)

	connection, err := nats.Connect(natsURL, nats.Timeout(2*time.Second),
		nats.Name("cache-control-runtime-integration"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	jetstream, err := connection.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.ToLower(strings.ReplaceAll(uuid.NewString(), "-", "")[:12])
	config := DefaultConfig()
	config.Replicas = 1
	config.CommandStream = "CC_CMD_" + strings.ToUpper(suffix)
	config.StatusStream = "CC_STATUS_" + strings.ToUpper(suffix)
	config.CommandSubjectPrefix = "cdnca.test.cache.command." + suffix
	config.StatusSubjectPrefix = "cdnca.test.cache.status." + suffix
	config.DLQSubjectPrefix = "cdnca.test.cache.dlq." + suffix
	config.Durable = "cc_status_" + suffix
	config.WorkerID = "cc_worker_" + suffix
	config.ClaimBatch = 2
	config.FetchTimeout = time.Second
	config.OperationTimeout = 2 * time.Second
	config.LeaseDuration = time.Minute
	config.AckWait = 2 * time.Second
	config.NakBaseDelay = 50 * time.Millisecond
	config.NakMaximumDelay = 200 * time.Millisecond
	config.Clock = func() time.Time { return runtimeTestNow }
	precreateProductionNATSResources(t, jetstream, config, true)

	leases := &integrationLeases{online: map[uuid.UUID]bool{fixture.nodeID: false}}
	runtime, err := NewRuntime(config, Dependencies{Pool: pool, NATS: connection, NodeLeases: leases})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })

	batch, err := runtime.RunSchedulerOnce(t.Context())
	if err != nil || batch.Claimed != 0 || batch.Published != 0 || batch.Offline != 1 {
		t.Fatalf("offline scheduler batch=%+v err=%v", batch, err)
	}
	operation, err := fixture.store.GetOperation(t.Context(), fixture.actor, fixture.operationID)
	if err != nil || operation.State != cachecontrol.StateQueued {
		t.Fatalf("offline operation=%+v err=%v", operation, err)
	}

	leases.set(fixture.nodeID, true)
	batch, err = runtime.RunSchedulerOnce(t.Context())
	if err != nil || batch.Claimed != 1 || batch.Published != 1 || batch.Recovered != 0 {
		t.Fatalf("reconnected scheduler batch=%+v err=%v", batch, err)
	}
	rawCommand, err := jetstream.GetMsg(config.CommandStream, 1)
	if err != nil {
		t.Fatal(err)
	}
	command := new(agentv1.CacheControlCommand)
	if err := proto.Unmarshal(rawCommand.Data, command); err != nil {
		t.Fatal(err)
	}
	if command.NodeId != fixture.nodeID.String() || command.ConfigVersionId != fixture.configID.String() ||
		command.ConfigRevision != 7 || command.ControlOperationId != fixture.operationID.String() {
		t.Fatalf("published command=%+v", command)
	}
	tenantField := command.ProtoReflect().Descriptor().Fields().ByNumber(17)
	if tenantField == nil || command.ProtoReflect().Get(tenantField).String() != fixture.tenantID.String() {
		t.Fatalf("published command tenant=%v want=%s", tenantField, fixture.tenantID)
	}

	batch, err = runtime.RunSchedulerOnce(t.Context())
	if err != nil || batch.Recovered != 1 || batch.Claimed != 0 || batch.Published != 1 ||
		batch.Duplicates != 1 {
		t.Fatalf("publish-unknown recovery batch=%+v err=%v", batch, err)
	}
	commandInfo, err := jetstream.StreamInfo(config.CommandStream)
	if err != nil || commandInfo.State.Msgs != 1 {
		t.Fatalf("deduplicated command stream info=%+v err=%v", commandInfo, err)
	}

	status := testStatus(command, agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED,
		agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS)
	replicaConfig := config
	replicaConfig.WorkerID += "_replica"
	replica, err := NewRuntime(replicaConfig, Dependencies{Pool: pool, NATS: connection, NodeLeases: leases})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replica.Close() })
	publishRuntimeStatus(t, jetstream, config, fixture.nodeID, "status-success", status)
	disposition, err := replica.ProcessStatusOnce(t.Context())
	if err != nil || disposition != DispositionAck {
		t.Fatalf("success status disposition=%s err=%v", disposition, err)
	}
	operation, err = fixture.store.GetOperation(t.Context(), fixture.actor, fixture.operationID)
	if err != nil || operation.State != cachecontrol.StateSucceeded ||
		operation.Progress.Completed != operation.Progress.Total {
		t.Fatalf("terminal operation=%+v err=%v", operation, err)
	}

	publishRuntimeStatus(t, jetstream, config, fixture.nodeID, "status-ack-loss", status)
	disposition, err = replica.ProcessStatusOnce(t.Context())
	if err != nil || disposition != DispositionTerm {
		t.Fatalf("ack-loss replay disposition=%s err=%v", disposition, err)
	}
	outOfOrder := proto.Clone(status).(*agentv1.CacheControlStatus)
	outOfOrder.Event.EventId = uuid.NewString()
	outOfOrder.State = agentv1.CacheControlState_CACHE_CONTROL_STATE_RUNNING
	outOfOrder.TransitionSequence = 2
	outOfOrder.Results = nil
	publishRuntimeStatus(t, jetstream, config, fixture.nodeID, "status-out-of-order", outOfOrder)
	disposition, err = replica.ProcessStatusOnce(t.Context())
	if err != nil || disposition != DispositionTerm {
		t.Fatalf("out-of-order status disposition=%s err=%v", disposition, err)
	}

	validPayload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	poison := append(append([]byte(nil), validPayload...), 0xa0, 0x06, 0x01)
	publishRuntimePayload(t, jetstream, config, fixture.nodeID, "status-poison", poison)
	disposition, err = replica.ProcessStatusOnce(t.Context())
	if err != nil || disposition != DispositionTerm {
		t.Fatalf("poison disposition=%s err=%v", disposition, err)
	}
	assertRuntimeDLQ(t, jetstream, config, poison)

	var reportAudits int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND action='cache.operation.report' AND resource_id=$2 AND result='success'`,
		fixture.actor.ScopeID, fixture.operationID.String()).Scan(&reportAudits); err != nil {
		t.Fatal(err)
	}
	if reportAudits != 1 {
		t.Fatalf("report audits=%d, want 1 after duplicate/out-of-order statuses", reportAudits)
	}
}

func TestReadyNodesExcludeCandidatesWithoutActiveConfig(t *testing.T) {
	pool := openRuntimeIntegrationDatabase(t)
	fixture := seedRuntimeIntegrationFixture(t, pool)
	staleNodeID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	if _, err := pool.Exec(t.Context(), seedRuntimeNodeSQL, staleNodeID, fixture.actor.ScopeID, "cache-runtime-stale-node", fixture.actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.CreateOperation(t.Context(), fixture.actor, cachecontrol.CreateOperationRequest{
		SiteID: fixture.siteID, Action: cachecontrol.ActionPurge, TargetType: cachecontrol.TargetExactURL,
		Targets: []string{"http://runtime.cache.example/assets/stale.js"},
		NodeIDs: []uuid.UUID{staleNodeID}, MaxRetries: 1,
		IdempotencyKey: "runtime-stale-config-operation", RequestID: "runtime-stale-config-request",
	}); err != nil {
		t.Fatal(err)
	}

	ready, err := (&postgresRepository{pool: pool}).readyNodes(
		t.Context(), runtimeTestNow, nil, 1000,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range ready {
		if node.NodeID == staleNodeID {
			t.Fatalf("ready nodes include stale-config candidate: %+v", ready)
		}
	}
}

type runtimeIntegrationFixture struct {
	actor       cachecontrol.Actor
	tenantID    uuid.UUID
	siteID      uuid.UUID
	nodeID      uuid.UUID
	configID    uuid.UUID
	operationID uuid.UUID
	store       *cachecontrol.Store
}

// seedRuntimeNodeSQL inserts an active node ($1 id, $2 scope, $3 name,
// $4 creator) with a display ID from the per-scope sequence, as node.Store
// allocates it (NOT NULL since migration 211).
const seedRuntimeNodeSQL = `WITH display AS (
		INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,now())
		ON CONFLICT(scope_id) DO UPDATE SET next_value=node_display_id_sequences.next_value+1,
			updated_at=EXCLUDED.updated_at
		RETURNING next_value-1 AS display_id
	)
	INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id)
	SELECT $1,display.display_id,$2,$3,'active',$4 FROM display`

func seedRuntimeIntegrationFixture(t *testing.T, pool *pgxpool.Pool) runtimeIntegrationFixture {
	t.Helper()
	fixture := runtimeIntegrationFixture{
		actor:  cachecontrol.Actor{UserID: uuid.New(), ScopeID: uuid.New()},
		nodeID: uuid.New(), configID: uuid.New(),
	}
	fixture.actor.ActorScopeID = fixture.actor.ScopeID
	fixture.tenantID = uuid.New()
	tenantID, siteID, roleID := fixture.tenantID, uuid.New(), uuid.New()
	fixture.siteID = siteID
	ctx := t.Context()
	for _, statement := range []struct {
		query     string
		arguments []any
	}{
		{`INSERT INTO tenants(id,display_name,status) VALUES($1,'Cache runtime tenant','active')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{fixture.actor.ScopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash,status)
		 VALUES($1,$2,'Cache runtime actor','test-hash','active')`, []any{fixture.actor.UserID, "cache-runtime-" + uuid.NewString()}},
		{`INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`, []any{fixture.actor.ScopeID, fixture.actor.UserID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role)
		 VALUES($1,$2,$3,'Cache runtime role',true)`, []any{roleID, fixture.actor.ScopeID, "cache-runtime-role-" + uuid.NewString()}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'sites.read'),($1,'sites.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{fixture.actor.ScopeID, fixture.actor.UserID, roleID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.arguments...); err != nil {
			t.Fatal(err)
		}
	}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		// display_id from the per-scope sequence, as site.Store allocates it
		// (NOT NULL since migration 210).
		if _, err := tx.Exec(ctx, `WITH display AS (
			INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,now())
			ON CONFLICT(scope_id) DO UPDATE SET next_value=site_display_id_sequences.next_value+1,
				updated_at=EXCLUDED.updated_at
			RETURNING next_value-1 AS display_id
		)
		INSERT INTO sites(
			id,display_id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
			https_enabled,enabled,status,created_by_user_id,updated_by_user_id
		) SELECT $1,display.display_id,$2,$3,'runtime.cache.example',$4,$5,$6,$6,true,true,'active',$3,$3 FROM display`,
			siteID, fixture.actor.ScopeID, fixture.actor.UserID, []string{"80"}, []string{"443"},
			[]string{"192.0.2.20"}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
			VALUES($1,1,'192.0.2.20',80,1,true)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, seedRuntimeNodeSQL, fixture.nodeID, fixture.actor.ScopeID, "cache-runtime-node",
		fixture.actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO config_versions(
		id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
		generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at
	) VALUES($1,$2,$3,$4,'cache-runtime','1','releasable',$5,$4,$6,$6)`, fixture.configID,
		fixture.actor.ScopeID, []byte("runtime-active-config"), make([]byte, 32),
		"cache-runtime-config-"+fixture.configID.String(), runtimeTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO node_config_state(
		node_id,configuration_scope_id,current_config_version_id,revision,updated_at
	) VALUES($1,$2,$3,7,$4)`, fixture.nodeID, fixture.actor.ScopeID,
		fixture.configID, runtimeTestNow); err != nil {
		t.Fatal(err)
	}
	store, err := cachecontrol.NewStore(pool, func() time.Time { return runtimeTestNow })
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateOperation(ctx, fixture.actor, cachecontrol.CreateOperationRequest{
		SiteID: siteID, Action: cachecontrol.ActionPrewarm, TargetType: cachecontrol.TargetExactURL,
		Targets: []string{"http://runtime.cache.example/assets/app.js"},
		NodeIDs: []uuid.UUID{fixture.nodeID}, MaxRetries: 1,
		IdempotencyKey: "runtime-operation", RequestID: "runtime-operation-request",
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.operationID, fixture.store = created.Operation.ID, store
	return fixture
}

type integrationLeases struct {
	mu     sync.RWMutex
	online map[uuid.UUID]bool
}

func (leases *integrationLeases) Exists(_ context.Context, nodeID uuid.UUID) (bool, error) {
	leases.mu.RLock()
	defer leases.mu.RUnlock()
	return leases.online[nodeID], nil
}

func (leases *integrationLeases) set(nodeID uuid.UUID, online bool) {
	leases.mu.Lock()
	defer leases.mu.Unlock()
	leases.online[nodeID] = online
}

func publishRuntimeStatus(
	t *testing.T,
	jetstream nats.JetStreamContext,
	config Config,
	nodeID uuid.UUID,
	messageID string,
	status *agentv1.CacheControlStatus,
) {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	publishRuntimePayload(t, jetstream, config, nodeID, messageID, payload)
}

func publishRuntimePayload(
	t *testing.T,
	jetstream nats.JetStreamContext,
	config Config,
	nodeID uuid.UUID,
	messageID string,
	payload []byte,
) {
	t.Helper()
	message := nats.NewMsg(config.StatusSubjectPrefix + "." + nodeID.String())
	message.Header.Set(nats.MsgIdHdr, messageID)
	message.Data = payload
	if _, err := jetstream.PublishMsg(message, nats.ExpectStream(config.StatusStream)); err != nil {
		t.Fatal(err)
	}
}

func assertRuntimeDLQ(t *testing.T, jetstream nats.JetStreamContext, config Config, poison []byte) {
	t.Helper()
	info, err := jetstream.StreamInfo(config.StatusStream)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(1); sequence <= info.State.LastSeq; sequence++ {
		message, err := jetstream.GetMsg(config.StatusStream, sequence)
		if err != nil || !strings.HasPrefix(message.Subject, config.DLQSubjectPrefix+".") {
			continue
		}
		if !bytes.Equal(message.Data, poison) ||
			message.Header.Get("CDNCA-Quarantine-Reason") != "protobuf_invalid" {
			t.Fatalf("DLQ message subject=%s header=%q", message.Subject, message.Header)
		}
		return
	}
	t.Fatal("cache poison message was not published to DLQ")
}

// openRuntimeIntegrationDatabase opens a schema at the release head (a
// template clone when TEST_DATABASE_TEMPLATE is set): the cache store and
// runtime under test read today's schema (tenant carriage 287, site domain
// facts 148, ...), which a replay through migration 80 lacks.
func openRuntimeIntegrationDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return databasetest.MigratedPool(t, nil)
}
