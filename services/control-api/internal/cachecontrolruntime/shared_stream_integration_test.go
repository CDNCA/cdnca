//go:build integration

package cachecontrolruntime

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

// A fresh native install creates exactly the profile's AGENT_COMMANDS /
// AGENT_DEPLOYMENT_STATUS streams and control_api_cache_status durable. The
// default runtime must bind to them, publish a site purge/prewarm command on
// the subject the Agent Gateway consumes (nats_cache_commands.go
// SubscribeCache), accept the Gateway's status reply and quarantine poison on
// the shared status stream. Needs an empty task-owned JetStream server.
func TestDefaultRuntimeDispatchesThroughNativeProfileSharedStreams(t *testing.T) {
	natsURL := os.Getenv("CACHE_CONTROL_SHARED_STREAM_NATS_URL")
	if natsURL == "" {
		t.Skip("CACHE_CONTROL_SHARED_STREAM_NATS_URL (empty task-owned JetStream) is not set")
	}
	pool := openRuntimeIntegrationDatabase(t)
	fixture := seedRuntimeIntegrationFixture(t, pool)
	connection, err := nats.Connect(natsURL, nats.Timeout(2*time.Second), nats.Name("cache-shared-stream-integration"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	jetstream, err := connection.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if account, err := jetstream.AccountInfo(); err != nil || account.Streams != 0 {
		t.Fatalf("JetStream server is not empty and task-owned: %+v err=%v", account, err)
	}
	createNativeProfileCacheResources(t, connection)

	config := DefaultConfig()
	config.Clock = func() time.Time { return runtimeTestNow }
	// Fetch/ack settings stay at their defaults: the profile durable pins them.
	leases := &integrationLeases{online: map[uuid.UUID]bool{fixture.nodeID: true}}
	runtime, err := NewRuntime(config, Dependencies{Pool: pool, NATS: connection, NodeLeases: leases})
	if err != nil {
		t.Fatalf("default cache runtime did not bind to the native profile streams: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })

	// The Agent Gateway's per-node durable on the shared command stream.
	nodeSubject := "cdnca.agent.commands.cache." + fixture.nodeID.String()
	durable := "node_cache_" + strings.ReplaceAll(fixture.nodeID.String(), "-", "_")
	if _, err := jetstream.AddConsumer("AGENT_COMMANDS", &nats.ConsumerConfig{
		Durable: durable, DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy,
		FilterSubject: nodeSubject, MaxRequestBatch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	gateway, err := jetstream.PullSubscribe(nodeSubject, durable, nats.Bind("AGENT_COMMANDS", durable))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Unsubscribe() })

	batch, err := runtime.RunSchedulerOnce(t.Context())
	if err != nil || batch.Claimed != 1 || batch.Published != 1 {
		t.Fatalf("scheduler batch=%+v err=%v", batch, err)
	}
	messages, err := gateway.Fetch(1, nats.MaxWait(2*time.Second))
	if err != nil || len(messages) != 1 {
		t.Fatalf("Gateway node consumer did not receive the cache command: %d err=%v", len(messages), err)
	}
	command := new(agentv1.CacheControlCommand)
	if err := proto.Unmarshal(messages[0].Data, command); err != nil {
		t.Fatal(err)
	}
	if command.NodeId != fixture.nodeID.String() || command.ControlOperationId != fixture.operationID.String() {
		t.Fatalf("Gateway received command %+v", command)
	}
	if err := messages[0].AckSync(); err != nil {
		t.Fatal(err)
	}

	// Gateway PublishCacheStatus: deployment-status.cache.<node> on the shared status stream.
	status := testStatus(command, agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED,
		agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS)
	publishRuntimeStatus(t, jetstream, config, fixture.nodeID, "shared-status-success", status)
	if disposition, err := runtime.ProcessStatusOnce(t.Context()); err != nil || disposition != DispositionAck {
		t.Fatalf("status disposition=%s err=%v", disposition, err)
	}
	operation, err := fixture.store.GetOperation(t.Context(), fixture.actor, fixture.operationID)
	if err != nil || operation.State != cachecontrol.StateSucceeded {
		t.Fatalf("operation after Gateway status = %+v err=%v", operation, err)
	}

	poison := []byte{0xa0, 0x06, 0x01}
	publishRuntimePayload(t, jetstream, config, fixture.nodeID, "shared-status-poison", poison)
	if disposition, err := runtime.ProcessStatusOnce(t.Context()); err != nil || disposition != DispositionTerm {
		t.Fatalf("poison disposition=%s err=%v", disposition, err)
	}
	assertRuntimeDLQ(t, jetstream, config, poison)
}

// createNativeProfileCacheResources creates the two shared Agent streams and
// the cache durable exactly as configure-nats.py does from the profile.
func createNativeProfileCacheResources(t *testing.T, connection *nats.Conn) {
	t.Helper()
	raw, err := os.ReadFile("../../../../scripts/native-runtime/native-nats-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		StreamDefaults   map[string]json.RawMessage   `json:"stream_defaults"`
		ConsumerDefaults map[string]json.RawMessage   `json:"consumer_defaults"`
		Streams          []map[string]json.RawMessage `json:"streams"`
		Consumers        []struct {
			Stream string                     `json:"stream"`
			Config map[string]json.RawMessage `json:"config"`
		} `json:"consumers"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	request := func(subject string, payload any) {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := connection.Request(subject, encoded, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		var response struct {
			Error *struct{ Description string } `json:"error"`
		}
		if json.Unmarshal(reply.Data, &response) != nil || response.Error != nil {
			t.Fatalf("%s rejected: %s", subject, reply.Data)
		}
	}
	merge := func(defaults, item map[string]json.RawMessage) map[string]json.RawMessage {
		merged := map[string]json.RawMessage{}
		for key, value := range defaults {
			merged[key] = value
		}
		for key, value := range item {
			merged[key] = value
		}
		return merged
	}
	for _, stream := range profile.Streams {
		var name string
		_ = json.Unmarshal(stream["name"], &name)
		if name == "AGENT_COMMANDS" || name == "AGENT_DEPLOYMENT_STATUS" {
			request("$JS.API.STREAM.CREATE."+name, merge(profile.StreamDefaults, stream))
		}
	}
	for _, consumer := range profile.Consumers {
		var durable string
		_ = json.Unmarshal(consumer.Config["durable_name"], &durable)
		if durable == DefaultConfig().Durable {
			request("$JS.API.CONSUMER.CREATE."+consumer.Stream+"."+durable, map[string]any{
				"stream_name": consumer.Stream, "config": merge(profile.ConsumerDefaults, consumer.Config),
				"action": "create",
			})
		}
	}
}
