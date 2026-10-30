package acmehttp01

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/nats-io/nats.go"
)

// The native installer pre-creates every durable from this profile and later
// rejects any drift, so the HTTP-01 status durable must match both the bind
// check and the shape NewNodeStatusConsumer self-creates on older installs.
func TestNativeNATSProfileCarriesHTTP01StatusConsumer(t *testing.T) {
	raw, err := os.ReadFile("../../../../scripts/native-runtime/native-nats-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		ConsumerDefaults map[string]json.RawMessage `json:"consumer_defaults"`
		Streams          []struct {
			Name     string   `json:"name"`
			Subjects []string `json:"subjects"`
		} `json:"streams"`
		Consumers []struct {
			Stream string                     `json:"stream"`
			Config map[string]json.RawMessage `json:"config"`
		} `json:"consumers"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	config := DefaultStatusConfig()
	var merged map[string]json.RawMessage
	for _, consumer := range profile.Consumers {
		var durable string
		_ = json.Unmarshal(consumer.Config["durable_name"], &durable)
		if durable != config.Durable {
			continue
		}
		if merged != nil || consumer.Stream != config.Stream {
			t.Fatalf("profile must carry exactly one %s durable on %s", config.Durable, config.Stream)
		}
		merged = make(map[string]json.RawMessage)
		for key, value := range profile.ConsumerDefaults {
			merged[key] = value
		}
		for key, value := range consumer.Config {
			merged[key] = value
		}
	}
	if merged == nil {
		t.Fatalf("native NATS profile is missing durable %s", config.Durable)
	}
	encoded, err := json.Marshal(merged)
	if err != nil {
		t.Fatal(err)
	}
	var actual nats.ConsumerConfig
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&actual); err != nil {
		t.Fatal(err)
	}
	if !sameOverlayStatusConsumer(&nats.ConsumerInfo{Config: actual}, config) {
		t.Fatalf("profile durable differs from the control-api bind check: %+v", actual)
	}
	// Mirrors the AddConsumer literal in NewNodeStatusConsumer (MaxRequestMaxBytes
	// stays 0), so a self-created durable never trips the installer drift check.
	expected := nats.ConsumerConfig{
		Durable: config.Durable, FilterSubject: config.SubjectPrefix + ".*",
		DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy, AckWait: config.AckWait,
		MaxDeliver: -1, ReplayPolicy: nats.ReplayInstantPolicy, MaxAckPending: config.MaxAckPending,
		MaxWaiting: config.MaxWaiting, MaxRequestBatch: 1, MaxRequestExpires: config.FetchTimeout,
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("profile durable differs from the self-created consumer:\n got %+v\nwant %+v", actual, expected)
	}
	for _, stream := range profile.Streams {
		if stream.Name == config.Stream && slices.Contains(stream.Subjects, config.SubjectPrefix+".*") {
			return
		}
	}
	t.Fatalf("profile stream %s does not carry %s.*", config.Stream, config.SubjectPrefix)
}
