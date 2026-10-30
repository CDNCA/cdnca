package cachecontrolruntime

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/nats-io/nats.go"
)

// The native installer pre-creates every stream and durable from this profile
// and rejects drift; the cache runtime never creates JetStream resources
// (nats.go bindVerifiedNATS), so a fresh install only gets cache purge and
// prewarm if the profile already satisfies the runtime's bind checks.
func TestNativeNATSProfileSatisfiesCacheRuntimeBind(t *testing.T) {
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
	merge := func(defaults, item map[string]json.RawMessage) []byte {
		merged := make(map[string]json.RawMessage, len(defaults)+len(item))
		for key, value := range defaults {
			merged[key] = value
		}
		for key, value := range item {
			merged[key] = value
		}
		encoded, err := json.Marshal(merged)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	config := DefaultConfig()
	streams := make(map[string]*nats.StreamInfo)
	for _, item := range profile.Streams {
		var stream nats.StreamConfig
		if err := json.Unmarshal(merge(profile.StreamDefaults, item), &stream); err != nil {
			t.Fatal(err)
		}
		streams[stream.Name] = &nats.StreamInfo{Config: stream}
	}
	for _, required := range requiredStreams(config) {
		if !sharedStreamCovers(streams[required.name], required, config) {
			t.Fatalf("native profile stream %s does not carry %v", required.name, required.subjects)
		}
	}

	var found int
	for _, consumer := range profile.Consumers {
		var durable string
		_ = json.Unmarshal(consumer.Config["durable_name"], &durable)
		if durable != config.Durable {
			continue
		}
		found++
		var actual nats.ConsumerConfig
		decoder := json.NewDecoder(bytes.NewReader(merge(profile.ConsumerDefaults, consumer.Config)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&actual); err != nil {
			t.Fatal(err)
		}
		actual.Name = actual.Durable // the server echoes the durable as the consumer name
		info := &nats.ConsumerInfo{Stream: consumer.Stream, Name: actual.Durable, Config: actual}
		if !sameConsumer(info, config.StatusStream, expectedConsumer(config)) {
			t.Fatalf("profile durable differs from the cache runtime bind check:\n got %+v\nwant %+v",
				actual, *expectedConsumer(config))
		}
	}
	if found != 1 {
		t.Fatalf("native profile carries %d %s durables, want 1", found, config.Durable)
	}
}
