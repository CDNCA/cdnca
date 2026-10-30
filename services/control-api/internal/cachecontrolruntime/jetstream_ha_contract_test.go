package cachecontrolruntime

import (
	"testing"

	"github.com/nats-io/nats.go"
)

// Native single-host NATS runs every stream at num_replicas=1
// (scripts/native-runtime/native-nats-profile.json stream_defaults), so the
// default must bind there; clustered deployments raise the minimum to 3.
func TestDefaultConfigBindsToSharedAgentStreamsOnSingleNodeNATS(t *testing.T) {
	config := DefaultConfig()
	if err := config.validate(); err != nil {
		t.Fatalf("DefaultConfig validate: %v", err)
	}
	if config.Replicas != 1 || config.CommandStream != "AGENT_COMMANDS" ||
		config.StatusStream != "AGENT_DEPLOYMENT_STATUS" {
		t.Fatalf("cache runtime does not default to the shared single-node Agent streams: %#v", config)
	}
	required := requiredStreams(config)
	if len(required) != 2 || required[0].name != "AGENT_COMMANDS" ||
		len(required[0].subjects) != 1 || required[0].subjects[0] != "cdnca.agent.commands.cache.*" ||
		required[1].name != "AGENT_DEPLOYMENT_STATUS" || len(required[1].subjects) != 2 ||
		required[1].subjects[0] != "cdnca.agent.deployment-status.cache.*" ||
		required[1].subjects[1] != "cdnca.agent.deployment-status.cache-dlq.*" {
		t.Fatalf("required shared stream subjects = %#v", required)
	}
}

func TestConfigRejectsInvalidReplicasOrOverlappingSubjects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"zero replicas", func(config *Config) { config.Replicas = 0 }},
		{"too many replicas", func(config *Config) { config.Replicas = maxStreamReplicas + 1 }},
		{"shared stream", func(config *Config) { config.StatusStream = config.CommandStream }},
		{"command overlaps status", func(config *Config) { config.CommandSubjectPrefix = config.StatusSubjectPrefix }},
		{"command overlaps dlq", func(config *Config) { config.CommandSubjectPrefix = config.DLQSubjectPrefix }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := DefaultConfig()
			test.mutate(&config)
			if err := config.validate(); err == nil {
				t.Fatal("invalid cache runtime configuration was accepted")
			}
		})
	}
	clustered := DefaultConfig()
	clustered.Replicas = 3
	if err := clustered.validate(); err != nil {
		t.Fatalf("clustered replica minimum rejected: %v", err)
	}
}

// The DLQ quarantine subject lives on the status stream, never the command
// stream, so poison statuses cannot be redelivered to nodes as commands.
func TestDLQRetentionIsIsolatedFromCommandStream(t *testing.T) {
	required := requiredStreams(DefaultConfig())
	command, status := required[0], required[1]
	for _, subject := range command.subjects {
		if subject == DefaultDLQSubjectPrefix+".*" {
			t.Fatalf("DLQ subject is required on the command stream: %#v", command)
		}
	}
	if command.name == status.name || status.subjects[1] != DefaultDLQSubjectPrefix+".*" {
		t.Fatalf("DLQ is not isolated from command retention: command=%#v status=%#v", command, status)
	}
}

// sharedAgentStream mirrors the AGENT_COMMANDS / AGENT_DEPLOYMENT_STATUS
// shape of native-nats-profile.json (other subjects included).
func sharedAgentStream(name string, subjects ...string) *nats.StreamInfo {
	return &nats.StreamInfo{Config: nats.StreamConfig{
		Name: name, Subjects: subjects, Retention: nats.LimitsPolicy, MaxConsumers: -1,
		MaxMsgs: 1_000_000, MaxBytes: 1 << 30, Discard: nats.DiscardOld, MaxMsgsPerSubject: -1,
		MaxMsgSize: 1 << 20, Storage: nats.FileStorage, Replicas: 1, Duplicates: 120_000_000_000,
	}}
}
