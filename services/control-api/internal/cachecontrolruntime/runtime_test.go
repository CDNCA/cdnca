package cachecontrolruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var runtimeTestNow = time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)

func TestSharedStreamCoverageMatchesGatewayReadiness(t *testing.T) {
	config := DefaultConfig()
	required := requiredStreams(config)
	command := sharedAgentStream("AGENT_COMMANDS",
		"cdnca.agent.commands.*", "cdnca.agent.commands.acme-http01.*",
		"cdnca.agent.commands.cache.*", "cdnca.agent.commands.cache-dlq.*",
		"cdnca.agent.commands.upgrade.*")
	status := sharedAgentStream("AGENT_DEPLOYMENT_STATUS",
		"cdnca.agent.deployment-status.*", "cdnca.agent.deployment-status.generic-v2.*.*",
		"cdnca.agent.deployment-status.cache.*", "cdnca.agent.deployment-status.cache-dlq.*",
		"cdnca.agent.deployment-status.upgrade.*")
	status.Config.Metadata = map[string]string{"_nats.level": "1", "_nats.ver": "2.12.15"}
	if !sharedStreamCovers(command, required[0], config) || !sharedStreamCovers(status, required[1], config) {
		t.Fatal("shared Agent streams carrying the cache subjects were rejected")
	}
	// Exactly the cache runtime's own subjects (dedicated streams) still bind.
	if !sharedStreamCovers(sharedAgentStream("AGENT_DEPLOYMENT_STATUS",
		"cdnca.agent.deployment-status.cache-dlq.*", "cdnca.agent.deployment-status.cache.*"),
		required[1], config) {
		t.Fatal("subject coverage was made order-dependent")
	}

	tests := []struct {
		name   string
		stream int
		mutate func(*nats.StreamConfig)
	}{
		{"name", 0, func(actual *nats.StreamConfig) { actual.Name += "_wrong" }},
		{"missing command subject", 0, func(actual *nats.StreamConfig) {
			actual.Subjects = []string{"cdnca.agent.commands.*", "cdnca.agent.commands.upgrade.*"}
		}},
		{"missing DLQ subject", 1, func(actual *nats.StreamConfig) {
			actual.Subjects = []string{"cdnca.agent.deployment-status.*", "cdnca.agent.deployment-status.cache.*"}
		}},
		{"missing status subject", 1, func(actual *nats.StreamConfig) {
			actual.Subjects = []string{"cdnca.agent.deployment-status.cache-dlq.*"}
		}},
		{"broad subject", 0, func(actual *nats.StreamConfig) {
			actual.Subjects = append(actual.Subjects, "cdnca.agent.commands.>")
		}},
		{"work queue retention", 1, func(actual *nats.StreamConfig) { actual.Retention = nats.WorkQueuePolicy }},
		{"memory storage", 0, func(actual *nats.StreamConfig) { actual.Storage = nats.MemoryStorage }},
		{"replicas below minimum", 0, func(actual *nats.StreamConfig) { actual.Replicas = 0 }},
		{"no duplicate window", 0, func(actual *nats.StreamConfig) { actual.Duplicates = 0 }},
		{"message size below payload", 0, func(actual *nats.StreamConfig) { actual.MaxMsgSize = 1024 }},
		{"no ack", 1, func(actual *nats.StreamConfig) { actual.NoAck = true }},
		{"sealed", 1, func(actual *nats.StreamConfig) { actual.Sealed = true }},
		{"mirror", 0, func(actual *nats.StreamConfig) { actual.Mirror = &nats.StreamSource{Name: "OTHER"} }},
		{"source", 0, func(actual *nats.StreamConfig) { actual.Sources = []*nats.StreamSource{{Name: "OTHER"}} }},
		{"subject transform", 0, func(actual *nats.StreamConfig) {
			actual.SubjectTransform = &nats.SubjectTransformConfig{Source: "cdnca.agent.commands.cache.*", Destination: "other.*"}
		}},
		{"republish", 1, func(actual *nats.StreamConfig) {
			actual.RePublish = &nats.RePublish{Source: ">", Destination: "other.>"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := command
			if test.stream == 1 {
				source = status
			}
			actual := &nats.StreamInfo{Config: source.Config}
			actual.Config.Subjects = append([]string(nil), source.Config.Subjects...)
			test.mutate(&actual.Config)
			if sharedStreamCovers(actual, required[test.stream], config) {
				t.Fatal("unsafe shared stream was accepted")
			}
		})
	}

	clustered := config
	clustered.Replicas = 3
	if sharedStreamCovers(command, required[0], clustered) {
		t.Fatal("single-replica stream accepted under a clustered replica minimum")
	}
	replicated := &nats.StreamInfo{Config: command.Config}
	replicated.Config.Replicas = 3
	if !sharedStreamCovers(replicated, required[0], clustered) {
		t.Fatal("three-replica stream rejected under a clustered replica minimum")
	}
	if sharedStreamCovers(nil, required[0], config) {
		t.Fatal("nil stream info accepted")
	}
}

func TestNATSConsumerContractIsExact(t *testing.T) {
	config := DefaultConfig()
	expected := expectedConsumer(config)
	valid := &nats.ConsumerInfo{Stream: config.StatusStream, Name: config.Durable, Config: *expected}
	valid.Config.Metadata = map[string]string{"_nats.level": "1", "_nats.ver": "2.11.4"}
	if !sameConsumer(valid, config.StatusStream, expected) {
		t.Fatal("exact consumer configuration was rejected")
	}

	tests := []struct {
		name   string
		mutate func(*nats.ConsumerInfo)
	}{
		{"stream", func(actual *nats.ConsumerInfo) { actual.Stream += "_wrong" }},
		{"info name", func(actual *nats.ConsumerInfo) { actual.Name += "_wrong" }},
		{"durable", func(actual *nats.ConsumerInfo) { actual.Config.Durable += "_wrong" }},
		{"config name", func(actual *nats.ConsumerInfo) { actual.Config.Name += "_wrong" }},
		{"description", func(actual *nats.ConsumerInfo) { actual.Config.Description = "wrong" }},
		{"user metadata", func(actual *nats.ConsumerInfo) { actual.Config.Metadata = map[string]string{"owner": "other"} }},
		{"deliver policy", func(actual *nats.ConsumerInfo) { actual.Config.DeliverPolicy = nats.DeliverLastPolicy }},
		{"start sequence", func(actual *nats.ConsumerInfo) { actual.Config.OptStartSeq = 1 }},
		{"start time", func(actual *nats.ConsumerInfo) { value := runtimeTestNow; actual.Config.OptStartTime = &value }},
		{"ack policy", func(actual *nats.ConsumerInfo) { actual.Config.AckPolicy = nats.AckAllPolicy }},
		{"ack wait", func(actual *nats.ConsumerInfo) { actual.Config.AckWait++ }},
		{"max deliver", func(actual *nats.ConsumerInfo) { actual.Config.MaxDeliver++ }},
		{"backoff", func(actual *nats.ConsumerInfo) { actual.Config.BackOff = []time.Duration{time.Second} }},
		{"filter subject", func(actual *nats.ConsumerInfo) { actual.Config.FilterSubject = "other.>" }},
		{"filter subjects", func(actual *nats.ConsumerInfo) { actual.Config.FilterSubjects = []string{"other.>"} }},
		{"replay policy", func(actual *nats.ConsumerInfo) { actual.Config.ReplayPolicy = nats.ReplayOriginalPolicy }},
		{"rate limit", func(actual *nats.ConsumerInfo) { actual.Config.RateLimit = 1 }},
		{"sample frequency", func(actual *nats.ConsumerInfo) { actual.Config.SampleFrequency = "100" }},
		{"max waiting", func(actual *nats.ConsumerInfo) { actual.Config.MaxWaiting++ }},
		{"max ack pending", func(actual *nats.ConsumerInfo) { actual.Config.MaxAckPending++ }},
		{"flow control", func(actual *nats.ConsumerInfo) { actual.Config.FlowControl = true }},
		{"heartbeat", func(actual *nats.ConsumerInfo) { actual.Config.Heartbeat = time.Second }},
		{"headers only", func(actual *nats.ConsumerInfo) { actual.Config.HeadersOnly = true }},
		{"max request batch", func(actual *nats.ConsumerInfo) { actual.Config.MaxRequestBatch++ }},
		{"max request expires", func(actual *nats.ConsumerInfo) { actual.Config.MaxRequestExpires++ }},
		{"max request bytes", func(actual *nats.ConsumerInfo) { actual.Config.MaxRequestMaxBytes-- }},
		{"push subject", func(actual *nats.ConsumerInfo) { actual.Config.DeliverSubject = "deliver" }},
		{"push group", func(actual *nats.ConsumerInfo) { actual.Config.DeliverGroup = "group" }},
		{"inactive threshold", func(actual *nats.ConsumerInfo) { actual.Config.InactiveThreshold = time.Second }},
		{"replicas", func(actual *nats.ConsumerInfo) { actual.Config.Replicas = 1 }},
		{"memory storage", func(actual *nats.ConsumerInfo) { actual.Config.MemoryStorage = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := &nats.ConsumerInfo{Stream: config.StatusStream, Name: config.Durable, Config: *expected}
			test.mutate(actual)
			if sameConsumer(actual, config.StatusStream, expected) {
				t.Fatal("consumer behavior mismatch was accepted")
			}
		})
	}
}

func TestNATSRequiredAPILevelIsFailClosed(t *testing.T) {
	for _, metadata := range []map[string]string{
		nil,
		{"_nats.level": "1", "_nats.req.level": "0", "_nats.ver": "2.11.4"},
	} {
		if !sameNATSMetadata(metadata, nil) {
			t.Fatalf("canonical metadata was rejected: %v", metadata)
		}
	}
	for _, requiredLevel := range []string{"", "00", "1", "2", "-1", "invalid"} {
		metadata := map[string]string{"_nats.req.level": requiredLevel}
		if sameNATSMetadata(metadata, nil) {
			t.Fatalf("unsupported required API level %q was accepted", requiredLevel)
		}
	}
}

func TestBindVerifiedNATSFailsClosedWithRedactedStage(t *testing.T) {
	config := DefaultConfig()
	secret := "nats://operator:secret@127.0.0.1:4222"
	_, _, err := bindVerifiedNATS(&failingJetStream{
		err: fmt.Errorf("%w contacting %s", context.DeadlineExceeded, secret),
	}, config)
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "operator") ||
		strings.Contains(err.Error(), "secret") || err.Error() != "cache control JetStream initialization failed: stream_info" {
		t.Fatalf("non-redacted or unstable stage error: %q", err)
	}
	if _, _, err := newNATS(nil, config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil connection error=%v", err)
	}
}

type failingJetStream struct {
	nats.JetStreamContext
	err error
}

func (jetstream *failingJetStream) StreamInfo(string, ...nats.JSOpt) (*nats.StreamInfo, error) {
	return nil, jetstream.err
}

func TestConfigBackoffAndDeterministicCommandContract(t *testing.T) {
	config := DefaultConfig()
	config.Clock = func() time.Time { return runtimeTestNow }
	if err := config.validate(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		delivery uint64
		want     time.Duration
	}{{1, time.Second}, {2, 2 * time.Second}, {3, 4 * time.Second}, {100, 30 * time.Second}} {
		if got := retryDelay(time.Second, 30*time.Second, test.delivery); got != test.want {
			t.Fatalf("retryDelay delivery=%d got=%s want=%s", test.delivery, got, test.want)
		}
	}

	for _, test := range []struct {
		action     cachecontrol.Action
		targetType cachecontrol.TargetType
		wantAction agentv1.CacheControlAction
		wantScope  agentv1.CacheControlScope
	}{
		{cachecontrol.ActionPurge, cachecontrol.TargetExactURL,
			agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_EXACT,
			agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_URL},
		{cachecontrol.ActionPurge, cachecontrol.TargetDirectoryPrefix,
			agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_PREFIX,
			agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_DIRECTORY},
		{cachecontrol.ActionPurge, cachecontrol.TargetWholeSite,
			agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_SITE,
			agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_SITE},
		{cachecontrol.ActionPrewarm, cachecontrol.TargetExactURL,
			agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PREWARM,
			agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_URL},
	} {
		claim := testClaim(test.action, test.targetType)
		command, err := buildCommand(claim)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt, err := buildCommand(claim)
		if err != nil {
			t.Fatal(err)
		}
		first, _ := proto.MarshalOptions{Deterministic: true}.Marshal(command)
		second, _ := proto.MarshalOptions{Deterministic: true}.Marshal(rebuilt)
		if !bytes.Equal(first, second) || command.Action != test.wantAction || command.Scope != test.wantScope ||
			command.TaskId != taskID(claim) || command.Event.GetTaskId() != command.TaskId ||
			command.Event.EventId != stableUUID("event:"+command.TaskId).String() ||
			command.Event.RequestId != stableUUID("request:"+command.TaskId).String() {
			t.Fatalf("command contract mismatch: %+v", command)
		}
		if test.targetType == cachecontrol.TargetWholeSite {
			emptyDigest := sha256Bytes("")
			if command.Targets[0].CanonicalUrl != "" || !bytes.Equal(command.Targets[0].Sha256, emptyDigest) {
				t.Fatalf("whole-site wire target=%+v", command.Targets[0])
			}
		}
	}
}

func TestCommandPreservesSparseTargetOrdinalsAndCarriesTenant(t *testing.T) {
	claim := testClaim(cachecontrol.ActionPrewarm, cachecontrol.TargetExactURL)
	claim.Targets = []cachecontrol.Target{
		{Ordinal: 2, CanonicalURL: "https://cache.example/assets/a.css", CanonicalPath: "/assets/a.css"},
		{Ordinal: 5, CanonicalURL: "https://cache.example/assets/b.css", CanonicalPath: "/assets/b.css"},
	}
	command, err := buildCommand(claim)
	if err != nil {
		t.Fatal(err)
	}
	if command.Targets[0].Index != 0 || command.Targets[0].TargetOrdinal != 2 ||
		command.Targets[1].Index != 1 || command.Targets[1].TargetOrdinal != 5 {
		t.Fatalf("sparse wire targets=%+v", command.Targets)
	}
	tenantField := command.ProtoReflect().Descriptor().Fields().ByNumber(17)
	if tenantField == nil || command.ProtoReflect().Get(tenantField).String() != claim.TenantID.String() {
		t.Fatalf("tenant field 17=%v claim tenant=%s", tenantField, claim.TenantID)
	}
	status := testStatus(command, agentv1.CacheControlState_CACHE_CONTROL_STATE_PARTIAL_FAILED,
		agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS)
	status.Results = append(status.Results, &agentv1.CacheControlTargetResult{
		Index: 1, TargetOrdinal: 5, Sha256: append([]byte(nil), command.Targets[1].Sha256...),
		State:      agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_FAILED,
		ResultCode: "failed", CauseCode: "origin_unavailable", Attempts: 1,
		CompletedTime: timestamppb.New(runtimeTestNow.Add(time.Second)),
	})
	if !commandMatchesStatus(command, status) {
		t.Fatal("status with matching tenant did not match command")
	}
	status.TenantId = uuid.NewString()
	if commandMatchesStatus(command, status) {
		t.Fatal("status with a different tenant matched command")
	}
}

func TestStatusDecodeTerminalMappingAndUnknownFieldRejection(t *testing.T) {
	config := DefaultConfig()
	claim := testClaim(cachecontrol.ActionPurge, cachecontrol.TargetExactURL)
	command, err := buildCommand(claim)
	if err != nil {
		t.Fatal(err)
	}
	status := testStatus(command, agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED,
		agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SKIPPED)
	payload, _ := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	delivery := &fakeDelivery{subject: config.StatusSubjectPrefix + "." + claim.NodeID.String(), data: payload, delivered: 1}
	decoded, reason := decodeStatus(delivery, config)
	if reason != "" || !commandMatchesStatus(command, decoded) {
		t.Fatalf("decode reason=%q status=%+v", reason, decoded)
	}
	results, err := terminalResults(command, decoded)
	if err != nil || len(results) != 1 || results[0].State != cachecontrol.ItemSucceeded {
		t.Fatalf("terminal results=%+v err=%v", results, err)
	}

	unknown := append(append([]byte(nil), payload...), 0xa0, 0x06, 0x01)
	delivery.data = unknown
	if _, reason := decodeStatus(delivery, config); reason != "protobuf_invalid" {
		t.Fatalf("unknown field reason=%q", reason)
	}
	delivery.data = payload
	delivery.subject = config.StatusSubjectPrefix + "." + uuid.NewString()
	if _, reason := decodeStatus(delivery, config); reason != "subject_mismatch" {
		t.Fatalf("subject mismatch reason=%q", reason)
	}

	partial := testStatus(command, agentv1.CacheControlState_CACHE_CONTROL_STATE_PARTIAL_FAILED,
		agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_FAILED)
	if _, err := terminalResults(command, partial); !errors.Is(err, cachecontrol.ErrInvalidInput) {
		t.Fatalf("one-target partial result err=%v", err)
	}
}

func TestProcessorAckLateTermNakAndQuarantine(t *testing.T) {
	config := DefaultConfig()
	config.Clock = func() time.Time { return runtimeTestNow }
	claim := testClaim(cachecontrol.ActionPrewarm, cachecontrol.TargetExactURL)
	command, err := buildCommand(claim)
	if err != nil {
		t.Fatal(err)
	}
	status := testStatus(command, agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED,
		agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS)
	payload, _ := proto.MarshalOptions{Deterministic: true}.Marshal(status)

	control := &fakeControl{open: []cachecontrol.Claim{claim}}
	source := &fakeDelivery{subject: config.StatusSubjectPrefix + "." + claim.NodeID.String(), data: payload, delivered: 1}
	runtime := testRuntime(config, control, source)
	disposition, err := runtime.ProcessStatusOnce(context.Background())
	if err != nil || disposition != DispositionAck || source.acks != 1 || len(control.reports) != 1 {
		t.Fatalf("terminal disposition=%s err=%v delivery=%+v reports=%d", disposition, err, source, len(control.reports))
	}

	control.open = nil
	source = &fakeDelivery{subject: source.subject, data: payload, delivered: 2}
	runtime.consumer = &fakeConsumer{delivery: source}
	disposition, err = runtime.ProcessStatusOnce(context.Background())
	if err != nil || disposition != DispositionTerm || source.terms != 1 || len(control.reports) != 1 {
		t.Fatalf("late disposition=%s err=%v delivery=%+v", disposition, err, source)
	}

	control.open = []cachecontrol.Claim{claim}
	control.reportErr = errors.New("temporary postgres outage")
	source = &fakeDelivery{subject: source.subject, data: payload, delivered: 2}
	runtime.consumer = &fakeConsumer{delivery: source}
	disposition, err = runtime.ProcessStatusOnce(context.Background())
	if disposition != DispositionNak || err == nil || source.naks != 1 || source.nakDelay != 2*time.Second {
		t.Fatalf("transient disposition=%s err=%v delivery=%+v", disposition, err, source)
	}

	control.reportErr = nil
	source = &fakeDelivery{subject: source.subject, data: append(payload, 0xa0, 0x06, 0x01), delivered: 1}
	runtime.consumer = &fakeConsumer{delivery: source}
	disposition, err = runtime.ProcessStatusOnce(context.Background())
	bus := runtime.bus.(*fakeBus)
	if err != nil || disposition != DispositionTerm || source.terms != 1 || bus.dlq != 1 {
		t.Fatalf("poison disposition=%s err=%v delivery=%+v dlq=%d", disposition, err, source, bus.dlq)
	}
}

func TestProcessorQuarantinesStateSequenceMismatch(t *testing.T) {
	config := DefaultConfig()
	config.Clock = func() time.Time { return runtimeTestNow }
	claim := testClaim(cachecontrol.ActionPrewarm, cachecontrol.TargetExactURL)
	command, err := buildCommand(claim)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name     string
		state    agentv1.CacheControlState
		sequence uint64
		terminal bool
	}{
		{name: "delivered as running", state: agentv1.CacheControlState_CACHE_CONTROL_STATE_DELIVERED, sequence: 2},
		{name: "running as delivered", state: agentv1.CacheControlState_CACHE_CONTROL_STATE_RUNNING, sequence: 1},
		{name: "terminal as delivered", state: agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED, sequence: 1, terminal: true},
		{name: "terminal as running", state: agentv1.CacheControlState_CACHE_CONTROL_STATE_FAILED, sequence: 2, terminal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			targetState := agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_FAILED
			if test.state == agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED {
				targetState = agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS
			}
			status := testStatus(command, test.state, targetState)
			status.TransitionSequence = test.sequence
			if !test.terminal {
				status.Results = nil
			}
			payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
			if err != nil {
				t.Fatal(err)
			}
			source := &fakeDelivery{
				subject: config.StatusSubjectPrefix + "." + claim.NodeID.String(), data: payload, delivered: 1,
			}
			control := &fakeControl{open: []cachecontrol.Claim{claim}}
			runtime := testRuntime(config, control, source)
			disposition, err := runtime.ProcessStatusOnce(context.Background())
			bus := runtime.bus.(*fakeBus)
			if err != nil || disposition != DispositionTerm || source.terms != 1 || bus.dlq != 1 || len(control.reports) != 0 {
				t.Fatalf("disposition=%s err=%v source=%+v dlq=%d reports=%d",
					disposition, err, source, bus.dlq, len(control.reports))
			}
		})
	}
}

func TestProcessorUsesDurableClaimOwnerAcrossRuntimeReplicas(t *testing.T) {
	config := DefaultConfig()
	config.WorkerID = "worker-b"
	config.Clock = func() time.Time { return runtimeTestNow }
	claim := testClaim(cachecontrol.ActionPrewarm, cachecontrol.TargetExactURL)
	claim.WorkerID = "worker-a"
	command, err := buildCommand(claim)
	if err != nil {
		t.Fatal(err)
	}
	status := testStatus(command, agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED,
		agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS)
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	control := &fakeControl{open: []cachecontrol.Claim{claim}, openOwner: "worker-a"}
	source := &fakeDelivery{
		subject: config.StatusSubjectPrefix + "." + claim.NodeID.String(), data: payload, delivered: 1,
	}
	runtime := testRuntime(config, control, source)
	disposition, err := runtime.ProcessStatusOnce(context.Background())
	if err != nil || disposition != DispositionAck || source.acks != 1 || source.terms != 0 ||
		len(control.reports) != 1 || control.reports[0].WorkerID != "worker-a" {
		t.Fatalf("cross-replica disposition=%s err=%v source=%+v reports=%+v",
			disposition, err, source, control.reports)
	}
}

func TestSchedulerReplaysBeforeClaimsAndSkipsOfflineNodes(t *testing.T) {
	config := DefaultConfig()
	config.ClaimBatch = 2
	config.Clock = func() time.Time { return runtimeTestNow }
	claim := testClaim(cachecontrol.ActionPurge, cachecontrol.TargetExactURL)
	control := &fakeControl{open: []cachecontrol.Claim{claim}}
	bus := &fakeBus{}
	runtime := &Runtime{config: config, control: control, repository: &fakeRepository{},
		leases: &fakeLeases{}, bus: bus, consumer: &fakeConsumer{err: ErrNoMessage}}
	result, err := runtime.RunSchedulerOnce(context.Background())
	if err != nil || result.Recovered != 1 || result.Published != 1 || control.claimCalls != 0 {
		t.Fatalf("recovery result=%+v err=%v claims=%d", result, err, control.claimCalls)
	}

	scopeA, scopeB := uuid.New(), uuid.New()
	onlineA, offlineA, onlineB := uuid.New(), uuid.New(), uuid.New()
	control.open = []cachecontrol.Claim{claim}
	control.claims = map[uuid.UUID][]cachecontrol.Claim{
		scopeA: {claimWithIdentity(claim, scopeA, onlineA)},
		scopeB: {claimWithIdentity(claim, scopeB, onlineB)},
	}
	runtime.repository = &fakeRepository{
		scopes: []uuid.UUID{scopeA, scopeB},
		nodes: []queuedNode{
			{ScopeID: scopeA, NodeID: onlineA},
			{ScopeID: scopeA, NodeID: offlineA},
			{ScopeID: scopeB, NodeID: onlineB},
		},
	}
	runtime.leases = &fakeLeases{online: map[uuid.UUID]bool{onlineA: true, onlineB: true}}
	result, err = runtime.RunSchedulerOnce(context.Background())
	if err != nil || result.Recovered != 1 || result.Claimed != 1 || result.Published != 2 ||
		result.Offline != 1 || len(control.claimOrder) != 1 || control.claimOrder[0] != scopeA {
		t.Fatalf("mixed recovery result=%+v err=%v order=%v", result, err, control.claimOrder)
	}

	control.open = nil
	control.claims[scopeA] = []cachecontrol.Claim{claimWithIdentity(claim, scopeA, onlineA)}
	runtime.config.ClaimBatch = 1
	result, err = runtime.RunSchedulerOnce(context.Background())
	if err != nil || result.Recovered != 0 || result.Claimed != 1 || result.Published != 1 ||
		len(control.claimOrder) != 2 || control.claimOrder[1] != scopeB {
		t.Fatalf("cross-batch fairness result=%+v err=%v order=%v", result, err, control.claimOrder)
	}
}

func TestSchedulerPagesPastOneThousandOfflineNodes(t *testing.T) {
	config := DefaultConfig()
	config.ClaimBatch = 1
	config.Clock = func() time.Time { return runtimeTestNow }
	scopeID, onlineNodeID := uuid.New(), uuid.New()
	claim := claimWithIdentity(testClaim(cachecontrol.ActionPurge, cachecontrol.TargetExactURL), scopeID, onlineNodeID)
	nodes := make([]queuedNode, 0, 1001)
	for index := 0; index < 1000; index++ {
		nodes = append(nodes, queuedNode{ScopeID: scopeID, NodeID: uuid.MustParse(fmt.Sprintf("00000000-0000-0000-0000-%012d", index+1))})
	}
	nodes = append(nodes, queuedNode{ScopeID: scopeID, NodeID: onlineNodeID})
	control := &fakeControl{claims: map[uuid.UUID][]cachecontrol.Claim{scopeID: {claim}}}
	repository := &fakeRepository{scopes: []uuid.UUID{scopeID}, nodes: nodes, honorLimit: true}
	runtime := &Runtime{
		config: config, control: control, repository: repository,
		leases: &fakeLeases{online: map[uuid.UUID]bool{onlineNodeID: true}},
		bus:    &fakeBus{}, consumer: &fakeConsumer{err: ErrNoMessage},
	}
	result, err := runtime.RunSchedulerOnce(context.Background())
	if err != nil || result.Claimed != 1 || result.Published != 1 || result.Offline != 1000 ||
		repository.readyCalls < 2 {
		t.Fatalf("paged scheduler result=%+v err=%v ready calls=%d", result, err, repository.readyCalls)
	}
}

func TestSchedulerClaimsMultipleOnlineNodesFromOneScopeInSameBatch(t *testing.T) {
	config := DefaultConfig()
	config.ClaimBatch = 2
	config.Clock = func() time.Time { return runtimeTestNow }
	scopeID, nodeA, nodeB := uuid.New(), uuid.New(), uuid.New()
	base := testClaim(cachecontrol.ActionPurge, cachecontrol.TargetExactURL)
	claimA := claimWithIdentity(base, scopeID, nodeA)
	claimB := claimWithIdentity(base, scopeID, nodeB)
	control := &nodeBoundFakeControl{fakeControl: fakeControl{claims: map[uuid.UUID][]cachecontrol.Claim{
		scopeID: {claimA, claimB},
	}}}
	runtime := &Runtime{
		config: config, control: control,
		repository: &fakeRepository{scopes: []uuid.UUID{scopeID}, nodes: []queuedNode{
			{ScopeID: scopeID, NodeID: nodeA},
			{ScopeID: scopeID, NodeID: nodeB},
		}},
		leases: &fakeLeases{online: map[uuid.UUID]bool{nodeA: true, nodeB: true}},
		bus:    &fakeBus{}, consumer: &fakeConsumer{err: ErrNoMessage},
	}

	result, err := runtime.RunSchedulerOnce(context.Background())
	if err != nil || result.Claimed != 2 || result.Published != 2 || control.claimCalls != 2 {
		t.Fatalf("multi-node batch result=%+v err=%v claim_calls=%d", result, err, control.claimCalls)
	}
}

func testClaim(action cachecontrol.Action, targetType cachecontrol.TargetType) cachecontrol.Claim {
	canonicalURL := "https://cache.example/assets/app.css"
	canonicalPath := "/assets/app.css"
	if targetType == cachecontrol.TargetDirectoryPrefix {
		canonicalURL, canonicalPath = "https://cache.example/assets/", "/assets/"
	}
	if targetType == cachecontrol.TargetWholeSite {
		canonicalURL, canonicalPath = "/", "/"
	}
	digest := sha256Array("request")
	return cachecontrol.Claim{
		OperationID: uuid.New(), ScopeID: uuid.New(), TenantID: uuid.New(), SiteID: uuid.New(), NodeID: uuid.New(),
		Action: action, TargetType: targetType, Attempt: 1, LeaseID: uuid.New(),
		WorkerID:  "worker-a",
		ClaimedAt: runtimeTestNow, LeaseExpiresAt: runtimeTestNow.Add(time.Hour),
		RequestDigest: digest, Priority: "normal", ConfigVersionID: uuid.New(), ConfigRevision: 7,
		Targets: []cachecontrol.Target{{Ordinal: 1, CanonicalURL: canonicalURL, CanonicalPath: canonicalPath}},
	}
}

func claimWithIdentity(claim cachecontrol.Claim, scopeID, nodeID uuid.UUID) cachecontrol.Claim {
	claim.ScopeID, claim.NodeID = scopeID, nodeID
	claim.OperationID, claim.LeaseID = uuid.New(), uuid.New()
	return claim
}

func testStatus(command *agentv1.CacheControlCommand, state agentv1.CacheControlState,
	targetState agentv1.CacheControlTargetState,
) *agentv1.CacheControlStatus {
	eventID := uuid.NewString()
	status := &agentv1.CacheControlStatus{
		Event: &commonv1.EventMetadata{
			EventId: eventID, RequestId: command.Event.RequestId,
			OccurredTime: timestamppb.New(runtimeTestNow.Add(time.Second)),
			CausationId:  stringPointer(command.Event.EventId), CorrelationId: command.Event.CorrelationId,
			TaskId: stringPointer(command.TaskId),
		},
		TaskId: command.TaskId, ScopeId: command.ScopeId, SiteId: command.SiteId,
		NodeId: command.NodeId, ControlOperationId: command.ControlOperationId,
		LeaseId: command.LeaseId, Attempt: command.Attempt,
		ConfigVersionId: command.ConfigVersionId, ConfigRevision: command.ConfigRevision,
		Action: command.Action, Scope: command.Scope, State: state, TransitionSequence: 3,
		RequestDigest: append([]byte(nil), command.RequestDigest...), ActiveConfigUnchanged: true,
		Results: []*agentv1.CacheControlTargetResult{{
			Index: 0, TargetOrdinal: command.Targets[0].TargetOrdinal,
			Sha256: append([]byte(nil), command.Targets[0].Sha256...),
			State:  targetState, ResultCode: "completed", Attempts: 1,
			CompletedTime: timestamppb.New(runtimeTestNow.Add(time.Second)),
		}},
	}
	status.TenantId = command.TenantId
	return status
}

func sha256Array(value string) [32]byte { return sha256.Sum256([]byte(value)) }
func sha256Bytes(value string) []byte {
	digest := sha256Array(value)
	return digest[:]
}

type fakeControl struct {
	open       []cachecontrol.Claim
	openOwner  string
	claims     map[uuid.UUID][]cachecontrol.Claim
	reports    []cachecontrol.ReportRequest
	reportErr  error
	claimCalls int
	claimOrder []uuid.UUID
}

type nodeBoundFakeControl struct{ fakeControl }

func (control *nodeBoundFakeControl) Claim(_ context.Context, request cachecontrol.ClaimRequest) ([]cachecontrol.Claim, error) {
	control.claimCalls++
	control.claimOrder = append(control.claimOrder, request.ScopeID)
	claims := control.claims[request.ScopeID]
	for claimIndex, claim := range claims {
		for _, nodeID := range request.OnlineNodeIDs {
			if claim.NodeID != nodeID {
				continue
			}
			control.claims[request.ScopeID] = append(claims[:claimIndex], claims[claimIndex+1:]...)
			return []cachecontrol.Claim{claim}, nil
		}
	}
	return nil, nil
}

func (control *fakeControl) OpenClaims(_ context.Context, request cachecontrol.OpenClaimsRequest) ([]cachecontrol.Claim, error) {
	if control.openOwner != "" && request.WorkerID != control.openOwner {
		return nil, nil
	}
	return append([]cachecontrol.Claim(nil), control.open...), nil
}
func (control *fakeControl) ResolveClaim(_ context.Context, identity cachecontrol.ClaimIdentity) (cachecontrol.Claim, error) {
	for _, claim := range control.open {
		if claim.ScopeID == identity.ScopeID && claim.OperationID == identity.OperationID &&
			claim.NodeID == identity.NodeID && claim.LeaseID == identity.LeaseID && claim.Attempt == identity.Attempt {
			return claim, nil
		}
	}
	return cachecontrol.Claim{}, cachecontrol.ErrNotFound
}
func (control *fakeControl) ReconcileExpired(context.Context, uuid.UUID, string) error { return nil }
func (control *fakeControl) Claim(_ context.Context, request cachecontrol.ClaimRequest) ([]cachecontrol.Claim, error) {
	control.claimCalls++
	control.claimOrder = append(control.claimOrder, request.ScopeID)
	claims := control.claims[request.ScopeID]
	if len(claims) == 0 {
		return nil, nil
	}
	control.claims[request.ScopeID] = claims[1:]
	return []cachecontrol.Claim{claims[0]}, nil
}
func (control *fakeControl) Report(_ context.Context, request cachecontrol.ReportRequest) (cachecontrol.ReportResult, error) {
	control.reports = append(control.reports, request)
	return cachecontrol.ReportResult{}, control.reportErr
}

type fakeRepository struct {
	scopes     []uuid.UUID
	nodes      []queuedNode
	honorLimit bool
	readyCalls int
}

func (repository *fakeRepository) activeScopes(context.Context) ([]uuid.UUID, error) {
	return append([]uuid.UUID(nil), repository.scopes...), nil
}
func (repository *fakeRepository) readyNodes(_ context.Context, _ time.Time, after *queuedNode, limit int) ([]queuedNode, error) {
	repository.readyCalls++
	if !repository.honorLimit {
		return append([]queuedNode(nil), repository.nodes...), nil
	}
	start := 0
	if after != nil {
		for index, node := range repository.nodes {
			if node.ScopeID == after.ScopeID && node.NodeID == after.NodeID {
				start = index + 1
				break
			}
		}
	}
	end := start + limit
	if end > len(repository.nodes) {
		end = len(repository.nodes)
	}
	return append([]queuedNode(nil), repository.nodes[start:end]...), nil
}

type fakeLeases struct{ online map[uuid.UUID]bool }

func (leases *fakeLeases) Exists(_ context.Context, nodeID uuid.UUID) (bool, error) {
	return leases.online[nodeID], nil
}

type fakeBus struct {
	commands []*agentv1.CacheControlCommand
	cancels  []*agentv1.CacheControlCancel
	dlq      int
}

func (bus *fakeBus) PublishCancel(_ context.Context, _ string, cancel *agentv1.CacheControlCancel) error {
	bus.cancels = append(bus.cancels, proto.Clone(cancel).(*agentv1.CacheControlCancel))
	return nil
}

func (bus *fakeBus) PublishCommand(_ context.Context, _ string, command *agentv1.CacheControlCommand) (bool, error) {
	bus.commands = append(bus.commands, proto.Clone(command).(*agentv1.CacheControlCommand))
	return false, nil
}
func (bus *fakeBus) PublishDLQ(context.Context, delivery, string) error { bus.dlq++; return nil }

type fakeConsumer struct {
	delivery delivery
	err      error
}

func (consumer *fakeConsumer) Next(context.Context) (delivery, error) {
	return consumer.delivery, consumer.err
}
func (consumer *fakeConsumer) Close() error { return nil }

type fakeDelivery struct {
	subject   string
	kind      string
	data      []byte
	delivered uint64
	acks      int
	naks      int
	terms     int
	nakDelay  time.Duration
}

func (source *fakeDelivery) Subject() string           { return source.subject }
func (source *fakeDelivery) Kind() string              { return source.kind }
func (source *fakeDelivery) Data() []byte              { return source.data }
func (source *fakeDelivery) NumDelivered() uint64      { return source.delivered }
func (source *fakeDelivery) Ack(context.Context) error { source.acks++; return nil }
func (source *fakeDelivery) Nak(_ context.Context, delay time.Duration) error {
	source.naks++
	source.nakDelay = delay
	return nil
}
func (source *fakeDelivery) Term(context.Context) error { source.terms++; return nil }

func testRuntime(config Config, control controlStore, source delivery) *Runtime {
	return &Runtime{
		config: config, control: control, repository: &fakeRepository{}, leases: &fakeLeases{},
		bus: &fakeBus{}, consumer: &fakeConsumer{delivery: source},
	}
}

func (control *fakeControl) SyncCarryingNodes(context.Context, uuid.UUID, string) (int, error) {
	return 0, nil
}

func (repository *fakeRepository) automaticScopes(context.Context, time.Time) ([]uuid.UUID, error) {
	return nil, nil
}
