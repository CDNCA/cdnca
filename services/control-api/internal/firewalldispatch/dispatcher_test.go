package firewalldispatch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var errInjected = errors.New("injected")

type fakeDB struct {
	tx       *fakeTx
	beginErr error
}

func (d *fakeDB) begin(context.Context) (dispatchTx, error) {
	if d.beginErr != nil {
		return nil, d.beginErr
	}
	return d.tx, nil
}

type fakeTx struct {
	claims         []claimedCommand
	loaded         claimedCommand
	claimErr       error
	loadErr        error
	promoted       []uuid.UUID
	published      []uuid.UUID
	retried        []uuid.UUID
	failed         []uuid.UUID
	acked          []uuid.UUID
	attempts       []int
	backoffs       []time.Time
	errorCodes     []string
	ackFingerprint string
	ackDisposition AckDisposition
	ackErr         error
	commits        int
	rollbacks      int
}

func (t *fakeTx) claim(_ context.Context, limit int, _ time.Time) ([]claimedCommand, error) {
	if t.claimErr != nil {
		return nil, t.claimErr
	}
	if len(t.claims) > limit {
		return append([]claimedCommand(nil), t.claims[:limit]...), nil
	}
	return append([]claimedCommand(nil), t.claims...), nil
}

func (t *fakeTx) promoteRetryable(_ context.Context, id uuid.UUID) error {
	t.promoted = append(t.promoted, id)
	return nil
}

func (t *fakeTx) markPublished(_ context.Context, id uuid.UUID, attempts int, _ time.Time) error {
	t.published = append(t.published, id)
	t.attempts = append(t.attempts, attempts)
	return nil
}

func (t *fakeTx) markFailure(_ context.Context, id uuid.UUID, attempts int, available time.Time, code string, terminal bool, _ time.Time) error {
	if terminal {
		t.failed = append(t.failed, id)
	} else {
		t.retried = append(t.retried, id)
	}
	t.attempts = append(t.attempts, attempts)
	t.backoffs = append(t.backoffs, available)
	t.errorCodes = append(t.errorCodes, code)
	return nil
}

func (t *fakeTx) loadForStatus(context.Context, *agentv1.FirewallStatus) (claimedCommand, error) {
	return t.loaded, t.loadErr
}

func (t *fakeTx) markAcked(_ context.Context, id uuid.UUID, _ string, _ *agentv1.FirewallStatus, fingerprint string, _ time.Time) (AckDisposition, error) {
	if t.ackErr != nil {
		return AckRejected, t.ackErr
	}
	if t.loaded.state == StateAcked && t.ackFingerprint != "" && t.ackFingerprint != fingerprint {
		return AckRejected, ErrStatusConflict
	}
	t.acked = append(t.acked, id)
	t.ackFingerprint = fingerprint
	t.loaded.state = StateAcked
	return t.ackDisposition, nil
}

func (t *fakeTx) commit(context.Context) error   { t.commits++; return nil }
func (t *fakeTx) rollback(context.Context) error { t.rollbacks++; return nil }

type publishCall struct {
	subject, messageID, stream string
	payload                    []byte
}

type fakeMessages struct {
	ack   *publishAck
	err   error
	calls []publishCall
}

func (m *fakeMessages) publish(_ context.Context, subject string, payload []byte, messageID, stream string) (*publishAck, error) {
	m.calls = append(m.calls, publishCall{subject: subject, payload: bytes.Clone(payload), messageID: messageID, stream: stream})
	return m.ack, m.err
}

func TestConfigBoundsAndNilDependenciesFailClosed(t *testing.T) {
	config := DefaultConfig()
	if err := config.validate(); err != nil {
		t.Fatal(err)
	}
	invalid := []Config{
		{},
		withConfig(config, func(c *Config) { c.BatchSize = 0 }),
		withConfig(config, func(c *Config) { c.BatchSize = 65 }),
		withConfig(config, func(c *Config) { c.OperationTimeout = 0 }),
		withConfig(config, func(c *Config) { c.LeaseTimeout = c.OperationTimeout }),
		withConfig(config, func(c *Config) { c.MaxAttempts = 15 }),
		withConfig(config, func(c *Config) { c.CommandSubjectPrefix = "cdnca.agent.>" }),
	}
	for index, candidate := range invalid {
		if candidate.validate() == nil {
			t.Fatalf("invalid config %d accepted", index)
		}
	}
	if _, err := newDispatcher(nil, &fakeMessages{}, config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil store error = %v", err)
	}
	if _, err := newDispatcher(&fakeDB{}, nil, config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil messages error = %v", err)
	}
}

func TestDispatchPublishesDeterministicTypedCommandAndSettlesExactPubAck(t *testing.T) {
	claim := validClaim(t, StatePending, 0)
	tx := &fakeTx{claims: []claimedCommand{claim}}
	messages := &fakeMessages{ack: &publishAck{stream: DefaultConfig().CommandStream, sequence: 9, duplicate: true}}
	dispatcher := testDispatcher(t, tx, messages)
	result, err := dispatcher.DispatchBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result != (BatchResult{Claimed: 1, Published: 1, Duplicates: 1}) || tx.commits != 1 || tx.rollbacks != 1 {
		t.Fatalf("result=%+v commits=%d rollbacks=%d", result, tx.commits, tx.rollbacks)
	}
	if len(messages.calls) != 1 || len(tx.published) != 1 || len(tx.retried) != 0 || len(tx.failed) != 0 {
		t.Fatalf("calls=%d published=%v retried=%v failed=%v", len(messages.calls), tx.published, tx.retried, tx.failed)
	}
	call := messages.calls[0]
	if call.subject != CommandSubjectPrefix+"."+claim.nodeID.String() || call.stream != CommandStream ||
		call.messageID != stableMessageID(claim.commandSHA256) || !bytes.Equal(call.payload, claim.commandBytes) || tx.attempts[0] != 1 {
		t.Fatalf("publish call=%+v attempts=%v", call, tx.attempts)
	}
}

func TestDispatchUnknownOutcomesRetryWithoutFalsePublication(t *testing.T) {
	cases := []struct {
		name string
		ack  *publishAck
		err  error
		code string
	}{
		{name: "nil_ack", code: "puback_missing"},
		{name: "wrong_stream", ack: &publishAck{stream: "WRONG", sequence: 1}, code: "puback_stream_mismatch"},
		{name: "zero_sequence", ack: &publishAck{stream: CommandStream}, code: "puback_invalid"},
		{name: "timeout", err: context.DeadlineExceeded, code: "publish_timeout"},
		{name: "unknown", err: errInjected, code: "publish_unknown"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			claim := validClaim(t, StateRetryable, 3)
			tx := &fakeTx{claims: []claimedCommand{claim}}
			dispatcher := testDispatcher(t, tx, &fakeMessages{ack: test.ack, err: test.err})
			result, err := dispatcher.DispatchBatch(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if result.Published != 0 || result.Retryable != 1 || len(tx.published) != 0 || len(tx.retried) != 1 ||
				len(tx.promoted) != 1 || tx.attempts[0] != 4 || tx.errorCodes[0] != test.code {
				t.Fatalf("result=%+v tx=%+v", result, tx)
			}
		})
	}
}

func TestDispatchExhaustionAndCancelledContext(t *testing.T) {
	exhausted := validClaim(t, StateRetryable, 15)
	tx := &fakeTx{claims: []claimedCommand{exhausted}}
	dispatcher := testDispatcher(t, tx, &fakeMessages{err: errInjected})
	result, err := dispatcher.DispatchBatch(context.Background())
	if err != nil || result.Exhausted != 1 || len(tx.failed) != 1 || tx.attempts[0] != 16 || len(tx.promoted) != 1 {
		t.Fatalf("result=%+v err=%v tx=%+v", result, err, tx)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cancelTx := &fakeTx{claims: []claimedCommand{validClaim(t, StatePending, 0)}}
	result, err = testDispatcher(t, cancelTx, &fakeMessages{}).DispatchBatch(cancelled)
	if !errors.Is(err, context.Canceled) || result.Published != 0 || cancelTx.commits != 0 || len(cancelTx.retried)+len(cancelTx.failed) != 0 {
		t.Fatalf("cancel result=%+v err=%v tx=%+v", result, err, cancelTx)
	}
}

func TestDispatchRejectsTamperedScopeDigestUnknownAndOrderingBeforePublish(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*claimedCommand)
	}{
		{name: "node", mutate: func(c *claimedCommand) { c.nodeID = uuid.New() }},
		{name: "tenant", mutate: func(c *claimedCommand) { c.tenantScopeID = uuid.New() }},
		{name: "site", mutate: func(c *claimedCommand) { c.siteID = uuid.New() }},
		{name: "idempotency", mutate: func(c *claimedCommand) { c.idempotencyKey = uuid.NewString() }},
		{name: "revision", mutate: func(c *claimedCommand) { c.policyVersion++ }},
		{name: "task_revision", mutate: func(c *claimedCommand) {
			mutateClaimCommand(t, c, func(command *agentv1.FirewallCommand) { command.TaskRevision++ })
		}},
		{name: "digest", mutate: func(c *claimedCommand) { c.commandSHA256[0] ^= 0xff }},
		{name: "unknown", mutate: func(c *claimedCommand) { c.commandBytes = append(c.commandBytes, 0xa0, 0x06, 0x01) }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			claim := validClaim(t, StatePending, 0)
			test.mutate(&claim)
			tx := &fakeTx{claims: []claimedCommand{claim}}
			messages := &fakeMessages{ack: &publishAck{stream: CommandStream, sequence: 1}}
			result, err := testDispatcher(t, tx, messages).DispatchBatch(context.Background())
			if err != nil || result.Exhausted != 1 || len(messages.calls) != 0 || len(tx.failed) != 1 {
				t.Fatalf("result=%+v err=%v calls=%d tx=%+v", result, err, len(messages.calls), tx)
			}
		})
	}
}

func TestHandleStatusCommitsExactAckReplayAndRejectsConflict(t *testing.T) {
	claim := validClaim(t, StatePublished, 1)
	status := validStatus(t, claim)
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	tx := &fakeTx{loaded: claim, ackDisposition: AckSettled}
	dispatcher := testDispatcher(t, tx, &fakeMessages{})
	disposition, err := dispatcher.HandleStatus(context.Background(), payload)
	if err != nil || disposition != AckSettled || tx.commits != 1 || len(tx.acked) != 1 || tx.ackFingerprint == "" {
		t.Fatalf("disposition=%v err=%v tx=%+v", disposition, err, tx)
	}

	replayTx := &fakeTx{loaded: withState(claim, StateAcked), ackDisposition: AckReplayed}
	disposition, err = testDispatcher(t, replayTx, &fakeMessages{}).HandleStatus(context.Background(), payload)
	if err != nil || disposition != AckReplayed || replayTx.commits != 1 {
		t.Fatalf("replay disposition=%v err=%v tx=%+v", disposition, err, replayTx)
	}

	conflict := proto.Clone(status).(*agentv1.FirewallStatus)
	conflict.State = agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_FAILED
	conflict.ActivePolicyVersion = conflict.ExpectedActivePolicyVersion
	conflict.ActivePolicyUnchanged = true
	conflict.ErrorCode = "APPLY_FAILED"
	bad, _ := proto.MarshalOptions{Deterministic: true}.Marshal(conflict)
	if _, err := dispatcher.HandleStatus(context.Background(), bad); !errors.Is(err, ErrStatusConflict) {
		t.Fatalf("conflicting terminal status error = %v", err)
	}
}

func TestHandleStatusRescuesLostPubAckAndRunStopsOnCancel(t *testing.T) {
	claim := validClaim(t, StateRetryable, 2)
	status := validStatus(t, claim)
	payload, _ := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	tx := &fakeTx{loaded: claim, ackDisposition: AckRescued}
	dispatcher := testDispatcher(t, tx, &fakeMessages{})
	disposition, err := dispatcher.HandleStatus(context.Background(), payload)
	if err != nil || disposition != AckRescued || len(tx.acked) != 1 {
		t.Fatalf("disposition=%v err=%v tx=%+v", disposition, err, tx)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dispatcher.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
}

func testDispatcher(t *testing.T, tx *fakeTx, messages *fakeMessages) *Dispatcher {
	t.Helper()
	dispatcher, err := newDispatcher(&fakeDB{tx: tx}, messages, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.now = func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }
	return dispatcher
}

func validClaim(t *testing.T, state string, attempts int) claimedCommand {
	t.Helper()
	tenant, site, node := uuid.New(), uuid.New(), uuid.New()
	task, event, request, idempotency := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	taskText := task.String()
	command := &agentv1.FirewallCommand{
		Event: &commonv1.EventMetadata{EventId: event.String(), RequestId: request.String(),
			OccurredTime: timestamppb.New(time.Unix(1_700_000_000, 0)), CorrelationId: request.String(), TaskId: &taskText},
		Schema: agentv1.FirewallSchema_FIREWALL_SCHEMA_V1, TaskId: task.String(), TaskRevision: 7,
		IdempotencyKey: idempotency.String(), TenantId: tenant.String(), SiteId: site.String(), NodeId: node.String(),
		PolicyVersion: 7, ExpectedActivePolicyVersion: 6,
		Operation:      agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY,
		RecoveryReason: agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE,
		Targets: []*agentv1.FirewallCIDRTarget{{Ordinal: 1, TenantId: tenant.String(), SiteId: site.String(),
			Action: agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_DENY, Cidr: "203.0.113.0/24", Source: "acl", ReasonCode: "ACL_MATCH"}},
		DeadlineTime: timestamppb.New(time.Unix(1_900_000_000, 0)),
	}
	unsigned, _ := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	digest := sha256.Sum256(unsigned)
	command.CommandSha256 = bytes.Clone(digest[:])
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	return claimedCommand{id: uuid.New(), tenantScopeID: tenant, siteID: site, nodeID: node,
		policyVersion: 7, expectedActiveVersion: 6, idempotencyKey: idempotency.String(), state: state,
		attempts: attempts, commandBytes: encoded, commandSHA256: digest}
}

func validStatus(t *testing.T, claim claimedCommand) *agentv1.FirewallStatus {
	t.Helper()
	command := new(agentv1.FirewallCommand)
	if err := proto.Unmarshal(claim.commandBytes, command); err != nil {
		t.Fatal(err)
	}
	causation, task := command.Event.EventId, command.TaskId
	return &agentv1.FirewallStatus{
		Event: &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: command.Event.RequestId,
			OccurredTime: timestamppb.New(time.Unix(1_800_000_000, 0)), CausationId: &causation,
			CorrelationId: command.Event.CorrelationId, TaskId: &task},
		Schema: command.Schema, TaskId: command.TaskId, TaskRevision: command.TaskRevision,
		IdempotencyKey: command.IdempotencyKey, TenantId: command.TenantId, SiteId: command.SiteId,
		NodeId: command.NodeId, PolicyVersion: command.PolicyVersion,
		ExpectedActivePolicyVersion: command.ExpectedActivePolicyVersion, Operation: command.Operation,
		RecoveryReason: command.RecoveryReason, CommandSha256: bytes.Clone(command.CommandSha256),
		State: agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_APPLIED, StatusRevision: 1,
		ActivePolicyVersion: command.PolicyVersion,
	}
}

func withConfig(config Config, change func(*Config)) Config { change(&config); return config }
func withState(command claimedCommand, state string) claimedCommand {
	command.state = state
	return command
}

func mutateClaimCommand(t *testing.T, claim *claimedCommand, mutate func(*agentv1.FirewallCommand)) {
	t.Helper()
	command := new(agentv1.FirewallCommand)
	if err := proto.Unmarshal(claim.commandBytes, command); err != nil {
		t.Fatal(err)
	}
	mutate(command)
	command.CommandSha256 = nil
	unsigned, _ := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	digest := sha256.Sum256(unsigned)
	command.CommandSha256 = bytes.Clone(digest[:])
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	claim.commandBytes = encoded
	claim.commandSHA256 = digest
}
