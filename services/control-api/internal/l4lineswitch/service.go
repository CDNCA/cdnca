package l4lineswitch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

var (
	metadataPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	traceparentPattern = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)
)

type Service struct {
	store        Store
	snapshots    SnapshotResolver
	publications PublicationCoordinator
	targets      TargetCoordinator
	drains       DrainCoordinator
	dns          DNSGate
	now          func() time.Time
}

// SetDNSGate makes health_gate wait for the scope's CNAME owners to stop
// resolving to the retiring nodes before their listeners are drained (FX27).
func (service *Service) SetDNSGate(gate DNSGate) { service.dns = gate }

func NewService(store Store, snapshots SnapshotResolver, publications PublicationCoordinator,
	targets TargetCoordinator, drains DrainCoordinator, now func() time.Time,
) (*Service, error) {
	if store == nil || snapshots == nil || publications == nil || targets == nil || drains == nil || now == nil {
		return nil, ErrInvalidInput
	}
	return &Service{store: store, snapshots: snapshots, publications: publications,
		targets: targets, drains: drains, now: now}, nil
}

func (service *Service) Start(ctx context.Context, request StartRequest) (Switch, error) {
	now := service.now().UTC().Truncate(time.Microsecond)
	if ctx == nil || !validStartRequest(request, now) {
		return Switch{}, ErrInvalidInput
	}
	from, err := service.snapshots.Resolve(ctx, request.Actor, request.ConfigurationScopeID, request.From)
	if err != nil {
		return Switch{}, err
	}
	to, err := service.snapshots.Resolve(ctx, request.Actor, request.ConfigurationScopeID, request.To)
	if err != nil {
		return Switch{}, err
	}
	if err := validSnapshots(from, to); err != nil {
		return Switch{}, err
	}
	prepareNodes, retiringNodes := switchNodeSets(from.NodeIDs, to.NodeIDs)
	digest, err := startRequestDigest(request, from, to, prepareNodes, retiringNodes)
	if err != nil {
		return Switch{}, err
	}
	switchID := uuid.NewSHA1(request.ConfigurationScopeID, digest[:])
	initial := Switch{
		ID: switchID, ConfigurationScopeID: request.ConfigurationScopeID,
		ExpectedSourceRevision: request.ExpectedSourceRevision, From: from, To: to,
		PrepareNodes: prepareNodes, RetiringNodes: retiringNodes, Health: request.Health, Drain: request.Drain,
		MaxAttempts: request.MaxAttempts, Deadline: request.Deadline.UTC(), RequestID: request.RequestID,
		CorrelationID: request.CorrelationID, Traceparent: request.Traceparent, State: StatePreparing,
		StateRevision: 1, DrainCommands: make(map[uuid.UUID]uuid.UUID), CreatedAt: now, UpdatedAt: now,
	}
	claimed, replayed, err := service.store.Claim(ctx, request.Actor, Claim{
		Switch: initial, IdempotencyKey: request.IdempotencyKey, RequestDigest: digest,
	})
	if err != nil {
		return Switch{}, err
	}
	if replayed && claimed.State != StatePreparing {
		claimed.Replayed = true
		return claimed, nil
	}
	prepared, err := service.publications.Prepare(ctx, request.Actor, claimed)
	if err != nil {
		return Switch{}, err
	}
	after := cloneSwitch(claimed)
	after.PreparePublication = prepared
	after.State = StateHealthGate
	after.ErrorCode = ""
	service.advance(&after, now)
	if err := service.store.CompareAndSwap(ctx, request.Actor, claimed, after); err != nil {
		return Switch{}, err
	}
	after.Replayed = replayed
	return after, nil
}

func (service *Service) Get(ctx context.Context, actor Actor, scopeID, switchID uuid.UUID) (Switch, error) {
	if ctx == nil || !validActor(actor) || scopeID == uuid.Nil || switchID == uuid.Nil {
		return Switch{}, ErrInvalidInput
	}
	return service.store.Get(ctx, actor, scopeID, switchID, PermissionRead)
}

func (service *Service) Latest(ctx context.Context, actor Actor, scopeID uuid.UUID) (Switch, error) {
	if ctx == nil || !validActor(actor) || scopeID == uuid.Nil {
		return Switch{}, ErrInvalidInput
	}
	return service.store.Latest(ctx, actor, scopeID, PermissionRead)
}

func (service *Service) Reconcile(ctx context.Context, actor Actor, scopeID, switchID uuid.UUID) (Switch, error) {
	if ctx == nil || !validAuthority(actor) || scopeID == uuid.Nil || switchID == uuid.Nil {
		return Switch{}, ErrInvalidInput
	}
	current, err := service.store.Get(ctx, actor, scopeID, switchID, PermissionManage)
	if err != nil {
		return Switch{}, err
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	if now.After(current.Deadline) && current.State != StateCompleted && current.State != StateRolledBack &&
		current.State != StateCompensatingOld && current.State != StateNeedsAttention {
		code := "SWITCH_DEADLINE_EXCEEDED"
		if current.State == StateHealthGate && service.dns != nil && len(current.RetiringNodes) > 0 &&
			current.PreparePublication.RolloutID != uuid.Nil {
			if status, err := service.publications.RolloutStatus(ctx, actor, current, current.PreparePublication.RolloutID); err == nil &&
				status == RolloutSucceeded {
				if gate, err := service.dns.Check(ctx, actor, current); err == nil && gate.State != DNSGateReady {
					code = "DNS_PROPAGATION_TIMEOUT"
				}
			}
		}
		return service.startCompensation(ctx, actor, current, now, code)
	}
	switch current.State {
	case StatePreparing:
		prepared, err := service.publications.Prepare(ctx, actor, current)
		if err != nil {
			return Switch{}, err
		}
		after := cloneSwitch(current)
		after.PreparePublication, after.State = prepared, StateHealthGate
		service.advance(&after, now)
		return after, service.store.CompareAndSwap(ctx, actor, current, after)
	case StateHealthGate:
		status, err := service.publications.RolloutStatus(ctx, actor, current, current.PreparePublication.RolloutID)
		if err != nil || status == RolloutPending {
			return current, err
		}
		if status == RolloutFailed {
			return service.startCompensation(ctx, actor, current, now, "TARGET_HEALTH_FAILED")
		}
		if status != RolloutSucceeded {
			return Switch{}, ErrConflict
		}
		if service.dns != nil && len(current.RetiringNodes) > 0 {
			// Waiting changes nothing durable: the next reconcile checks again,
			// and the switch deadline still bounds the wait.
			gate, err := service.dns.Check(ctx, actor, current)
			if err != nil {
				return current, err
			}
			if gate.State != DNSGateReady {
				waiting := cloneSwitch(current)
				waiting.DNSGate = &gate
				return waiting, nil
			}
		}
		commands, err := service.buildDrainCommands(ctx, actor, current)
		if err != nil {
			return service.startCompensation(ctx, actor, current, now, "DRAIN_PLAN_FAILED")
		}
		if err := service.targets.Activate(ctx, actor, current); err != nil {
			return current, err
		}
		after := cloneSwitch(current)
		for nodeID, command := range commands {
			after.DrainCommands[nodeID] = uuid.MustParse(command.CommandId)
		}
		if len(after.DrainCommands) == 0 {
			after.State = StateCompleted
		} else {
			after.State = StateDrainingOld
		}
		service.advance(&after, now)
		if err := service.store.CompareAndSwap(ctx, actor, current, after); err != nil {
			return Switch{}, err
		}
		if after.State == StateCompleted {
			return after, nil
		}
		if err := service.publishDrainCommands(ctx, actor, after, commands); err != nil {
			return after, err
		}
		return after, nil
	case StateDrainingOld:
		commands, err := service.buildDrainCommands(ctx, actor, current)
		if err != nil || !sameDrainCommands(current, commands) {
			return service.startCompensation(ctx, actor, current, now, "DRAIN_PLAN_INVALID")
		}
		if err := service.targets.Activate(ctx, actor, current); err != nil {
			return current, err
		}
		if err := service.publishDrainCommands(ctx, actor, current, commands); err != nil {
			return current, err
		}
		pending := false
		for _, nodeID := range current.RetiringNodes {
			status, err := service.drains.Status(ctx, actor, commands[nodeID])
			if err != nil {
				return current, err
			}
			switch status {
			case DrainPending:
				pending = true
			case DrainCompleted:
			case DrainFailed:
				return service.startCompensation(ctx, actor, current, now, "DRAIN_FAILED")
			default:
				return current, ErrConflict
			}
		}
		if pending {
			return current, nil
		}
		after := cloneSwitch(current)
		after.State, after.ErrorCode = StateCompleted, ""
		service.advance(&after, now)
		return after, service.store.CompareAndSwap(ctx, actor, current, after)
	case StateCompensatingOld:
		status, err := service.publications.RolloutStatus(ctx, actor, current, current.CompensationPublication.RolloutID)
		if err != nil || status == RolloutPending {
			return current, err
		}
		if status == RolloutFailed {
			after := cloneSwitch(current)
			after.State, after.ErrorCode = StateNeedsAttention, "COMPENSATION_FAILED"
			service.advance(&after, now)
			if err := service.store.CompareAndSwap(ctx, actor, current, after); err != nil {
				return Switch{}, err
			}
			return after, ErrUnsafeRollback
		}
		if status != RolloutSucceeded {
			return current, ErrConflict
		}
		if len(current.DrainCommands) > 0 {
			if err := service.targets.Restore(ctx, actor, current); err != nil {
				return current, err
			}
		}
		after := cloneSwitch(current)
		after.State = StateRolledBack
		service.advance(&after, now)
		return after, service.store.CompareAndSwap(ctx, actor, current, after)
	case StateCompleted, StateRolledBack, StateNeedsAttention:
		return current, nil
	default:
		return Switch{}, ErrConflict
	}
}

func (service *Service) buildDrainCommands(ctx context.Context, actor Actor, value Switch) (map[uuid.UUID]*agentv1.DrainCommand, error) {
	commands, err := service.drains.Build(ctx, actor, value)
	if err != nil {
		return nil, err
	}
	if len(commands) != len(value.RetiringNodes) {
		return nil, ErrConflict
	}
	for _, nodeID := range value.RetiringNodes {
		command := commands[nodeID]
		expectedID := uuid.NewSHA1(value.ID, nodeID[:])
		if command == nil || command.NodeId != nodeID.String() || command.CommandId != expectedID.String() {
			return nil, ErrConflict
		}
	}
	return commands, nil
}

func (service *Service) publishDrainCommands(ctx context.Context, actor Actor, value Switch, commands map[uuid.UUID]*agentv1.DrainCommand) error {
	for _, nodeID := range value.RetiringNodes {
		if err := service.drains.Publish(ctx, actor, commands[nodeID]); err != nil {
			return err
		}
	}
	return nil
}

func sameDrainCommands(value Switch, commands map[uuid.UUID]*agentv1.DrainCommand) bool {
	if len(value.DrainCommands) != len(commands) {
		return false
	}
	for nodeID, commandID := range value.DrainCommands {
		command := commands[nodeID]
		if command == nil || command.CommandId != commandID.String() || command.NodeId != nodeID.String() {
			return false
		}
	}
	return true
}

func (service *Service) startCompensation(ctx context.Context, actor Actor, current Switch, now time.Time, code string) (Switch, error) {
	if current.State == StatePreparing || current.State == StateHealthGate && current.PreparePublication.ID == uuid.Nil {
		after := cloneSwitch(current)
		after.State, after.ErrorCode = StateRolledBack, code
		service.advance(&after, now)
		return after, service.store.CompareAndSwap(ctx, actor, current, after)
	}
	publication, err := service.publications.Compensate(ctx, actor, current)
	if err != nil {
		return current, err
	}
	after := cloneSwitch(current)
	after.CompensationPublication = publication
	after.State, after.ErrorCode = StateCompensatingOld, code
	service.advance(&after, now)
	return after, service.store.CompareAndSwap(ctx, actor, current, after)
}

func (service *Service) advance(value *Switch, now time.Time) {
	value.StateRevision++
	value.UpdatedAt = now
}

func validStartRequest(request StartRequest, now time.Time) bool {
	return validActor(request.Actor) && request.ConfigurationScopeID != uuid.Nil && request.ExpectedSourceRevision > 0 &&
		validSnapshotReference(request.From) && validSnapshotReference(request.To) && request.From != request.To &&
		request.Health.ActivationTimeout > 0 && request.Health.ActivationTimeout <= 24*time.Hour &&
		request.Health.ObservationWindow > 0 && request.Health.ObservationWindow <= 24*time.Hour &&
		request.Health.RequiredConsecutiveSuccesses > 0 && request.Health.RequiredConsecutiveSuccesses <= 100 &&
		request.Drain.HealthTimeout > 0 && request.Drain.HealthTimeout <= 5*time.Minute &&
		request.Drain.MaxDrain > 0 && request.Drain.MaxDrain <= 24*time.Hour && request.MaxAttempts > 0 && request.MaxAttempts <= 10 &&
		request.Deadline.After(now) && !request.Deadline.After(now.Add(24*time.Hour)) &&
		metadataPattern.MatchString(request.IdempotencyKey) && request.RequestID != uuid.Nil &&
		request.CorrelationID != uuid.Nil && validTraceparent(request.Traceparent)
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.SessionID != uuid.Nil &&
		(actor.ScopeKind == "tenant" || actor.ScopeKind == "platform") && actor.Credential != "" &&
		len(actor.Credential) <= 8192 && !strings.ContainsAny(actor.Credential, " \t\r\n") && actor.WorkloadID == ""
}

func validAuthority(actor Actor) bool {
	return validActor(actor) || actor.WorkloadID == ReconcilerWorkloadID && actor.UserID == uuid.Nil &&
		actor.ScopeID == uuid.Nil && actor.SessionID == uuid.Nil && actor.ScopeKind == "" && actor.Credential == ""
}

func workloadAuthority(actor Actor) bool {
	return actor.WorkloadID == ReconcilerWorkloadID && validAuthority(actor)
}

func validSnapshotReference(reference SnapshotReference) bool {
	return reference.ID != uuid.Nil && reference.Revision > 0 && reference.SHA256 != ([32]byte{})
}

func validSnapshots(from, to Snapshot) error {
	if !validSnapshotReference(from.Reference) || !validSnapshotReference(to.Reference) || from.Reference == to.Reference ||
		len(from.NodeIDs) == 0 || len(from.NodeIDs) > maxSwitchNodes || len(to.NodeIDs) == 0 || len(to.NodeIDs) > maxSwitchNodes {
		return ErrInvalidInput
	}
	for _, nodes := range [][]uuid.UUID{from.NodeIDs, to.NodeIDs} {
		seen := make(map[uuid.UUID]struct{}, len(nodes))
		for _, nodeID := range nodes {
			if nodeID == uuid.Nil {
				return ErrInvalidInput
			}
			if _, duplicate := seen[nodeID]; duplicate {
				return ErrInvalidInput
			}
			seen[nodeID] = struct{}{}
		}
	}
	return nil
}

func switchNodeSets(from, to []uuid.UUID) ([]uuid.UUID, []uuid.UUID) {
	prepare := slices.Clone(to)
	prepare = append(prepare, from...)
	sort.Slice(prepare, func(i, j int) bool { return bytes.Compare(prepare[i][:], prepare[j][:]) < 0 })
	prepare = slices.Compact(prepare)
	toSet := make(map[uuid.UUID]struct{}, len(to))
	for _, nodeID := range to {
		toSet[nodeID] = struct{}{}
	}
	retiring := make([]uuid.UUID, 0, len(from))
	for _, nodeID := range from {
		if _, stays := toSet[nodeID]; !stays {
			retiring = append(retiring, nodeID)
		}
	}
	sort.Slice(retiring, func(i, j int) bool { return bytes.Compare(retiring[i][:], retiring[j][:]) < 0 })
	return prepare, retiring
}

func startRequestDigest(request StartRequest, from, to Snapshot, prepare, retiring []uuid.UUID) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		Schema                 string
		ConfigurationScopeID   uuid.UUID
		ExpectedSourceRevision int64
		From, To               Snapshot
		Prepare, Retiring      []uuid.UUID
		Health                 HealthPolicy
		Drain                  DrainPolicy
		MaxAttempts            uint32
		Deadline               time.Time
	}{"cdnca.l4-line-switch.request/v1", request.ConfigurationScopeID, request.ExpectedSourceRevision,
		from, to, prepare, retiring, request.Health, request.Drain, request.MaxAttempts, request.Deadline.UTC()})
	if err != nil {
		return [32]byte{}, errors.Join(ErrInvalidInput, err)
	}
	return sha256.Sum256(encoded), nil
}

func validTraceparent(value string) bool {
	if !traceparentPattern.MatchString(value) {
		return false
	}
	return value[3:35] != strings.Repeat("0", 32) && value[36:52] != strings.Repeat("0", 16)
}

func cloneSwitch(value Switch) Switch {
	value.From.NodeIDs = slices.Clone(value.From.NodeIDs)
	value.To.NodeIDs = slices.Clone(value.To.NodeIDs)
	value.PrepareNodes = slices.Clone(value.PrepareNodes)
	value.RetiringNodes = slices.Clone(value.RetiringNodes)
	drainCommands := value.DrainCommands
	value.DrainCommands = make(map[uuid.UUID]uuid.UUID, len(drainCommands))
	for nodeID, commandID := range drainCommands {
		value.DrainCommands[nodeID] = commandID
	}
	return value
}
