package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
)

var (
	ErrPortTransitionInvalid          = errors.New("gateway port transition is invalid")
	ErrPortTransitionConflict         = errors.New("gateway port transition conflicts with active state")
	ErrPortTransitionIdentityMismatch = errors.New("gateway port transition node identity changed")
	ErrPortTransitionIncomplete       = errors.New("gateway port transition cohort is incomplete")
)

type PortTransitionListenerFactory func(context.Context, string) (net.Listener, error)

type portTransitionState struct {
	id                    string
	revision              uint64
	oldExternal           string
	newExternal           string
	oldEndpoint           *agentv1.GatewayEndpoint
	newEndpoint           *agentv1.GatewayEndpoint
	newListener           net.Listener
	compatibilityDeadline time.Time
	rollbackDeadline      time.Time
	expectedCertificates  map[string]string
	connected             map[string]bool
	terminalCommand       *agentv1.GatewayPortTransitionCommand
}

type PortTransitionManager struct {
	mu          sync.Mutex
	oldListener net.Listener
	oldExternal string
	listen      PortTransitionListenerFactory
	now         func() time.Time
	active      *portTransitionState
	completed   *agentv1.GatewayPortTransitionCommand
	serve       func(net.Listener) error
	promote     func()
}

func (m *PortTransitionManager) ConfigurePromote(promote func()) error {
	if m == nil || promote == nil {
		return ErrPortTransitionInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.promote != nil || m.active != nil {
		return ErrPortTransitionConflict
	}
	m.promote = promote
	return nil
}

func NewPortTransitionManager(oldListener net.Listener, oldExternal string, listen PortTransitionListenerFactory, now func() time.Time) *PortTransitionManager {
	return &PortTransitionManager{oldListener: oldListener, oldExternal: oldExternal, listen: listen, now: now}
}

func (m *PortTransitionManager) ConfigureServe(serve func(net.Listener) error) error {
	if m == nil || serve == nil {
		return ErrPortTransitionInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.serve != nil || m.active != nil {
		return ErrPortTransitionConflict
	}
	m.serve = serve
	return nil
}

func (m *PortTransitionManager) Prepare(ctx context.Context, command *agentv1.GatewayPortTransitionCommand) (*agentv1.GatewayPortTransitionCommand, error) {
	if m == nil || ctx == nil || m.oldListener == nil || m.listen == nil || m.now == nil ||
		command == nil || command.Action != agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_SWITCH ||
		validateGatewayPortTransitionCommand(command, m.now()) != nil {
		return nil, ErrPortTransitionInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if command.OldEndpoint.Address != m.oldExternal {
		return nil, ErrPortTransitionConflict
	}
	if m.completed != nil && m.completed.TransitionId == command.TransitionId {
		return nil, ErrPortTransitionConflict
	}
	if m.active != nil {
		if m.active.id != command.TransitionId || m.active.revision != command.Revision || m.active.newExternal != command.NewEndpoint.Address {
			return nil, ErrPortTransitionConflict
		}
		m.active.expectedCertificates[command.NodeId] = command.CertificateSha256
		return proto.Clone(command).(*agentv1.GatewayPortTransitionCommand), nil
	}
	listener, err := m.listen(ctx, command.NewEndpoint.ListenAddress)
	if err != nil {
		return nil, err
	}
	if m.serve == nil {
		_ = listener.Close()
		return nil, ErrPortTransitionConflict
	}
	if err := m.serve(listener); err != nil {
		_ = listener.Close()
		return nil, err
	}
	m.active = &portTransitionState{id: command.TransitionId, revision: command.Revision,
		oldExternal: command.OldEndpoint.Address, newExternal: command.NewEndpoint.Address, newListener: listener,
		oldEndpoint:           proto.Clone(command.OldEndpoint).(*agentv1.GatewayEndpoint),
		newEndpoint:           proto.Clone(command.NewEndpoint).(*agentv1.GatewayEndpoint),
		compatibilityDeadline: command.CompatibilityDeadline.AsTime(), rollbackDeadline: command.RollbackDeadline.AsTime(),
		expectedCertificates: map[string]string{command.NodeId: command.CertificateSha256}, connected: make(map[string]bool)}
	m.completed = nil
	return proto.Clone(command).(*agentv1.GatewayPortTransitionCommand), nil
}

func (m *PortTransitionManager) RecordConnection(transitionID string, revision uint64, nodeID, certificateSHA256 string) error {
	if m == nil {
		return ErrPortTransitionInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil || m.active.id != transitionID || m.active.revision != revision {
		return ErrPortTransitionConflict
	}
	expected, ok := m.active.expectedCertificates[nodeID]
	if !ok || expected != certificateSHA256 {
		return ErrPortTransitionIdentityMismatch
	}
	m.active.connected[nodeID] = true
	return nil
}

func (m *PortTransitionManager) Finalize(transitionID string, requiredNodeIDs []string) error {
	if m == nil || len(requiredNodeIDs) == 0 {
		return ErrPortTransitionInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil && m.completed != nil && m.completed.TransitionId == transitionID &&
		m.completed.Action == agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE &&
		len(requiredNodeIDs) == 1 && requiredNodeIDs[0] == m.completed.NodeId {
		return nil
	}
	if m.active == nil || m.active.id != transitionID {
		return ErrPortTransitionConflict
	}
	if m.active.terminalCommand != nil && m.active.terminalCommand.Action != agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE {
		return ErrPortTransitionConflict
	}
	seen := make(map[string]struct{}, len(requiredNodeIDs))
	for _, nodeID := range requiredNodeIDs {
		if _, exists := seen[nodeID]; exists || !m.active.connected[nodeID] {
			return ErrPortTransitionIncomplete
		}
		seen[nodeID] = struct{}{}
	}
	markPortTransitionPlannedClose(m.oldListener)
	if err := m.oldListener.Close(); err != nil {
		return err
	}
	if m.promote != nil {
		m.promote()
	}
	m.oldListener = m.active.newListener
	m.oldExternal = m.active.newExternal
	m.completed = m.active.terminalCommand
	m.active = nil
	return nil
}

func (m *PortTransitionManager) ValidateAction(command *agentv1.GatewayPortTransitionCommand) (*agentv1.GatewayPortTransitionCommand, error) {
	if m == nil || command == nil || command.Action != agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE &&
		command.Action != agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK {
		return nil, ErrPortTransitionInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.completed != nil && proto.Equal(m.completed, command) {
		return proto.Clone(command).(*agentv1.GatewayPortTransitionCommand), nil
	}
	// Only an already completed command may replay beyond its execution deadline.
	if validateGatewayPortTransitionCommand(command, m.now()) != nil {
		return nil, ErrPortTransitionInvalid
	}
	if m.active == nil || m.active.id != command.TransitionId || m.active.revision != command.Revision ||
		!proto.Equal(m.active.oldEndpoint, command.OldEndpoint) || !proto.Equal(m.active.newEndpoint, command.NewEndpoint) {
		return nil, ErrPortTransitionConflict
	}
	if m.active.expectedCertificates[command.NodeId] != command.CertificateSha256 {
		return nil, ErrPortTransitionIdentityMismatch
	}
	if m.active.terminalCommand != nil && !proto.Equal(m.active.terminalCommand, command) {
		return nil, ErrPortTransitionConflict
	}
	// Retain the complete admitted command until the next transition. After a
	// terminal listener mutation, an unacknowledged delivery must still reach
	// the Agent's exact durable status replay without admitting identity drift.
	m.active.terminalCommand = proto.Clone(command).(*agentv1.GatewayPortTransitionCommand)
	return proto.Clone(command).(*agentv1.GatewayPortTransitionCommand), nil
}

func (m *PortTransitionManager) Rollback(transitionID string) error {
	if m == nil {
		return ErrPortTransitionInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil && m.completed != nil && m.completed.TransitionId == transitionID &&
		m.completed.Action == agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK {
		return nil
	}
	if m.active == nil || m.active.id != transitionID {
		return ErrPortTransitionConflict
	}
	if m.active.terminalCommand != nil && m.active.terminalCommand.Action != agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK {
		return ErrPortTransitionConflict
	}
	markPortTransitionPlannedClose(m.active.newListener)
	if err := m.active.newListener.Close(); err != nil {
		return err
	}
	m.completed = m.active.terminalCommand
	m.active = nil
	return nil
}

func (m *PortTransitionManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return nil
	}
	markPortTransitionPlannedClose(m.active.newListener)
	err := m.active.newListener.Close()
	m.active = nil
	return err
}

func markPortTransitionPlannedClose(listener net.Listener) {
	if planned, ok := listener.(interface{ MarkPlannedClose() }); ok {
		planned.MarkPlannedClose()
	}
}

func validateGatewayPortTransitionCommand(command *agentv1.GatewayPortTransitionCommand, now time.Time) error {
	if command == nil || proto.Size(command) > 1<<20 || command.Schema != agentv1.GatewayPortTransitionSchema_GATEWAY_PORT_TRANSITION_SCHEMA_V1 ||
		!validGatewayPortTransitionEvent(command.Event) || !canonicalUUID(command.TransitionId) ||
		!canonicalUUID(command.NodeId) || command.Revision == 0 || command.ExpectedNodeRevision == 0 ||
		!validGatewayEndpoint(command.OldEndpoint, true) || !validGatewayEndpoint(command.NewEndpoint, true) ||
		command.OldEndpoint.Address == command.NewEndpoint.Address || command.OldEndpoint.ServerName != command.NewEndpoint.ServerName ||
		command.CompatibilityDeadline == nil || command.CompatibilityDeadline.CheckValid() != nil ||
		command.RollbackDeadline == nil || command.RollbackDeadline.CheckValid() != nil ||
		!command.RollbackDeadline.AsTime().After(command.CompatibilityDeadline.AsTime()) ||
		!validPortTransitionSHA256(command.CertificateSha256) {
		return ErrPortTransitionInvalid
	}
	switch command.Action {
	case agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_SWITCH:
		if !command.CompatibilityDeadline.AsTime().After(now) {
			return ErrPortTransitionInvalid
		}
	case agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE,
		agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK:
		if now.After(command.RollbackDeadline.AsTime()) {
			return ErrPortTransitionInvalid
		}
	default:
		return ErrPortTransitionInvalid
	}
	return nil
}

func validGatewayPortTransitionEvent(event *commonv1.EventMetadata) bool {
	return event != nil && canonicalUUID(event.EventId) && canonicalUUID(event.RequestId) &&
		event.OccurredTime != nil && event.OccurredTime.CheckValid() == nil && canonicalUUID(event.CorrelationId) &&
		(event.TaskId == nil || canonicalUUID(*event.TaskId)) && boundedMetadata(event.Traceparent, false)
}

func boundedMetadata(value string, required bool) bool {
	if value == "" {
		return !required
	}
	if len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validGatewayEndpoint(endpoint *agentv1.GatewayEndpoint, requireListen bool) bool {
	if endpoint == nil || endpoint.Address == "" || endpoint.ServerName == "" || strings.TrimSpace(endpoint.Address) != endpoint.Address || strings.TrimSpace(endpoint.ServerName) != endpoint.ServerName {
		return false
	}
	if _, _, err := net.SplitHostPort(endpoint.Address); err != nil {
		return false
	}
	if requireListen {
		if endpoint.ListenAddress == "" {
			return false
		}
		if _, _, err := net.SplitHostPort(endpoint.ListenAddress); err != nil {
			return false
		}
	}
	return true
}

func validPortTransitionSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func sortedPortTransitionNodes(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
