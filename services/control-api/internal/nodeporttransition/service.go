package nodeporttransition

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	minimumCompatibilityWindow = time.Minute
	maximumCompatibilityWindow = 24 * time.Hour
	maximumRollbackWindow      = 48 * time.Hour
)

type Store interface {
	Create(context.Context, Transition, [32]byte) (Transition, error)
	Get(context.Context, uuid.UUID) (Transition, error)
	ApplyStatus(context.Context, StatusReport) (Transition, error)
	EnqueueAction(context.Context, Actor, ActionRequest, CommandAction) (Transition, error)
}

type Service struct {
	store Store
	now   func() time.Time
	newID func() uuid.UUID
}

func (s *Service) Finalize(ctx context.Context, actor Actor, request ActionRequest) (Transition, error) {
	return s.enqueueAction(ctx, actor, request, ActionFinalize)
}

func (s *Service) Rollback(ctx context.Context, actor Actor, request ActionRequest) (Transition, error) {
	return s.enqueueAction(ctx, actor, request, ActionRollback)
}

func (s *Service) enqueueAction(ctx context.Context, actor Actor, request ActionRequest, action CommandAction) (Transition, error) {
	if s == nil || s.store == nil || ctx == nil || actor.ScopeID == uuid.Nil || actor.UserID == uuid.Nil ||
		request.TransitionID == uuid.Nil || request.NodeID == uuid.Nil ||
		!validRequestIdentity(request.RequestID, request.IdempotencyKey) ||
		action != ActionFinalize && action != ActionRollback {
		return Transition{}, ErrInvalidInput
	}
	current, err := s.store.Get(ctx, request.TransitionID)
	if err != nil {
		return Transition{}, err
	}
	if current.ScopeID != actor.ScopeID || current.NodeID != request.NodeID {
		return Transition{}, ErrNotFound
	}
	return s.store.EnqueueAction(ctx, actor, request, action)
}

func NewService(store Store, now func() time.Time, newID func() uuid.UUID) *Service {
	return &Service{store: store, now: now, newID: newID}
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (Transition, error) {
	if s == nil || s.store == nil || ctx == nil || id == uuid.Nil {
		return Transition{}, ErrInvalidInput
	}
	return s.store.Get(ctx, id)
}

func (s *Service) Create(ctx context.Context, actor Actor, request CreateRequest) (Transition, error) {
	if s == nil || s.store == nil || s.now == nil || s.newID == nil || ctx == nil ||
		actor.ScopeID == uuid.Nil || actor.UserID == uuid.Nil || request.NodeID == uuid.Nil ||
		request.ExpectedNodeRevision < 1 || !validRequestIdentity(request.RequestID, request.IdempotencyKey) ||
		!validEndpointPair(request.OldEndpoint, request.NewEndpoint) {
		return Transition{}, ErrInvalidInput
	}
	now := s.now().UTC()
	compatibility := request.CompatibilityDeadline.UTC()
	rollback := request.RollbackDeadline.UTC()
	if !rollback.After(compatibility) ||
		request.CertificateSHA256 != "" && !validSHA256(request.CertificateSHA256) {
		return Transition{}, ErrInvalidInput
	}
	encoded, err := json.Marshal(struct {
		NodeID                uuid.UUID `json:"node_id"`
		ExpectedNodeRevision  int64     `json:"expected_node_revision"`
		OldEndpoint           Endpoint  `json:"old_endpoint"`
		NewEndpoint           Endpoint  `json:"new_endpoint"`
		CompatibilityDeadline time.Time `json:"compatibility_deadline"`
		RollbackDeadline      time.Time `json:"rollback_deadline"`
		CertificateSHA256     string    `json:"certificate_sha256"`
	}{request.NodeID, request.ExpectedNodeRevision, request.OldEndpoint, request.NewEndpoint,
		compatibility, rollback, request.CertificateSHA256})
	if err != nil {
		return Transition{}, err
	}
	digest := sha256.Sum256(encoded)
	value := Transition{ID: s.newID(), ScopeID: actor.ScopeID, NodeID: request.NodeID, Revision: 1,
		ExpectedNodeRevision: request.ExpectedNodeRevision, OldEndpoint: request.OldEndpoint, NewEndpoint: request.NewEndpoint,
		CompatibilityDeadline: compatibility, RollbackDeadline: rollback, CertificateSHA256: request.CertificateSHA256,
		State: StatePreparing, ActiveEndpoint: request.OldEndpoint, RequestID: request.RequestID,
		IdempotencyKey: request.IdempotencyKey, CreatedByUserID: actor.UserID, CreatedAt: now, UpdatedAt: now}
	return s.store.Create(ctx, value, digest)
}

func (s *Service) ApplyStatus(ctx context.Context, report StatusReport) (Transition, error) {
	if s == nil || s.store == nil || ctx == nil || report.TransitionID == uuid.Nil || report.NodeID == uuid.Nil ||
		report.Revision == 0 || report.Revision > math.MaxInt64 || report.StatusRevision == 0 || report.StatusRevision > math.MaxInt64 || report.EventID == uuid.Nil || report.PubAckStream == "" ||
		report.PubAckSequence == 0 || report.PubAckSequence > math.MaxInt64 || !validState(report.State) || !validErrorCode(report.ErrorCode) ||
		!validSHA256(report.CertificateSHA256) || len(report.PayloadSHA256) != sha256.Size ||
		(report.State == StateFailed || report.State == StateRolledBack) && report.ErrorCode == "" {
		return Transition{}, ErrInvalidInput
	}
	current, err := s.store.Get(ctx, report.TransitionID)
	if err != nil {
		return Transition{}, err
	}
	if current.NodeID != report.NodeID || current.Revision != report.Revision {
		return Transition{}, ErrConflict
	}
	if report.ActiveEndpoint.ServerName != current.OldEndpoint.ServerName {
		return Transition{}, ErrConflict
	}
	if report.ActiveEndpoint.ListenAddress == "" {
		switch report.ActiveEndpoint.Address {
		case current.OldEndpoint.Address:
			report.ActiveEndpoint = current.OldEndpoint
		case current.NewEndpoint.Address:
			report.ActiveEndpoint = current.NewEndpoint
		}
	}
	if !validEndpoint(report.ActiveEndpoint) {
		return Transition{}, ErrInvalidInput
	}
	if current.CertificateSHA256 != "" && current.CertificateSHA256 != report.CertificateSHA256 {
		return Transition{}, ErrUnauthenticated
	}
	if report.StatusRevision > current.StatusRevision && !validTransition(current.State, report.State) {
		return Transition{}, ErrConflict
	}
	if report.State == StateSwitched || report.State == StateFinalized {
		if report.ActiveEndpoint != current.NewEndpoint || report.ErrorCode != "" {
			return Transition{}, ErrConflict
		}
	} else if (report.State == StateRolledBack || report.State == StateFailed) && report.ActiveEndpoint != current.OldEndpoint {
		return Transition{}, ErrConflict
	}
	return s.store.ApplyStatus(ctx, report)
}

func validEndpointPair(oldEndpoint, newEndpoint Endpoint) bool {
	if !validEndpoint(oldEndpoint) || !validEndpoint(newEndpoint) || oldEndpoint == newEndpoint || oldEndpoint.ServerName != newEndpoint.ServerName {
		return false
	}
	oldHost, oldPort, _ := net.SplitHostPort(oldEndpoint.Address)
	newHost, newPort, _ := net.SplitHostPort(newEndpoint.Address)
	_, oldListenPort, _ := net.SplitHostPort(oldEndpoint.ListenAddress)
	_, newListenPort, _ := net.SplitHostPort(newEndpoint.ListenAddress)
	return strings.EqualFold(oldHost, newHost) && oldPort != newPort && oldListenPort != newListenPort
}

func validEndpoint(value Endpoint) bool {
	if value.Address == "" || value.ServerName == "" || value.ListenAddress == "" ||
		value.Address != strings.TrimSpace(value.Address) || value.ServerName != strings.TrimSpace(value.ServerName) ||
		value.ListenAddress != strings.TrimSpace(value.ListenAddress) {
		return false
	}
	host, port, err := net.SplitHostPort(value.Address)
	if err != nil || host == "" || port == "" || strings.ContainsAny(value.ServerName, " /\\") {
		return false
	}
	parsedPort, err := net.LookupPort("tcp", port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return false
	}
	listenHost, listenPort, err := net.SplitHostPort(value.ListenAddress)
	if err != nil || listenHost == "" || listenPort == "" {
		return false
	}
	parsedListenPort, err := net.LookupPort("tcp", listenPort)
	return err == nil && parsedListenPort >= 1 && parsedListenPort <= 65535
}

func validRequestIdentity(requestID, key string) bool {
	parsed, err := uuid.Parse(requestID)
	return err == nil && parsed.String() == requestID && len(key) >= 1 && len(key) <= 128 && key == strings.TrimSpace(key)
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func validErrorCode(value string) bool {
	if len(value) > 64 || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validState(value State) bool {
	switch value {
	case StatePreparing, StateSwitching, StateSwitched, StateFailed, StateRolledBack, StateFinalized:
		return true
	default:
		return false
	}
}

func validTransition(from, to State) bool {
	switch from {
	case StatePreparing:
		return to == StateSwitching || to == StateFailed
	case StateSwitching:
		return to == StateSwitched || to == StateFailed || to == StateRolledBack
	case StateSwitched:
		return to == StateFinalized || to == StateRolledBack || to == StateFailed
	case StateFailed:
		return to == StateRolledBack
	default:
		return false
	}
}
