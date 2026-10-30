package nodeporttransition

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type memoryStore struct {
	transition Transition
	created    int
	updated    int
}

func (s *memoryStore) Create(_ context.Context, value Transition, _ [32]byte) (Transition, error) {
	if s.created > 0 {
		return s.transition, nil
	}
	s.created++
	s.transition = value
	return value, nil
}

func (s *memoryStore) Get(_ context.Context, _ uuid.UUID) (Transition, error) {
	return s.transition, nil
}

func (s *memoryStore) ApplyStatus(_ context.Context, status StatusReport) (Transition, error) {
	if status.StatusRevision <= s.transition.StatusRevision {
		return Transition{}, ErrConflict
	}
	s.updated++
	s.transition.State = status.State
	s.transition.ActiveEndpoint = status.ActiveEndpoint
	s.transition.StatusRevision = status.StatusRevision
	return s.transition, nil
}

func (s *memoryStore) EnqueueAction(_ context.Context, _ Actor, _ ActionRequest, _ CommandAction) (Transition, error) {
	return s.transition, nil
}

func TestCreateSealsVersionedCompatibilityWindow(t *testing.T) {
	now := time.Date(2026, 8, 9, 8, 0, 0, 0, time.UTC)
	store := &memoryStore{}
	service := NewService(store, func() time.Time { return now }, func() uuid.UUID {
		return uuid.MustParse("11111111-1111-4111-8111-111111111111")
	})
	actor := Actor{ScopeID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), UserID: uuid.MustParse("33333333-3333-4333-8333-333333333333")}
	request := CreateRequest{
		NodeID: uuid.MustParse("44444444-4444-4444-8444-444444444444"), ExpectedNodeRevision: 7,
		OldEndpoint:           Endpoint{Address: "gateway.example.com:7443", ServerName: "gateway.example.com", ListenAddress: "0.0.0.0:7443"},
		NewEndpoint:           Endpoint{Address: "gateway.example.com:8443", ServerName: "gateway.example.com", ListenAddress: "0.0.0.0:8443"},
		CompatibilityDeadline: now.Add(30 * time.Minute), RollbackDeadline: now.Add(45 * time.Minute),
		RequestID: "55555555-5555-4555-8555-555555555555", IdempotencyKey: "node08-port-1",
	}
	created, err := service.Create(context.Background(), actor, request)
	if err != nil {
		t.Fatal(err)
	}
	if created.Revision != 1 || created.State != StatePreparing || created.OldEndpoint != request.OldEndpoint || created.NewEndpoint != request.NewEndpoint {
		t.Fatalf("unexpected transition: %+v", created)
	}
	if created.ExpectedNodeRevision != 7 || created.CompatibilityDeadline != request.CompatibilityDeadline || created.RollbackDeadline != request.RollbackDeadline {
		t.Fatalf("transition lost its immutable compatibility identity: %+v", created)
	}
}

func TestCreateRejectsIdentityAndWindowAmbiguity(t *testing.T) {
	now := time.Date(2026, 8, 9, 8, 0, 0, 0, time.UTC)
	service := NewService(&memoryStore{}, func() time.Time { return now }, uuid.New)
	actor := Actor{ScopeID: uuid.New(), UserID: uuid.New()}
	valid := CreateRequest{NodeID: uuid.New(), ExpectedNodeRevision: 1,
		OldEndpoint:           Endpoint{Address: "gateway.example.com:7443", ServerName: "gateway.example.com", ListenAddress: "0.0.0.0:7443"},
		NewEndpoint:           Endpoint{Address: "gateway.example.com:8443", ServerName: "gateway.example.com", ListenAddress: "0.0.0.0:8443"},
		CompatibilityDeadline: now.Add(30 * time.Minute), RollbackDeadline: now.Add(time.Hour),
		RequestID: uuid.NewString(), IdempotencyKey: "node08-port-2"}
	for name, mutate := range map[string]func(*CreateRequest){
		"same endpoint":                   func(value *CreateRequest) { value.NewEndpoint = value.OldEndpoint },
		"server name drift":               func(value *CreateRequest) { value.NewEndpoint.ServerName = "other.example.com" },
		"rollback precedes compatibility": func(value *CreateRequest) { value.RollbackDeadline = value.CompatibilityDeadline },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if _, err := service.Create(context.Background(), actor, request); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("got %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestApplyStatusIsMonotonicAndBoundToSameCertificateIdentity(t *testing.T) {
	store := &memoryStore{transition: Transition{
		ID: uuid.New(), ScopeID: uuid.New(), NodeID: uuid.New(), Revision: 4, State: StateSwitching,
		OldEndpoint:       Endpoint{Address: "gateway.example.com:7443", ServerName: "gateway.example.com", ListenAddress: "0.0.0.0:7443"},
		NewEndpoint:       Endpoint{Address: "gateway.example.com:8443", ServerName: "gateway.example.com", ListenAddress: "0.0.0.0:8443"},
		CertificateSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}}
	service := NewService(store, time.Now, uuid.New)
	valid := StatusReport{PayloadSHA256: make([]byte, 32), TransitionID: store.transition.ID, NodeID: store.transition.NodeID, Revision: 4,
		StatusRevision: 1, State: StateSwitched, ActiveEndpoint: store.transition.NewEndpoint,
		CertificateSHA256: store.transition.CertificateSHA256, EventID: uuid.New(),
		PubAckStream: portTransitionStatusStream, PubAckSequence: 1}
	if _, err := service.ApplyStatus(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	valid.StatusRevision = 1
	if _, err := service.ApplyStatus(context.Background(), valid); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale status got %v, want ErrConflict", err)
	}
	valid.StatusRevision = 2
	valid.CertificateSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := service.ApplyStatus(context.Background(), valid); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("identity drift got %v, want ErrUnauthenticated", err)
	}
}

func TestApplyStatusRejectsUnrepresentableOrIncompleteReceipts(t *testing.T) {
	for name, mutate := range map[string]func(*StatusReport){
		"revision overflow":      func(r *StatusReport) { r.Revision = 1 << 63 },
		"status overflow":        func(r *StatusReport) { r.StatusRevision = 1 << 63 },
		"sequence overflow":      func(r *StatusReport) { r.PubAckSequence = 1 << 63 },
		"missing payload digest": func(r *StatusReport) { r.PayloadSHA256 = nil },
		"missing failure reason": func(r *StatusReport) { r.State = StateFailed; r.ErrorCode = "" },
	} {
		t.Run(name, func(t *testing.T) {
			report := StatusReport{TransitionID: uuid.New(), NodeID: uuid.New(), Revision: 1, StatusRevision: 1, State: StateSwitched, EventID: uuid.New(), PubAckStream: portTransitionStatusStream, PubAckSequence: 1, CertificateSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PayloadSHA256: make([]byte, 32)}
			mutate(&report)
			if _, err := NewService(&memoryStore{}, time.Now, uuid.New).ApplyStatus(t.Context(), report); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("invalid receipt accepted: %v", err)
			}
		})
	}
}
