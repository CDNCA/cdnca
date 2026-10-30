package identityverificationhttp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
)

type productionEvidenceSourceStub struct {
	mu           sync.Mutex
	capabilities RuntimeEvidenceSourceCapabilities
	capability   func() RuntimeEvidenceSourceCapabilities
	reserve      func(context.Context, RuntimeEvidenceReserveRequest) (RuntimeEvidenceReserveResult, error)
	abort        func(context.Context, string) error
	quarantine   func(context.Context, string) error
	publish      func(context.Context, RuntimeEvidencePublishRequest) error
}

func (source *productionEvidenceSourceStub) Capabilities() RuntimeEvidenceSourceCapabilities {
	if source.capability != nil {
		return source.capability()
	}
	return source.capabilities
}

func (source *productionEvidenceSourceStub) Reserve(ctx context.Context,
	request RuntimeEvidenceReserveRequest,
) (RuntimeEvidenceReserveResult, error) {
	if source.reserve == nil {
		return RuntimeEvidenceReserveResult{}, errUnexpectedCall
	}
	return source.reserve(ctx, request)
}

func (source *productionEvidenceSourceStub) Abort(ctx context.Context, reservationID string) error {
	if source.abort == nil {
		return errUnexpectedCall
	}
	return source.abort(ctx, reservationID)
}

func (source *productionEvidenceSourceStub) Quarantine(ctx context.Context, reservationID string) error {
	if source.quarantine == nil {
		return errUnexpectedCall
	}
	return source.quarantine(ctx, reservationID)
}

func (source *productionEvidenceSourceStub) Publish(ctx context.Context,
	request RuntimeEvidencePublishRequest,
) error {
	if source.publish == nil {
		return errUnexpectedCall
	}
	return source.publish(ctx, request)
}

func productionEvidenceCapabilities() RuntimeEvidenceSourceCapabilities {
	return RuntimeEvidenceSourceCapabilities{TrustedFacts: true, DurableReservations: true,
		ActorRequestBinding: true, AtomicTransitions: true, IdempotentTransitions: true}
}

func TestProductionRuntimeDisabledDoesNotTouchEvidenceSource(t *testing.T) {
	source := &productionEvidenceSourceStub{capability: func() RuntimeEvidenceSourceCapabilities {
		t.Fatal("disabled production runtime touched evidence source")
		return RuntimeEvidenceSourceCapabilities{}
	}}
	runtime, err := NewProductionRuntime(ProductionRuntimeConfig{},
		ProductionRuntimeDependencies{EvidenceSource: source})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	runtime.ServeHTTP(response, httptest.NewRequest(http.MethodGet, apiPrefix+"/cases/"+uuid.NewString(), nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled production runtime status=%d", response.Code)
	}
}

func TestProductionRuntimeEnabledFailsClosedWithoutAtomicEvidenceSource(t *testing.T) {
	valid := runtimeUnitDependencies(t)
	dependencies := ProductionRuntimeDependencies{Pool: valid.Pool, Identity: valid.Identity,
		IAM: valid.IAM, Clock: valid.Clock}
	config := ProductionRuntimeConfig{Runtime: RuntimeConfig{Enabled: true,
		Service: ServiceConfig{CursorKey: bytes.Repeat([]byte{0x81}, 32)}},
		Evidence: RuntimeEvidenceConfig{ResolverName: "trusted-kyc"}}
	var typedNil *productionEvidenceSourceStub
	tests := map[string]RuntimeEvidenceSource{
		"nil":       nil,
		"typed nil": typedNil,
		"no trusted facts": &productionEvidenceSourceStub{capabilities: RuntimeEvidenceSourceCapabilities{
			DurableReservations: true, ActorRequestBinding: true, AtomicTransitions: true,
			IdempotentTransitions: true}},
		"no durable reservation": &productionEvidenceSourceStub{capabilities: RuntimeEvidenceSourceCapabilities{
			TrustedFacts: true, ActorRequestBinding: true, AtomicTransitions: true,
			IdempotentTransitions: true}},
		"no actor binding": &productionEvidenceSourceStub{capabilities: RuntimeEvidenceSourceCapabilities{
			TrustedFacts: true, DurableReservations: true, AtomicTransitions: true,
			IdempotentTransitions: true}},
		"no atomic transitions": &productionEvidenceSourceStub{capabilities: RuntimeEvidenceSourceCapabilities{
			TrustedFacts: true, DurableReservations: true, ActorRequestBinding: true,
			IdempotentTransitions: true}},
		"no idempotency": &productionEvidenceSourceStub{capabilities: RuntimeEvidenceSourceCapabilities{
			TrustedFacts: true, DurableReservations: true, ActorRequestBinding: true,
			AtomicTransitions: true}},
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			current := dependencies
			current.EvidenceSource = source
			runtime, err := NewProductionRuntime(config, current)
			if runtime != nil || !errors.Is(err, ErrTrustedEvidenceSourceRequired) {
				t.Fatalf("NewProductionRuntime() = (%T,%v), want nil ErrTrustedEvidenceSourceRequired", runtime, err)
			}
		})
	}
	dependencies.EvidenceSource = &productionEvidenceSourceStub{capability: func() RuntimeEvidenceSourceCapabilities {
		panic("source configuration secret")
	}}
	if runtime, err := NewProductionRuntime(config, dependencies); runtime != nil ||
		!errors.Is(err, ErrTrustedEvidenceSourceRequired) {
		t.Fatalf("panicking source NewProductionRuntime() = (%T,%v)", runtime, err)
	}
}

func TestProductionRuntimeBuildsPackageAdapterFromAtomicEvidenceSource(t *testing.T) {
	valid := runtimeUnitDependencies(t)
	source := &productionEvidenceSourceStub{capabilities: productionEvidenceCapabilities()}
	runtime, err := NewProductionRuntime(ProductionRuntimeConfig{Runtime: RuntimeConfig{Enabled: true,
		Service: ServiceConfig{CursorKey: bytes.Repeat([]byte{0x82}, 32)}},
		Evidence: RuntimeEvidenceConfig{ResolverName: "trusted-kyc"}},
		ProductionRuntimeDependencies{Pool: valid.Pool, Identity: valid.Identity, IAM: valid.IAM,
			EvidenceSource: source, Clock: valid.Clock})
	if err != nil || runtime == nil || runtime.Handler() == nil {
		t.Fatalf("NewProductionRuntime() = (%T,%v)", runtime, err)
	}
	handler, ok := runtime.Handler().(*Handler)
	if !ok {
		t.Fatalf("runtime handler=%T", runtime.Handler())
	}
	adapter, ok := handler.service.resolver.(*RuntimeEvidenceAdapter)
	if !ok || adapter.source != source || adapter.resolverName != "trusted-kyc" {
		t.Fatalf("runtime resolver=%T", handler.service.resolver)
	}
}

func TestRuntimeEvidenceAdapterBindsTrustedFactsWithoutRawCredential(t *testing.T) {
	actor := testActor()
	digest := evidenceRequestDigest(CreateDraftInput{Kind: identityverification.KindPersonalInitial,
		EvidenceToken: string(bytes.Repeat([]byte{'a'}, 32))})
	claimDigest := [32]byte{1, 2, 3}
	evidence := personalResolvedEvidence(0x91)
	var captured RuntimeEvidenceReserveRequest
	source := &productionEvidenceSourceStub{capabilities: productionEvidenceCapabilities(),
		reserve: func(_ context.Context, request RuntimeEvidenceReserveRequest) (RuntimeEvidenceReserveResult, error) {
			captured = request
			return RuntimeEvidenceReserveResult{ReservationID: "reservation-00000000000000000001",
				ResolverReference:   "source/reservation-00000000000000000001",
				EvidenceClaimDigest: claimDigest, Evidence: evidence}, nil
		}}
	adapter, err := NewRuntimeEvidenceAdapter(RuntimeEvidenceConfig{ResolverName: "trusted-kyc"}, source)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := adapter.Reserve(t.Context(), actor,
		EvidenceReference{Kind: evidence.Kind, Token: string(bytes.Repeat([]byte{'a'}, 32))},
		"create-key", digest)
	if err != nil {
		t.Fatal(err)
	}
	if captured.ActorUserID != actor.UserID || captured.TenantScopeID != actor.ScopeID ||
		captured.SessionID != actor.SessionID() || captured.IdempotencyKey != "create-key" ||
		captured.EvidenceRequestDigest != digest || captured.Kind != evidence.Kind ||
		reservation.ResolverName != "trusted-kyc" || reservation.EvidenceClaimDigest != claimDigest {
		t.Fatalf("captured=%#v reservation=%#v", captured, reservation)
	}
	if reservation.ID == "" || reservation.ResolverReference == "" || reservation.Evidence.Kind != evidence.Kind {
		t.Fatalf("invalid reservation=%#v", reservation)
	}
}

func TestRuntimeEvidenceAdapterReleaseAndPublishFailureSemantics(t *testing.T) {
	var mu sync.Mutex
	aborted := 0
	quarantined := 0
	published := make([]RuntimeEvidencePublishRequest, 0, 2)
	publishErr := error(nil)
	source := &productionEvidenceSourceStub{capabilities: productionEvidenceCapabilities(),
		abort: func(_ context.Context, reservationID string) error {
			mu.Lock()
			defer mu.Unlock()
			if reservationID != "reservation-00000000000000000002" {
				return ErrInvalidEvidence
			}
			aborted++
			return nil
		}, quarantine: func(_ context.Context, reservationID string) error {
			mu.Lock()
			defer mu.Unlock()
			if reservationID != "reservation-00000000000000000003" {
				return ErrInvalidEvidence
			}
			quarantined++
			return nil
		}, publish: func(_ context.Context, request RuntimeEvidencePublishRequest) error {
			mu.Lock()
			defer mu.Unlock()
			published = append(published, request)
			return publishErr
		}}
	adapter, err := NewRuntimeEvidenceAdapter(RuntimeEvidenceConfig{ResolverName: "trusted-kyc"}, source)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := adapter.Abort(t.Context(), "reservation-00000000000000000002"); err != nil {
			t.Fatal(err)
		}
		if err := adapter.Quarantine(t.Context(), "reservation-00000000000000000003"); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	if aborted != 2 || quarantined != 2 {
		t.Fatalf("abort=%d quarantine=%d", aborted, quarantined)
	}
	mu.Unlock()

	request := identityverification.SettlementCommitRequest{ResolverName: "trusted-kyc",
		ResolverReference: "source/reservation-00000000000000000002", TenantScopeID: uuid.New(),
		ActorUserID: uuid.New(), CaseID: uuid.New(), IdempotencyKey: "create-key",
		RequestDigest: [32]byte{1}, EvidenceClaimDigest: [32]byte{2}}
	result, err := adapter.Publish(t.Context(), request)
	if err != nil || result.Outcome != identityverification.SettlementCommitSucceeded {
		t.Fatalf("Publish(success) = %#v,%v", result, err)
	}
	mu.Lock()
	if len(published) != 1 || published[0].TenantScopeID != request.TenantScopeID ||
		published[0].ActorUserID != request.ActorUserID || published[0].CaseID != request.CaseID ||
		published[0].IdempotencyKey != request.IdempotencyKey ||
		published[0].CoreRequestDigest != request.RequestDigest ||
		published[0].EvidenceClaimDigest != request.EvidenceClaimDigest {
		t.Fatalf("published=%#v", published)
	}
	publishErr = ErrEvidenceUnavailable
	mu.Unlock()
	result, err = adapter.Publish(t.Context(), request)
	if err != nil || result.Outcome != identityverification.SettlementCommitRetry ||
		result.FailureCode != "resolver_unavailable" {
		t.Fatalf("Publish(retry) = %#v,%v", result, err)
	}
	mu.Lock()
	publishErr = ErrEvidenceReservationConflict
	mu.Unlock()
	result, err = adapter.Publish(t.Context(), request)
	if err != nil || result.Outcome != identityverification.SettlementCommitPermanent ||
		result.FailureCode != "reservation_conflict" {
		t.Fatalf("Publish(conflict) = %#v,%v", result, err)
	}
	mu.Lock()
	publishErr = ErrInvalidEvidence
	mu.Unlock()
	result, err = adapter.Publish(t.Context(), request)
	if err != nil || result.Outcome != identityverification.SettlementCommitPermanent ||
		result.FailureCode != "reservation_invalid" {
		t.Fatalf("Publish(invalid) = %#v,%v", result, err)
	}
}
