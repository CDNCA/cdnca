package controlplaneupgradehttp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/google/uuid"
)

func TestNativeReplayChecksActorAfterConcurrentPublisherCAS(t *testing.T) {
	handler, repository, request, _ := nativeFixture(t)
	otherActor := request
	otherActor.ActorUserID, otherActor.ActorScopeID = uuid.New(), uuid.New()
	if _, err := handler.Publish(t.Context(), otherActor); err != nil {
		t.Fatal(err)
	}
	// Simulate the other actor publishing between our initial read-only replay
	// check and PlanPublisher's CAS/replay loop. It must not return their receipt.
	handler.config.Repository = &nativeConcurrentPublication{nativeMemoryRepository: repository}
	if _, err := handler.Publish(t.Context(), request); !errors.Is(err, controlplaneupgrade.ErrIdempotencyConflict) || repository.writes != 1 {
		t.Fatalf("cross-actor racing replay accepted: err=%v writes=%d", err, repository.writes)
	}
}

type nativeConcurrentPublication struct {
	*nativeMemoryRepository
	reads int
}

func (repository *nativeConcurrentPublication) Read(ctx context.Context) (controlplaneupgrade.SecretDocument, error) {
	repository.reads++
	if repository.reads == 1 {
		return controlplaneupgrade.SecretDocument{ResourceVersion: "0"}, nil
	}
	return repository.nativeMemoryRepository.Read(ctx)
}

func TestNativeRequestRejectsAmbiguousRevisionAndIdempotencyHeaders(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*http.Request)
	}{
		{name: "leading zero", edit: func(r *http.Request) { r.Header.Set("If-Match", `"00"`) }},
		{name: "duplicate revision", edit: func(r *http.Request) { r.Header.Add("If-Match", `"0"`) }},
		{name: "duplicate idempotency", edit: func(r *http.Request) { r.Header.Add("Idempotency-Key", "native-upgrade-1") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, repository, input, _ := nativeFixture(t)
			request := httptest.NewRequest(http.MethodPost, nativePlanPath, bytes.NewReader(input.Bundle))
			request.Header.Set("If-Match", `"0"`)
			request.Header.Set("Idempotency-Key", input.IdempotencyKey)
			request.Header.Set("Content-Type", "application/json")
			test.edit(request)
			response := httptest.NewRecorder()
			handler.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || repository.writes != 0 {
				t.Fatalf("ambiguous header accepted status=%d writes=%d", response.Code, repository.writes)
			}
		})
	}
}

func TestNativeConstructorRejectsMaintenanceStatusAliasing(t *testing.T) {
	handler, _, _, _ := nativeFixture(t)
	for _, path := range []string{handler.config.StatusFile, handler.config.StateFile} {
		config := handler.config
		config.MaintenanceFile = path
		if _, err := NewNative(config); !errors.Is(err, controlplaneupgrade.ErrInvalidConfig) {
			t.Fatalf("status and maintenance file alias accepted err=%v", err)
		}
	}
}
