//go:build integration

package identityverificationhttp

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
)

type blockingSettlementPublisher struct {
	delegate registrySettlementCommitter
	entered  chan struct{}
	release  chan struct{}
}

func (publisher *blockingSettlementPublisher) Configured() bool {
	return publisher != nil && publisher.delegate.Configured()
}

func (publisher *blockingSettlementPublisher) Publish(ctx context.Context,
	request identityverification.SettlementCommitRequest,
) (identityverification.SettlementCommitResult, error) {
	select {
	case publisher.entered <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return identityverification.SettlementCommitResult{}, ctx.Err()
	case <-publisher.release:
		return publisher.delegate.Publish(ctx, request)
	}
}

func TestRuntimePublisherDoesNotStarveSingleConnectionHTTPPool(t *testing.T) {
	fixture := newHTTPIntegrationFixture(t)
	token := integrationToken('q')
	fixture.registry.add(fixture.applicant.Actor, token,
		integrationPersonalEvidence(identityverification.KindPersonalInitial, bytesOf(32, 0x91), 0x92))
	draft := decodeCase(t, fixture.create(t, "applicant", identityverification.KindPersonalInitial,
		token, "runtime-pool-starvation", http.StatusCreated))

	pool := openNamedHTTPPool(t, fixture.pool, "identity-verification-runtime-pool-"+uuid.NewString())
	identityService, err := identity.NewService(identity.NewStore(pool), fixture.tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	publisher := &blockingSettlementPublisher{delegate: registrySettlementCommitter{registry: fixture.registry},
		entered: make(chan struct{}, 1), release: make(chan struct{})}
	runtime, err := NewRuntime(RuntimeConfig{Enabled: true,
		Core:    identityverification.Config{ReviewTTL: 2 * time.Hour, RetentionPeriod: 24 * time.Hour},
		Service: ServiceConfig{CursorKey: []byte("0123456789abcdef0123456789abcdef")},
		Settlement: identityverification.SettlementWorkerConfig{
			LeaseDuration: time.Minute, RetryDelay: time.Millisecond, MaxAttempts: 3,
		}, WorkerIdlePoll: time.Millisecond, WorkerErrorBackoff: time.Millisecond,
	}, RuntimeDependencies{Pool: pool, Identity: identityService, IAM: fixture.iam,
		Resolver: fixture.registry, SettlementPublisher: publisher, Clock: fixture.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(t.Context()) }()
	released := false
	defer func() {
		if !released {
			close(publisher.release)
		}
		_ = runtime.Close()
		select {
		case <-runDone:
		case <-time.After(2 * time.Second):
			t.Error("runtime did not stop")
		}
	}()
	select {
	case <-publisher.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("publisher was not called")
	}

	requestCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	response := integrationRequestContext(requestCtx, runtime, fixture.applicant.token, http.MethodGet,
		apiPrefix+"/cases/"+draft.ID.String(), "", "", 0)
	cancel()
	if response.Code != http.StatusOK {
		t.Fatalf("HTTP request starved behind publisher: status=%d body=%s", response.Code, response.Body.String())
	}

	close(publisher.release)
	released = true
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		var state string
		if err := fixture.pool.QueryRow(t.Context(), `SELECT state
			FROM identity_verification_evidence_settlements WHERE case_id=$1`, draft.ID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state == identityverification.SettlementSettled {
			break
		}
		select {
		case <-deadline.C:
			t.Fatalf("settlement did not recover after publisher release: state=%s", state)
		case <-time.After(time.Millisecond):
		}
	}
}
