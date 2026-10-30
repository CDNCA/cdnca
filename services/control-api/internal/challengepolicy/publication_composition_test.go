package challengepolicy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
)

type compositionSecretPublisher struct {
	publication challengepublication.SecretPublication
	calls       int
}

func (publisher *compositionSecretPublisher) PublishChallengeSecret(
	_ context.Context,
	request challengepublication.PublishRequest,
	material challengepublication.ArtifactMaterial,
) (challengepublication.SecretPublication, error) {
	publisher.calls++
	if material.Policy.PolicyVersion != uint64(request.Policy.Revision) || len(material.Keys) != 1 ||
		material.Keys[0].KeyID != "challenge-current" || len(material.Keys[0].Secret) != 32 {
		return challengepublication.SecretPublication{}, challengepublication.ErrInvalidRuntime
	}
	return publisher.publication, nil
}

type compositionRolloutReader struct {
	status challengepublication.RolloutStatus
}

func (reader compositionRolloutReader) ChallengeRolloutStatus(
	context.Context, challengepublication.StatusRequest,
) (challengepublication.RolloutStatus, error) {
	return reader.status, nil
}

func TestPublicationCompositionBindsAdaptersToExactHealthyRollout(t *testing.T) {
	snapshot := testPublicationSnapshot()
	rolloutID, configVersionID, publicationID := uuid.New(), uuid.New(), uuid.New()
	nodeIDs := []uuid.UUID{uuid.New(), uuid.New()}
	secret := challengepublication.SecretPublication{
		RolloutID: rolloutID, ConfigVersionID: configVersionID, Revision: 1,
	}
	secretPublisher := &compositionSecretPublisher{publication: secret}
	rolloutReader := compositionRolloutReader{status: challengepublication.RolloutStatus{
		RolloutID: rolloutID, ConfigVersionID: configVersionID, Revision: 1,
		State: challengepublication.StateHealthy, Total: len(nodeIDs), Healthy: len(nodeIDs),
	}}
	keyMaterial := make([]byte, 32)
	for index := range keyMaterial {
		keyMaterial[index] = byte(index + 1)
	}
	keyCalls, configCalls := 0, 0
	keys := challengepublication.KeyResolverFunc(func(
		_ context.Context, request challengepublication.PublicationSnapshot,
	) (challengepublication.ResolvedKeys, error) {
		keyCalls++
		if request.PolicyID != snapshot.PolicyID || request.TenantScopeID != snapshot.TenantScopeID ||
			request.SiteID != snapshot.SiteID || request.KeyReference != snapshot.KeyReference {
			return challengepublication.ResolvedKeys{}, challengepublication.ErrKeyUnavailable
		}
		return challengepublication.ResolvedKeys{Current: challengepublication.ArtifactSecret{
			KeyID: "challenge-current", Secret: keyMaterial,
		}}, nil
	})
	configs := challengepublication.ConfigPublisherFunc(func(
		_ context.Context, request challengepublication.BindingRequest,
	) (challengepublication.ConfigPublication, error) {
		configCalls++
		if request.TenantScopeID != snapshot.TenantScopeID || request.TenantID != snapshot.TenantID ||
			request.SiteID != snapshot.SiteID || request.PolicyID != snapshot.PolicyID ||
			request.PolicyRevision != snapshot.Revision || request.Secret != secret {
			return challengepublication.ConfigPublication{}, challengepublication.ErrInvalidRuntime
		}
		return challengepublication.ConfigPublication{PublicationID: publicationID, Revision: 9}, nil
	})
	runtime, err := challengepublication.NewRuntime(keys, secretPublisher, rolloutReader, configs)
	if err != nil {
		t.Fatal(err)
	}
	planner := &publicationPlannerStub{plan: PublicationPlan{
		NodeIDs: nodeIDs,
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: time.Second, ObservationWindow: time.Second, RequiredConsecutiveSuccesses: 1,
		},
		Deadline: time.Now().Add(time.Minute),
	}}
	verifier := &publicationVerifierStub{nodes: nodeIDs}
	coordinator, err := NewPublicationCoordinator(
		&publicationPolicySourceStub{snapshot: snapshot}, runtime, planner, verifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	actor := testPublicationCommand(snapshot).Actor
	handler, err := NewPublicationHandler(AuthenticatorFunc(func(*http.Request) (Actor, error) {
		return actor, nil
	}), coordinator)
	if err != nil {
		t.Fatal(err)
	}
	base := "/v1/tenant-scopes/" + snapshot.TenantScopeID.String() + "/challenge-policies/" +
		snapshot.PolicyID.String() + "/publications"

	publishResponse := httptest.NewRecorder()
	handler.ServeHTTP(publishResponse, publicationRequest(t, http.MethodPost, base, true))
	assertPublicationHTTPResponse(t, publishResponse, http.StatusAccepted, snapshot.PolicyID, rolloutID)
	if keyCalls != 1 || secretPublisher.calls != 1 || configCalls != 0 {
		t.Fatalf("publish calls: keys=%d secret=%d config=%d", keyCalls, secretPublisher.calls, configCalls)
	}
	for index, value := range keyMaterial {
		if value != byte(index+1) {
			t.Fatal("runtime cleared resolver-owned key material")
		}
	}

	promoteResponse := httptest.NewRecorder()
	handler.ServeHTTP(promoteResponse,
		publicationRequest(t, http.MethodPost, base+"/"+rolloutID.String()+"/promote", true))
	assertPublicationHTTPResponse(t, promoteResponse, http.StatusOK, snapshot.PolicyID, rolloutID)
	if configCalls != 1 || verifier.calls != 2 {
		t.Fatalf("promote calls: config=%d verifier=%d", configCalls, verifier.calls)
	}
}
