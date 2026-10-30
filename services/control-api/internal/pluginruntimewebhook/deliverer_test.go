package pluginruntimewebhook

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeauth"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhook"
	"github.com/google/uuid"
)

type providerFunc func(context.Context, RuntimeAuthorizationRequest) (RuntimeAuthorizationFacts, error)

func (provider providerFunc) RuntimeAuthorization(ctx context.Context,
	request RuntimeAuthorizationRequest) (RuntimeAuthorizationFacts, error) {
	return provider(ctx, request)
}

type verifierFunc func([]byte, []byte, pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error)

func (verifier verifierFunc) Authorize(identityJSON, decisionJSON []byte,
	expected pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
	return verifier(identityJSON, decisionJSON, expected)
}

type typedNilProvider struct{}

func (*typedNilProvider) RuntimeAuthorization(context.Context,
	RuntimeAuthorizationRequest) (RuntimeAuthorizationFacts, error) {
	panic("typed-nil provider called")
}

type typedNilVerifier struct{}

func (*typedNilVerifier) Authorize([]byte, []byte,
	pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
	panic("typed-nil verifier called")
}

type recordingDeliverer struct {
	calls    int
	items    []pluginwebhook.QueueItem
	attempts []uint64
	secrets  [][]byte
	result   pluginwebhook.SendResult
}

func (deliverer *recordingDeliverer) DeliverV2(_ context.Context, item pluginwebhook.QueueItem,
	attempt uint64, secret []byte) pluginwebhook.SendResult {
	deliverer.calls++
	deliverer.items = append(deliverer.items, item)
	deliverer.attempts = append(deliverer.attempts, attempt)
	deliverer.secrets = append(deliverer.secrets, append([]byte(nil), secret...))
	return deliverer.result
}

func validQueueItem() pluginwebhook.QueueItem {
	return pluginwebhook.QueueItem{
		Schema:         pluginwebhook.QueueSchemaV2,
		DeliveryID:     uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		IdempotencyKey: "plugin-webhook-v2-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Event: pluginwebhook.CloudEvent{
			ID:   uuid.MustParse("55555555-5555-4555-8555-555555555555").String(),
			Type: "io.cdnca.dns.v1.changed",
		},
		TargetScopeID:   uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		TenantID:        uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		SubscriptionID:  uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		SecretVersionID: uuid.MustParse("77777777-7777-4777-8777-777777777777"),
		EventID:         uuid.MustParse("55555555-5555-4555-8555-555555555555"),
	}
}

func matchingAuthorization(expected pluginruntimeauth.ExpectedAction) pluginruntimeauth.Authorization {
	return pluginruntimeauth.Authorization{
		InstallationID: expected.InstallationID,
		RequestID:      expected.RequestID,
		CapabilityKind: expected.CapabilityKind,
		CapabilityCode: expected.CapabilityCode,
	}
}

func TestAuthorizedDelivererUsesFreshCurrentActionAndClearsProofs(t *testing.T) {
	installationID := uuid.MustParse("66666666-6666-4666-8666-666666666666")
	item := validQueueItem()
	requests := make([]RuntimeAuthorizationRequest, 0, 2)
	identities := make([][]byte, 0, 2)
	decisions := make([][]byte, 0, 2)
	provider := providerFunc(func(_ context.Context, request RuntimeAuthorizationRequest) (RuntimeAuthorizationFacts, error) {
		requests = append(requests, request)
		identity := []byte("fresh-identity-proof")
		decision := []byte("fresh-decision-proof")
		identities = append(identities, identity)
		decisions = append(decisions, decision)
		return RuntimeAuthorizationFacts{IdentityJSON: identity, DecisionJSON: decision}, nil
	})
	verified := 0
	verifier := verifierFunc(func(identityJSON, decisionJSON []byte,
		expected pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
		verified++
		if string(identityJSON) != "fresh-identity-proof" || string(decisionJSON) != "fresh-decision-proof" {
			t.Fatal("provider proofs changed before verification")
		}
		return matchingAuthorization(expected), nil
	})
	delegate := &recordingDeliverer{result: pluginwebhook.SendResult{Success: true, Code: "delivered", StatusCode: 204}}
	deliverer, err := NewAuthorizedDeliverer(installationID, provider, verifier, delegate)
	if err != nil {
		t.Fatal(err)
	}
	if _, implementsV1 := any(deliverer).(pluginwebhook.Deliverer); implementsV1 {
		t.Fatal("authorized deliverer must not implement the v1 Deliver contract")
	}

	for attempt := uint64(1); attempt <= 2; attempt++ {
		result := deliverer.DeliverV2(t.Context(), item, attempt, []byte("runtime-secret"))
		if !result.Success || result.Code != "delivered" {
			t.Fatalf("attempt %d result = %+v", attempt, result)
		}
	}
	if len(requests) != 2 || verified != 2 || delegate.calls != 2 || requests[0] != requests[1] {
		t.Fatalf("fresh authorization counts requests=%+v verified=%d delegate=%d", requests, verified, delegate.calls)
	}
	want := RuntimeAuthorizationRequest{
		InstallationID: installationID, TargetScopeID: item.TargetScopeID, TenantID: item.TenantID,
		SubscriptionID: item.SubscriptionID, DeliveryID: item.DeliveryID, EventID: item.EventID,
		RequestID: item.DeliveryID.String(), CapabilityKind: "webhook", CapabilityCode: item.Event.Type,
	}
	if requests[0] != want || delegate.items[0].IdempotencyKey != item.IdempotencyKey ||
		delegate.items[1].DeliveryID != item.DeliveryID || delegate.attempts[0] != 1 || delegate.attempts[1] != 2 {
		t.Fatalf("delivery binding changed: request=%+v items=%+v attempts=%v", requests[0], delegate.items, delegate.attempts)
	}
	for index := range identities {
		if !bytes.Equal(identities[index], make([]byte, len(identities[index]))) ||
			!bytes.Equal(decisions[index], make([]byte, len(decisions[index]))) {
			t.Fatalf("proof %d was not cleared", index)
		}
	}
}

func TestAuthorizedDelivererFailsClosedBeforeDelegate(t *testing.T) {
	installationID := uuid.MustParse("66666666-6666-4666-8666-666666666666")
	item := validQueueItem()
	tests := []struct {
		name       string
		provider   providerFunc
		verifier   verifierFunc
		wantCode   string
		wantRetry  bool
		wantVerify int
	}{
		{name: "provider failure", provider: func(context.Context, RuntimeAuthorizationRequest) (RuntimeAuthorizationFacts, error) {
			return RuntimeAuthorizationFacts{}, errors.New("provider unavailable")
		}, wantCode: "runtime_authorization_unavailable", wantRetry: true},
		{name: "empty proof", provider: func(context.Context, RuntimeAuthorizationRequest) (RuntimeAuthorizationFacts, error) {
			return RuntimeAuthorizationFacts{}, nil
		}, wantCode: "runtime_authorization_denied"},
		{name: "trust unavailable", verifier: func([]byte, []byte, pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
			return pluginruntimeauth.Authorization{}, pluginruntimeauth.ErrTrustUnavailable
		}, wantCode: "runtime_authorization_unavailable", wantRetry: true, wantVerify: 1},
		{name: "denied", verifier: func([]byte, []byte, pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
			return pluginruntimeauth.Authorization{}, pluginruntimeauth.ErrDenied
		}, wantCode: "runtime_authorization_denied", wantVerify: 1},
		{name: "invalid", verifier: func([]byte, []byte, pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
			return pluginruntimeauth.Authorization{}, pluginruntimeauth.ErrInvalid
		}, wantCode: "runtime_authorization_denied", wantVerify: 1},
		{name: "binding mismatch", verifier: func(_ []byte, _ []byte, expected pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
			authorization := matchingAuthorization(expected)
			authorization.RequestID = uuid.NewString()
			return authorization, nil
		}, wantCode: "runtime_authorization_denied", wantVerify: 1},
		{name: "capability mismatch", verifier: func(_ []byte, _ []byte, expected pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
			authorization := matchingAuthorization(expected)
			authorization.CapabilityCode = "io.cdnca.webhook.v1.test"
			return authorization, nil
		}, wantCode: "runtime_authorization_denied", wantVerify: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proof := []byte("proof")
			provider := test.provider
			if provider == nil {
				provider = func(context.Context, RuntimeAuthorizationRequest) (RuntimeAuthorizationFacts, error) {
					return RuntimeAuthorizationFacts{IdentityJSON: proof, DecisionJSON: proof}, nil
				}
			}
			verifications := 0
			verifier := test.verifier
			if verifier == nil {
				verifier = func(_ []byte, _ []byte, expected pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
					verifications++
					return matchingAuthorization(expected), nil
				}
			} else {
				wrapped := verifier
				verifier = func(identityJSON, decisionJSON []byte, expected pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
					verifications++
					return wrapped(identityJSON, decisionJSON, expected)
				}
			}
			delegate := &recordingDeliverer{}
			deliverer, err := NewAuthorizedDeliverer(installationID, provider, verifier, delegate)
			if err != nil {
				t.Fatal(err)
			}
			result := deliverer.DeliverV2(t.Context(), item, 1, []byte("secret"))
			if result.Success || result.Code != test.wantCode || result.Retryable != test.wantRetry ||
				delegate.calls != 0 || verifications != test.wantVerify {
				t.Fatalf("result=%+v delegate=%d verify=%d", result, delegate.calls, verifications)
			}
		})
	}
}

func TestAuthorizedDelivererRejectsUnknownEventBeforeAuthorization(t *testing.T) {
	installationID := uuid.MustParse("66666666-6666-4666-8666-666666666666")
	item := validQueueItem()
	item.Event.Type = "io.cdnca.unknown.v1.event"
	providerCalls := 0
	verifierCalls := 0
	delegate := &recordingDeliverer{}
	deliverer, err := NewAuthorizedDeliverer(installationID,
		providerFunc(func(context.Context, RuntimeAuthorizationRequest) (RuntimeAuthorizationFacts, error) {
			providerCalls++
			return RuntimeAuthorizationFacts{IdentityJSON: []byte("identity"), DecisionJSON: []byte("decision")}, nil
		}),
		verifierFunc(func([]byte, []byte, pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
			verifierCalls++
			return pluginruntimeauth.Authorization{}, nil
		}), delegate)
	if err != nil {
		t.Fatal(err)
	}
	result := deliverer.DeliverV2(t.Context(), item, 1, []byte("secret"))
	if result.Success || result.Code != "runtime_authorization_denied" || result.Retryable ||
		providerCalls != 0 || verifierCalls != 0 || delegate.calls != 0 {
		t.Fatalf("unknown event crossed authorization fence: result=%+v provider=%d verifier=%d delegate=%d",
			result, providerCalls, verifierCalls, delegate.calls)
	}
}

func TestAuthorizedDelivererRejectsInvalidConstructionAndAction(t *testing.T) {
	providerCalls := 0
	provider := providerFunc(func(context.Context, RuntimeAuthorizationRequest) (RuntimeAuthorizationFacts, error) {
		providerCalls++
		return RuntimeAuthorizationFacts{IdentityJSON: []byte("identity"), DecisionJSON: []byte("decision")}, nil
	})
	verifier := verifierFunc(func(_ []byte, _ []byte, expected pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
		return matchingAuthorization(expected), nil
	})
	delegate := &recordingDeliverer{}
	installationID := uuid.MustParse("66666666-6666-4666-8666-666666666666")
	if _, err := NewAuthorizedDeliverer(uuid.Nil, provider, verifier, delegate); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil installation error = %v", err)
	}
	if _, err := NewAuthorizedDeliverer(installationID, nil, verifier, delegate); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil provider error = %v", err)
	}
	if _, err := NewAuthorizedDeliverer(installationID, provider, nil, delegate); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil verifier error = %v", err)
	}
	if _, err := NewAuthorizedDeliverer(installationID, provider, verifier, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil delegate error = %v", err)
	}
	var nilProvider *typedNilProvider
	if _, err := NewAuthorizedDeliverer(installationID, nilProvider, verifier, delegate); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("typed-nil provider error = %v", err)
	}
	var nilVerifier *typedNilVerifier
	if _, err := NewAuthorizedDeliverer(installationID, provider, nilVerifier, delegate); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("typed-nil verifier error = %v", err)
	}
	var nilDelegate *recordingDeliverer
	if _, err := NewAuthorizedDeliverer(installationID, provider, verifier, nilDelegate); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("typed-nil delegate error = %v", err)
	}
	deliverer, err := NewAuthorizedDeliverer(installationID, provider, verifier, delegate)
	if err != nil {
		t.Fatal(err)
	}
	invalid := validQueueItem()
	invalid.Event.Type = ""
	for _, call := range []func() pluginwebhook.SendResult{
		func() pluginwebhook.SendResult {
			return deliverer.DeliverV2(nil, validQueueItem(), 1, []byte("secret"))
		},
		func() pluginwebhook.SendResult {
			return deliverer.DeliverV2(t.Context(), validQueueItem(), 0, []byte("secret"))
		},
		func() pluginwebhook.SendResult { return deliverer.DeliverV2(t.Context(), validQueueItem(), 1, nil) },
		func() pluginwebhook.SendResult { return deliverer.DeliverV2(t.Context(), invalid, 1, []byte("secret")) },
	} {
		result := call()
		if result.Code != "runtime_authorization_denied" || result.Retryable || result.Success {
			t.Fatalf("invalid action result = %+v", result)
		}
	}
	if providerCalls != 0 || delegate.calls != 0 {
		t.Fatalf("invalid action crossed fence: provider=%d delegate=%d", providerCalls, delegate.calls)
	}
}
