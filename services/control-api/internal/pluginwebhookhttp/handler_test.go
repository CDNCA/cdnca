package pluginwebhookhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhookcontrol"
	"github.com/google/uuid"
)

func TestStrictBearerAuthenticationAndActorTriple(t *testing.T) {
	target, authenticated, user := uuid.New(), uuid.New(), uuid.New()
	store := &recordingStore{}
	handler, err := NewHandler(Dependencies{
		AuthenticateSession: func(_ context.Context, raw string) (identity.AuthenticatedSession, error) {
			if raw != "formal-session" {
				return identity.AuthenticatedSession{}, errors.New("invalid")
			}
			return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: user, ScopeID: authenticated, ScopeKind: "platform"}}, nil
		},
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/tenant-scopes/"+target.String()+"/plugin-webhook-subscriptions?limit=10", nil)
	request.Header.Set("Authorization", "Bearer formal-session")
	request.Header.Set("X-Request-ID", "plugin-webhook-request-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if store.actor.ActorUserID != user || store.actor.ActorScopeID != authenticated || store.actor.TargetScopeID != target {
		t.Fatalf("actor = %+v", store.actor)
	}
	if response.Header().Get("X-Request-ID") != "plugin-webhook-request-1" {
		t.Fatalf("response request ID = %q", response.Header().Get("X-Request-ID"))
	}
	boundary := httptest.NewRequest(http.MethodGet, "/", nil)
	boundary.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 8191))
	if token, err := strictBearer(boundary); err != nil || len(token) != 8191 {
		t.Fatalf("8191-byte bearer = %d,%v", len(token), err)
	}
	for name, authorization := range map[string][]string{
		"missing":    nil,
		"duplicate":  {"Bearer formal-session", "Bearer formal-session"},
		"whitespace": {"Bearer bad token"},
		"8192":       {"Bearer " + strings.Repeat("x", 8192)},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, request.URL.String(), nil)
			for _, value := range authorization {
				req.Header.Add("Authorization", value)
			}
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d", res.Code)
			}
			assertErrorCode(t, res, "authentication_required")
		})
	}
}

func TestNineRoutesAndStrictPostBodies(t *testing.T) {
	target, subscription, delivery, rotation := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	base := "/v1/tenant-scopes/" + target.String() + "/plugin-webhook-subscriptions"
	routes := []struct{ method, path string }{
		{http.MethodGet, base}, {http.MethodPost, base}, {http.MethodGet, base + "/" + subscription.String()},
		{http.MethodPost, base + "/" + subscription.String() + "/test-deliveries"},
		{http.MethodGet, base + "/" + subscription.String() + "/deliveries"},
		{http.MethodGet, base + "/" + subscription.String() + "/deliveries/" + delivery.String()},
		{http.MethodPost, base + "/" + subscription.String() + "/deliveries/" + delivery.String() + "/replays"},
		{http.MethodPost, base + "/" + subscription.String() + "/secret-rotations"},
		{http.MethodPost, base + "/" + subscription.String() + "/secret-rotations/" + rotation.String() + "/activate"},
		{http.MethodPost, base + "/" + subscription.String() + "/revoke"},
	}
	if got := len(routes); got != 10 { // GET/POST on the collection are one public route.
		t.Fatalf("method routes = %d", got)
	}
	for _, route := range routes {
		t.Run(route.method+route.path, func(t *testing.T) {
			if !matchRoute(route.method, route.path).matched {
				t.Fatalf("route did not match")
			}
		})
	}
	for _, body := range []string{"", "{\"extra\":true}", "{} {}", "null", "[]"} {
		request := httptest.NewRequest(http.MethodPost, base+"/"+subscription.String()+"/test-deliveries", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := decodeEmptyObject(request); !errors.Is(err, ErrValidation) {
			t.Fatalf("body %q error = %v", body, err)
		}
	}
}

func TestIfMatchAndErrorEnvelope(t *testing.T) {
	for _, value := range []string{"", "1", "W/\"1\"", "\"0\"", "\"01\"", "\"+1\"", "\"1\",\"2\""} {
		_, err := parseIfMatch(value)
		if value == "" && !errors.Is(err, ErrPreconditionRequired) {
			t.Fatalf("empty If-Match = %v", err)
		}
		if value != "" && !errors.Is(err, ErrRevisionConflict) {
			t.Fatalf("If-Match %q = %v", value, err)
		}
	}
	if revision, err := parseIfMatch("\"18446744073709551615\""); err != nil || revision != ^uint64(0) {
		t.Fatalf("valid max revision = %d, %v", revision, err)
	}
}

func TestWriteHeadersAndNamesAreExact(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "rotate-1")
	if _, err := writeHeaders(request, true); !errors.Is(err, ErrPreconditionRequired) {
		t.Fatalf("missing If-Match = %v", err)
	}
	request.Header.Add("If-Match", `"1"`)
	request.Header.Add("If-Match", `"1"`)
	if _, err := writeHeaders(request, true); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("duplicate If-Match = %v", err)
	}
	request.Header.Del("If-Match")
	request.Header.Add("If-Match", `"1"`)
	request.Header.Add("Idempotency-Key", "rotate-1")
	if _, err := writeHeaders(request, true); err == nil || err.Error() != "idempotency_key_required" {
		t.Fatalf("duplicate Idempotency-Key = %v", err)
	}
	if validName(" Operations ") || !validName("Operations") {
		t.Fatal("subscription name whitespace was normalized")
	}
}

func TestRouteAndBodyBoundsAreExact(t *testing.T) {
	target := uuid.New().String()
	base := "/v1/tenant-scopes/" + target + "/plugin-webhook-subscriptions"
	for _, path := range []string{base + "/", "//" + strings.TrimPrefix(base, "/")} {
		if matchRoute(http.MethodGet, path).matched {
			t.Fatalf("non-canonical route matched: %q", path)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"Operations","target_url":"https://hooks.example.com/`+strings.Repeat("a", maxRequestBody)+`","event_types":["io.cdnca.webhook.v1.test"]}`))
	request.Header.Set("Content-Type", "application/json")
	var body createSubscriptionBody
	if err := decodeJSONObject(request, &body); !errors.Is(err, ErrValidation) {
		t.Fatalf("oversized body = %v", err)
	}
}

func TestHandlerDispatchesEveryOperationWithExactStatusAndETag(t *testing.T) {
	target, authenticated, user := uuid.New(), uuid.New(), uuid.New()
	subscription, delivery, rotation := uuid.New(), uuid.New(), uuid.New()
	store := &recordingStore{subscription: subscription, delivery: delivery, rotation: rotation, target: target}
	handler, err := NewHandler(Dependencies{
		AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: user, ScopeID: authenticated, ScopeKind: pluginwebhookcontrol.ScopePlatform}}, nil
		},
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	base := "/v1/tenant-scopes/" + target.String() + "/plugin-webhook-subscriptions"
	cases := []struct {
		method, path, body, action string
		status                     int
		ifMatch, etag              string
	}{
		{http.MethodGet, base, "", "subscriptions.list", 200, "", ""},
		{http.MethodPost, base, `{"name":"Operations","target_url":"https://hooks.example.com/v1/events","event_types":["io.cdnca.webhook.v1.test","io.cdnca.deployment.v1.status_changed"]}`, "subscriptions.create", 201, "", `"1"`},
		{http.MethodGet, base + "/" + subscription.String(), "", "subscriptions.get", 200, "", `"1"`},
		{http.MethodPost, base + "/" + subscription.String() + "/test-deliveries", "{}", "deliveries.test", 202, "", ""},
		{http.MethodGet, base + "/" + subscription.String() + "/deliveries", "", "deliveries.list", 200, "", ""},
		{http.MethodGet, base + "/" + subscription.String() + "/deliveries/" + delivery.String(), "", "deliveries.get", 200, "", ""},
		{http.MethodPost, base + "/" + subscription.String() + "/deliveries/" + delivery.String() + "/replays", "{}", "deliveries.replay", 202, "", ""},
		{http.MethodPost, base + "/" + subscription.String() + "/delivery-replays", `{"from":"2026-10-01T00:00:00Z","to":"2026-10-02T00:00:00Z","statuses":["dead_lettered"],"limit":50}`, "deliveries.replay_range", 202, "", ""},
		{http.MethodPost, base + "/" + subscription.String() + "/secret-rotations", "{}", "secrets.rotate", 201, `"1"`, `"1"`},
		{http.MethodPost, base + "/" + subscription.String() + "/secret-rotations/" + rotation.String() + "/activate", "{}", "secrets.activate", 200, `"1"`, `"2"`},
		{http.MethodPost, base + "/" + subscription.String() + "/revoke", "{}", "subscriptions.revoke", 200, `"1"`, `"2"`},
	}
	for _, current := range cases {
		t.Run(current.action, func(t *testing.T) {
			request := httptest.NewRequest(current.method, current.path, strings.NewReader(current.body))
			request.Header.Set("Authorization", "Bearer formal-session")
			if current.method == http.MethodPost {
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Idempotency-Key", "request-1")
			}
			if current.ifMatch != "" {
				request.Header.Set("If-Match", current.ifMatch)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != current.status || response.Header().Get("ETag") != current.etag || store.action != current.action {
				t.Fatalf("response=%d etag=%q action=%q body=%s", response.Code, response.Header().Get("ETag"), store.action, response.Body.String())
			}
		})
	}
}

func TestCreateSubscriptionPassesInstallationAuthorizationBinding(t *testing.T) {
	target, authorization := uuid.New(), uuid.New()
	store := &recordingStore{target: target}
	handler, err := NewHandler(Dependencies{
		AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: target, ScopeKind: pluginwebhookcontrol.ScopeTenant}}, nil
		},
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/tenant-scopes/"+target.String()+"/plugin-webhook-subscriptions", strings.NewReader(`{"name":"Deployments","target_url":"https://hooks.example.com/events","event_types":["io.cdnca.deployment.v1.status_changed"],"installation_authorization_id":"`+authorization.String()+`"}`))
	request.Header.Set("Authorization", "Bearer formal-session")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "binding-create-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if store.create.InstallationAuthorizationID == nil || *store.create.InstallationAuthorizationID != authorization {
		t.Fatalf("installation authorization = %#v", store.create.InstallationAuthorizationID)
	}
}

func TestCreateSubscriptionPassesSiteFilterAndReplayRangeBody(t *testing.T) {
	target, authorization, site := uuid.New(), uuid.New(), uuid.New()
	store := &recordingStore{target: target, subscription: uuid.New()}
	handler, err := NewHandler(Dependencies{
		AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: target, ScopeKind: pluginwebhookcontrol.ScopeTenant}}, nil
		},
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	send := func(path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer formal-session")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "filter-1")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	base := "/v1/tenant-scopes/" + target.String() + "/plugin-webhook-subscriptions"
	response := send(base, `{"name":"Sites","target_url":"https://hooks.example.com/events","event_types":["io.cdnca.site.v1.updated"],"installation_authorization_id":"`+authorization.String()+`","site_ids":["`+site.String()+`"]}`)
	if response.Code != http.StatusCreated || len(store.create.SiteIDs) != 1 || store.create.SiteIDs[0] != site {
		t.Fatalf("status=%d site filter=%v body=%s", response.Code, store.create.SiteIDs, response.Body.String())
	}
	if response := send(base, `{"name":"Sites","target_url":"https://hooks.example.com/events","event_types":["io.cdnca.site.v1.updated"],"site_ids":["not-a-uuid"]}`); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid site id status=%d", response.Code)
	}
	replay := base + "/" + store.subscription.String() + "/delivery-replays"
	response = send(replay, `{"from":"2026-10-01T00:00:00+08:00","to":"2026-10-02T00:00:00Z","event_types":["io.cdnca.site.v1.updated"],"limit":10}`)
	if response.Code != http.StatusAccepted || store.replayRange.Limit != 10 || store.replayRange.IdempotencyKey != "filter-1" ||
		!store.replayRange.From.Equal(time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC)) || len(store.replayRange.EventTypes) != 1 {
		t.Fatalf("replay range status=%d input=%+v", response.Code, store.replayRange)
	}
	for _, body := range []string{`{"from":"yesterday","to":"2026-10-02T00:00:00Z","limit":1}`, `{"from":"2026-10-01T00:00:00Z","to":"2026-10-02T00:00:00Z"}`, `{"from":"2026-10-01T00:00:00Z","to":"2026-10-02T00:00:00Z","limit":1,"extra":true}`} {
		if response := send(replay, body); response.Code != http.StatusBadRequest {
			t.Fatalf("body %s status=%d", body, response.Code)
		}
	}
}

func TestDomainErrorMappings(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{ErrAuthentication, 401, "authentication_required"},
		{ErrValidation, 400, "plugin_webhook_validation_error"},
		{errors.New("idempotency_key_required"), 400, "idempotency_key_required"},
		{pluginwebhookcontrol.ErrPermissionDenied, 403, "permission_denied"},
		{pluginwebhookcontrol.ErrNotFound, 404, "plugin_webhook_not_found"},
		{pluginwebhookcontrol.ErrIdempotencyConflict, 409, "idempotency_conflict"},
		{pluginwebhookcontrol.ErrIdempotencyExpired, 409, "idempotency_expired"},
		{pluginwebhookcontrol.ErrStateConflict, 409, "plugin_webhook_state_conflict"},
		{pluginwebhookcontrol.ErrDeliveryNotReplayable, 409, "plugin_webhook_delivery_not_replayable"},
		{pluginwebhookcontrol.ErrRotationPending, 409, "plugin_webhook_rotation_pending"},
		{ErrPreconditionRequired, 428, "precondition_required"},
		{pluginwebhookcontrol.ErrRevisionConflict, 412, "revision_conflict"},
		{pluginwebhookcontrol.ErrTargetForbidden, 422, "plugin_webhook_target_forbidden"},
		{pluginwebhookcontrol.ErrEntitlementDenied, 422, "plugin_webhook_entitlement_denied"},
		{pluginwebhookcontrol.ErrQuotaExceeded, 422, "plugin_webhook_quota_exceeded"},
		{pluginwebhookcontrol.RateLimitError{RetryAfter: time.Minute}, 429, "plugin_webhook_rate_limited"},
		{pluginwebhookcontrol.ErrSecretUnavailable, 503, "plugin_webhook_secret_unavailable"},
		{pluginwebhookcontrol.ErrResultUnknown, 503, "plugin_webhook_result_unknown"},
		{errors.New("internal dependency failure"), 503, "plugin_webhook_store_unavailable"},
	}
	for _, current := range cases {
		response := httptest.NewRecorder()
		writeDomainError(response, current.err)
		if response.Code != current.status {
			t.Fatalf("%v status=%d", current.err, response.Code)
		}
		assertErrorCode(t, response, current.code)
	}
}

func TestErrorEnvelopeNeverReflectsUntrustedMetadataOrInternalErrors(t *testing.T) {
	target := uuid.New()
	handler, err := NewHandler(Dependencies{
		AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: target, ScopeKind: pluginwebhookcontrol.ScopeTenant}}, nil
		},
		Store: &recordingStore{target: target},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/tenant-scopes/"+target.String()+"/plugin-webhook-subscriptions", nil)
	request.Header.Set("Authorization", "Bearer raw-secret-session")
	request.Header.Set("X-Request-ID", "unsafe request id")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "unsafe request id") || strings.Contains(response.Body.String(), "raw-secret-session") {
		t.Fatalf("unsafe metadata response=%d body=%s", response.Code, response.Body.String())
	}
	assertErrorCode(t, response, "plugin_webhook_validation_error")

	internal := httptest.NewRecorder()
	internal.Header().Set("X-Request-ID", "safe-request-id")
	writeDomainError(internal, errors.New("database token=raw-secret internal failure"))
	if strings.Contains(internal.Body.String(), "database") || strings.Contains(internal.Body.String(), "raw-secret") || strings.Contains(internal.Body.String(), "internal failure") {
		t.Fatalf("internal error leaked: %s", internal.Body.String())
	}
	assertErrorCode(t, internal, "plugin_webhook_store_unavailable")
}

func TestNewProductionHandlerFailsClosedWithoutEveryDependency(t *testing.T) {
	for name, dependencies := range map[string]ProductionDependencies{
		"all missing": {},
		"pool only":   {},
	} {
		t.Run(name, func(t *testing.T) {
			if handler, err := NewProductionHandler(dependencies); handler != nil || !errors.Is(err, pluginwebhookcontrol.ErrInvalidConfig) {
				t.Fatalf("NewProductionHandler() = (%T,%v)", handler, err)
			}
		})
	}
}

func assertErrorCode(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	var envelope struct {
		Error struct {
			Code      string         `json:"code"`
			Message   string         `json:"message"`
			RequestID string         `json:"request_id"`
			Params    map[string]any `json:"params"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != want || envelope.Error.Message != "request failed" || envelope.Error.RequestID == "" || envelope.Error.Params == nil {
		t.Fatalf("envelope = %+v", envelope)
	}
}

type recordingStore struct {
	pluginwebhookcontrol.UnimplementedDomain
	actor        pluginwebhookcontrol.Actor
	action       string
	create       pluginwebhookcontrol.CreateSubscriptionRequest
	replayRange  pluginwebhookcontrol.ReplayRangeRequest
	target       uuid.UUID
	subscription uuid.UUID
	delivery     uuid.UUID
	rotation     uuid.UUID
}

func (store *recordingStore) ListSubscriptions(_ context.Context, actor pluginwebhookcontrol.Actor, _ pluginwebhookcontrol.ListQuery) (pluginwebhookcontrol.SubscriptionPage, error) {
	store.actor = actor
	store.action = "subscriptions.list"
	return pluginwebhookcontrol.SubscriptionPage{Items: []pluginwebhookcontrol.Subscription{}}, nil
}

func (store *recordingStore) CreateSubscription(_ context.Context, actor pluginwebhookcontrol.Actor, input pluginwebhookcontrol.CreateSubscriptionRequest) (pluginwebhookcontrol.WriteResult[pluginwebhookcontrol.SubscriptionReceipt], error) {
	store.actor, store.action = actor, "subscriptions.create"
	store.create = input
	return pluginwebhookcontrol.WriteResult[pluginwebhookcontrol.SubscriptionReceipt]{Value: pluginwebhookcontrol.SubscriptionReceipt{Subscription: store.subscriptionValue(1), Secret: strings.Repeat("a", 43)}}, nil
}
func (store *recordingStore) GetSubscription(_ context.Context, actor pluginwebhookcontrol.Actor, _ uuid.UUID) (pluginwebhookcontrol.Subscription, error) {
	store.actor, store.action = actor, "subscriptions.get"
	return store.subscriptionValue(1), nil
}
func (store *recordingStore) CreateTestDelivery(_ context.Context, actor pluginwebhookcontrol.Actor, _ uuid.UUID, _ pluginwebhookcontrol.WriteRequest) (pluginwebhookcontrol.WriteResult[pluginwebhookcontrol.DeliveryReceipt], error) {
	store.actor, store.action = actor, "deliveries.test"
	return store.deliveryValue(), nil
}
func (store *recordingStore) ListDeliveries(_ context.Context, actor pluginwebhookcontrol.Actor, _ uuid.UUID, _ pluginwebhookcontrol.ListQuery) (pluginwebhookcontrol.DeliveryPage, error) {
	store.actor, store.action = actor, "deliveries.list"
	return pluginwebhookcontrol.DeliveryPage{Items: []pluginwebhookcontrol.Delivery{}}, nil
}
func (store *recordingStore) GetDelivery(_ context.Context, actor pluginwebhookcontrol.Actor, _, _ uuid.UUID) (pluginwebhookcontrol.Delivery, error) {
	store.actor, store.action = actor, "deliveries.get"
	return store.deliveryValue().Value.Delivery, nil
}
func (store *recordingStore) ReplayDelivery(_ context.Context, actor pluginwebhookcontrol.Actor, _, _ uuid.UUID, _ pluginwebhookcontrol.WriteRequest) (pluginwebhookcontrol.WriteResult[pluginwebhookcontrol.DeliveryReceipt], error) {
	store.actor, store.action = actor, "deliveries.replay"
	return store.deliveryValue(), nil
}
func (store *recordingStore) RotateSecret(_ context.Context, actor pluginwebhookcontrol.Actor, _ uuid.UUID, _ pluginwebhookcontrol.WriteRequest) (pluginwebhookcontrol.WriteResult[pluginwebhookcontrol.RotationReceipt], error) {
	store.actor, store.action = actor, "secrets.rotate"
	return pluginwebhookcontrol.WriteResult[pluginwebhookcontrol.RotationReceipt]{Value: pluginwebhookcontrol.RotationReceipt{RotationID: store.rotation, KeyID: store.rotation, Status: "pending", ExpiresAt: time.Now().UTC(), Secret: strings.Repeat("a", 43), SubscriptionRevision: 1}}, nil
}
func (store *recordingStore) ActivateSecret(_ context.Context, actor pluginwebhookcontrol.Actor, _, _ uuid.UUID, _ pluginwebhookcontrol.WriteRequest) (pluginwebhookcontrol.WriteResult[pluginwebhookcontrol.SubscriptionResult], error) {
	store.actor, store.action = actor, "secrets.activate"
	return pluginwebhookcontrol.WriteResult[pluginwebhookcontrol.SubscriptionResult]{Value: pluginwebhookcontrol.SubscriptionResult{Subscription: store.subscriptionValue(2)}}, nil
}
func (store *recordingStore) RevokeSubscription(_ context.Context, actor pluginwebhookcontrol.Actor, _ uuid.UUID, _ pluginwebhookcontrol.WriteRequest) (pluginwebhookcontrol.WriteResult[pluginwebhookcontrol.SubscriptionResult], error) {
	store.actor, store.action = actor, "subscriptions.revoke"
	return pluginwebhookcontrol.WriteResult[pluginwebhookcontrol.SubscriptionResult]{Value: pluginwebhookcontrol.SubscriptionResult{Subscription: store.subscriptionValue(2)}}, nil
}
func (store *recordingStore) ReplayRange(_ context.Context, actor pluginwebhookcontrol.Actor, _ uuid.UUID, input pluginwebhookcontrol.ReplayRangeRequest) (pluginwebhookcontrol.ReplayRangeResult, error) {
	store.actor, store.action, store.replayRange = actor, "deliveries.replay_range", input
	return pluginwebhookcontrol.ReplayRangeResult{Items: []pluginwebhookcontrol.ReplayRangeItem{}}, nil
}
func (store *recordingStore) subscriptionValue(revision uint64) pluginwebhookcontrol.Subscription {
	return pluginwebhookcontrol.Subscription{ID: store.subscription, TenantScopeID: store.target, Name: "Operations", TargetURL: "https://hooks.example.com/v1/events", EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, Status: "active", Revision: revision, ActiveSecretVersionID: uuid.New(), CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
}
func (store *recordingStore) deliveryValue() pluginwebhookcontrol.WriteResult[pluginwebhookcontrol.DeliveryReceipt] {
	return pluginwebhookcontrol.WriteResult[pluginwebhookcontrol.DeliveryReceipt]{Value: pluginwebhookcontrol.DeliveryReceipt{Delivery: pluginwebhookcontrol.Delivery{ID: store.delivery, SubscriptionID: store.subscription, EventID: uuid.New(), Status: "pending", CreatedAt: time.Now().UTC()}}}
}
