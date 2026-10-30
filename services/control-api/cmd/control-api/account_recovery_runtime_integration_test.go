//go:build integration

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoveryhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

func TestAccountRecoveryRuntimeConstructorAndPublicRoutesWithPostgreSQL17(t *testing.T) {
	pool := openNotificationRuntimeDatabase(t)
	var version string
	if err := pool.QueryRow(t.Context(), `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(version, "17.") {
		t.Fatalf("PostgreSQL version = %q, want 17.x", version)
	}

	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	username := "recovery-runtime-" + strings.ReplaceAll(userID.String(), "-", "")[:12]
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Recovery runtime tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash,email)
		 VALUES($1,$2,'Recovery runtime user','test-hash','runtime@example.test')`, []any{userID, username}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	config := validAccountRecoveryRuntimeConfig(t)
	sender := &accountRecoveryIntegrationSender{deliveries: make(chan accountrecovery.RecoveryDelivery, 1)}
	bridge := &accountRecoveryIntegrationBridge{sender: sender}
	resolver := func(request *http.Request) (accountrecoveryhttp.TrustedContext, error) {
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-API-Key"} {
			if request.Header.Get(name) != "" {
				t.Errorf("ambient authentication header %s reached trusted resolver", name)
			}
		}
		return accountrecoveryhttp.TrustedContext{
			TenantID: tenantID, ScopeID: scopeID, RequestID: request.Header.Get("X-Request-ID"),
			TraceID: "runtime-trace", SourceIP: "127.0.0.1",
		}, nil
	}
	_, err = openAccountRecoveryRuntime(t.Context(), config, pool, nil, accountRecoveryRuntimeDependencies{
		TrustedContext: resolver, Notifications: bridge,
	})
	if err == nil || err.Error() != "verify account recovery notification configuration" || bridge.dispatcher != nil {
		t.Fatalf("missing notification template did not fail closed before registration: %v", err)
	}
	if err := store.SaveTemplate(t.Context(), notification.TemplateDefinition{
		Ref:     notification.TemplateRef{ID: "account_recovery_email", Version: 1, Channel: notification.ChannelEmail},
		Subject: "Reset your password", Body: "Use the secure recovery link.", Variables: []string{},
	}); err != nil {
		t.Fatal(err)
	}

	secret := "notification-runtime-secret"
	failingBridge := &accountRecoveryIntegrationBridge{
		sender: sender, readyError: errors.New(secret),
	}
	_, err = openAccountRecoveryRuntime(t.Context(), config, pool, nil, accountRecoveryRuntimeDependencies{
		TrustedContext: resolver, Notifications: failingBridge,
	})
	if !errors.Is(err, failingBridge.readyError) || err.Error() != "verify account recovery notification delivery runtime" ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("notification readiness failure was not redacted: %v", err)
	}

	runtime, err := openAccountRecoveryRuntime(t.Context(), config, pool, nil, accountRecoveryRuntimeDependencies{
		TrustedContext: resolver, Notifications: bridge,
	})
	if err != nil {
		t.Fatalf("open account recovery runtime: %v", err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("close account recovery runtime: %v", err)
		}
	})
	if bridge.dispatcher == nil || runtime.Health().State != "ready" {
		t.Fatalf("runtime did not register dispatcher: health=%#v", runtime.Health())
	}

	handler := withAccountRecoveryRoutes(http.NotFoundHandler(), runtime)
	requestBody, _ := json.Marshal(map[string]string{"username": username})
	request := httptest.NewRequest(http.MethodPost, accountRecoveryRequestPath, strings.NewReader(string(requestBody)))
	setAccountRecoveryIntegrationHeaders(request, "runtime-request")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), "account_recovery_request_accepted") {
		t.Fatalf("account recovery request status=%d body=%q", response.Code, response.Body.String())
	}

	worker, err := notification.NewWorkerWithAnonymousDispatcher(
		store, accountRecoveryRejectingMemberSender{}, bridge.dispatcher, notification.DefaultWorkerConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := worker.ProcessBatch(t.Context())
	if err != nil || batch.Succeeded != 1 || batch.Claimed != 1 {
		t.Fatalf("notification batch = (%#v, %v)", batch, err)
	}
	var delivery accountrecovery.RecoveryDelivery
	select {
	case delivery = <-sender.deliveries:
	case <-time.After(time.Second):
		t.Fatal("account recovery delivery was not dispatched")
	}
	parsedRecoveryURL, err := url.Parse(delivery.RecoveryURL)
	if err != nil || parsedRecoveryURL.Scheme != "https" || parsedRecoveryURL.RawQuery != "" || parsedRecoveryURL.Fragment == "" {
		t.Fatal("recovery delivery URL did not preserve fragment-only credentials")
	}
	fragment, err := url.ParseQuery(parsedRecoveryURL.Fragment)
	if err != nil || fragment.Get("token") == "" || fragment.Get("recovery_context") == "" {
		t.Fatal("recovery delivery URL fragment is incomplete")
	}

	confirmationBody, _ := json.Marshal(map[string]string{
		"token": fragment.Get("token"), "recovery_context": fragment.Get("recovery_context"),
		"new_password": "runtime-password-2", "confirm_password": "runtime-password-2",
	})
	confirmation := httptest.NewRequest(
		http.MethodPost, accountRecoveryConfirmationPath, strings.NewReader(string(confirmationBody)),
	)
	setAccountRecoveryIntegrationHeaders(confirmation, "runtime-confirmation")
	confirmationResponse := httptest.NewRecorder()
	handler.ServeHTTP(confirmationResponse, confirmation)
	if confirmationResponse.Code != http.StatusNoContent {
		t.Fatalf("account recovery confirmation status=%d body=%q", confirmationResponse.Code, confirmationResponse.Body.String())
	}

	if err := runtime.Close(); err != nil || !bridge.registration.closed.Load() || runtime.Health().State != "stopped" {
		t.Fatalf("runtime close error=%v health=%#v registration_closed=%v",
			err, runtime.Health(), bridge.registration.closed.Load())
	}
}

func setAccountRecoveryIntegrationHeaders(request *http.Request, idempotencyKey string) {
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("X-Request-ID", idempotencyKey)
	request.Header.Set("Authorization", "Bearer ambient-token")
	request.Header.Set("Proxy-Authorization", "ambient-proxy-token")
	request.Header.Set("Cookie", "cdnca_refresh=ambient-cookie")
	request.Header.Set("X-API-Key", "ambient-api-key")
}

type accountRecoveryIntegrationSender struct {
	deliveries chan accountrecovery.RecoveryDelivery
}

func (sender *accountRecoveryIntegrationSender) SendRecovery(
	_ context.Context,
	delivery accountrecovery.RecoveryDelivery,
) notification.SendResult {
	sender.deliveries <- delivery
	return notification.SendResult{}
}

type accountRecoveryRejectingMemberSender struct{}

func (accountRecoveryRejectingMemberSender) Send(
	context.Context,
	notification.DeliveryAttempt,
) notification.SendResult {
	return notification.SendResult{Failure: &notification.Failure{
		Class: notification.FailurePermanent, Code: "unexpected_member_delivery",
	}}
}

type accountRecoveryIntegrationBridge struct {
	sender       accountrecovery.RecoverySender
	readyError   error
	dispatcher   notification.AnonymousDispatcher
	registration *accountRecoveryIntegrationRegistration
}

func (bridge *accountRecoveryIntegrationBridge) Ready(
	_ context.Context,
	switches notification.ChannelSwitches,
) error {
	if bridge.readyError != nil {
		return bridge.readyError
	}
	if !switches.Email || switches.SMS {
		return errors.New("unexpected notification channel configuration")
	}
	return nil
}

func (bridge *accountRecoveryIntegrationBridge) RecoverySender() accountrecovery.RecoverySender {
	return bridge.sender
}

func (bridge *accountRecoveryIntegrationBridge) RegisterAnonymousDispatcher(
	_ context.Context,
	dispatcher notification.AnonymousDispatcher,
) (accountRecoveryDispatcherRegistration, error) {
	bridge.dispatcher = dispatcher
	bridge.registration = &accountRecoveryIntegrationRegistration{}
	return bridge.registration, nil
}

type accountRecoveryIntegrationRegistration struct {
	closed atomic.Bool
}

func (registration *accountRecoveryIntegrationRegistration) Close(context.Context) error {
	registration.closed.Store(true)
	return nil
}
