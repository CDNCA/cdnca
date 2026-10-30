package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type httpManagedPasswordResetStepUp struct {
	err   error
	calls int
}

func (consumer *httpManagedPasswordResetStepUp) BeginManagedPasswordResetAuthorityMutation(
	ctx context.Context,
	tx pgx.Tx,
	scopes []uuid.UUID,
) ([]uuid.UUID, error) {
	return iamstage2b.BeginAuthorityMutation(ctx, tx, iamstage2b.OperationMFAConsumeStepUp, scopes)
}

func (consumer *httpManagedPasswordResetStepUp) ConsumeManagedPasswordResetStepUp(
	_ context.Context,
	tx pgx.Tx,
	actor identity.ManagedPasswordResetStepUpActor,
	_ []uuid.UUID,
	request identity.ManagedPasswordResetStepUpRequest,
) (identity.ManagedPasswordResetStepUpEvidence, error) {
	consumer.calls++
	if tx == nil {
		return identity.ManagedPasswordResetStepUpEvidence{}, identity.ErrManagedPasswordResetUnavailable
	}
	if consumer.err != nil {
		return identity.ManagedPasswordResetStepUpEvidence{}, consumer.err
	}
	return identity.ManagedPasswordResetStepUpEvidence{
		ProofID: uuid.New(), ActorUserID: actor.UserID, ActorScopeID: actor.ScopeID,
		SessionID: actor.SessionID, TenantID: request.TenantID, Method: "totp",
		Audience: request.Audience, Action: request.Action, VerifiedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Minute), UseOrdinal: 1,
		ResourceBindingDigest: append([]byte(nil), request.ResourceBindingDigest...),
	}, nil
}

func TestManagedPasswordResetHTTPUsesBearerStepUpAndExactTenantTarget(t *testing.T) {
	pool := isolatedTestPool(t)
	adminHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	if _, err := store.BootstrapPlatformUser(t.Context(), "reset-admin", "Reset Admin", adminHash,
		"reset-admin-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("identity-managed-password-reset-http-secret", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	stepUp := &httpManagedPasswordResetStepUp{}
	service.SetManagedPasswordResetStepUpConsumer(stepUp)
	server := httptest.NewServer(New(pool, service, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CookieSecure: false}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	admin, _ := loginWithPassword(t, client, server.URL, "reset-admin", testPassword)
	target := createManagedUser(t, client, server.URL, admin.AccessToken, "create-reset-target", map[string]any{
		"username": "reset-target", "password": tenantPassword, "display_name": "Reset Target",
		"email": nil, "phone": nil, "role": identity.UserRoleOwner,
	})
	body := map[string]any{
		"expected_revision": target.Revision,
		"password_reset": map[string]any{
			"tenant_scope_id": target.ScopeID.String(), "new_password": newTenantPassword,
			"step_up_token": "opaque-http-reset-proof",
		},
	}

	stepUp.err = identity.ErrManagedPasswordResetStepUpRequired
	response := identityRequest(t, client, http.MethodPatch, server.URL+"/v1/admin/users/"+target.ID.String(),
		body, admin.AccessToken, "reset-target-password-denied", "reset-target-password-denied-request")
	assertError(t, response, http.StatusPreconditionRequired, "mfa_step_up_required", "reset-target-password-denied-request")
	response.Body.Close()

	stepUp.err = nil
	response = identityRequest(t, client, http.MethodPatch, server.URL+"/v1/admin/users/"+target.ID.String(),
		body, admin.AccessToken, "reset-target-password", "reset-target-password-request")
	var updated identity.ManagedUser
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	if updated.ID != target.ID || updated.ScopeID != target.ScopeID || updated.TenantID == nil || target.TenantID == nil || *updated.TenantID != *target.TenantID ||
		updated.Revision != target.Revision+1 || stepUp.calls != 2 {
		t.Fatalf("reset response=%#v step-up calls=%d", updated, stepUp.calls)
	}

	wrongScope := cloneBody(body)
	wrongScope["password_reset"] = map[string]any{
		"tenant_scope_id": uuid.NewString(), "new_password": "another-password-long-enough",
		"step_up_token": "other-proof",
	}
	response = identityRequest(t, client, http.MethodPatch, server.URL+"/v1/admin/users/"+target.ID.String(),
		wrongScope, admin.AccessToken, "reset-target-wrong-scope", "reset-target-wrong-scope-request")
	assertError(t, response, http.StatusNotFound, "user_not_found", "reset-target-wrong-scope-request")
	response.Body.Close()

	mixed := cloneBody(body)
	mixed["display_name"] = "must not mix modes"
	response = identityRequest(t, client, http.MethodPatch, server.URL+"/v1/admin/users/"+target.ID.String(),
		mixed, admin.AccessToken, "reset-target-mixed", "reset-target-mixed-request")
	assertError(t, response, http.StatusBadRequest, "validation_error", "reset-target-mixed-request")
	response.Body.Close()
}
