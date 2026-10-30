package mfahttp

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/google/uuid"
)

// An omitted tenant_id requests a platform-scoped proof; the service decides
// whether the session may hold one.
func TestCreateStepUpWithoutTenantRequestsPlatformScope(t *testing.T) {
	var got mfa.StepUpRequest
	handler := testHandler(t, &serviceStub{create: func(_ context.Context, _ mfa.Actor,
		request mfa.StepUpRequest) (mfa.StepUpResult, error) {
		got = request
		return mfa.StepUpResult{ProofID: uuid.New(), Token: "PLATFORM-PROOF", Method: mfa.MethodTOTP, MaxUses: 1,
			IssuedAt: time.Unix(1, 0), ExpiresAt: time.Unix(301, 0)}, nil
	}}, testSession())
	body := `{"audience":"migrate-import","action":"migrate_import.job.confirm",` +
		`"authentication":{"method":"totp","code":"123456"},"ttl_seconds":300,"max_uses":1}`
	response := serve(t, handler, http.MethodPost, apiPrefix+"/step-up-proofs", body, nil)
	assertStatus(t, response, http.StatusCreated)
	if !got.PlatformScope || got.TenantID != uuid.Nil {
		t.Fatalf("request = %+v, want platform scope without tenant", got)
	}

	bad := `{"tenant_id":"","audience":"x","action":"y","authentication":{"method":"totp","code":"123456"},` +
		`"ttl_seconds":0,"max_uses":1}`
	assertAPIError(t, serve(t, handler, http.MethodPost, apiPrefix+"/step-up-proofs", bad, nil),
		http.StatusBadRequest, "mfa_invalid_request")
}
