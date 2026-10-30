package errorpagecontrol

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestRuntimeAPIKeyActorIsValidAndRedacted(t *testing.T) {
	tenantID := uuid.New()
	const credential = "cfk_runtime.secret-material"
	actor := Actor{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
		Credential: CredentialReference{Kind: CredentialKindAPIKey, ID: uuid.New()},
		rawSession: credential, tenantID: &tenantID,
	}
	if err := validateRuntimeActor(actor); err != nil {
		t.Fatalf("validate API-key actor: %v", err)
	}
	for _, encoded := range []string{actor.String(), actor.GoString()} {
		if strings.Contains(encoded, credential) {
			t.Fatalf("API-key actor formatting leaked raw credential: %q", encoded)
		}
	}
}

func TestRuntimeAuthenticatorRecognizesCdncaKeyBeforeDependencyUse(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/error-pages/assets", nil)
	request.Header.Set("Authorization", "CdncaKey cfk_runtime.secret")
	actor, err := (runtimeAuthenticator{}).Authenticate(request)
	if actor != (Actor{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unconfigured CdncaKey authentication = (%+v,%v), want zero actor ErrUnavailable", actor, err)
	}
}

func TestRuntimeAuthorizerUsesCredentialSpecificTransactionalVerification(t *testing.T) {
	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"AuthenticateWithKeyID(request.Context(), rawToken)",
		"AuthorizeSession(ctx, tx, actor.rawSession, targetScopeID, permission)",
		"AuthorizeAPIKey(ctx, tx, actor.rawSession, targetScopeID, permission)",
		"sealed.CredentialKind() != actor.Credential.Kind",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("runtime credential flow is missing %q", required)
		}
	}
}

type credentialAuditCapture struct {
	event audit.Event
}

func (capture *credentialAuditCapture) Append(_ context.Context, _ pgx.Tx, event audit.Event) error {
	capture.event = event
	return nil
}

func TestErrorPageAuditRecordsCredentialReferenceWithoutRawSecret(t *testing.T) {
	capture := &credentialAuditCapture{}
	service := &Service{auditor: capture}
	const rawCredential = "cfk_audit.secret-material"
	actor := Actor{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
		Credential: CredentialReference{Kind: CredentialKindAPIKey, ID: uuid.New()},
		rawSession: rawCredential,
	}
	if err := service.appendAudit(t.Context(), nil, &actor, actor.ScopeID, "error_page.rule.create",
		"error_page_rule", uuid.NewString(), WriteMetadata{RequestID: "api-key-audit", TraceID: "trace"},
		"success", nil); err != nil {
		t.Fatal(err)
	}
	if capture.event.Payload["credential_kind"] != CredentialKindAPIKey ||
		capture.event.Payload["credential_id"] != actor.Credential.ID.String() {
		t.Fatalf("credential audit payload = %#v", capture.event.Payload)
	}
	if strings.Contains(fmt.Sprintf("%#v", capture.event), rawCredential) {
		t.Fatal("audit event retained raw API-key secret")
	}
}
