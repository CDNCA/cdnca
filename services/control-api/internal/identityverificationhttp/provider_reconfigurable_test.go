package identityverificationhttp

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// reconfigurableProviderStub is a KYC provider whose configuration comes from
// the system settings page: no name until configured, EnsureCredentials
// answers "not configured" until then.
type reconfigurableProviderStub struct{ name string }

func (stub *reconfigurableProviderStub) Configured() bool { return true }
func (stub *reconfigurableProviderStub) Name() string     { return stub.name }
func (stub *reconfigurableProviderStub) Close()           {}
func (stub *reconfigurableProviderStub) EnsureCredentials(context.Context) error {
	if stub.name == "" {
		return ErrProviderNotConfigured
	}
	return nil
}
func (stub *reconfigurableProviderStub) CreateSession(context.Context, ProviderSessionCreate) (ProviderSessionCreated, error) {
	return ProviderSessionCreated{}, ErrProviderNotConfigured
}
func (stub *reconfigurableProviderStub) VerifyCallback(context.Context, ProviderCallbackEnvelope) (VerifiedProviderCallback, error) {
	return VerifiedProviderCallback{}, ErrProviderNotConfigured
}

// reconfigurableObjectsStub is a private object store whose KMS key ID comes
// from the page ("" until configured).
type reconfigurableObjectsStub struct{ keyID string }

func (stub *reconfigurableObjectsStub) Configured() bool { return true }
func (stub *reconfigurableObjectsStub) EncryptionKeyID(context.Context) (string, error) {
	if stub.keyID == "" {
		return "", ErrProviderNotConfigured
	}
	return stub.keyID, nil
}
func (stub *reconfigurableObjectsStub) PresignPut(context.Context, PrivateObjectPresignRequest) (PrivateObjectPresignResult, error) {
	return PrivateObjectPresignResult{}, ErrProviderNotConfigured
}
func (stub *reconfigurableObjectsStub) Stat(context.Context, string) (PrivateObjectReference, error) {
	return PrivateObjectReference{}, ErrProviderNotConfigured
}
func (stub *reconfigurableObjectsStub) Delete(context.Context, PrivateObjectReference) (PrivateObjectDeleteReceipt, error) {
	return PrivateObjectDeleteReceipt{}, ErrProviderNotConfigured
}

type allowProviderWrites struct{}

func (allowProviderWrites) AuthorizeProviderWrite(context.Context, pgx.Tx, identityverification.Actor) error {
	return nil
}

type discardAudit struct{}

func (discardAudit) Append(context.Context, pgx.Tx, audit.Event) error { return nil }

// With the KYC provider configured on the system settings
// page the provider workflow is mounted before any configuration exists; the
// identity verification entries then answer 503
// identity_verification_not_configured instead of a validation error, and no
// database work happens.
func TestReconfigurableProviderWorkflowAnswersNotConfigured(t *testing.T) {
	// never connected: every call below must refuse before touching it
	pool, err := pgxpool.New(t.Context(), "postgres://unused@127.0.0.1:1/unused?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	provider, objects := &reconfigurableProviderStub{}, &reconfigurableObjectsStub{}
	workflow, err := NewProviderWorkflow(pool, discardAudit{}, allowProviderWrites{}, objects, provider, ProviderWorkflowConfig{
		TokenKey: make([]byte, 32), ResolverName: "trusted-kyc"})
	if err != nil {
		t.Fatalf("mount without a provider name or KMS key ID: %v", err)
	}
	if !workflow.Configured() {
		t.Fatal("reconfigurable workflow reports unconfigured")
	}
	actor := testActor()
	_, err = workflow.StartSession(t.Context(), actor, StartProviderSessionRequest{Kind: "personal_initial", Provider: "trusted-kyc",
		IdempotencyKey: "idem-1", RequestID: "request-1"})
	if !errors.Is(err, ErrProviderNotConfigured) {
		t.Fatalf("start session err=%v", err)
	}
	if status, code, _ := providerPublicError(err); status != http.StatusServiceUnavailable || code != "identity_verification_not_configured" {
		t.Fatalf("public error = %d %s", status, code)
	}
	_, err = workflow.CreateUpload(t.Context(), actor, CreateProviderUploadRequest{SessionID: uuid.New(),
		MaterialKind: identityverification.MaterialIdentityDocument, ContentType: "image/png", SizeBytes: 10,
		SHA256: sha256.Sum256([]byte("x")), IdempotencyKey: "idem-2", RequestID: "request-2"})
	if !errors.Is(err, ErrProviderNotConfigured) {
		t.Fatalf("create upload err=%v", err)
	}
	if _, err := workflow.ApplyCallback(t.Context(), ProviderCallbackEnvelope{Provider: "trusted-kyc", Body: []byte("{}"), Header: http.Header{}}); !errors.Is(err, ErrProviderNotConfigured) {
		t.Fatalf("callback err=%v", err)
	}

	// configured on the page: the name check applies again (a wrong
	// provider name is a validation error, not "not configured")
	provider.name, objects.keyID = "trusted-kyc", "kms-key-1"
	if _, err := workflow.StartSession(t.Context(), actor, StartProviderSessionRequest{Kind: "personal_initial", Provider: "other-kyc",
		IdempotencyKey: "idem-3", RequestID: "request-3"}); !errors.Is(err, ErrProviderInvalid) {
		t.Fatalf("wrong provider err=%v", err)
	}
	if _, err := workflow.ApplyCallback(t.Context(), ProviderCallbackEnvelope{Provider: "other-kyc", Body: []byte("{}"), Header: http.Header{}}); !errors.Is(err, ErrProviderCallbackAuth) {
		t.Fatalf("wrong callback provider err=%v", err)
	}
}

// A provider without that runtime hook keeps the static checks: a provider
// name and an encryption key ID are required to mount.
func TestStaticProviderWorkflowStillNeedsNameAndKeyID(t *testing.T) {
	pool, err := pgxpool.New(t.Context(), "postgres://unused@127.0.0.1:1/unused?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	provider, err := NewHTTPSKYCProvider(HTTPSKYCProviderConfig{Name: "trusted-kyc", Endpoint: "https://kyc.example.test",
		CallbackKeyID: "callback-key-1", CallbackMaxAge: time.Minute}, http.DefaultClient, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if _, err := NewProviderWorkflow(pool, discardAudit{}, allowProviderWrites{}, staticObjectsStub{}, provider, ProviderWorkflowConfig{
		TokenKey: make([]byte, 32), ResolverName: "trusted-kyc"}); !errors.Is(err, ErrInvalidService) {
		t.Fatalf("static store without a key ID mounted: %v", err)
	}
}

type staticObjectsStub struct{}

func (staticObjectsStub) Configured() bool { return true }
func (staticObjectsStub) PresignPut(context.Context, PrivateObjectPresignRequest) (PrivateObjectPresignResult, error) {
	return PrivateObjectPresignResult{}, ErrProviderObjectUnavailable
}
func (staticObjectsStub) Stat(context.Context, string) (PrivateObjectReference, error) {
	return PrivateObjectReference{}, ErrProviderObjectUnavailable
}
func (staticObjectsStub) Delete(context.Context, PrivateObjectReference) (PrivateObjectDeleteReceipt, error) {
	return PrivateObjectDeleteReceipt{}, ErrProviderObjectUnavailable
}
