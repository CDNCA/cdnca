package sitecapture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type repositoryStub struct {
	request UpdateRequest
	digest  [32]byte
	audit   AuditFact
	result  WriteResult
	err     error
}

func (stub *repositoryStub) Get(context.Context, Actor, uuid.UUID, uuid.UUID) (Policy, error) {
	return stub.result.Policy, stub.err
}

func (stub *repositoryStub) CompareAndSwap(_ context.Context, _ Actor, request UpdateRequest, digest [32]byte, audit AuditFact) (WriteResult, error) {
	stub.request, stub.digest, stub.audit = request, digest, audit
	if stub.result.Policy.SiteID == uuid.Nil {
		stub.result.Policy = Policy{ScopeID: request.ScopeID, SiteID: request.SiteID, Revision: request.ExpectedRevision + 1,
			Document: request.Document, EvidenceDigest: hex.EncodeToString(digest[:])}
	}
	return stub.result, stub.err
}

func testActor(scopeID uuid.UUID, permissions ...string) Actor {
	return Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: "tenant", SessionID: uuid.New(), Permissions: permissions}
}

func policyFixture(scopeID, siteID uuid.UUID, revision int64) Policy {
	policy := Policy{ScopeID: scopeID, SiteID: siteID, Revision: revision, Document: PolicyDocument{
		Methods: []string{}, URIPrefixes: []string{}, RequestHeaderAllowlist: []string{}, ResponseHeaderAllowlist: []string{},
		RequestBodyFieldAllowlist: []string{}, ResponseBodyFieldAllowlist: []string{}, MaxValueBytes: 4096, MaxBodyBytes: 64 << 10, MaxEventBytes: 1 << 20,
	}}
	encoded, _ := json.Marshal(policy.Document)
	digest := sha256.Sum256(encoded)
	policy.EvidenceDigest = hex.EncodeToString(digest[:])
	return policy
}

func TestUpdateCanonicalizesPolicyAndBindsAtomicAudit(t *testing.T) {
	scopeID, siteID := uuid.New(), uuid.New()
	repository := &repositoryStub{}
	service, _ := NewService(repository)
	request := UpdateRequest{
		ScopeID: scopeID, SiteID: siteID, ExpectedRevision: 3, IdempotencyKey: "capture-3", RequestID: "request-3", TraceID: "trace-3",
		Document: PolicyDocument{Enabled: true, Methods: []string{"post", "GET", "GET"}, URIPrefixes: []string{"/checkout", "/api"},
			RequestHeaderAllowlist: []string{"authorization", "X-Request-ID"}, RequestBodyFieldAllowlist: []string{"password", "profile"}},
	}
	if _, err := service.Update(t.Context(), testActor(scopeID, PermissionManage), request); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(repository.request.Document.Methods, []string{"GET", "POST"}) ||
		!reflect.DeepEqual(repository.request.Document.URIPrefixes, []string{"/api", "/checkout"}) ||
		!reflect.DeepEqual(repository.request.Document.RequestHeaderAllowlist, []string{"Authorization", "X-Request-Id"}) {
		t.Fatalf("canonical document=%+v", repository.request.Document)
	}
	if repository.digest == ([32]byte{}) || repository.audit.DocumentSHA256 != repository.digest || repository.audit.Action != AuditActionSet ||
		repository.audit.ScopeID != scopeID || repository.audit.SiteID != siteID || repository.audit.ExpectedRevision != 3 {
		t.Fatalf("digest/audit not transaction-bound: %x %+v", repository.digest, repository.audit)
	}
}

func TestUpdateFailsClosedBeforeRepository(t *testing.T) {
	scopeID, siteID := uuid.New(), uuid.New()
	base := UpdateRequest{ScopeID: scopeID, SiteID: siteID, IdempotencyKey: "capture", RequestID: "request", TraceID: "trace"}
	for name, document := range map[string]PolicyDocument{
		"disabled opt in": {Methods: []string{"GET"}},
		"enabled empty":   {Enabled: true},
		"unsafe prefix":   {Enabled: true, URIPrefixes: []string{"/api?key=raw"}, RequestHeaderAllowlist: []string{"X-Safe"}},
		"trace method":    {Enabled: true, Methods: []string{"TRACE"}, RequestHeaderAllowlist: []string{"X-Safe"}},
	} {
		t.Run(name, func(t *testing.T) {
			repository := &repositoryStub{}
			service, _ := NewService(repository)
			request := base
			request.Document = document
			if _, err := service.Update(t.Context(), testActor(scopeID, PermissionManage), request); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error=%v", err)
			}
			if repository.request.SiteID != uuid.Nil {
				t.Fatal("invalid policy reached repository")
			}
		})
	}
}

func TestServiceFencesTenantAndPermission(t *testing.T) {
	scopeID, otherScope, siteID := uuid.New(), uuid.New(), uuid.New()
	repository := &repositoryStub{}
	service, _ := NewService(repository)
	if _, err := service.Get(t.Context(), testActor(scopeID, PermissionRead), otherScope, siteID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant error=%v", err)
	}
	if _, err := service.Get(t.Context(), testActor(scopeID), scopeID, siteID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("permission error=%v", err)
	}
	forged := testActor(scopeID, "platform.admin", PermissionRead)
	if _, err := service.Get(t.Context(), forged, otherScope, siteID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant platform-admin forgery error=%v", err)
	}
}

func TestServiceRejectsRepositoryFactWithWrongIdentityOrEvidence(t *testing.T) {
	scopeID, siteID := uuid.New(), uuid.New()
	policy := policyFixture(scopeID, siteID, 1)
	policy.SiteID = uuid.New()
	repository := &repositoryStub{result: WriteResult{Policy: policy}}
	service, _ := NewService(repository)
	if _, err := service.Get(t.Context(), testActor(scopeID, PermissionRead), scopeID, siteID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("identity error=%v", err)
	}
	policy = policyFixture(scopeID, siteID, 1)
	policy.EvidenceDigest = strings.Repeat("a", 64)
	repository.result.Policy = policy
	if _, err := service.Get(t.Context(), testActor(scopeID, PermissionRead), scopeID, siteID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("evidence error=%v", err)
	}
}
