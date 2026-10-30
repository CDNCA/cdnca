package sitecapture

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestPostgresStoreRequiresDatabase(t *testing.T) {
	if _, err := NewPostgresStore(nil, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewPostgresStore nil dependencies error=%v", err)
	}
}

func TestPostgresStoreRejectsNonCanonicalPolicyAndAuditForgery(t *testing.T) {
	scopeID, siteID := uuid.New(), uuid.New()
	actor := testActor(scopeID, PermissionManage)
	document := PolicyDocument{
		Enabled: true, Methods: []string{"GET"}, URIPrefixes: []string{"/api"},
		RequestHeaderAllowlist: []string{"Authorization"}, RequestBodyFieldAllowlist: []string{},
		ResponseHeaderAllowlist: []string{}, ResponseBodyFieldAllowlist: []string{},
		MaxValueBytes: 4096, MaxBodyBytes: 64 << 10, MaxEventBytes: 1 << 20,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	request := UpdateRequest{ScopeID: scopeID, SiteID: siteID, ExpectedRevision: 2,
		IdempotencyKey: "capture-2", RequestID: "request-2", TraceID: "trace-2", Document: document}
	audit := AuditFact{Action: AuditActionSet, ActorUserID: actor.UserID, ScopeID: scopeID, SiteID: siteID,
		ExpectedRevision: 2, RequestID: request.RequestID, TraceID: request.TraceID, DocumentSHA256: digest}
	if err := validateStoreWrite(actor, request, digest, audit); err != nil {
		t.Fatalf("valid write rejected: %v", err)
	}

	nonCanonical := request
	nonCanonical.Document.Methods = []string{"get", "GET"}
	nonCanonicalBytes, _ := json.Marshal(nonCanonical.Document)
	nonCanonicalDigest := sha256.Sum256(nonCanonicalBytes)
	nonCanonicalAudit := audit
	nonCanonicalAudit.DocumentSHA256 = nonCanonicalDigest
	if err := validateStoreWrite(actor, nonCanonical, nonCanonicalDigest, nonCanonicalAudit); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("non-canonical document error=%v", err)
	}

	for name, mutate := range map[string]func(*AuditFact){
		"action":            func(value *AuditFact) { value.Action = "site.capture_policy.forged" },
		"actor":             func(value *AuditFact) { value.ActorUserID = uuid.New() },
		"scope":             func(value *AuditFact) { value.ScopeID = uuid.New() },
		"site":              func(value *AuditFact) { value.SiteID = uuid.New() },
		"revision":          func(value *AuditFact) { value.ExpectedRevision++ },
		"request":           func(value *AuditFact) { value.RequestID = "forged" },
		"trace":             func(value *AuditFact) { value.TraceID = "forged" },
		"document evidence": func(value *AuditFact) { value.DocumentSHA256 = sha256.Sum256([]byte("forged")) },
	} {
		t.Run(name, func(t *testing.T) {
			forged := audit
			mutate(&forged)
			if err := validateStoreWrite(actor, request, digest, forged); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("forged audit error=%v", err)
			}
		})
	}
}

func TestPostgresStoreSQLAuthorityContract(t *testing.T) {
	content, err := os.ReadFile("store_postgres.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	for _, required := range []string{
		"protocol.AcquireShared",
		"protocol.AcquireScopes",
		"FROM auth_sessions",
		"session.revoked_at",
		"session.expires_at",
		"JOIN users",
		"user_row.status",
		`userStatus != "active"`,
		"JOIN memberships",
		"membership.status",
		`membershipStatus != "active"`,
		"FROM role_assignments",
		"JOIN role_permissions",
		"platform.admin",
		"PermissionRead",
		"PermissionManage",
		"site.owner_user_id",
		"site_capture_policy_receipts",
		"site_capture_policy_revisions",
		"site_capture_policy_heads",
		"canonicalDocument",
		"subtle.ConstantTimeCompare",
		"store.auditor.Append",
		"ScopeID: request.ScopeID",
		"pgx.BeginFunc",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("Postgres store missing authority marker %q", required)
		}
	}
	if strings.Contains(source, "actor.Permissions") {
		t.Fatal("Postgres store must not trust caller-provided permissions")
	}
}
