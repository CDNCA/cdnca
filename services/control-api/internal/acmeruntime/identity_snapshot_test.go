package acmeruntime

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestValidateIssuanceRequestSnapshotRejectsScopeAsTenant(t *testing.T) {
	tenantID, scopeID, actorID := uuid.New(), uuid.New(), uuid.New()
	raw := []byte(`{"TenantID":"` + scopeID.String() + `","ScopeID":"` + scopeID.String() + `","ActorUserID":"` + actorID.String() + `","OperationID":"op-1","DirectoryURL":"https://ca.example/directory","CertificateKeyRef":"cert-key"}`)
	if _, err := validateIssuanceRequestSnapshot(raw, issuanceSnapshotExpectation{
		TenantID: tenantID, ScopeID: scopeID, ActorUserID: actorID,
		OperationID: "op-1", DirectoryURL: "https://ca.example/directory", CertificateKeyRef: "cert-key",
	}); err == nil {
		t.Fatal("snapshot accepted scope id as tenant id")
	}
}

func TestValidateIssuanceRequestSnapshotRejectsLegacyMissingScope(t *testing.T) {
	tenantID, scopeID, actorID := uuid.New(), uuid.New(), uuid.New()
	raw := []byte(`{"TenantID":"` + tenantID.String() + `","ActorUserID":"` + actorID.String() + `","OperationID":"op-1","DirectoryURL":"https://ca.example/directory","CertificateKeyRef":"cert-key"}`)
	if _, err := validateIssuanceRequestSnapshot(raw, issuanceSnapshotExpectation{
		TenantID: tenantID, ScopeID: scopeID, ActorUserID: actorID,
		OperationID: "op-1", DirectoryURL: "https://ca.example/directory", CertificateKeyRef: "cert-key",
	}); err == nil {
		t.Fatal("legacy snapshot without scope id was accepted")
	}
}

func TestValidateIssuanceRequestSnapshotAcceptsIndependentTenantAndScope(t *testing.T) {
	tenantID, scopeID, actorID := uuid.New(), uuid.New(), uuid.New()
	raw := []byte(`{"TenantID":"` + tenantID.String() + `","ScopeID":"` + scopeID.String() + `","ActorUserID":"` + actorID.String() + `","OperationID":"op-1","DirectoryURL":"https://ca.example/directory","CertificateKeyRef":"cert-key"}`)
	if _, err := validateIssuanceRequestSnapshot(raw, issuanceSnapshotExpectation{
		TenantID: tenantID, ScopeID: scopeID, ActorUserID: actorID,
		OperationID: "op-1", DirectoryURL: "https://ca.example/directory", CertificateKeyRef: "cert-key",
	}); err != nil {
		t.Fatalf("valid independent tenant/scope snapshot rejected: %v", err)
	}
}

func TestBuildRequestValidatesExistingSnapshotBeforeKeySideEffects(t *testing.T) {
	source, err := os.ReadFile("dispatcher.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	start := strings.Index(text, "func (d *Dispatcher) buildRequest")
	if start < 0 {
		t.Fatal("buildRequest is missing")
	}
	validation := strings.Index(text[start:], "validateIssuanceRequestSnapshot(requestSnapshot")
	keySideEffect := strings.Index(text[start:], "d.keys.ensureKey")
	if validation < 0 || keySideEffect < 0 || validation > keySideEffect ||
		!strings.Contains(text[start:], "operation.request_snapshot") {
		t.Fatal("existing operation snapshot is not validated before key side effects")
	}
}
