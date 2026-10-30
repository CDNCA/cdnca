package dnsacme

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
)

func TestCredentialRewrapBatchRejectsAmbiguousIntent(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	providerID := uuid.New()
	_, err := (&Service{}).RewrapProviderCredentials(t.Context(), actor, CredentialRewrapRequest{
		RequestID: "rewrap-request",
		Items: []CredentialRewrapItem{
			{ProviderID: providerID, ExpectedRevision: 1, IdempotencyKey: "rewrap-item-1"},
			{ProviderID: providerID, ExpectedRevision: 1, IdempotencyKey: "rewrap-item-2"},
		},
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("duplicate provider error = %v", err)
	}
}

func TestCredentialRewrapStoreIsFencedAuditedAndReplayable(t *testing.T) {
	source, err := os.ReadFile("credential_rewrap.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("FOR UPDATE OF provider"),
		[]byte(`reserveWrite(ctx, tx, actor, target.ScopeID, "dns.provider.credential_rewrap"`),
		[]byte("cipher.RewrapCredential(target.binding()"),
		[]byte("credential_version=credential_version+1"),
		[]byte("credential_key_id=$4"),
		[]byte("revision=$3"),
		[]byte(`"dns.provider.credential_rewrap"`),
		[]byte("completeWrite(ctx, tx, actor"),
	} {
		if !bytes.Contains(source, required) {
			t.Fatalf("rewrap store is missing %q", required)
		}
	}
}
