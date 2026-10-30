package dnsacme

import (
	"bytes"
	"os"
	"testing"
)

func TestProviderCredentialProductionPathsRequireBoundCipher(t *testing.T) {
	service, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("EncryptCredential(binding, credentialJSON)"),
		[]byte("EncryptCredential(target.binding(), credentialJSON)"),
		[]byte("DecryptCredential(CredentialBinding{"),
	} {
		if !bytes.Contains(service, required) {
			t.Fatalf("service is missing bound credential path %q", required)
		}
	}
	if !bytes.Contains(store, []byte("scope.tenant_id")) ||
		!bytes.Contains(store, []byte("scope.tenant_id=$8")) {
		t.Fatal("store does not transactionally fence credential tenant authority")
	}
}
