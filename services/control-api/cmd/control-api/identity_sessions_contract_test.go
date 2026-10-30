package main

import (
	"bytes"
	"os"
	"testing"
)

func TestIAM12CanonicalControlContractAggregatesIdentitySessions(t *testing.T) {
	root, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := os.ReadFile("../../../../api/control-identity-sessions.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("  /v1/identity/sessions:\n    $ref: '../../control-identity-sessions.openapi.yaml#/paths/~1v1~1identity~1sessions'"),
		[]byte("  /v1/identity/session-families/{family_id}:\n    $ref: '../../control-identity-sessions.openapi.yaml#/paths/~1v1~1identity~1session-families~1{family_id}'"),
	} {
		if !bytes.Contains(root, required) {
			t.Fatalf("canonical control contract missing %q", required)
		}
	}
	for _, required := range [][]byte{
		[]byte("operationId: listCurrentIdentitySessionFamilies"),
		[]byte("operationId: revokeCurrentIdentitySessionFamily"),
		[]byte("x-required-permissions: []"),
	} {
		if !bytes.Contains(fragment, required) {
			t.Fatalf("identity session fragment missing %q", required)
		}
	}
}
