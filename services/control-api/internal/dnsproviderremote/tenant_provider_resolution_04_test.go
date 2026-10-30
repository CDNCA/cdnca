package dnsproviderremote

import (
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
)

func TestTenantProviderResolution04SignedHandleBindsTenantAndScope(t *testing.T) {
	tenantID := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	scopeID := uuid.MustParse("20000000-0000-4000-8000-000000000001")
	providerID := uuid.MustParse("30000000-0000-4000-8000-000000000001")
	zoneID := uuid.MustParse("40000000-0000-4000-8000-000000000001")
	challenge := acmeworker.ChallengeIdentity{
		TenantID: tenantID, OperationID: uuid.NewString(), AttemptID: uuid.New(),
		ProviderRef: providerID.String(), ChallengeType: acmeworker.ChallengeDNS01,
		RecordName: "_acme-challenge.example.test.", ExactValue: "value",
	}
	setRemoteUUIDField04(t, &challenge, "ScopeID", scopeID)
	setRemoteUUIDField04(t, &challenge, "ProviderID", providerID)
	setRemoteUUIDField04(t, &challenge, "ZoneID", zoneID)
	config := ProviderConfig{
		TenantScopeID: scopeID, ProviderID: providerID, ProviderType: providerCloudflare,
		ZoneID: zoneID, ZoneName: "example.test", Credentials: map[string]string{"api_token": "token"},
	}
	setRemoteUUIDField04(t, &config, "TenantID", tenantID)
	setRemoteUUIDField04(t, &config, "ScopeID", scopeID)
	keyring, err := NewHandleKeyring(HandleKey{ID: "active", Secret: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	handle, err := encodeHandle(challenge, config, recordHandle{
		Provider: providerCloudflare, Zone: "example.test", ZoneID: "remote-zone",
		RecordID: "remote-record", Owner: challenge.RecordName,
	}, keyring)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := decodeHandle(handle.RecordRef, keyring)
	if err != nil {
		t.Fatal(err)
	}
	assertRemoteStringField04(t, payload, "TenantID", tenantID.String())
	assertRemoteStringField04(t, payload, "ScopeID", scopeID.String())

	for _, field := range []string{"TenantID", "ScopeID"} {
		tampered := challenge
		setRemoteUUIDField04(t, &tampered, field, uuid.New())
		if ErrorCodeOf(bindHandlePayload(payload, tampered)) != CodeRecordMismatch {
			t.Fatalf("signed handle accepted tampered %s", field)
		}
	}
}

func setRemoteUUIDField04(t *testing.T, target any, name string, value uuid.UUID) {
	t.Helper()
	field := reflect.ValueOf(target).Elem().FieldByName(name)
	if !field.IsValid() || !field.CanSet() || field.Type() != reflect.TypeOf(uuid.UUID{}) {
		t.Fatalf("%T is missing explicit uuid.UUID field %s", target, name)
	}
	field.Set(reflect.ValueOf(value))
}

func assertRemoteStringField04(t *testing.T, target any, name, want string) {
	t.Helper()
	field := reflect.ValueOf(target).FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.String || field.String() != want {
		t.Fatalf("handle payload %s = %q, want %q", name, field.String(), want)
	}
}
