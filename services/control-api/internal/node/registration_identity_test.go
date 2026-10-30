package node

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// fz-x13: input and credential format are rejected before any database work
// (the Service here has no store; reaching it would panic).
func TestRecoverRegisteredIdentityRejectsBeforeStore(t *testing.T) {
	service := &Service{registration: testRegistrationKeys(t)}
	valid := RecoverIdentityRequest{
		Credential:         "nrk1." + strings.Repeat("0", 32) + "." + strings.Repeat("A", 43),
		MachineFingerprint: strings.Repeat("ab", 32), CSRSHA256: strings.Repeat("cd", 32), RequestID: "req-1",
	}
	cases := []struct {
		name   string
		change func(*RecoverIdentityRequest)
		want   error
	}{
		{"fingerprint not hex", func(r *RecoverIdentityRequest) { r.MachineFingerprint = "XYZ" }, ErrInvalidInput},
		{"fingerprint upper case", func(r *RecoverIdentityRequest) { r.MachineFingerprint = strings.Repeat("AB", 32) }, ErrInvalidInput},
		{"csr digest short", func(r *RecoverIdentityRequest) { r.CSRSHA256 = strings.Repeat("cd", 31) }, ErrInvalidInput},
		{"request id missing", func(r *RecoverIdentityRequest) { r.RequestID = "" }, ErrInvalidInput},
		{"credential empty", func(r *RecoverIdentityRequest) { r.Credential = "" }, ErrInvalidRegistrationCredential},
		{"credential one-time token", func(r *RecoverIdentityRequest) { r.Credential = strings.Repeat("A", 43) }, ErrInvalidRegistrationCredential},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.change(&request)
			if _, err := service.RecoverRegisteredIdentity(context.Background(), request); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	if _, err := (&Service{}).RecoverRegisteredIdentity(context.Background(), valid); !errors.Is(err, ErrRegistrationUnavailable) {
		t.Fatalf("unconfigured error = %v", err)
	}
}

// The current-key rule shared by Register and identity recovery: a reset
// (new key ID) or a changed server secret rejects the copied credential.
func TestRegistrationKeyRecordAccepts(t *testing.T) {
	keys := testRegistrationKeys(t)
	scope, keyID := uuid.New(), uuid.New()
	credential := keys.credential(scope, keyID)
	current := registrationKeyRecord{keyID: keyID, digest: credentialDigest(credential), available: true}
	if err := current.accepts(keyID, credential); err != nil {
		t.Fatalf("current credential rejected: %v", err)
	}
	other := keys.credential(scope, uuid.New())
	for name, check := range map[string]error{
		"no key issued":   registrationKeyRecord{}.accepts(keyID, credential),
		"reset key":       current.accepts(uuid.New(), other),
		"digest mismatch": registrationKeyRecord{keyID: keyID, digest: credentialDigest(other), available: true}.accepts(keyID, credential),
	} {
		if !errors.Is(check, ErrInvalidRegistrationCredential) {
			t.Errorf("%s: error = %v", name, check)
		}
	}
}
