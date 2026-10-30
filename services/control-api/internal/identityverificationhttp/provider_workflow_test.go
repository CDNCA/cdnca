package identityverificationhttp

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
)

func TestIAM10ProviderStateTransitionsAreMonotonic(t *testing.T) {
	tests := []struct {
		current  string
		incoming string
		want     string
		applied  bool
	}{
		{ProviderSessionPending, ProviderSessionProcessing, ProviderSessionProcessing, true},
		{ProviderSessionPending, ProviderSessionSucceeded, ProviderSessionSucceeded, true},
		{ProviderSessionProcessing, ProviderSessionPending, ProviderSessionProcessing, false},
		{ProviderSessionSucceeded, ProviderSessionProcessing, ProviderSessionSucceeded, false},
		{ProviderSessionFailed, ProviderSessionSucceeded, ProviderSessionFailed, false},
		{ProviderSessionCanceled, ProviderSessionExpired, ProviderSessionCanceled, false},
	}
	for _, test := range tests {
		got, applied, err := advanceProviderSessionState(test.current, test.incoming)
		if err != nil || got != test.want || applied != test.applied {
			t.Errorf("advanceProviderSessionState(%q,%q)=(%q,%t,%v), want (%q,%t,nil)",
				test.current, test.incoming, got, applied, err, test.want, test.applied)
		}
	}
	for _, invalid := range [][2]string{{"", ProviderSessionPending}, {ProviderSessionPending, "unknown"},
		{ProviderSessionCreating, ProviderSessionProcessing}} {
		if _, _, err := advanceProviderSessionState(invalid[0], invalid[1]); err == nil {
			t.Errorf("invalid transition %q -> %q was accepted", invalid[0], invalid[1])
		}
	}
}

func TestIAM10ProviderInputsBindActorSessionAndPrivateObjectFacts(t *testing.T) {
	actor := testActor()
	sessionID := uuid.New()
	uploadID := uuid.New()
	digest := sha256.Sum256([]byte("private-material"))
	request := StartProviderSessionRequest{
		Kind: identityverification.KindEnterprise, Provider: "trusted-kyc",
		IdempotencyKey: "provider-session-1", RequestID: "request-provider-session-1",
	}
	if err := validateStartProviderSession(actor, request); err != nil {
		t.Fatal(err)
	}
	upload := CreateProviderUploadRequest{SessionID: sessionID,
		MaterialKind: identityverification.MaterialBusinessLicense,
		ContentType:  "image/jpeg", SizeBytes: 1024, SHA256: digest,
		IdempotencyKey: "provider-upload-1", RequestID: "request-provider-upload-1"}
	if err := validateCreateProviderUpload(actor, upload); err != nil {
		t.Fatal(err)
	}
	key, err := privateProviderObjectKey(actor, sessionID, uploadID)
	if err != nil {
		t.Fatal(err)
	}
	want := "identity-verification/" + actor.ScopeID.String() + "/" + actor.UserID.String() +
		"/" + sessionID.String() + "/" + uploadID.String()
	if key != want {
		t.Fatalf("private object key=%q want %q", key, want)
	}

	invalid := upload
	invalid.ContentType = "text/html"
	if err := validateCreateProviderUpload(actor, invalid); err == nil {
		t.Fatal("unsafe content type was accepted")
	}
	invalid = upload
	invalid.SizeBytes = maximumProviderMaterialBytes + 1
	if err := validateCreateProviderUpload(actor, invalid); err == nil {
		t.Fatal("oversized material was accepted")
	}
	invalid = upload
	invalid.SHA256 = [sha256.Size]byte{}
	if err := validateCreateProviderUpload(actor, invalid); err == nil {
		t.Fatal("zero object digest was accepted")
	}
}

func TestIAM10ProviderCallbackFreshnessAndExactBinding(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	sessionID := uuid.New()
	digest := sha256.Sum256([]byte("normalized-callback"))
	callback := VerifiedProviderCallback{Provider: "trusted-kyc", EventID: "event-1",
		Nonce: "nonce-0000000000000001", SessionID: sessionID, ExternalSessionID: "external-session-1",
		State: ProviderSessionSucceeded, OccurredAt: now.Add(-time.Minute), ReceivedAt: now,
		PayloadSHA256: digest, SignatureSHA256: sha256.Sum256([]byte("signature")),
		VerificationKeyID: "callback-key-1", SubjectFingerprint: sha256.Sum256([]byte("subject"))}
	if err := validateVerifiedProviderCallback(callback, now, 5*time.Minute, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*VerifiedProviderCallback){
		"future":          func(value *VerifiedProviderCallback) { value.OccurredAt = now.Add(time.Minute) },
		"stale":           func(value *VerifiedProviderCallback) { value.OccurredAt = now.Add(-6 * time.Minute) },
		"missing session": func(value *VerifiedProviderCallback) { value.SessionID = uuid.Nil },
		"unknown state":   func(value *VerifiedProviderCallback) { value.State = "unknown" },
		"zero digest":     func(value *VerifiedProviderCallback) { value.PayloadSHA256 = [sha256.Size]byte{} },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := callback
			mutate(&invalid)
			if err := validateVerifiedProviderCallback(invalid, now, 5*time.Minute, 30*time.Second); err == nil {
				t.Fatal("invalid verified callback was accepted")
			}
		})
	}
}
