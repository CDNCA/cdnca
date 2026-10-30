package plugininstallation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The pending sync and the controller confirmation (license migration 076): signed requests whose canonical
// bytes match licensing.CanonicalPluginInstallationControllerConfirmRequest, pending rows only from the pending
// sync, and stable license failures mapped to the existing errors.
func TestActivationClientPendingSyncAndControllerConfirm(t *testing.T) {
	now := time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)
	installationPublic, installationPrivate, _ := ed25519.GenerateKey(rand.Reader)
	licensePublic, licensePrivate, _ := ed25519.GenerateKey(rand.Reader)
	tenantID, installationID := uuid.New(), uuid.New()
	authorizationID := uuid.MustParse("01a14444-0000-7000-8000-000000000001")
	verificationID := uuid.MustParse("01a14444-0000-7000-8000-000000000002")
	userID := uuid.MustParse("01a14444-0000-7000-8000-000000000003")
	rowStatus, confirmCode := StatusPendingConfirmation, ""
	var confirmBody []byte
	doer := activationDoerFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		var envelope struct {
			Schema string `json:"schema"`
		}
		_ = json.Unmarshal(body, &envelope)
		var responseBody []byte
		switch envelope.Schema {
		case pendingSyncRequestSchema, candidateSyncRequestSchema:
			var wire candidateSyncRequestWire
			if json.Unmarshal(body, &wire) != nil {
				t.Fatalf("pending request=%s", body)
			}
			canonical, _ := json.Marshal(wire.candidateSyncRequestPayload)
			proof, _ := base64.RawURLEncoding.DecodeString(wire.Proof)
			if !ed25519.Verify(installationPublic, framed(candidateSyncRequestDomain, canonical), proof) {
				t.Fatal("pending request proof invalid")
			}
			requestDigest := sha256.Sum256(framed("cdnca-plugin-installation-candidate-sync-idempotency/v1",
				append(canonical, proof...)))
			batch := candidateSyncBatchWire{Schema: candidateSyncBatchSchema, RequestID: wire.RequestID,
				RequestDigest: hex.EncodeToString(requestDigest[:]), CustomerID: uuid.New(), InstallationID: installationID,
				Candidates: []candidateSyncCandidateWire{{AuthorizationID: authorizationID,
					VerificationID: verificationID, PluginID: "acme.market", PluginVersion: "1.0.0", ResourceScope: "tenant", EntrypointType: "external_https",
					ManifestSHA256: digest("a"), ConfigurationSchemaSHA256: digest("b"),
					ManifestScopes: []string{"plugin.read"}, ApprovedScopes: []string{"plugin.read"},
					SensitiveScopes: []string{"plugin.read"}, NewScopes: []string{}, Status: rowStatus, Revision: 1,
					UpdatedAt: now}}, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Algorithm: "Ed25519",
				KeyID: "license-plugin-key-1"}
			unsigned, _ := json.Marshal(batch)
			batch.Signature = base64.RawURLEncoding.EncodeToString(
				ed25519.Sign(licensePrivate, framed(candidateSyncBatchDomain, unsigned)))
			responseBody, _ = json.Marshal(batch)
		case controllerConfirmRequestSchema:
			confirmBody = body
			if confirmCode != "" {
				return &http.Response{StatusCode: http.StatusConflict, Body: io.NopCloser(bytes.NewReader(
					[]byte(`{"code":"` + confirmCode + `","request_id":"r-1"}`)))}, nil
			}
			var wire controllerConfirmRequestWire
			_ = json.Unmarshal(body, &wire)
			responseBody, _ = json.Marshal(controllerConfirmResultWire{Schema: controllerConfirmResultSchema,
				RequestID: wire.RequestID, InstallationID: installationID, AuthorizationID: authorizationID,
				VerificationID: verificationID, Status: "authorized", Revision: 2, ControllerUserID: userID,
				ControllerUsername: "ctl-admin", ConfirmedAt: now})
		default:
			t.Fatalf("unexpected schema %q", envelope.Schema)
		}
		return &http.Response{StatusCode: http.StatusOK,
			Body: io.NopCloser(bytes.NewReader(append(responseBody, '\n')))}, nil
	})
	client, err := NewActivationClient(ActivationClientConfig{BaseURL: "https://license.example", HTTP: doer,
		InstallationID: installationID, PrivateKey: installationPrivate,
		Trust: activationTrustForTest{keyID: "license-plugin-key-1", public: licensePublic},
		Now:   func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.DiscoverPending(context.Background(), CandidateDiscoveryRequest{RequestID: "pending-1",
		TenantID: tenantID, Limit: 100})
	if err != nil || len(page.Items) != 1 || page.Items[0].AuthorizationStatus != StatusPendingConfirmation ||
		page.Items[0].Installation.Status != StatusPendingConfirmation || page.Items[0].Installation.Revision != 1 {
		t.Fatalf("pending page=%+v err=%v", page, err)
	}
	// A pending row in the regular sync, or a regular row in the pending sync, is a protocol violation.
	if _, err := client.Discover(context.Background(), CandidateDiscoveryRequest{RequestID: "candidate-1",
		TenantID: tenantID, Limit: 100}); err == nil {
		t.Fatal("regular sync accepted a pending row")
	}

	request := PendingConfirmRequest{RequestID: "confirm-1", IdempotencyKey: "confirm-1", AuthorizationID: authorizationID,
		VerificationID: verificationID, ExpectedRevision: 1, ApprovedScopes: []string{"plugin.read"},
		SensitivePermissionsConfirmed: true, UserID: userID, Username: "ctl-admin"}
	result, err := client.ConfirmPending(context.Background(), request)
	if err != nil || result.Revision != 2 || result.AuthorizationID != authorizationID {
		t.Fatalf("confirm=%+v err=%v", result, err)
	}
	var wire controllerConfirmRequestWire
	if err := json.Unmarshal(confirmBody, &wire); err != nil {
		t.Fatal(err)
	}
	canonical, _ := json.Marshal(wire.controllerConfirmRequestPayload)
	// Byte-for-byte what license-service re-encodes (licensing.CanonicalPluginInstallationControllerConfirmRequest).
	want := `{"schema":"cdnca.plugin-installation-controller-confirm-request/v1","request_id":"confirm-1",` +
		`"idempotency_key":"confirm-1","installation_id":"` + installationID.String() + `",` +
		`"authorization_id":"01a14444-0000-7000-8000-000000000001","verification_id":"01a14444-0000-7000-8000-000000000002",` +
		`"expected_revision":1,"approved_scopes":["plugin.read"],"sensitive_permissions_confirmed":true,` +
		`"new_permissions_confirmed":false,"controller_user_id":"01a14444-0000-7000-8000-000000000003",` +
		`"controller_username":"ctl-admin","requested_at":"2032-04-05T06:07:08Z"}`
	if string(canonical) != want {
		t.Fatalf("canonical confirm request:\n got %s\nwant %s", canonical, want)
	}
	proof, _ := base64.RawURLEncoding.DecodeString(wire.Proof)
	if !ed25519.Verify(installationPublic, framed(controllerConfirmRequestDomain, canonical), proof) {
		t.Fatal("confirm proof invalid")
	}
	for code, want := range map[string]error{"controller_confirmation_unavailable": ErrFactDenied,
		"scope_approval_required": ErrConsentRequired, "lifecycle_stale": ErrRevisionConflict} {
		confirmCode = code
		if _, err := client.ConfirmPending(context.Background(), request); !errors.Is(err, want) {
			t.Fatalf("%s err=%v want %v", code, err, want)
		}
	}
	confirmCode, rowStatus = "", "authorized"
	if _, err := client.DiscoverPending(context.Background(), CandidateDiscoveryRequest{RequestID: "pending-2",
		TenantID: tenantID, Limit: 100}); err == nil {
		t.Fatal("pending sync accepted a regular row")
	}
	if _, err := client.ConfirmPending(context.Background(), PendingConfirmRequest{RequestID: "confirm-2",
		IdempotencyKey: "confirm-2", AuthorizationID: authorizationID, VerificationID: verificationID,
		ExpectedRevision: 1, ApprovedScopes: []string{"plugin.read"}, UserID: userID}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("confirm without username err=%v", err)
	}
}
