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

// PLUG-CLIENT-CLOCK-01：签名响应须用收完响应后的时刻验收（IssuedAt 未来性、ExpiresAt、信任验签），
// 请求载荷/proof/digest 仍用发送前的 requestedAt。

type receiveClockCase struct {
	name     string
	issued   time.Duration // 签发时刻相对发送时刻
	received time.Duration // 收完响应时刻相对发送时刻
	tamper   bool
	// duringBody 为真时，时钟在读取响应 body 到 EOF 时才推进到 received（模拟读 body 期间跨秒）。
	duringBody bool
	wantErr    error
}

func receiveClockCases() []receiveClockCase {
	return []receiveClockCase{
		{name: "same_second_positive"},
		{name: "valid_response_crosses_second", issued: time.Second, received: time.Second},
		{name: "body_read_crosses_second", issued: time.Second, received: time.Second, duringBody: true},
		{name: "actually_future_rejected", issued: 2 * time.Second, received: time.Second, wantErr: ErrActivationInvalid},
		{name: "expires_at_exact_boundary_rejected", received: 60 * time.Second, wantErr: ErrActivationInvalid},
		{name: "last_valid_second_accepted", received: 59 * time.Second},
		{name: "expired_at_receipt_rejected", received: 61 * time.Second, wantErr: ErrActivationInvalid},
		{name: "tamper_rejected", tamper: true, wantErr: ErrActivationInvalid},
	}
}

// receiveClock 是可注入时钟：发送前为 started，响应返回（或 body 读完）后为 started+received。
type receiveClock struct{ current time.Time }

func (clock *receiveClock) now() time.Time { return clock.current }

// eofClockBody 在 body 读到 EOF 时推进时钟。
type eofClockBody struct {
	reader  io.Reader
	advance func()
}

func (body *eofClockBody) Read(buffer []byte) (int, error) {
	count, err := body.reader.Read(buffer)
	if errors.Is(err, io.EOF) && body.advance != nil {
		body.advance()
		body.advance = nil
	}
	return count, err
}

func (*eofClockBody) Close() error { return nil }

func receiveClockResponse(clock *receiveClock, at time.Time, duringBody bool, payload []byte) *http.Response {
	body := &eofClockBody{reader: bytes.NewReader(append(payload, '\n'))}
	if duringBody {
		body.advance = func() { clock.current = at }
	} else {
		clock.current = at
	}
	return &http.Response{StatusCode: http.StatusOK, Body: body}
}

// recordingTrust 记录每次 VerifyDetached 收到的验收时刻。
type recordingTrust struct {
	activationTrustForTest
	verifiedAt []time.Time
}

func (trust *recordingTrust) VerifyDetached(keyID string, payload, signature []byte, issuedAt, now time.Time) error {
	trust.verifiedAt = append(trust.verifiedAt, now)
	return trust.activationTrustForTest.VerifyDetached(keyID, payload, signature, issuedAt, now)
}

func assertReceiveClock(t *testing.T, tc receiveClockCase, err error, trust *recordingTrust, received time.Time) {
	t.Helper()
	if !errors.Is(err, tc.wantErr) {
		t.Fatalf("receive-time validation err=%v want=%v", err, tc.wantErr)
	}
	if tc.wantErr != nil && err != nil && !errors.Is(err, ErrActivationInvalid) {
		t.Fatalf("validation failure must stay ErrActivationInvalid: %v", err)
	}
	for _, at := range trust.verifiedAt {
		if !at.Equal(received) {
			t.Fatalf("trust verified at %s, want receive time %s", at, received)
		}
	}
	if tc.wantErr == nil && len(trust.verifiedAt) == 0 {
		t.Fatal("accepted response without trust verification")
	}
}

func TestCandidateSyncUsesReceiveClock(t *testing.T) { candidateSyncReceiveClock(t, false) }

func TestPendingSyncUsesReceiveClock(t *testing.T) { candidateSyncReceiveClock(t, true) }

func candidateSyncReceiveClock(t *testing.T, pending bool) {
	for _, tc := range receiveClockCases() {
		t.Run(tc.name, func(t *testing.T) {
			started := time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)
			received := started.Add(tc.received)
			clock := &receiveClock{current: started}
			_, installationPrivate, _ := ed25519.GenerateKey(rand.Reader)
			licensePublic, licensePrivate, _ := ed25519.GenerateKey(rand.Reader)
			tenantID, installationID := uuid.New(), uuid.New()
			status := "authorized"
			if pending {
				status = StatusPendingConfirmation
			}
			doer := activationDoerFunc(func(request *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}
				var wire candidateSyncRequestWire
				if err := json.Unmarshal(body, &wire); err != nil || !wire.RequestedAt.Equal(started) {
					t.Fatalf("request err=%v requested_at=%v", err, wire.RequestedAt)
				}
				canonical, _ := json.Marshal(wire.candidateSyncRequestPayload)
				proof, _ := base64.RawURLEncoding.DecodeString(wire.Proof)
				requestDigest := sha256.Sum256(framed("cdnca-plugin-installation-candidate-sync-idempotency/v1",
					append(canonical, proof...)))
				issued := started.Add(tc.issued)
				batch := candidateSyncBatchWire{Schema: candidateSyncBatchSchema, RequestID: wire.RequestID,
					RequestDigest: hex.EncodeToString(requestDigest[:]), CustomerID: uuid.New(), InstallationID: installationID,
					Candidates: []candidateSyncCandidateWire{{AuthorizationID: uuid.New(), VerificationID: uuid.New(),
						PluginID: "acme.example", PluginVersion: "1.2.0", ResourceScope: "tenant", EntrypointType: "external_https",
						ManifestSHA256: digest("a"), ConfigurationSchemaSHA256: digest("b"),
						ManifestScopes: []string{"plugin.read"}, ApprovedScopes: []string{"plugin.read"},
						SensitiveScopes: []string{}, NewScopes: []string{}, Status: status, Revision: 2, UpdatedAt: issued}},
					IssuedAt: issued, ExpiresAt: issued.Add(time.Minute), Algorithm: "Ed25519", KeyID: "license-plugin-key-1"}
				unsigned, _ := json.Marshal(batch)
				batch.Signature = base64.RawURLEncoding.EncodeToString(
					ed25519.Sign(licensePrivate, framed(candidateSyncBatchDomain, unsigned)))
				if tc.tamper {
					batch.Candidates[0].PluginVersion = "1.2.1"
				}
				responseBody, _ := json.Marshal(batch)
				return receiveClockResponse(clock, received, tc.duringBody, responseBody), nil
			})
			trust := &recordingTrust{activationTrustForTest: activationTrustForTest{keyID: "license-plugin-key-1",
				public: licensePublic}}
			client, err := NewActivationClient(ActivationClientConfig{BaseURL: "https://license.example", HTTP: doer,
				InstallationID: installationID, PrivateKey: installationPrivate, Trust: trust, Now: clock.now})
			if err != nil {
				t.Fatal(err)
			}
			input := CandidateDiscoveryRequest{RequestID: "receive-clock-sync", TenantID: tenantID, Limit: 100}
			var page Page
			if pending {
				page, err = client.DiscoverPending(context.Background(), input)
			} else {
				page, err = client.Discover(context.Background(), input)
			}
			assertReceiveClock(t, tc, err, trust, received)
			if err == nil && len(page.Items) != 1 {
				t.Fatalf("accepted page items=%d", len(page.Items))
			}
		})
	}
}

func TestActivationResolveUsesReceiveClock(t *testing.T) {
	for _, tc := range receiveClockCases() {
		t.Run(tc.name, func(t *testing.T) {
			started := time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)
			received := started.Add(tc.received)
			clock := &receiveClock{current: started}
			_, installationPrivate, _ := ed25519.GenerateKey(rand.Reader)
			licensePublic, licensePrivate, _ := ed25519.GenerateKey(rand.Reader)
			installationID, verificationID := uuid.New(), uuid.New()
			doer := activationDoerFunc(func(request *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}
				var requestWire activationRequestWireForTest
				if err := json.Unmarshal(body, &requestWire); err != nil || !requestWire.RequestedAt.Equal(started) {
					t.Fatalf("request err=%v requested_at=%v", err, requestWire.RequestedAt)
				}
				response := signedActivationResponseForTest(t, body, licensePrivate, requestWire)
				var batch activationBatchWireForTest
				if err := json.Unmarshal(response, &batch); err != nil {
					t.Fatal(err)
				}
				batch.IssuedAt = started.Add(tc.issued)
				batch.ExpiresAt = batch.IssuedAt.Add(time.Minute)
				unsignedFacts := make([]activationFactUnsignedForTest, len(batch.Facts))
				for i, fact := range batch.Facts {
					unsignedFacts[i] = activationFactUnsignedForTest{Schema: fact.Schema, Scope: fact.Scope,
						Decision: fact.Decision, StableReasonCode: fact.StableReasonCode}
					factPayload, _ := json.Marshal(activationFactPayloadForTest{activationSharedForTest: batch.activationSharedForTest,
						FactSchema: fact.Schema, Scope: fact.Scope, FactDecision: fact.Decision, FactStableReasonCode: fact.StableReasonCode})
					batch.Facts[i].Signature = base64.RawURLEncoding.EncodeToString(
						ed25519.Sign(licensePrivate, framed(activationFactDomain, factPayload)))
				}
				batchPayload, _ := json.Marshal(activationBatchPayloadForTest{activationSharedForTest: batch.activationSharedForTest,
					Facts: unsignedFacts})
				batch.Signature = base64.RawURLEncoding.EncodeToString(
					ed25519.Sign(licensePrivate, framed(activationBatchDomain, batchPayload)))
				if tc.tamper {
					batch.PluginVersion = "1.2.1"
				}
				response, _ = json.Marshal(batch)
				return receiveClockResponse(clock, received, tc.duringBody, response), nil
			})
			trust := &recordingTrust{activationTrustForTest: activationTrustForTest{keyID: "license-plugin-key-1",
				public: licensePublic}}
			client, err := NewActivationClient(ActivationClientConfig{BaseURL: "https://license.example", HTTP: doer,
				InstallationID: installationID, PrivateKey: installationPrivate, Trust: trust, Now: clock.now})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Resolve(context.Background(), ActivationResolveRequest{RequestID: "receive-clock-resolve",
				IdempotencyKey: "receive-clock-resolve", VerificationID: verificationID,
				Action: ActivationInstall, RequestedScopes: []string{"plugin.read"}})
			assertReceiveClock(t, tc, err, trust, received)
		})
	}
}
