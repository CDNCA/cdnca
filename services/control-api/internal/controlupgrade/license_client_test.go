package controlupgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
)

func TestLicenseClientCommandGrantExactHeadersProofAndBody(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	installationID := uuid.MustParse("00000000-0000-4000-8000-000000000004")
	profile := CommandProfile{
		Platform: "linux", Architecture: "amd64",
		Compatibility: entitlement.UpgradeExecutionCompatibility{MinAgentVersion: "1.0.0", MaxAgentVersion: "2.0.0"},
		Health: entitlement.UpgradeExecutionHealthPolicy{Command: []string{"{artifact}", "--version"},
			ActivationTimeoutNanoseconds: int64(time.Minute), ObservationWindowNanoseconds: int64(time.Minute),
			IntervalNanoseconds: int64(time.Second), ProbeTimeoutNanoseconds: int64(time.Second),
			RequiredConsecutiveSuccesses: 3},
		Rollout:  entitlement.UpgradeExecutionRolloutPolicy{Percentage: 100},
		Rollback: entitlement.UpgradeExecutionRollbackPolicy{Automatic: true},
	}
	input := CommandGrantRequest{IdempotencyKey: "command.intent.1",
		PlanID: "00000000-0000-4000-8000-000000000020", PlanRevision: 2,
		BatchID:   "00000000-0000-4000-8000-000000000023",
		CommandID: "00000000-0000-4000-8000-000000000021", NodeID: "00000000-0000-4000-8000-000000000022",
		Operation: "forward", ArtifactBundle: []byte(`{"algorithm":"Ed25519"}`),
		ForwardProfile: profile, RollbackProfile: profile}
	var calls int
	transport := roundTripUpgradeFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		wantPath := "/activation/v1/installations/" + installationID.String() + "/upgrade-command-grants:issue"
		if request.Method != http.MethodPost || request.URL.Path != wantPath || request.URL.RawQuery != "" {
			t.Fatalf("request target = %s %s", request.Method, request.URL.String())
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		wantBody, _ := json.Marshal(IssueUpgradeCommandGrantHTTPBody{
			Schema: upgradeCommandGrantRequestSchema, PlanID: input.PlanID, PlanRevision: input.PlanRevision,
			BatchID: input.BatchID, CommandID: input.CommandID, NodeID: input.NodeID,
			Operation: input.Operation, UpgradePlanArtifactBundle: base64.RawURLEncoding.EncodeToString(input.ArtifactBundle),
			ForwardProfile: input.ForwardProfile, RollbackProfile: input.RollbackProfile,
		})
		if !bytes.Equal(body, wantBody) {
			t.Fatalf("request body = %s, want %s", body, wantBody)
		}
		for _, name := range []string{"Idempotency-Key", "X-Request-ID", "X-CDNCA-Installation-ID", "X-CDNCA-Requested-At", "X-CDNCA-Proof"} {
			if len(request.Header.Values(name)) != 1 {
				t.Fatalf("%s values = %#v", name, request.Header.Values(name))
			}
		}
		if request.Header.Get("Idempotency-Key") != input.IdempotencyKey ||
			request.Header.Get("X-CDNCA-Installation-ID") != installationID.String() ||
			request.Header.Get("X-CDNCA-Requested-At") != "1800000000" {
			t.Fatalf("frozen headers = %#v", request.Header)
		}
		proof, err := base64.RawURLEncoding.DecodeString(request.Header.Get("X-CDNCA-Proof"))
		if err != nil || !ed25519.Verify(privateKey.Public().(ed25519.PublicKey),
			commandGrantRequestProof(wantPath, input.IdempotencyKey, installationID.String(), now.Unix(), body), proof) {
			t.Fatal("command grant request proof did not bind exact method/path/key/installation/time/body")
		}
		return &http.Response{StatusCode: http.StatusServiceUnavailable,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(bytes.NewBufferString(`{"code":"signer_unavailable","request_id":"license-request"}`))}, nil
	})
	client, err := NewLicenseClient("https://license.example.test", transport, installationID, privateKey, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.IssueCommandGrant(context.Background(), input); !errors.Is(err, ErrLicenseUnavailable) {
		t.Fatalf("IssueCommandGrant() error = %v, want unavailable", err)
	}
	if calls != 1 {
		t.Fatalf("HTTP calls = %d, want 1", calls)
	}
}

func TestDecodeCanonicalLicenseJSONAcceptsServerJSONEncoderNewline(t *testing.T) {
	var decoded struct {
		ID string `json:"id"`
	}
	if err := decodeCanonicalLicenseJSON([]byte(`{"id":"00000000-0000-4000-8000-000000000001"}`+"\n"), &decoded); err != nil {
		t.Fatalf("decodeCanonicalLicenseJSON() error = %v", err)
	}
	if decoded.ID == "" {
		t.Fatal("decodeCanonicalLicenseJSON() returned an empty id")
	}
}

func TestLicenseClientPlanArtifactBundleExactHeadersProofAndBody(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x63}, ed25519.SeedSize))
	installationID := uuid.MustParse("00000000-0000-4000-8000-000000000004")
	input := PlanArtifactBundleRequest{IdempotencyKey: "bundle.intent.1", RequestID: "bundle-request-1",
		PlanID: "00000000-0000-4000-8000-000000000020", InitialPlanRevision: 1,
		ParentUpgradeGrant: []byte(`{"algorithm":"Ed25519"}`), CommandIssuanceNotAfter: now.Add(6 * time.Hour).Unix()}
	transport := roundTripUpgradeFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		wantPath := "/activation/v1/installations/" + installationID.String() +
			"/upgrade-plan-artifact-bundles:issue"
		wantBody, _ := json.Marshal(IssueUpgradePlanArtifactBundleHTTPBody{
			Schema: upgradePlanArtifactBundleRequestSchema, PlanID: input.PlanID,
			InitialPlanRevision:     input.InitialPlanRevision,
			ParentUpgradeGrant:      base64.RawURLEncoding.EncodeToString(input.ParentUpgradeGrant),
			CommandIssuanceNotAfter: input.CommandIssuanceNotAfter})
		if request.URL.Path != wantPath || !bytes.Equal(body, wantBody) ||
			request.Header.Get("X-Request-ID") != input.RequestID {
			t.Fatalf("bundle request = %s %s %#v", request.URL.Path, body, request.Header)
		}
		proof, err := base64.RawURLEncoding.DecodeString(request.Header.Get("X-CDNCA-Proof"))
		if err != nil || !ed25519.Verify(privateKey.Public().(ed25519.PublicKey),
			upgradeRequestProof("cdnca-upgrade-plan-artifact-bundle-request-proof/v1", wantPath,
				input.IdempotencyKey, installationID.String(), now.Unix(), body), proof) {
			t.Fatal("bundle proof did not bind exact request")
		}
		return &http.Response{StatusCode: http.StatusServiceUnavailable,
			Body: io.NopCloser(bytes.NewBufferString(`{"code":"signer_unavailable"}`))}, nil
	})
	client, err := NewLicenseClient("https://license.example.test", transport, installationID, privateKey,
		func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.IssuePlanArtifactBundle(context.Background(), input); !errors.Is(err, ErrLicenseUnavailable) {
		t.Fatalf("IssuePlanArtifactBundle() error = %v", err)
	}
}

func TestLicenseClientParentGrantUsesStableReplayIdentity(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x62}, ed25519.SeedSize))
	installationID := uuid.MustParse("00000000-0000-4000-8000-000000000004")
	input := ParentGrantRequest{IdempotencyKey: "parent." + string(bytes.Repeat([]byte{'a'}, 64)),
		CurrentVersion: "1.0.0", ProtocolVersion: 2}
	var bodies [][]byte
	transport := roundTripUpgradeFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		bodies = append(bodies, bytes.Clone(body))
		if request.Header.Get("Idempotency-Key") != input.IdempotencyKey ||
			request.URL.Path != "/activation/v1/installations/"+installationID.String()+"/upgrade-grants:issue" {
			t.Fatalf("parent grant request = %s %#v", request.URL.Path, request.Header)
		}
		return nil, errors.New("ambiguous transport outcome")
	})
	client, err := NewLicenseClient("https://license.example.test", transport, installationID, privateKey, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := client.IssueParentGrant(context.Background(), input); !errors.Is(err, ErrLicenseOutcomeUnknown) {
			t.Fatalf("IssueParentGrant() error = %v, want unknown", err)
		}
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("unknown parent retry changed exact request body: %q / %q", bodies[0], bodies[1])
	}
}

func TestLicenseClientParentReceiptV2UsesFreshProofAndStableLogicalDigest(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x64}, ed25519.SeedSize))
	installationID := uuid.MustParse("00000000-0000-4000-8000-000000000004")
	receipt := ParentGrantReceipt{ID: "00000000-0000-4000-8000-000000000091",
		PlanID: "00000000-0000-4000-8000-000000000092", InstallationID: installationID.String(),
		GrantID: "00000000-0000-4000-8000-000000000093", RequestSchema: parentGrantReceiptRequestSchema,
		RequestDigestSchema: 2, Sequence: 3, Status: parentGrantReceiptApplied,
		InstalledVersion: "2.0.0", ObservedAt: time.Unix(1_800_000_001, 0).UTC()}
	digest, err := parentGrantReceiptLogicalDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.LogicalDigest = digest
	requestTimes := []int64{1_800_000_100, 1_800_000_101}
	var calls int
	var bodies [][]byte
	transport := roundTripUpgradeFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		if request.URL.Path != "/installation/v1/upgrade-grant-receipts" ||
			request.Header.Get("Authorization") != "" || request.Header.Get("Idempotency-Key") != "" {
			t.Fatalf("receipt target/headers = %s %#v", request.URL.Path, request.Header)
		}
		var wire struct {
			Schema           string  `json:"schema"`
			RequestID        string  `json:"request_id"`
			InstallationID   string  `json:"installation_id"`
			RequestedAt      int64   `json:"requested_at"`
			GrantID          string  `json:"grant_id"`
			Status           string  `json:"status"`
			InstalledVersion string  `json:"installed_version"`
			ErrorCode        *string `json:"error_code"`
			ObservedAt       int64   `json:"observed_at"`
			Proof            string  `json:"proof"`
		}
		if err := json.Unmarshal(body, &wire); err != nil {
			t.Fatal(err)
		}
		if wire.Schema != parentGrantReceiptRequestSchema || wire.RequestID != receipt.ID ||
			wire.InstallationID != receipt.InstallationID || wire.GrantID != receipt.GrantID ||
			wire.Status != receipt.Status || wire.InstalledVersion != receipt.InstalledVersion ||
			wire.RequestedAt != requestTimes[calls] || wire.ObservedAt != receipt.ObservedAt.Unix() || wire.ErrorCode != nil {
			t.Fatalf("receipt body = %#v", wire)
		}
		proof, err := base64.RawURLEncoding.DecodeString(wire.Proof)
		if err != nil || !ed25519.Verify(privateKey.Public().(ed25519.PublicKey),
			upgradeLengthPrefixedDigest("cdnca-upgrade-grant-receipt-proof/v1", wire.Schema,
				wire.RequestID, wire.InstallationID, strconv.FormatInt(wire.RequestedAt, 10), wire.GrantID,
				wire.Status, wire.InstalledVersion, "", strconv.FormatInt(wire.ObservedAt, 10)), proof) {
			t.Fatal("receipt proof did not bind exact v2 fields")
		}
		calls++
		response := `{"schema":"upgrade-grant.receipt-response/v1","request_id":"` + receipt.ID +
			`","receipt_id":"00000000-0000-4000-8000-000000000094","accepted_status":"applied","received_at":1800000200}` + "\n"
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(response))}, nil
	})
	clockCall := 0
	client, err := NewLicenseClient("https://license.example.test", transport, installationID, privateKey,
		func() time.Time { value := time.Unix(requestTimes[clockCall], 0).UTC(); clockCall++; return value })
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		response, err := client.RecordParentGrantReceipt(t.Context(), receipt)
		if err != nil || response.RequestID != receipt.ID || response.AcceptedStatus != receipt.Status ||
			response.ReceiptID != "00000000-0000-4000-8000-000000000094" {
			t.Fatalf("receipt response = (%#v,%v)", response, err)
		}
	}
	if len(bodies) != 2 || bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("fresh retry did not replace requested_at/proof: %q / %q", bodies[0], bodies[1])
	}
	if got, err := parentGrantReceiptLogicalDigest(receipt); err != nil || got != digest {
		t.Fatalf("retry changed logical digest = (%q,%v), want %q", got, err, digest)
	}
}

// License verifies the parent grant proof over the Idempotency-Key it receives
// (services/license-service internal/httpapi issueUpgradeGrant), never over
// X-Request-ID, so the proof must hold when the console request ID differs.
func TestLicenseClientParentGrantProofCoversIdempotencyKey(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x63}, ed25519.SeedSize))
	installationID := uuid.MustParse("00000000-0000-4000-8000-000000000005")
	input := ParentGrantRequest{IdempotencyKey: "parent." + string(bytes.Repeat([]byte{'b'}, 32)),
		RequestID: "control-upgrade-request-ae18b187-01ec-4cd8-b620-7e43fab0452c", CurrentVersion: "1.0.27", ProtocolVersion: 1}
	transport := roundTripUpgradeFunc(func(request *http.Request) (*http.Response, error) {
		var body struct {
			Component       string `json:"component"`
			CurrentVersion  string `json:"current_version"`
			ProtocolVersion int    `json:"protocol_version"`
			Proof           string `json:"proof"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		proof, _ := base64.RawURLEncoding.DecodeString(body.Proof)
		message := upgradeLengthPrefixedDigest("cdnca-upgrade-grant-request-proof/v1", request.Header.Get("Idempotency-Key"),
			installationID.String(), body.Component, body.CurrentVersion, strconv.Itoa(body.ProtocolVersion))
		if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), message, proof) {
			return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		}
		return nil, errors.New("proof accepted")
	})
	client, err := NewLicenseClient("https://license.example.test", transport, installationID, privateKey, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.IssueParentGrant(context.Background(), input); !errors.Is(err, ErrLicenseOutcomeUnknown) {
		t.Fatalf("IssueParentGrant() error = %v, want the proof to verify over the Idempotency-Key", err)
	}
}

func TestLicenseClientParentReceiptPermanentHTTPClassification(t *testing.T) {
	permanent := map[int]bool{400: true, 401: true, 403: true, 404: true, 409: true, 422: true,
		408: false, 425: false, 429: false, 500: false, 502: false, 503: false, 504: false}
	for status, wantPermanent := range permanent {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			err := mapParentGrantReceiptHTTPStatus(status)
			if errors.Is(err, ErrLicenseReceiptPermanent) != wantPermanent ||
				errors.Is(err, ErrLicenseReceiptRetryable) == wantPermanent {
				t.Fatalf("status %d error = %v", status, err)
			}
		})
	}
}

func commandGrantRequestProof(path, key, installationID string, requestedAt int64, body []byte) []byte {
	return upgradeRequestProof("cdnca-upgrade-command-grant-request-proof/v1", path, key,
		installationID, requestedAt, body)
}

func upgradeRequestProof(domain, path, key, installationID string, requestedAt int64, body []byte) []byte {
	bodyDigest := sha256.Sum256(body)
	return upgradeLengthPrefixedDigest(domain, http.MethodPost, path, key, installationID,
		strconv.FormatInt(requestedAt, 10),
		base64.RawURLEncoding.EncodeToString(bodyDigest[:]))
}

type roundTripUpgradeFunc func(*http.Request) (*http.Response, error)

func (function roundTripUpgradeFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}
