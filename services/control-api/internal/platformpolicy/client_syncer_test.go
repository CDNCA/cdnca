package platformpolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestClientResolveAndAcknowledge(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	signed := testSignedPolicy(t, now, installationID, ScopeInstallation, 1, "", ActionApply, privateKey)
	target, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient("https://license.example.test/base/", roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" ||
			request.Header.Get("X-Request-ID") == "" {
			t.Fatalf("unexpected request: %s %#v", request.Method, request.Header)
		}
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		switch request.URL.Path {
		case "/base/installation/v1/platform-policies:resolve":
			var payload ResolveRequest
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.ActivePolicySHA256 == nil || *payload.ActivePolicySHA256 != "" ||
				payload.Cursor == nil || *payload.Cursor != "" || payload.KnownETag == nil || *payload.KnownETag != "" {
				t.Fatalf("resolve unset string fields must be present and empty: %#v", payload)
			}
			proof, _ := base64.RawURLEncoding.DecodeString(payload.Proof)
			if !ed25519.Verify(publicKey, ResolveProofMessage(payload), proof) {
				t.Fatal("resolve request proof did not verify")
			}
			response := struct {
				Schema         string            `json:"schema"`
				RequestID      string            `json:"request_id"`
				InstallationID string            `json:"installation_id"`
				ResolvedAt     int64             `json:"resolved_at"`
				Cursor         string            `json:"cursor"`
				ETag           string            `json:"etag"`
				NotModified    bool              `json:"not_modified"`
				Targets        []json.RawMessage `json:"targets"`
			}{ResolveResponseSchema, payload.RequestID, installationID.String(), now.Unix(), "cursor", "etag", false,
				[]json.RawMessage{target}}
			return policyJSONResponse(t, http.StatusOK, response), nil
		case "/base/installation/v1/platform-policy-acknowledgements":
			var payload AckRequest
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			proof, _ := base64.RawURLEncoding.DecodeString(payload.Proof)
			if !ed25519.Verify(publicKey, AckProofMessage(payload), proof) {
				t.Fatal("ack request proof did not verify")
			}
			response := struct {
				Schema            string `json:"schema"`
				RequestID         string `json:"request_id"`
				AcknowledgementID string `json:"acknowledgement_id"`
				AcceptedStatus    string `json:"accepted_status"`
				ReceivedAt        int64  `json:"received_at"`
			}{AckResponseSchema, payload.RequestID, uuid.NewString(), payload.Status, now.Unix()}
			return policyJSONResponse(t, http.StatusOK, response), nil
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
			return nil, nil
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := client.Resolve(context.Background(), ResolveInput{
		InstallationID: installationID, ControlVersion: "1.4.0", ControlProtocolVersion: 1,
	}, privateKey, now)
	if err != nil || len(resolved.Targets) != 1 || resolved.Targets[0].Signed.Envelope.TargetRevisionID != signed.Envelope.TargetRevisionID {
		t.Fatalf("Resolve() = (%#v, %v)", resolved, err)
	}
	acknowledged, err := client.Acknowledge(context.Background(), AckInput{
		InstallationID: installationID, TargetRevisionID: signed.Envelope.TargetRevisionID,
		ScopeKind: ScopeInstallation, ScopeRevision: 1,
		CanonicalPolicySHA256: signed.Envelope.CanonicalPolicySHA256, Status: AckApplied, ObservedAt: now,
	}, privateKey, now)
	if err != nil || acknowledged.AcceptedStatus != AckApplied {
		t.Fatalf("Acknowledge() = (%#v, %v)", acknowledged, err)
	}
}

func TestClientStrictResponsesAndRetryClassification(t *testing.T) {
	for _, rawURL := range []string{"", "http://license.test", "https://user@license.test", "https://license.test?secret=x"} {
		if _, err := NewClient(rawURL, nil); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("NewClient(%q) error = %v", rawURL, err)
		}
	}
	response := &http.Response{StatusCode: http.StatusTooManyRequests, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(`{"error":{"code":"rate_limited"}}`))}
	response.Header.Set("Retry-After", "7")
	err := decodeServiceError(response)
	delay, retry := retryable(err)
	if !retry || delay != 7*time.Second {
		t.Fatalf("retryable() = (%s, %t), want (7s, true)", delay, retry)
	}
	response = &http.Response{StatusCode: http.StatusBadRequest, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(`{"code":"invalid_request","request_id":"request-1"}`))}
	var serviceError *ServiceError
	if err := decodeServiceError(response); !errors.As(err, &serviceError) || serviceError.Code != "invalid_request" {
		t.Fatalf("decodeServiceError(top-level code) = %#v", err)
	}
	response = &http.Response{StatusCode: http.StatusConflict, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(`{"code":"cursor_invalid"}`))}
	if err := decodeServiceError(response); !errors.As(err, &serviceError) ||
		serviceError.StatusCode != http.StatusConflict || serviceError.Code != "cursor_invalid" || serviceError.Retryable() {
		t.Fatalf("decodeServiceError(cursor_invalid) = %#v", err)
	}
	badOrder := []byte(`{"schema":"platform-policy.resolve-response/v1","request_id":"r","installation_id":"` +
		uuid.NewString() + `","resolved_at":1,"cursor":"","etag":"","not_modified":false,"targets":[]}`)
	if _, err := decodeResolveResponse(badOrder, "r", uuid.New()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("decodeResolveResponse(invalid) error = %v", err)
	}
}

func TestDecodeResolveResponseRejectsInternalTargetWrapper(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	installationID := uuid.New()
	_, privateKey := testPolicyKey()
	signed := testSignedPolicy(t, now, installationID, ScopeInstallation, 1, "", ActionApply, privateKey)
	encoded, err := json.Marshal(struct {
		Schema         string `json:"schema"`
		RequestID      string `json:"request_id"`
		InstallationID string `json:"installation_id"`
		ResolvedAt     int64  `json:"resolved_at"`
		Cursor         string `json:"cursor"`
		ETag           string `json:"etag"`
		NotModified    bool   `json:"not_modified"`
		Targets        []any  `json:"targets"`
	}{
		Schema: ResolveResponseSchema, RequestID: "resolve-request",
		InstallationID: installationID.String(), ResolvedAt: now.Unix(),
		NotModified: false, Targets: []any{map[string]any{"target": signed}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeResolveResponse(encoded, "resolve-request", installationID); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("decodeResolveResponse(wrapper) error = %v", err)
	}
}

func TestClientResolveAcceptsTwoLargeValidTargets(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	installationID := uuid.New()
	_, privateKey := testPolicyKey()
	policy := largeValidPolicy(t)
	global := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
	installation := testSignedPolicy(t, now, installationID, ScopeInstallation, 1, "", ActionApply, privateKey)
	for _, signed := range []*SignedPlatformPolicy{&global, &installation} {
		signed.Policy = &policy
		canonical, err := CanonicalPolicy(signed.Policy)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(canonical)
		signed.Envelope.CanonicalPolicySHA256 = base64.RawURLEncoding.EncodeToString(digest[:])
		resignTestPolicy(t, signed, privateKey)
	}
	globalWire, _ := json.Marshal(global)
	installationWire, _ := json.Marshal(installation)
	client, err := NewClient("https://license.example.test", roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var payload ResolveRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		response := struct {
			Schema         string            `json:"schema"`
			RequestID      string            `json:"request_id"`
			InstallationID string            `json:"installation_id"`
			ResolvedAt     int64             `json:"resolved_at"`
			Cursor         string            `json:"cursor"`
			ETag           string            `json:"etag"`
			NotModified    bool              `json:"not_modified"`
			Targets        []json.RawMessage `json:"targets"`
		}{ResolveResponseSchema, payload.RequestID, installationID.String(), now.Unix(), "", "", false,
			[]json.RawMessage{globalWire, installationWire}}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded) <= maxSignedPolicyBytes || len(encoded) > maxResolveResponseBytes {
			t.Fatalf("large resolve response size = %d", len(encoded))
		}
		return &http.Response{StatusCode: http.StatusOK,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(bytes.NewReader(encoded))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := client.Resolve(context.Background(), ResolveInput{
		InstallationID: installationID, ControlVersion: "1.4.0", ControlProtocolVersion: 1,
	}, privateKey, now)
	if err != nil || len(resolved.Targets) != 2 {
		t.Fatalf("Resolve(large targets) = (%d, %v)", len(resolved.Targets), err)
	}
}

func largeValidPolicy(t *testing.T) Policy {
	t.Helper()
	for width := 180; width <= 245; width++ {
		versions := make([]string, 256)
		for index := range versions {
			versions[index] = "1.4.0-" + strings.Repeat("a", width) + fmt.Sprintf("x%03d", index)
		}
		policy := Policy{
			Schema: PolicySchema, MinimumControlVersion: "1.4.0",
			BlockedControlVersions: versions, AllowedReleaseChannels: []string{"stable"},
			PluginMarket: PluginMarket{Enabled: false, TrustedCatalogIDs: []string{}},
		}
		if canonical, err := CanonicalPolicy(&policy); err == nil && len(canonical) > 64900 {
			return policy
		}
	}
	t.Fatal("could not build a large valid policy")
	return Policy{}
}

func TestSyncerAppliesValidPolicyAndKeepsLastKnownGoodOffline(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := now
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	signed := testSignedPolicy(t, now, installationID, ScopeInstallation, 1, "", ActionApply, privateKey)
	wire, _ := json.Marshal(signed)
	store := &memoryPolicyStore{}
	client := &memoryPolicyClient{resolve: ResolveResult{ResolvedAt: now, Cursor: "cursor", ETag: "etag",
		Targets: []ResolvedTarget{{Signed: signed, Encoded: wire}}}}
	state := NewState(func() time.Time { return clock })
	syncer, err := NewSyncer(context.Background(), SyncerConfig{
		Client: client, Store: store, Trust: testPolicyTrust(t, publicKey), State: state,
		InstallationID: installationID, PrivateKey: privateKey, ControlVersion: "1.4.0",
		ProtocolVersion: 1, Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.applied) != 1 || store.position.Cursor == nil || *store.position.Cursor != "cursor" {
		t.Fatalf("store after sync = applied:%d position:%#v", len(store.applied), store.position)
	}
	snapshot, stale := state.Snapshot()
	if stale || snapshot.Source != ScopeInstallation || snapshot.TargetRevisionID != signed.Envelope.TargetRevisionID {
		t.Fatalf("state after sync = (%#v, %t)", snapshot, stale)
	}

	client.resolveErr = errors.New("license service unavailable")
	if err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("SyncOnce() succeeded while service was unavailable")
	}
	snapshot, stale = state.Snapshot()
	if stale || snapshot.TargetRevisionID != signed.Envelope.TargetRevisionID {
		t.Fatalf("offline sync changed LKG = (%#v, %t)", snapshot, stale)
	}
	clock = now.Add(2 * time.Hour)
	decision := state.ReleaseChannel("stable", true)
	if decision.Allowed || !decision.Stale || decision.Reason != DecisionPolicyStale {
		t.Fatalf("expired offline LKG decision = %#v", decision)
	}
}

func TestSyncerRecoversFromInvalidCursorOnce(t *testing.T) {
	now := time.Date(2026, 9, 13, 18, 0, 0, 0, time.UTC)
	previousResolvedAt := now.Add(-time.Minute)
	cursor, etag := "stale-cursor", "stale-etag"
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	active := testSignedPolicy(t, now, installationID, ScopeInstallation, 7, uuid.NewString(), ActionApply, privateKey)
	next := testSignedPolicy(t, now, installationID, ScopeInstallation, 8,
		active.Envelope.TargetRevisionID, ActionApply, privateKey)
	nextWire, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryPolicyStore{local: LocalState{
		GlobalHead:         &ScopeHead{ScopeRevision: 3},
		InstallationHead:   &ScopeHead{TargetRevisionID: active.Envelope.TargetRevisionID, ScopeRevision: 7},
		InstallationActive: &StoredTarget{Signed: active},
		Position:           SyncPosition{Cursor: &cursor, ETag: &etag, ResolvedAt: &previousResolvedAt},
	}}
	client := &scriptedPolicyClient{steps: []resolveStep{
		{err: &ServiceError{StatusCode: http.StatusConflict, Code: "cursor_invalid"}},
		{result: ResolveResult{ResolvedAt: now, Cursor: "fresh-cursor", ETag: "fresh-etag",
			Targets: []ResolvedTarget{{Signed: next, Encoded: nextWire}}}},
	}}
	syncer, err := NewSyncer(context.Background(), SyncerConfig{
		Client: client, Store: store, Trust: testPolicyTrust(t, publicKey), State: NewState(func() time.Time { return now }),
		InstallationID: installationID, PrivateKey: privateKey, ControlVersion: "1.4.0",
		ProtocolVersion: 1, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(client.inputs) != 2 || client.inputs[0].Cursor == nil || *client.inputs[0].Cursor != cursor ||
		client.inputs[0].KnownETag == nil || *client.inputs[0].KnownETag != etag ||
		client.inputs[1].Cursor != nil || client.inputs[1].KnownETag != nil {
		t.Fatalf("resolve inputs = %#v", client.inputs)
	}
	for index, input := range client.inputs {
		if input.KnownGlobalRevision != 3 || input.KnownInstallationRevision != 7 ||
			input.ActiveTargetRevisionID == nil || *input.ActiveTargetRevisionID != active.Envelope.TargetRevisionID ||
			input.ActivePolicySHA256 == nil || *input.ActivePolicySHA256 != active.Envelope.CanonicalPolicySHA256 {
			t.Fatalf("resolve input %d lost policy state: %#v", index, input)
		}
	}
	if len(store.positions) != 2 || store.positions[0].Cursor != nil || store.positions[0].ETag != nil ||
		store.positions[0].ResolvedAt == nil || !store.positions[0].ResolvedAt.Equal(previousResolvedAt) ||
		store.positions[1].Cursor == nil || *store.positions[1].Cursor != "fresh-cursor" ||
		store.positions[1].ETag == nil || *store.positions[1].ETag != "fresh-etag" {
		t.Fatalf("saved positions = %#v", store.positions)
	}
	if len(store.applied) != 1 || store.applied[0].Signed.Envelope.TargetRevisionID != next.Envelope.TargetRevisionID {
		t.Fatalf("applied policies = %#v", store.applied)
	}
}

func TestSyncerDoesNotRetryOtherCursorConflicts(t *testing.T) {
	now := time.Date(2026, 9, 13, 18, 0, 0, 0, time.UTC)
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	for _, serviceError := range []*ServiceError{
		{StatusCode: http.StatusConflict, Code: "revision_ahead"},
		{StatusCode: http.StatusBadRequest, Code: "cursor_invalid"},
	} {
		t.Run(fmt.Sprintf("%d_%s", serviceError.StatusCode, serviceError.Code), func(t *testing.T) {
			cursor := "stale-cursor"
			store := &memoryPolicyStore{local: LocalState{Position: SyncPosition{Cursor: &cursor}}}
			client := &scriptedPolicyClient{steps: []resolveStep{{err: serviceError}}}
			syncer, err := NewSyncer(context.Background(), SyncerConfig{
				Client: client, Store: store, Trust: testPolicyTrust(t, publicKey), State: NewState(func() time.Time { return now }),
				InstallationID: installationID, PrivateKey: privateKey, ControlVersion: "1.4.0",
				ProtocolVersion: 1, Now: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := syncer.SyncOnce(context.Background()); !errors.Is(err, serviceError) {
				t.Fatalf("SyncOnce() error = %v, want %v", err, serviceError)
			}
			if len(client.inputs) != 1 || len(store.positions) != 0 {
				t.Fatalf("resolve calls=%d positions=%#v", len(client.inputs), store.positions)
			}
		})
	}
}

func TestSyncerStopsWhenInvalidCursorClearFails(t *testing.T) {
	now := time.Date(2026, 9, 13, 18, 0, 0, 0, time.UTC)
	cursor := "stale-cursor"
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	clearErr := errors.New("persist cleared cursor")
	store := &memoryPolicyStore{local: LocalState{Position: SyncPosition{Cursor: &cursor}}, savePositionErr: clearErr}
	client := &scriptedPolicyClient{steps: []resolveStep{{err: &ServiceError{
		StatusCode: http.StatusConflict, Code: "cursor_invalid",
	}}}}
	syncer, err := NewSyncer(context.Background(), SyncerConfig{
		Client: client, Store: store, Trust: testPolicyTrust(t, publicKey), State: NewState(func() time.Time { return now }),
		InstallationID: installationID, PrivateKey: privateKey, ControlVersion: "1.4.0",
		ProtocolVersion: 1, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(context.Background()); !errors.Is(err, clearErr) {
		t.Fatalf("SyncOnce() error = %v, want %v", err, clearErr)
	}
	if len(client.inputs) != 1 || len(store.positions) != 0 {
		t.Fatalf("resolve calls=%d positions=%#v", len(client.inputs), store.positions)
	}
}

func TestSyncerBoundsInvalidCursorRecoveryToOneRetry(t *testing.T) {
	now := time.Date(2026, 9, 13, 18, 0, 0, 0, time.UTC)
	cursor := "stale-cursor"
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	store := &memoryPolicyStore{local: LocalState{Position: SyncPosition{Cursor: &cursor}}}
	secondErr := &ServiceError{StatusCode: http.StatusConflict, Code: "cursor_invalid"}
	client := &scriptedPolicyClient{steps: []resolveStep{
		{err: &ServiceError{StatusCode: http.StatusConflict, Code: "cursor_invalid"}},
		{err: secondErr},
	}}
	syncer, err := NewSyncer(context.Background(), SyncerConfig{
		Client: client, Store: store, Trust: testPolicyTrust(t, publicKey), State: NewState(func() time.Time { return now }),
		InstallationID: installationID, PrivateKey: privateKey, ControlVersion: "1.4.0",
		ProtocolVersion: 1, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(context.Background()); !errors.Is(err, secondErr) {
		t.Fatalf("SyncOnce() error = %v, want %v", err, secondErr)
	}
	if len(client.inputs) != 2 || len(store.positions) != 1 || store.positions[0].Cursor != nil ||
		store.positions[0].ETag != nil {
		t.Fatalf("recovery calls=%d positions=%#v", len(client.inputs), store.positions)
	}
}

func TestSyncerRejectsTamperedTargetWithoutReplacingState(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	signed := testSignedPolicy(t, now, installationID, ScopeInstallation, 1, "", ActionApply, privateKey)
	signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	signature[0] ^= 1
	signed.Signature = base64.RawURLEncoding.EncodeToString(signature)
	wire, _ := json.Marshal(signed)
	store := &memoryPolicyStore{}
	state := NewState(func() time.Time { return now })
	syncer, err := NewSyncer(context.Background(), SyncerConfig{
		Client: &memoryPolicyClient{resolve: ResolveResult{ResolvedAt: now,
			Targets: []ResolvedTarget{{Signed: signed, Encoded: wire}}}},
		Store: store, Trust: testPolicyTrust(t, publicKey), State: state,
		InstallationID: installationID, PrivateKey: privateKey, ControlVersion: "1.4.0",
		ProtocolVersion: 1, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.applied) != 0 || len(store.rejections) != 1 || store.rejections[0] != "invalid_signature" {
		t.Fatalf("tampered target result: applied=%d rejected=%v", len(store.applied), store.rejections)
	}
	if snapshot, _ := state.Snapshot(); !snapshot.Defaulted {
		t.Fatalf("tampered target replaced state: %#v", snapshot)
	}
}

type policyRevocationGate map[string]bool

func (gate policyRevocationGate) CheckSigner(class entitlementguard.SignerArtifactClass, keyID string) error {
	if class == entitlementguard.SignerArtifactPolicy && gate[keyID] {
		return &entitlementguard.SignerRevokedError{Class: class, KeyID: keyID}
	}
	return nil
}

func TestSyncerRejectsCandidateFromRevokedSignerAndKeepsLKG(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	signed := testSignedPolicy(t, now, installationID, ScopeInstallation, 1, "", ActionApply, privateKey)
	wire, _ := json.Marshal(signed)
	store := &memoryPolicyStore{}
	state := NewState(func() time.Time { return now })
	trust := testPolicyTrust(t, publicKey)
	trust.SetSignerRevocationGate(policyRevocationGate{"platform-policy-test-key": true})
	syncer, err := NewSyncer(context.Background(), SyncerConfig{
		Client: &memoryPolicyClient{resolve: ResolveResult{ResolvedAt: now,
			Targets: []ResolvedTarget{{Signed: signed, Encoded: wire}}}},
		Store: store, Trust: trust, SignerRevocation: trust, State: state,
		InstallationID: installationID, PrivateKey: privateKey, ControlVersion: "1.4.0",
		ProtocolVersion: 1, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// license-service only accepts its fixed acknowledgement codes; a revoked
	// signer is reported upstream as an untrusted signing key.
	if len(store.applied) != 0 || len(store.rejections) != 1 || store.rejections[0] != "unknown_signing_key" {
		t.Fatalf("revoked signer result: applied=%d rejected=%v", len(store.applied), store.rejections)
	}
	if snapshot, _ := state.Snapshot(); !snapshot.Defaulted {
		t.Fatalf("revoked signer replaced state: %#v", snapshot)
	}
	if RejectionCode(ErrSignerRevoked) != "unknown_signing_key" {
		t.Fatal("ErrSignerRevoked must map to an acknowledgement code license-service accepts")
	}
}

func TestSyncerAppliesDurableFutureCandidateWithoutPublisherReplay(t *testing.T) {
	baseTime := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := baseTime
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	active := testSignedPolicy(t, baseTime, installationID, ScopeInstallation, 1, "", ActionApply, privateKey)
	future := testSignedPolicy(t, baseTime, installationID, ScopeInstallation, 2,
		active.Envelope.TargetRevisionID, ActionApply, privateKey)
	future.Envelope.ValidFrom = baseTime.Add(time.Hour).Unix()
	future.Envelope.ExpiresAt = baseTime.Add(2 * time.Hour).Unix()
	resignTestPolicy(t, &future, privateKey)
	futureWire, _ := json.Marshal(future)
	store := &memoryPolicyStore{
		local: LocalState{
			InstallationHead: &ScopeHead{TargetRevisionID: active.Envelope.TargetRevisionID,
				ScopeRevision: 1, CanonicalPolicySHA256: active.Envelope.CanonicalPolicySHA256, Signature: active.Signature},
			InstallationActive: &StoredTarget{Signed: active},
		},
		candidates: []StoredTarget{{Signed: future, Encoded: futureWire}},
	}
	state := NewState(func() time.Time { return clock })
	syncer, err := NewSyncer(context.Background(), SyncerConfig{
		Client: &memoryPolicyClient{resolveErr: errors.New("publisher offline")},
		Store:  store, Trust: testPolicyTrust(t, publicKey), State: state,
		InstallationID: installationID, PrivateKey: privateKey, ControlVersion: "1.4.0",
		ProtocolVersion: 1, Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("SyncOnce() succeeded while publisher was offline")
	}
	if snapshot, _ := state.Snapshot(); snapshot.TargetRevisionID != active.Envelope.TargetRevisionID {
		t.Fatalf("future candidate replaced active early: %#v", snapshot)
	}
	clock = baseTime.Add(time.Hour + time.Second)
	if err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("SyncOnce() succeeded while publisher remained offline")
	}
	if snapshot, stale := state.Snapshot(); stale || snapshot.TargetRevisionID != future.Envelope.TargetRevisionID {
		t.Fatalf("due durable candidate was not applied offline: (%#v, %t)", snapshot, stale)
	}
}

func TestSyncerRestoreIgnoresNewerHeadAndKeepsExpiredLKG(t *testing.T) {
	baseTime := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := baseTime.Add(2 * time.Hour)
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	active := testSignedPolicy(t, baseTime, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
	store := &memoryPolicyStore{local: LocalState{
		GlobalHead: &ScopeHead{TargetRevisionID: uuid.NewString(), ScopeRevision: 2,
			CanonicalPolicySHA256: active.Envelope.CanonicalPolicySHA256, Signature: active.Signature},
		GlobalActive: &StoredTarget{Signed: active},
	}}
	state := NewState(func() time.Time { return clock })
	if _, err := NewSyncer(context.Background(), SyncerConfig{
		Client: &memoryPolicyClient{}, Store: store, Trust: testPolicyTrust(t, publicKey), State: state,
		InstallationID: installationID, PrivateKey: privateKey, ControlVersion: "1.4.0",
		ProtocolVersion: 1, Now: func() time.Time { return clock },
	}); err != nil {
		t.Fatalf("NewSyncer() failed to restore LKG behind head: %v", err)
	}
	if snapshot, stale := state.Snapshot(); !stale || snapshot.TargetRevisionID != active.Envelope.TargetRevisionID {
		t.Fatalf("expired LKG restore = (%#v, %t)", snapshot, stale)
	}
}

func TestSyncerDefersUnknownKeyWhenKeysetRefreshFails(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	installationID := uuid.New()
	oldPublic, oldPrivate := testPolicyKey()
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	rotatedPrivate := ed25519.NewKeyFromSeed(seed)
	rotatedPublic := rotatedPrivate.Public().(ed25519.PublicKey)
	signed := testSignedPolicy(t, now, installationID, ScopeInstallation, 1, "", ActionApply, rotatedPrivate)
	signed.Envelope.KeyID = "rotated-platform-policy-key"
	resignTestPolicy(t, &signed, rotatedPrivate)
	wire, _ := json.Marshal(signed)
	trust := testPolicyTrust(t, oldPublic)
	refreshCalls := 0
	keysets := keysetRefreshFunc(func(context.Context) error {
		refreshCalls++
		if refreshCalls == 1 {
			return errors.New("keyset service unavailable")
		}
		return trust.ApplyVerifiedKeys([]entitlementguard.VerificationKey{
			{KeyID: "platform-policy-test-key", PublicKey: oldPublic},
			{KeyID: signed.Envelope.KeyID, PublicKey: rotatedPublic},
		})
	})
	store := &memoryPolicyStore{}
	state := NewState(func() time.Time { return now })
	syncer, err := NewSyncer(context.Background(), SyncerConfig{
		Client: &memoryPolicyClient{resolve: ResolveResult{ResolvedAt: now,
			Targets: []ResolvedTarget{{Signed: signed, Encoded: wire}}}},
		Store: store, Trust: trust, Keysets: keysets, State: state,
		InstallationID: installationID, PrivateKey: oldPrivate, ControlVersion: "1.4.0",
		ProtocolVersion: 1, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.rejections) != 0 || len(store.applied) != 0 || len(store.candidates) != 1 {
		t.Fatalf("refresh failure made unknown key terminal: rejected=%v applied=%d candidates=%d",
			store.rejections, len(store.applied), len(store.candidates))
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.rejections) != 0 || len(store.applied) != 1 {
		t.Fatalf("recovered keyset did not apply candidate: rejected=%v applied=%d", store.rejections, len(store.applied))
	}
}

func TestSyncerRunUsesFailureBackoffIndependentOfSyncInterval(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	stop := errors.New("stop wait")
	var delays []time.Duration
	syncer, err := NewSyncer(context.Background(), SyncerConfig{
		Client: &memoryPolicyClient{resolveErr: errors.New("offline")}, Store: &memoryPolicyStore{},
		Trust: testPolicyTrust(t, publicKey), State: NewState(func() time.Time { return now }),
		InstallationID: installationID, PrivateKey: privateKey, ControlVersion: "1.4.0", ProtocolVersion: 1,
		Now: func() time.Time { return now }, SyncInterval: time.Minute, BackoffMin: time.Second,
		BackoffMax: 4 * time.Second, Wait: func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			if len(delays) == 2 {
				return stop
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.Run(context.Background()); !errors.Is(err, stop) {
		t.Fatalf("Run() error = %v", err)
	}
	if len(delays) != 2 || delays[0] != time.Second || delays[1] != 2*time.Second {
		t.Fatalf("failure delays = %v, want [1s 2s]", delays)
	}
}

type resolveStep struct {
	result ResolveResult
	err    error
}

type scriptedPolicyClient struct {
	steps  []resolveStep
	inputs []ResolveInput
}

func (client *scriptedPolicyClient) Resolve(_ context.Context, input ResolveInput,
	_ ed25519.PrivateKey, _ time.Time) (ResolveResult, error) {
	client.inputs = append(client.inputs, input)
	index := len(client.inputs) - 1
	if index >= len(client.steps) {
		return ResolveResult{}, errors.New("unexpected platform policy resolve call")
	}
	return client.steps[index].result, client.steps[index].err
}

func (*scriptedPolicyClient) Acknowledge(context.Context, AckInput,
	ed25519.PrivateKey, time.Time) (AckResult, error) {
	return AckResult{}, nil
}

type memoryPolicyClient struct {
	resolve    ResolveResult
	resolveErr error
}

type keysetRefreshFunc func(context.Context) error

func (function keysetRefreshFunc) Refresh(ctx context.Context) error { return function(ctx) }

func (client *memoryPolicyClient) Resolve(context.Context, ResolveInput, ed25519.PrivateKey, time.Time) (ResolveResult, error) {
	return client.resolve, client.resolveErr
}

func (*memoryPolicyClient) Acknowledge(context.Context, AckInput, ed25519.PrivateKey, time.Time) (AckResult, error) {
	return AckResult{}, nil
}

type memoryPolicyStore struct {
	local           LocalState
	position        SyncPosition
	positions       []SyncPosition
	savePositionErr error
	candidates      []StoredTarget
	applied         []VerifiedPolicy
	rejections      []string
}

func (store *memoryPolicyStore) Load(context.Context) (LocalState, error) { return store.local, nil }

func (store *memoryPolicyStore) PendingCandidates(context.Context, time.Time, int) ([]StoredTarget, error) {
	return append([]StoredTarget(nil), store.candidates...), nil
}

func (store *memoryPolicyStore) RecordFetched(_ context.Context, encoded []byte,
	signed SignedPlatformPolicy, _ time.Time) (bool, error) {
	for _, candidate := range store.candidates {
		if candidate.Signed.Envelope.TargetRevisionID == signed.Envelope.TargetRevisionID {
			return false, nil
		}
	}
	store.candidates = append(store.candidates, StoredTarget{Signed: cloneSigned(signed), Encoded: append([]byte(nil), encoded...)})
	return true, nil
}

func (store *memoryPolicyStore) RecordRejected(_ context.Context, targetID string, code string, _ time.Time) error {
	store.rejections = append(store.rejections, code)
	for index := range store.candidates {
		if store.candidates[index].Signed.Envelope.TargetRevisionID == targetID {
			store.candidates = append(store.candidates[:index], store.candidates[index+1:]...)
			break
		}
	}
	return nil
}

func (store *memoryPolicyStore) Apply(_ context.Context, verified VerifiedPolicy, _ time.Time) error {
	store.applied = append(store.applied, verified)
	for index := range store.candidates {
		if store.candidates[index].Signed.Envelope.TargetRevisionID == verified.Signed.Envelope.TargetRevisionID {
			store.candidates = append(store.candidates[:index], store.candidates[index+1:]...)
			break
		}
	}
	head := &ScopeHead{TargetRevisionID: verified.Signed.Envelope.TargetRevisionID,
		ScopeRevision:         verified.Signed.Envelope.ScopeRevision,
		CanonicalPolicySHA256: verified.Signed.Envelope.CanonicalPolicySHA256, Signature: verified.Signed.Signature}
	active := &StoredTarget{Signed: verified.Signed}
	if verified.Signed.Envelope.ScopeKind == ScopeGlobal {
		store.local.GlobalHead, store.local.GlobalActive = head, active
	} else {
		store.local.InstallationHead, store.local.InstallationActive = head, active
	}
	return nil
}

func (store *memoryPolicyStore) SavePosition(_ context.Context, position SyncPosition, _ time.Time) error {
	if store.savePositionErr != nil {
		return store.savePositionErr
	}
	store.position, store.local.Position = position, position
	store.positions = append(store.positions, position)
	return nil
}

func (*memoryPolicyStore) PendingAcks(context.Context, time.Time, int) ([]PendingAck, error) {
	return nil, nil
}

func (*memoryPolicyStore) CompleteAck(context.Context, uuid.UUID, time.Time) error { return nil }

func (*memoryPolicyStore) DeferAck(context.Context, uuid.UUID, string, time.Time, time.Time) error {
	return nil
}

func policyJSONResponse(t *testing.T, status int, value any) *http.Response {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(bytes.NewReader(encoded))}
}
