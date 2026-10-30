package securitybundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

var (
	fixedNow  = time.Date(2026, 7, 22, 14, 0, 0, 0, time.UTC)
	tenantID  = uuid.MustParse("018f0000-0000-7000-8000-000000000010")
	siteID    = uuid.MustParse("018f0000-0000-7000-8000-000000000020")
	policyID  = uuid.MustParse("018f0000-0000-7000-8000-000000000030")
	rolloutID = uuid.MustParse("018f0000-0000-7000-8000-000000000040")
	nodeA     = uuid.MustParse("018f0000-0000-7000-8000-000000000051")
	nodeB     = uuid.MustParse("018f0000-0000-7000-8000-000000000052")
)

type testSigner struct {
	keyID      string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	corrupt    bool
}

func (signer testSigner) KeyID() string { return signer.keyID }

func (signer testSigner) PublicKey() ed25519.PublicKey {
	return slices.Clone(signer.publicKey)
}

func (signer testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	signature := ed25519.Sign(signer.privateKey, payload)
	if signer.corrupt {
		signature[0] ^= 0xff
	}
	return signature, nil
}

func TestPublisherPlansCanonicalBoundBundleAndVerifierChecksTime(t *testing.T) {
	publisher, signer := newTestPublisher(t)
	request := validPublishRequest()
	originalTargets := slices.Clone(request.TargetNodeIDs)
	result, err := publisher.Plan(context.Background(), request, nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	plan := result.Plan
	if result.Replayed || plan.BundleID == uuid.Nil || plan.Bundle.Payload.SchemaVersion != SchemaVersion ||
		plan.Bundle.Payload.IssuedAt != fixedNow.Unix() || plan.Bundle.Payload.ExpiresAt != fixedNow.Add(5*time.Minute).Unix() {
		t.Fatalf("plan = %#v", result)
	}
	if !slices.Equal(plan.Bundle.Payload.TargetNodeIDs, []uuid.UUID{nodeA, nodeB}) ||
		!slices.Equal(request.TargetNodeIDs, originalTargets) {
		t.Fatalf("target normalization mutated input or was unstable: input=%v payload=%v", request.TargetNodeIDs, plan.Bundle.Payload.TargetNodeIDs)
	}
	if sha256.Sum256(plan.CanonicalPayload) != plan.CanonicalPayloadSHA256 ||
		plan.Bundle.PayloadSHA256 != hex.EncodeToString(plan.CanonicalPayloadSHA256[:]) ||
		plan.Bundle.Payload.RuntimeSnapshotSHA256 != hex.EncodeToString(plan.RuntimeSnapshotSHA256[:]) {
		t.Fatal("plan hashes do not cover their canonical payloads")
	}
	canonicalBundle, err := json.Marshal(plan.Bundle)
	if err != nil || !bytes.Equal(canonicalBundle, plan.BundleJSON) {
		t.Fatal("bundle JSON is not canonical")
	}

	options := verifyOptions(request, fixedNow)
	verified, err := Verify(plan.BundleJSON, map[string]ed25519.PublicKey{signer.keyID: signer.publicKey}, options)
	if err != nil || verified.Payload.BundleID != plan.BundleID {
		t.Fatalf("Verify = (%#v, %v)", verified, err)
	}
	options.Now = fixedNow.Add(-time.Second)
	if _, err := Verify(plan.BundleJSON, map[string]ed25519.PublicKey{signer.keyID: signer.publicKey}, options); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("pre-issuance Verify error = %v, want ErrNotYetValid", err)
	}
	options.Now = fixedNow.Add(5*time.Minute - time.Second)
	if _, err := Verify(plan.BundleJSON, map[string]ed25519.PublicKey{signer.keyID: signer.publicKey}, options); err != nil {
		t.Fatalf("last valid second Verify: %v", err)
	}
	options.Now = fixedNow.Add(5 * time.Minute)
	if _, err := Verify(plan.BundleJSON, map[string]ed25519.PublicKey{signer.keyID: signer.publicKey}, options); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry Verify error = %v, want ErrExpired", err)
	}
}

func TestPublisherIdempotencyAndConcurrentDeterminism(t *testing.T) {
	publisher, _ := newTestPublisher(t)
	request := validPublishRequest()
	first, err := publisher.Plan(context.Background(), request, nil)
	if err != nil {
		t.Fatalf("first Plan: %v", err)
	}
	second, err := publisher.Plan(context.Background(), request, nil)
	if err != nil || !samePlan(first.Plan, second.Plan) {
		t.Fatalf("repeat Plan differs: err=%v", err)
	}
	replayed, err := publisher.Plan(context.Background(), request, &first.Plan)
	if err != nil || !replayed.Replayed || !samePlan(first.Plan, replayed.Plan) {
		t.Fatalf("idempotent replay = (%#v, %v)", replayed, err)
	}

	equivalent := request
	equivalent.TargetNodeIDs = []uuid.UUID{nodeA, nodeB, nodeA}
	equivalentResult, err := publisher.Plan(context.Background(), equivalent, &first.Plan)
	if err != nil || !equivalentResult.Replayed || !samePlan(first.Plan, equivalentResult.Plan) {
		t.Fatalf("semantically equal target replay = (%#v, %v)", equivalentResult, err)
	}

	conflict := request
	conflict.TargetNodeIDs = []uuid.UUID{nodeA}
	if _, err := publisher.Plan(context.Background(), conflict, &first.Plan); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed target Plan error = %v, want ErrIdempotencyConflict", err)
	}

	const workers = 32
	results := make(chan PublicationPlan, workers)
	errorsFound := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := publisher.Plan(context.Background(), request, nil)
			if err != nil {
				errorsFound <- err
				return
			}
			results <- result.Plan
		}()
	}
	wait.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		t.Fatalf("concurrent Plan: %v", err)
	}
	for result := range results {
		if !samePlan(first.Plan, result) {
			t.Fatal("concurrent Plan produced non-deterministic result")
		}
	}
}

func TestVerifyRejectsCrossBindingReplayAndUnknownKey(t *testing.T) {
	publisher, signer := newTestPublisher(t)
	request := validPublishRequest()
	result, err := publisher.Plan(context.Background(), request, nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	keys := map[string]ed25519.PublicKey{signer.keyID: signer.publicKey}
	base := verifyOptions(request, fixedNow)

	tests := []struct {
		name   string
		mutate func(*VerifyOptions)
	}{
		{name: "tenant", mutate: func(value *VerifyOptions) { value.TenantScopeID = uuid.New() }},
		{name: "site", mutate: func(value *VerifyOptions) { value.SiteID = uuid.New() }},
		{name: "policy", mutate: func(value *VerifyOptions) { value.PolicyID = uuid.New() }},
		{name: "policy version", mutate: func(value *VerifyOptions) { value.PolicyVersion++ }},
		{name: "expected active version", mutate: func(value *VerifyOptions) { value.ExpectedActiveVersion++ }},
		{name: "rollout", mutate: func(value *VerifyOptions) { value.RolloutID = uuid.New() }},
		{name: "idempotency", mutate: func(value *VerifyOptions) { value.IdempotencyKey = "security-other" }},
		{name: "targets", mutate: func(value *VerifyOptions) { value.TargetNodeIDs = []uuid.UUID{nodeA} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := base
			test.mutate(&options)
			if _, err := Verify(result.Plan.BundleJSON, keys, options); !errors.Is(err, ErrBindingMismatch) {
				t.Fatalf("Verify error = %v, want ErrBindingMismatch", err)
			}
		})
	}
	if _, err := Verify(result.Plan.BundleJSON, map[string]ed25519.PublicKey{}, base); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key Verify error = %v, want ErrUnknownKey", err)
	}
}

func TestVerifyRejectsTamperingAndInvalidTrustedPayload(t *testing.T) {
	publisher, signer := newTestPublisher(t)
	request := validPublishRequest()
	result, err := publisher.Plan(context.Background(), request, nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	keys := map[string]ed25519.PublicKey{signer.keyID: signer.publicKey}
	options := verifyOptions(request, fixedNow)

	tampered := result.Plan.Bundle
	tampered.Payload.TargetNodeIDs = []uuid.UUID{nodeA}
	tamperedJSON, _ := json.Marshal(tampered)
	if _, err := Verify(tamperedJSON, keys, options); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("target tamper Verify error = %v, want ErrInvalidBundle", err)
	}

	tampered = result.Plan.Bundle
	tampered.Payload.RuntimeSnapshotSHA256 = string(bytes.Repeat([]byte{'0'}, sha256.Size*2))
	tamperedJSON, _ = json.Marshal(tampered)
	if _, err := Verify(tamperedJSON, keys, options); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("snapshot hash tamper Verify error = %v, want ErrInvalidBundle", err)
	}

	tampered = result.Plan.Bundle
	signature, _ := base64.RawURLEncoding.DecodeString(tampered.Signature)
	signature[0] ^= 0xff
	tampered.Signature = base64.RawURLEncoding.EncodeToString(signature)
	tamperedJSON, _ = json.Marshal(tampered)
	if _, err := Verify(tamperedJSON, keys, options); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("signature tamper Verify error = %v, want ErrInvalidSignature", err)
	}

	unsafe := result.Plan.Bundle
	unsafe.Payload.RuntimeSnapshot.Rules[0].Conditions[0].Operator = "regex"
	snapshotJSON, _ := json.Marshal(unsafe.Payload.RuntimeSnapshot)
	snapshotDigest := sha256.Sum256(snapshotJSON)
	unsafe.Payload.RuntimeSnapshotSHA256 = hex.EncodeToString(snapshotDigest[:])
	unsafe = resignBundle(t, unsafe, signer)
	unsafeJSON, _ := json.Marshal(unsafe)
	if _, err := Verify(unsafeJSON, keys, options); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("trusted unsafe payload Verify error = %v, want ErrInvalidBundle", err)
	}

	duplicateTopLevel := bytes.Replace(result.Plan.BundleJSON, []byte(`{"algorithm":"Ed25519"`),
		[]byte(`{"algorithm":"Ed25519","algorithm":"Ed25519"`), 1)
	if _, err := Verify(duplicateTopLevel, keys, options); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("duplicate-key Verify error = %v, want ErrInvalidBundle", err)
	}
}

func TestPublisherRejectsInvalidScopeAndSignerOutput(t *testing.T) {
	publisher, signer := newTestPublisher(t)
	request := validPublishRequest()
	request.TenantScopeID = uuid.New()
	if _, err := publisher.Plan(context.Background(), request, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cross-tenant Plan error = %v, want ErrInvalidInput", err)
	}

	badSigner := signer
	badSigner.corrupt = true
	badPublisher, err := NewPublisher(badSigner, Config{Clock: func() time.Time { return fixedNow }, Validity: 5 * time.Minute})
	if err != nil {
		t.Fatalf("NewPublisher bad signer fixture: %v", err)
	}
	if _, err := badPublisher.Plan(context.Background(), validPublishRequest(), nil); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("corrupt signature Plan error = %v, want ErrSigningFailed", err)
	}
}

func newTestPublisher(t *testing.T) (*Publisher, testSigner) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	signer := testSigner{keyID: "security-test-key-1", privateKey: privateKey, publicKey: privateKey.Public().(ed25519.PublicKey)}
	publisher, err := NewPublisher(signer, Config{Clock: func() time.Time { return fixedNow }, Validity: 5 * time.Minute})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	return publisher, signer
}

func validPublishRequest() PublishRequest {
	return PublishRequest{
		TenantScopeID: tenantID, SiteID: siteID, Policy: validPolicy(),
		TargetNodeIDs: []uuid.UUID{nodeB, nodeA, nodeB}, ExpectedActiveVersion: 6,
		RolloutID: rolloutID, IdempotencyKey: "security-publish-1",
	}
}

func validPolicy() securitypolicy.Policy {
	return securitypolicy.Policy{
		ID: policyID, ScopeID: tenantID, Kind: securitypolicy.KindWAF, Name: "WAF", Enabled: true,
		DefaultAction: securitypolicy.ActionAllow, Revision: 7,
		Rules: []securitypolicy.Rule{{
			ID: uuid.MustParse("018f0000-0000-7000-8000-000000000061"), Name: "block", Priority: 10, Enabled: true,
			Conditions: []securitypolicy.Condition{
				{Field: "method", Operator: "in", Values: []string{"POST", "GET"}},
				{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"2001:db8::1/64", "10.0.0.9/24"}},
			},
			Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
		}},
	}
}

func verifyOptions(request PublishRequest, now time.Time) VerifyOptions {
	return VerifyOptions{
		Now: now, TenantScopeID: request.TenantScopeID, SiteID: request.SiteID,
		PolicyID: request.Policy.ID, PolicyVersion: request.Policy.Revision,
		TargetNodeIDs: request.TargetNodeIDs, ExpectedActiveVersion: request.ExpectedActiveVersion,
		RolloutID: request.RolloutID, IdempotencyKey: request.IdempotencyKey,
	}
}

func samePlan(left, right PublicationPlan) bool {
	return left.IdempotencyKey == right.IdempotencyKey && left.RequestSHA256 == right.RequestSHA256 &&
		left.BundleID == right.BundleID && left.CanonicalPayloadSHA256 == right.CanonicalPayloadSHA256 &&
		left.RuntimeSnapshotSHA256 == right.RuntimeSnapshotSHA256 &&
		bytes.Equal(left.CanonicalPayload, right.CanonicalPayload) && bytes.Equal(left.BundleJSON, right.BundleJSON)
}

func resignBundle(t *testing.T, bundle SignedBundle, signer testSigner) SignedBundle {
	t.Helper()
	canonicalPayload, err := json.Marshal(bundle.Payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	digest := sha256.Sum256(canonicalPayload)
	bundle.PayloadSHA256 = hex.EncodeToString(digest[:])
	payload, err := json.Marshal(signingDocument{
		Algorithm: entitlement.Algorithm, KeyID: signer.keyID, PayloadSHA256: bundle.PayloadSHA256, Payload: bundle.Payload,
	})
	if err != nil {
		t.Fatalf("marshal signing document: %v", err)
	}
	signature, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	bundle.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return bundle
}
