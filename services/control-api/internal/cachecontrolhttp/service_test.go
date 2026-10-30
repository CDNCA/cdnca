package cachecontrolhttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
)

func TestOperationCursorBindsSnapshotScopeAndFilters(t *testing.T) {
	scopeID, userID, siteID := uuid.New(), uuid.New(), uuid.New()
	snapshotPosition := int64(42)
	snapshotTime := time.Date(2026, 7, 23, 4, 0, 0, 0, time.UTC)
	firstID, secondID := uuid.New(), uuid.New()
	calls := 0
	reader := &fakeReader{operationPage: func(_ context.Context, actor cachecontrol.Actor, query OperationPageQuery) (OperationReadPage, error) {
		calls++
		if actor.ScopeID != scopeID || query.Filters.SiteID == nil || *query.Filters.SiteID != siteID || !slices.Equal(query.Filters.States, []cachecontrol.State{cachecontrol.StateQueued}) {
			t.Fatalf("actor=%+v query=%+v", actor, query)
		}
		if calls == 1 {
			if query.SnapshotPosition != 0 || query.BeforeCreated != nil || query.BeforeID != nil {
				t.Fatalf("first query=%+v", query)
			}
			return OperationReadPage{SnapshotPosition: snapshotPosition, HasMore: true, Items: []OperationSummary{
				testOperationSummary(firstID, siteID, snapshotTime.Add(-time.Second)),
			}}, nil
		}
		if query.SnapshotPosition != snapshotPosition || query.BeforeCreated == nil ||
			!query.BeforeCreated.Equal(snapshotTime.Add(-time.Second)) || query.BeforeID == nil || *query.BeforeID != firstID {
			t.Fatalf("cursor query=%+v", query)
		}
		return OperationReadPage{SnapshotPosition: snapshotPosition, Items: []OperationSummary{
			testOperationSummary(secondID, siteID, snapshotTime.Add(-2*time.Second)),
		}}, nil
	}}
	service, err := NewService(&fakeControl{}, reader, bytes.Repeat([]byte{0x2f}, 32))
	if err != nil {
		t.Fatal(err)
	}
	principal := principal(userID, scopeID, "tenant", PermissionOperationsRead)
	filters := OperationFilters{SiteID: &siteID, States: []cachecontrol.State{cachecontrol.StateQueued}}
	first, err := service.Operations(t.Context(), principal, AudienceTenant, nil, OperationListInput{Filters: filters, Limit: 1})
	if err != nil || first.NextCursor == "" || len(first.Items) != 1 {
		t.Fatalf("first page=%+v err=%v", first, err)
	}
	second, err := service.Operations(t.Context(), principal, AudienceTenant, nil, OperationListInput{
		Filters: filters, Limit: 1, Cursor: first.NextCursor,
	})
	if err != nil || second.NextCursor != "" || len(second.Items) != 1 || second.Items[0].ID != secondID {
		t.Fatalf("second page=%+v err=%v", second, err)
	}
	changed := filters
	changed.States = []cachecontrol.State{cachecontrol.StateFailed}
	if _, err := service.Operations(t.Context(), principal, AudienceTenant, nil, OperationListInput{
		Filters: changed, Limit: 1, Cursor: first.NextCursor,
	}); err != ErrInvalidRequest {
		t.Fatalf("filter-bound cursor err=%v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(first.NextCursor)
	if err != nil || len(decoded) <= 32 {
		t.Fatalf("decode cursor: bytes=%d err=%v", len(decoded), err)
	}
	payloadFlip := bytes.Clone(decoded)
	payloadFlip[0] ^= 1
	macFlip := bytes.Clone(decoded)
	macFlip[len(macFlip)-1] ^= 1
	tailReplacement := byte('A')
	if first.NextCursor[len(first.NextCursor)-1] == tailReplacement {
		tailReplacement = 'B'
	}
	differentLegalTail := first.NextCursor[:len(first.NextCursor)-1] + string(tailReplacement)

	nonCanonicalBytes := bytes.Clone(decoded)
	if len(nonCanonicalBytes)%3 == 0 {
		nonCanonicalBytes = append(nonCanonicalBytes, 0)
	}
	nonCanonicalTrailingBits := base64.RawURLEncoding.EncodeToString(nonCanonicalBytes)
	const rawURLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	lastIndex := strings.IndexByte(rawURLAlphabet, nonCanonicalTrailingBits[len(nonCanonicalTrailingBits)-1])
	nonCanonicalTrailingBits = nonCanonicalTrailingBits[:len(nonCanonicalTrailingBits)-1] + string(rawURLAlphabet[lastIndex+1])
	if roundTrip, err := base64.RawURLEncoding.DecodeString(nonCanonicalTrailingBits); err != nil || !bytes.Equal(roundTrip, nonCanonicalBytes) {
		t.Fatalf("non-strict trailing bits fixture: bytes_equal=%t err=%v", bytes.Equal(roundTrip, nonCanonicalBytes), err)
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(nonCanonicalTrailingBits); err == nil {
		t.Fatal("strict base64 accepted non-canonical trailing bits fixture")
	}

	invalidCursors := []struct {
		name  string
		value string
	}{
		{"different legal tail", differentLegalTail},
		{"payload byte flip", base64.RawURLEncoding.EncodeToString(payloadFlip)},
		{"MAC byte flip", base64.RawURLEncoding.EncodeToString(macFlip)},
		{"non-canonical trailing base64 bits", nonCanonicalTrailingBits},
		{"bad base64 alphabet", first.NextCursor[:len(first.NextCursor)-1] + "+"},
		{"truncated", first.NextCursor[:len(first.NextCursor)-1]},
	}
	for _, test := range invalidCursors {
		t.Run(test.name, func(t *testing.T) {
			if test.value == first.NextCursor {
				t.Fatal("tamper fixture did not change cursor")
			}
			for attempt := 0; attempt < 100; attempt++ {
				if _, err := service.Operations(t.Context(), principal, AudienceTenant, nil, OperationListInput{
					Filters: filters, Limit: 1, Cursor: test.value,
				}); err != ErrInvalidRequest {
					t.Fatalf("attempt=%d err=%v", attempt, err)
				}
			}
		})
	}
	if calls != 2 {
		t.Fatalf("reader called for invalid cursor: calls=%d", calls)
	}
}

func TestCacheActorAllowsOnlyPlatformAdminWildcard(t *testing.T) {
	targetScopeID := uuid.New()
	platform := principal(uuid.New(), uuid.New(), "platform", "platform.admin")
	actor, err := cacheActor(platform, AudiencePlatform, &targetScopeID, PermissionOperationsRead)
	if err != nil {
		t.Fatalf("platform.admin wildcard error = %v", err)
	}
	if actor.UserID != platform.UserID || actor.ScopeID != targetScopeID || actor.ActorScopeID != platform.ScopeID {
		t.Fatalf("platform.admin actor = %+v", actor)
	}
	tenantWithPermission := principal(uuid.New(), targetScopeID, "tenant", PermissionOperationsRead)
	tenantActor, err := cacheActor(tenantWithPermission, AudienceTenant, nil, PermissionOperationsRead)
	if err != nil || tenantActor.ScopeID != targetScopeID || tenantActor.ActorScopeID != targetScopeID {
		t.Fatalf("tenant actor = %+v error = %v", tenantActor, err)
	}

	tenant := principal(uuid.New(), targetScopeID, "tenant", "platform.admin")
	if _, err := cacheActor(tenant, AudienceTenant, nil, PermissionOperationsRead); err != ErrPermissionDenied {
		t.Fatalf("tenant platform.admin error = %v, want permission denied", err)
	}
	if _, err := cacheActor(tenant, AudiencePlatform, &targetScopeID, PermissionOperationsRead); err != ErrPermissionDenied {
		t.Fatalf("tenant cross-audience error = %v, want permission denied", err)
	}
}

func TestBuildDispatchEnvelopeV2MatchesEdgeTaskContract(t *testing.T) {
	operationID, tenantID, scopeID, siteID, nodeID, leaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	secretURL := "https://example.com/assets/app.js?signature=edge-only-secret"
	operation := cachecontrol.Operation{
		ID: operationID, TenantID: tenantID, ScopeID: scopeID, SiteID: siteID,
		Action: cachecontrol.ActionPurge, TargetType: cachecontrol.TargetExactURL,
	}
	claim := cachecontrol.Claim{
		OperationID: operationID, ScopeID: scopeID, SiteID: siteID, NodeID: nodeID,
		Action: cachecontrol.ActionPurge, TargetType: cachecontrol.TargetExactURL,
		LeaseID: leaseID, Attempt: 2,
		Targets: []cachecontrol.Target{{Ordinal: 1, CanonicalURL: secretURL, CanonicalPath: "/assets/app.js"}},
	}
	deadline := time.Date(2026, 7, 23, 5, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	envelope, err := BuildDispatchEnvelopeV2(operation, claim, DispatchParameters{
		ConfigVersionID: "config-1042", ConfigRevision: 42, DeliveryAttempt: 3,
		ValidationTime: deadline.Add(-time.Hour), Deadline: deadline,
		Budget: DispatchBudgetV2{MaxAttempts: 3, MaxConcurrency: 1, MaxPurgeEntries: 1000,
			MaxScanEntries: 10000, MaxScanBytes: 8 << 20, MaxScanDuration: 5 * time.Second,
			InitialRetryBackoff: time.Second, MaximumRetryBackoff: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(envelope.Task)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		`"schema_version":2`, `"scope":"url"`, `"action":"purge_exact"`,
		`"config_version_id":"config-1042"`, secretURL,
	} {
		if !strings.Contains(string(encoded), fragment) {
			t.Fatalf("dispatch contract missing %q: %s", fragment, encoded)
		}
	}
	if envelope.Task.TaskID != envelope.Task.OperationID || envelope.Task.Deadline.Location() != time.UTC ||
		envelope.Correlation.LeaseID != leaseID || envelope.Correlation.OperationID != operationID ||
		envelope.Correlation.Attempt != 2 {
		t.Fatalf("dispatch envelope=%+v", envelope)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &keys); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"schema_version", "task_id", "operation_id", "tenant_id", "site_id", "scope",
		"config_version_id", "config_revision", "delivery_attempt", "deadline", "budget", "action", "targets"}
	if len(keys) != len(wantKeys) {
		t.Fatalf("dispatch keys=%v", keys)
	}
	for _, key := range wantKeys {
		if _, exists := keys[key]; !exists {
			t.Fatalf("dispatch key %q missing", key)
		}
	}
}
