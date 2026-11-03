package cachecontrolhttp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
)

func TestDispatchCorrelationPreservesAndMapsSparseOrdinals(t *testing.T) {
	for _, ordinals := range [][]int{{1}, {2}, {2, 5}} {
		operation, claim, parameters := dispatchPurgeFixture()
		claim.Targets = make([]cachecontrol.Target, len(ordinals))
		for index, ordinal := range ordinals {
			claim.Targets[index] = cachecontrol.Target{
				Ordinal: ordinal, CanonicalURL: "https://example.com/item/" + string(rune('a'+index)) + "?signature=private-value",
				CanonicalPath: "/item/" + string(rune('a'+index)),
			}
		}
		envelope, err := BuildDispatchEnvelopeV2(operation, claim, parameters)
		if err != nil {
			t.Fatalf("ordinals=%v: %v", ordinals, err)
		}
		if len(envelope.Correlation.Targets) != len(ordinals) {
			t.Fatalf("ordinals=%v correlation=%+v", ordinals, envelope.Correlation.Targets)
		}
		items := make([]DispatchResultItemV2, len(ordinals))
		for index := range ordinals {
			correlation := envelope.Correlation.Targets[index]
			if correlation.Index != index || correlation.TargetOrdinal != ordinals[index] ||
				correlation.TargetDigest != targetDigestForTest(claim.Targets[index].CanonicalURL) {
				t.Fatalf("ordinals=%v correlation=%+v", ordinals, correlation)
			}
			edgeIndex := len(ordinals) - 1 - index
			items[index] = DispatchResultItemV2{
				Index: edgeIndex, TargetDigest: envelope.Correlation.Targets[edgeIndex].TargetDigest,
			}
		}
		mapped, err := MapDispatchResultTargetsV2(envelope.Correlation, items)
		if err != nil || len(mapped) != len(ordinals) {
			t.Fatalf("ordinals=%v mapped=%+v err=%v", ordinals, mapped, err)
		}
		for index, ordinal := range ordinals {
			if mapped[index].TargetOrdinal != ordinal {
				t.Fatalf("ordinals=%v mapped=%+v", ordinals, mapped)
			}
		}
		encoded, err := json.Marshal(envelope.Correlation)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "private-value") || strings.Contains(string(encoded), "https://") {
			t.Fatalf("correlation leaked target URL: %s", encoded)
		}
		items[0].TargetDigest = strings.Repeat("0", 64)
		if _, err := MapDispatchResultTargetsV2(envelope.Correlation, items); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("tampered digest err=%v", err)
		}
	}
}

func TestDispatchResultMappingRejectsAmbiguousOrTamperedItems(t *testing.T) {
	operation, claim, parameters := dispatchPurgeFixture()
	claim.Targets = []cachecontrol.Target{
		{Ordinal: 2, CanonicalURL: "https://example.com/two?secret=do-not-return", CanonicalPath: "/two"},
		{Ordinal: 5, CanonicalURL: "https://example.com/five", CanonicalPath: "/five"},
	}
	envelope, err := BuildDispatchEnvelopeV2(operation, claim, parameters)
	if err != nil {
		t.Fatal(err)
	}
	valid := []DispatchResultItemV2{
		{Index: 0, TargetDigest: envelope.Correlation.Targets[0].TargetDigest},
		{Index: 1, TargetDigest: envelope.Correlation.Targets[1].TargetDigest},
	}
	tests := []struct {
		name  string
		items []DispatchResultItemV2
	}{
		{"missing item", valid[:1]},
		{"duplicate index", []DispatchResultItemV2{valid[0], valid[0]}},
		{"out of range index", []DispatchResultItemV2{valid[0], {Index: 2, TargetDigest: valid[1].TargetDigest}}},
		{"missing digest", []DispatchResultItemV2{valid[0], {Index: 1}}},
		{"tampered digest", []DispatchResultItemV2{valid[0], {Index: 1, TargetDigest: strings.Repeat("0", 64)}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := MapDispatchResultTargetsV2(envelope.Correlation, test.items)
			if !errors.Is(err, ErrInvalidRequest) || strings.Contains(err.Error(), "do-not-return") || strings.Contains(err.Error(), "https://") {
				t.Fatalf("err=%v", err)
			}
		})
	}
	corrupt := envelope.Correlation
	corrupt.Targets = append([]DispatchTargetCorrelation(nil), corrupt.Targets...)
	corrupt.Targets[1].Index = corrupt.Targets[0].Index
	if _, err := MapDispatchResultTargetsV2(corrupt, valid); !errors.Is(err, ErrInvalidStoreResponse) {
		t.Fatalf("corrupt correlation err=%v", err)
	}
	claim.Targets[1].Ordinal = claim.Targets[0].Ordinal
	if _, err := BuildDispatchEnvelopeV2(operation, claim, parameters); !errors.Is(err, ErrInvalidStoreResponse) ||
		strings.Contains(err.Error(), "do-not-return") || strings.Contains(err.Error(), "https://") {
		t.Fatalf("duplicate ordinal err=%v", err)
	}
}

func TestDispatchV2WireConstraints(t *testing.T) {
	tests := []struct {
		name   string
		change func(*cachecontrol.Operation, *cachecontrol.Claim, *DispatchParameters)
	}{
		{"delivery zero", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) { p.DeliveryAttempt = 0 }},
		{"delivery over maximum", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.DeliveryAttempt = EdgeCacheTaskV2MaxDeliveryAttempt + 1
		}},
		{"validation time missing", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.ValidationTime = time.Time{}
		}},
		{"deadline over horizon", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Deadline = p.ValidationTime.Add(EdgeCacheTaskV2MaxDeadlineHorizon + time.Nanosecond)
		}},
		{"attempts zero", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaxAttempts = 0
		}},
		{"attempts over maximum", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaxAttempts = EdgeCacheTaskV2MaxAttempts + 1
		}},
		{"initial backoff short", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.InitialRetryBackoff = time.Millisecond - 1
		}},
		{"initial backoff long", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.InitialRetryBackoff = EdgeCacheTaskV2MaxInitialBackoff + time.Nanosecond
		}},
		{"maximum backoff below initial", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaximumRetryBackoff = p.Budget.InitialRetryBackoff - time.Nanosecond
		}},
		{"maximum backoff long", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaximumRetryBackoff = EdgeCacheTaskV2MaxRetryBackoff + time.Nanosecond
		}},
		{"purge concurrency", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaxConcurrency = 2
		}},
		{"purge entries zero", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaxPurgeEntries = 0
		}},
		{"purge entries over maximum", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaxPurgeEntries = EdgeCacheTaskV2MaxPurgeEntries + 1
		}},
		{"purge scan entries zero", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaxScanEntries = 0
		}},
		{"purge scan entries over maximum", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaxScanEntries = EdgeCacheTaskV2MaxScanEntries + 1
		}},
		{"purge scan bytes zero", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaxScanBytes = 0
		}},
		{"purge scan bytes over maximum", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaxScanBytes = EdgeCacheTaskV2MaxScanBytes + 1
		}},
		{"purge scan duration short", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaxScanDuration = time.Millisecond - 1
		}},
		{"purge scan duration over maximum", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaxScanDuration = EdgeCacheTaskV2MaxScanDuration + time.Nanosecond
		}},
		{"purge bytes", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaxTotalBytes = 1
		}},
		{"purge resource bytes", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.MaxResourceBytes = 1
		}},
		{"purge rate", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) {
			p.Budget.RequestsPerSecond = 1
		}},
		{"purge burst", func(_ *cachecontrol.Operation, _ *cachecontrol.Claim, p *DispatchParameters) { p.Budget.Burst = 1 }},
		{"empty targets", func(_ *cachecontrol.Operation, c *cachecontrol.Claim, _ *DispatchParameters) { c.Targets = nil }},
		{"too many targets", func(_ *cachecontrol.Operation, c *cachecontrol.Claim, _ *DispatchParameters) {
			c.Targets = dispatchTargets(EdgeCacheTaskV2MaxTargets+1, 64)
		}},
		{"target over byte maximum", func(_ *cachecontrol.Operation, c *cachecontrol.Claim, _ *DispatchParameters) {
			c.Targets = dispatchTargets(1, EdgeCacheTaskV2MaxTargetBytes+1)
		}},
		{"targets over total byte maximum", func(_ *cachecontrol.Operation, c *cachecontrol.Claim, _ *DispatchParameters) {
			c.Targets = dispatchTargets(5, (EdgeCacheTaskV2MaxTaskTargetBytes/5)+1)
		}},
		{"claim action mismatch", func(_ *cachecontrol.Operation, c *cachecontrol.Claim, _ *DispatchParameters) {
			c.Action = cachecontrol.ActionPrewarm
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation, claim, parameters := dispatchPurgeFixture()
			test.change(&operation, &claim, &parameters)
			if _, err := BuildDispatchEnvelopeV2(operation, claim, parameters); err == nil {
				t.Fatal("invalid Edge v2 task was accepted")
			}
		})
	}

	prewarmTests := []struct {
		name   string
		change func(*DispatchBudgetV2)
	}{
		{"concurrency zero", func(b *DispatchBudgetV2) { b.MaxConcurrency = 0 }},
		{"concurrency over maximum", func(b *DispatchBudgetV2) { b.MaxConcurrency = EdgeCacheTaskV2MaxConcurrency + 1 }},
		{"purge entries", func(b *DispatchBudgetV2) { b.MaxPurgeEntries = 1 }},
		{"scan entries", func(b *DispatchBudgetV2) { b.MaxScanEntries = 1 }},
		{"scan bytes", func(b *DispatchBudgetV2) { b.MaxScanBytes = 1 }},
		{"scan duration", func(b *DispatchBudgetV2) { b.MaxScanDuration = time.Millisecond }},
		{"resource bytes zero", func(b *DispatchBudgetV2) { b.MaxResourceBytes = 0 }},
		{"resource bytes over maximum", func(b *DispatchBudgetV2) {
			b.MaxResourceBytes = EdgeCacheTaskV2MaxResourceBytes + 1
			b.MaxTotalBytes = b.MaxResourceBytes
		}},
		{"total below resource", func(b *DispatchBudgetV2) { b.MaxTotalBytes = b.MaxResourceBytes - 1 }},
		{"total over maximum", func(b *DispatchBudgetV2) { b.MaxTotalBytes = EdgeCacheTaskV2MaxTotalBytes + 1 }},
		{"rate zero", func(b *DispatchBudgetV2) { b.RequestsPerSecond = 0 }},
		{"rate over maximum", func(b *DispatchBudgetV2) { b.RequestsPerSecond = EdgeCacheTaskV2MaxRequestsPerSecond + 0.1 }},
		{"burst zero", func(b *DispatchBudgetV2) { b.Burst = 0 }},
		{"burst over maximum", func(b *DispatchBudgetV2) { b.Burst = EdgeCacheTaskV2MaxBurst + 1 }},
	}
	for _, test := range prewarmTests {
		t.Run("prewarm "+test.name, func(t *testing.T) {
			operation, claim, parameters := dispatchPrewarmFixture()
			test.change(&parameters.Budget)
			if _, err := BuildDispatchEnvelopeV2(operation, claim, parameters); err == nil {
				t.Fatal("invalid Edge v2 prewarm task was accepted")
			}
		})
	}
}

func dispatchPurgeFixture() (cachecontrol.Operation, cachecontrol.Claim, DispatchParameters) {
	operationID, tenantID, scopeID, siteID, nodeID, leaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	operation := cachecontrol.Operation{
		ID: operationID, TenantID: tenantID, ScopeID: scopeID, SiteID: siteID,
		Action: cachecontrol.ActionPurge, TargetType: cachecontrol.TargetExactURL,
	}
	claim := cachecontrol.Claim{
		OperationID: operationID, ScopeID: scopeID, SiteID: siteID, Action: operation.Action,
		TargetType: operation.TargetType, NodeID: nodeID, LeaseID: leaseID, Attempt: 1,
		Targets: []cachecontrol.Target{{Ordinal: 1, CanonicalURL: "https://example.com/a?x=1", CanonicalPath: "/a"}},
	}
	now := time.Date(2026, 7, 23, 8, 0, 0, 0, time.UTC)
	parameters := DispatchParameters{
		ConfigVersionID: "config-1", ConfigRevision: 1, DeliveryAttempt: 1,
		ValidationTime: now, Deadline: now.Add(time.Hour),
		Budget: DispatchBudgetV2{MaxAttempts: 1, MaxConcurrency: 1, MaxPurgeEntries: 1,
			MaxScanEntries: 1, MaxScanBytes: 1, MaxScanDuration: time.Millisecond,
			InitialRetryBackoff: time.Millisecond, MaximumRetryBackoff: time.Millisecond},
	}
	return operation, claim, parameters
}

func dispatchPrewarmFixture() (cachecontrol.Operation, cachecontrol.Claim, DispatchParameters) {
	operation, claim, parameters := dispatchPurgeFixture()
	operation.Action = cachecontrol.ActionPrewarm
	claim.Action = operation.Action
	parameters.Budget = DispatchBudgetV2{
		MaxAttempts: 1, MaxConcurrency: 1, MaxResourceBytes: 1, MaxTotalBytes: 1,
		RequestsPerSecond: 1, Burst: 1,
		InitialRetryBackoff: time.Millisecond, MaximumRetryBackoff: time.Millisecond,
	}
	return operation, claim, parameters
}

func dispatchTargets(count, targetBytes int) []cachecontrol.Target {
	targets := make([]cachecontrol.Target, count)
	for index := range targets {
		prefix := "https://example.com/a?item=" + strconv.Itoa(index) + "&padding="
		target := prefix + strings.Repeat("x", targetBytes-len(prefix))
		targets[index] = cachecontrol.Target{Ordinal: index + 1, CanonicalURL: target, CanonicalPath: "/a"}
	}
	return targets
}

func targetDigestForTest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
