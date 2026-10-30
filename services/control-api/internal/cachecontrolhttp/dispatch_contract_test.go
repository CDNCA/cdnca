package cachecontrolhttp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
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

func TestDispatchBuilderOutputPassesEdgeV2Validator(t *testing.T) {
	now := time.Date(2026, 7, 23, 9, 0, 0, 0, time.UTC)
	purgeMinOperation, purgeMinClaim, purgeMinParameters := dispatchPurgeFixture()
	purgeMinParameters.ValidationTime = now
	purgeMinParameters.Deadline = now
	purgeMaxOperation, purgeMaxClaim, purgeMaxParameters := dispatchPurgeFixture()
	purgeMaxParameters.ValidationTime = now
	purgeMaxParameters.DeliveryAttempt = EdgeCacheTaskV2MaxDeliveryAttempt
	purgeMaxParameters.Deadline = now.Add(EdgeCacheTaskV2MaxDeadlineHorizon)
	purgeMaxParameters.Budget = DispatchBudgetV2{
		MaxAttempts: EdgeCacheTaskV2MaxAttempts, MaxConcurrency: 1,
		MaxPurgeEntries:     EdgeCacheTaskV2MaxPurgeEntries,
		MaxScanEntries:      EdgeCacheTaskV2MaxScanEntries,
		MaxScanBytes:        EdgeCacheTaskV2MaxScanBytes,
		MaxScanDuration:     EdgeCacheTaskV2MaxScanDuration,
		InitialRetryBackoff: EdgeCacheTaskV2MaxInitialBackoff,
		MaximumRetryBackoff: EdgeCacheTaskV2MaxRetryBackoff,
	}
	purgeBatchOperation, purgeBatchClaim, purgeBatchParameters := dispatchPurgeFixture()
	purgeBatchParameters.ValidationTime = now
	purgeBatchClaim.Targets = dispatchTargets(EdgeCacheTaskV2MaxTargets, 64)
	purgeBytesOperation, purgeBytesClaim, purgeBytesParameters := dispatchPurgeFixture()
	purgeBytesParameters.ValidationTime = now
	purgeBytesClaim.Targets = dispatchTargets(4, EdgeCacheTaskV2MaxTargetBytes)
	prewarmMinOperation, prewarmMinClaim, prewarmMinParameters := dispatchPrewarmFixture()
	prewarmMinParameters.ValidationTime = now
	prewarmMinParameters.Deadline = now
	prewarmMaxOperation, prewarmMaxClaim, prewarmMaxParameters := dispatchPrewarmFixture()
	prewarmMaxParameters.ValidationTime = now
	prewarmMaxParameters.DeliveryAttempt = EdgeCacheTaskV2MaxDeliveryAttempt
	prewarmMaxParameters.Deadline = now.Add(EdgeCacheTaskV2MaxDeadlineHorizon)
	prewarmMaxParameters.Budget = DispatchBudgetV2{
		MaxAttempts: EdgeCacheTaskV2MaxAttempts, MaxConcurrency: EdgeCacheTaskV2MaxConcurrency,
		MaxResourceBytes: EdgeCacheTaskV2MaxResourceBytes, MaxTotalBytes: EdgeCacheTaskV2MaxTotalBytes,
		RequestsPerSecond: EdgeCacheTaskV2MaxRequestsPerSecond, Burst: EdgeCacheTaskV2MaxBurst,
		InitialRetryBackoff: EdgeCacheTaskV2MaxInitialBackoff,
		MaximumRetryBackoff: EdgeCacheTaskV2MaxRetryBackoff,
	}
	inputs := []struct {
		operation  cachecontrol.Operation
		claim      cachecontrol.Claim
		parameters DispatchParameters
		port       uint16
	}{
		{purgeMinOperation, purgeMinClaim, purgeMinParameters, 0},
		{purgeMaxOperation, purgeMaxClaim, purgeMaxParameters, 0},
		{purgeBatchOperation, purgeBatchClaim, purgeBatchParameters, 0},
		{purgeBytesOperation, purgeBytesClaim, purgeBytesParameters, 0},
		{prewarmMinOperation, prewarmMinClaim, prewarmMinParameters, 8443},
		{prewarmMaxOperation, prewarmMaxClaim, prewarmMaxParameters, 8443},
	}
	type edgeCase struct {
		Task            DispatchTaskV2 `json:"task"`
		Site            map[string]any `json:"site"`
		ExpectedDigests []string       `json:"expected_digests"`
	}
	site := func(task DispatchTaskV2, prewarmPort uint16) map[string]any {
		prewarmPathPrefix := ""
		if prewarmPort != 0 {
			prewarmPathPrefix = edgeconfig.CachePrewarmPathPrefix(task.TenantID, task.SiteID,
				task.ConfigVersionID, "example.com", 443, edgeconfig.ProtocolHTTPS)
		}
		return map[string]any{
			"TenantID": task.TenantID, "SiteID": task.SiteID, "ConfigVersionID": task.ConfigVersionID,
			"ConfigRevision": task.ConfigRevision, "Domain": "example.com", "ListenPort": uint16(443),
			"Scheme": "https", "CacheEnabled": true, "PrewarmPort": prewarmPort, "PrewarmPathPrefix": prewarmPathPrefix,
		}
	}
	payload := struct {
		Now      time.Time `json:"now"`
		Contract struct {
			SchemaVersion      int           `json:"schema_version"`
			MaxDeliveryAttempt int           `json:"max_delivery_attempt"`
			MaxTargetBytes     int           `json:"max_target_bytes"`
			MaxInitialBackoff  time.Duration `json:"max_initial_backoff"`
			MaxRetryBackoff    time.Duration `json:"max_retry_backoff"`
		} `json:"contract"`
		Config struct {
			MaxBatchItems         int           `json:"max_batch_items"`
			MaxTaskTargetBytes    int           `json:"max_task_target_bytes"`
			MaxAttempts           int           `json:"max_attempts"`
			MaxTaskConcurrency    int           `json:"max_task_concurrency"`
			MaxPurgeEntries       int           `json:"max_purge_entries"`
			MaxScanEntries        int           `json:"max_scan_entries"`
			MaxScanBytes          int64         `json:"max_scan_bytes"`
			MaxScanDuration       time.Duration `json:"max_scan_duration"`
			MaxResponseBytes      int64         `json:"max_response_bytes"`
			MaxTaskBytes          int64         `json:"max_task_bytes"`
			SiteRequestsPerSecond float64       `json:"site_requests_per_second"`
			SiteBurst             int           `json:"site_burst"`
			MaxDeadlineHorizon    time.Duration `json:"max_deadline_horizon"`
		} `json:"config"`
		Cases []edgeCase `json:"cases"`
	}{Now: now}
	payload.Contract.SchemaVersion = EdgeCacheTaskSchemaVersion
	payload.Contract.MaxDeliveryAttempt = EdgeCacheTaskV2MaxDeliveryAttempt
	payload.Contract.MaxTargetBytes = EdgeCacheTaskV2MaxTargetBytes
	payload.Contract.MaxInitialBackoff = EdgeCacheTaskV2MaxInitialBackoff
	payload.Contract.MaxRetryBackoff = EdgeCacheTaskV2MaxRetryBackoff
	payload.Config.MaxBatchItems = EdgeCacheTaskV2MaxTargets
	payload.Config.MaxTaskTargetBytes = EdgeCacheTaskV2MaxTaskTargetBytes
	payload.Config.MaxAttempts = EdgeCacheTaskV2MaxAttempts
	payload.Config.MaxTaskConcurrency = EdgeCacheTaskV2MaxConcurrency
	payload.Config.MaxPurgeEntries = EdgeCacheTaskV2MaxPurgeEntries
	payload.Config.MaxScanEntries = EdgeCacheTaskV2MaxScanEntries
	payload.Config.MaxScanBytes = EdgeCacheTaskV2MaxScanBytes
	payload.Config.MaxScanDuration = EdgeCacheTaskV2MaxScanDuration
	payload.Config.MaxResponseBytes = EdgeCacheTaskV2MaxResourceBytes
	payload.Config.MaxTaskBytes = EdgeCacheTaskV2MaxTotalBytes
	payload.Config.SiteRequestsPerSecond = EdgeCacheTaskV2MaxRequestsPerSecond
	payload.Config.SiteBurst = EdgeCacheTaskV2MaxBurst
	payload.Config.MaxDeadlineHorizon = EdgeCacheTaskV2MaxDeadlineHorizon
	for _, input := range inputs {
		envelope, err := BuildDispatchEnvelopeV2(input.operation, input.claim, input.parameters)
		if err != nil {
			t.Fatal(err)
		}
		digests := make([]string, len(envelope.Correlation.Targets))
		for index, target := range envelope.Correlation.Targets {
			digests[index] = target.TargetDigest
		}
		payload.Cases = append(payload.Cases, edgeCase{
			Task: envelope.Task, Site: site(envelope.Task, input.port), ExpectedDigests: digests,
		})
	}
	validateTasksWithEdge(t, payload)
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

func validateTasksWithEdge(t *testing.T, payload any) {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "../../../.."))
	edgeRoot := filepath.Join(repositoryRoot, "agents/edge-agent")
	temporary := t.TempDir()
	injected := filepath.Join(temporary, "cachecontrolhttp_overlay_test.go")
	source := `package cachetask

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestCacheControlHTTPDispatchOverlay(t *testing.T) {
	var payload struct {
			Now time.Time ` + "`json:\"now\"`" + `
			Contract struct {
				SchemaVersion int ` + "`json:\"schema_version\"`" + `
				MaxDeliveryAttempt int ` + "`json:\"max_delivery_attempt\"`" + `
				MaxTargetBytes int ` + "`json:\"max_target_bytes\"`" + `
				MaxInitialBackoff time.Duration ` + "`json:\"max_initial_backoff\"`" + `
				MaxRetryBackoff time.Duration ` + "`json:\"max_retry_backoff\"`" + `
			} ` + "`json:\"contract\"`" + `
			Config struct {
				MaxBatchItems int ` + "`json:\"max_batch_items\"`" + `
				MaxTaskTargetBytes int ` + "`json:\"max_task_target_bytes\"`" + `
				MaxAttempts int ` + "`json:\"max_attempts\"`" + `
				MaxTaskConcurrency int ` + "`json:\"max_task_concurrency\"`" + `
				MaxPurgeEntries int ` + "`json:\"max_purge_entries\"`" + `
				MaxScanEntries int ` + "`json:\"max_scan_entries\"`" + `
				MaxScanBytes int64 ` + "`json:\"max_scan_bytes\"`" + `
				MaxScanDuration time.Duration ` + "`json:\"max_scan_duration\"`" + `
				MaxResponseBytes int64 ` + "`json:\"max_response_bytes\"`" + `
				MaxTaskBytes int64 ` + "`json:\"max_task_bytes\"`" + `
				SiteRequestsPerSecond float64 ` + "`json:\"site_requests_per_second\"`" + `
				SiteBurst int ` + "`json:\"site_burst\"`" + `
				MaxDeadlineHorizon time.Duration ` + "`json:\"max_deadline_horizon\"`" + `
			} ` + "`json:\"config\"`" + `
			Cases []struct {
				Task Task ` + "`json:\"task\"`" + `
				Site SiteContext ` + "`json:\"site\"`" + `
				ExpectedDigests []string ` + "`json:\"expected_digests\"`" + `
			} ` + "`json:\"cases\"`" + `
		}
	encoded, err := os.ReadFile(os.Getenv("CACHECONTROLHTTP_EDGE_CASES_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	if SchemaVersion != payload.Contract.SchemaVersion || maxTargetLength != payload.Contract.MaxTargetBytes {
		t.Fatalf("Edge v2 fixed contract drifted: schema=%d target=%d", SchemaVersion, maxTargetLength)
	}
	config := DefaultConfig()
	if config.MaxBatchItems != payload.Config.MaxBatchItems || config.MaxTaskTargetBytes != payload.Config.MaxTaskTargetBytes ||
		config.MaxAttempts != payload.Config.MaxAttempts || config.MaxTaskConcurrency != payload.Config.MaxTaskConcurrency ||
		config.MaxPurgeEntries != payload.Config.MaxPurgeEntries || config.MaxScanEntries != payload.Config.MaxScanEntries ||
		config.MaxScanBytes != payload.Config.MaxScanBytes || config.MaxScanDuration != payload.Config.MaxScanDuration ||
		config.MaxResponseBytes != payload.Config.MaxResponseBytes || config.MaxTaskBytes != payload.Config.MaxTaskBytes ||
		config.SiteRequestsPerSecond != payload.Config.SiteRequestsPerSecond || config.SiteBurst != payload.Config.SiteBurst ||
		config.MaxDeadlineHorizon != payload.Config.MaxDeadlineHorizon {
		t.Fatalf("Edge v2 defaults drifted: %+v", config)
	}
	for index, item := range payload.Cases {
		item.Site.CacheIdentity = CacheNamespaceID(item.Site.TenantID, item.Site.SiteID, item.Site.ConfigVersionID)
		normalized, err := normalizeTask(item.Task, item.Site, config, payload.Now)
		if err != nil {
			t.Fatalf("case %d: %v", index, err)
		}
		if len(normalized.Targets) != len(item.ExpectedDigests) {
			t.Fatalf("case %d digest count: %d != %d", index, len(normalized.Targets), len(item.ExpectedDigests))
		}
		for targetIndex, digest := range item.ExpectedDigests {
			if digest != "" && normalized.Targets[targetIndex].Digest != digest {
				t.Fatalf("case %d target %d digest mismatch", index, targetIndex)
			}
		}
	}
	base := payload.Cases[0]
	base.Site.CacheIdentity = CacheNamespaceID(base.Site.TenantID, base.Site.SiteID, base.Site.ConfigVersionID)
	invalid := []Task{base.Task, base.Task, base.Task}
	invalid[0].DeliveryAttempt = payload.Contract.MaxDeliveryAttempt + 1
	invalid[1].Budget.InitialRetryBackoff = payload.Contract.MaxInitialBackoff + time.Nanosecond
	invalid[1].Budget.MaximumRetryBackoff = invalid[1].Budget.InitialRetryBackoff
	invalid[2].Budget.MaximumRetryBackoff = payload.Contract.MaxRetryBackoff + time.Nanosecond
	for index, task := range invalid {
		if _, err := normalizeTask(task, base.Site, config, payload.Now); err == nil {
			t.Fatalf("Edge accepted adapter boundary +1 case %d", index)
		}
	}
}
`
	if err := os.WriteFile(injected, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(temporary, "overlay.json")
	overlay, err := json.Marshal(struct {
		Replace map[string]string `json:"Replace"`
	}{Replace: map[string]string{
		filepath.Join(edgeRoot, "internal/cachetask/cachecontrolhttp_overlay_test.go"): injected,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "test", "-count=1", "-run", "^TestCacheControlHTTPDispatchOverlay$", "-overlay", overlayPath, "./internal/cachetask")
	command.Dir = edgeRoot
	// 用例经文件传入：JSON 超过 Linux 单个环境变量上限 128KiB（exec 会 E2BIG）。
	casesPath := filepath.Join(temporary, "edge-cases.json")
	if err := os.WriteFile(casesPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	command.Env = append(os.Environ(), "CACHECONTROLHTTP_EDGE_CASES_FILE="+casesPath)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Edge v2 validator rejected builder output: %v\n%s", err, output)
	}
}
