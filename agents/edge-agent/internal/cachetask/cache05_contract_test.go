package cachetask

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestCACHE05RetryAfterOverridesAndCapsLocalBackoff(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{name: "delta", raw: "12", want: 12 * time.Second},
		{name: "http-date", raw: now.Add(15 * time.Second).Format(http.TimeFormat), want: 15 * time.Second},
		{name: "cap", raw: "120", want: 30 * time.Second},
		{name: "invalid", raw: "later", want: time.Second},
		{name: "past", raw: now.Add(-time.Second).Format(http.TimeFormat), want: time.Second},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := retryDelayWithServerHint(time.Second, test.raw, now, 30*time.Second); got != test.want {
				t.Fatalf("delay = %s, want %s", got, test.want)
			}
		})
	}
}

func TestCACHE05SiteLimiterIdentitySurvivesConfigRevisionChanges(t *testing.T) {
	t.Parallel()
	first := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	second := testSite("tenant-a", "site-a", "config-v2", "cache.example.test", 18080, 19080, 2)
	if first.CacheIdentity == second.CacheIdentity {
		t.Fatal("fixture cache identities must differ")
	}
	if got, want := siteLimiterIdentity(first), siteLimiterIdentity(second); got != want {
		t.Fatalf("site limiter drifted across config revisions: %q != %q", got, want)
	}
}

func TestCACHE05CarrierReconcilesReceiptWithActiveRevision(t *testing.T) {
	t.Parallel()
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 7)
	task := cache05Task(site)
	executor := cache05ExecutorFunc(func(_ context.Context, input Task) (Result, error) {
		return cache05Result(input), nil
	})
	carrier, err := NewCarrier(executor, cache05ResolverFunc(func(context.Context, string, string, string, uint64) (SiteContext, error) {
		return site, nil
	}))
	if err != nil {
		t.Fatalf("new carrier: %v", err)
	}
	receipt, err := carrier.ExecuteReceipt(context.Background(), task)
	if err != nil {
		t.Fatalf("execute carrier: %v", err)
	}
	if !receipt.ActiveConfigUnchanged || receipt.ConfigRevision != task.ConfigRevision ||
		receipt.ConfigVersionID != task.ConfigVersionID || receipt.OperationID != task.OperationID {
		t.Fatalf("receipt did not reconcile active revision: %+v", receipt)
	}
}

func TestCACHE05CarrierRejectsRevisionChangeAndMismatchedReceipt(t *testing.T) {
	t.Parallel()
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 7)
	task := cache05Task(site)
	t.Run("active revision changed", func(t *testing.T) {
		calls := 0
		resolver := cache05ResolverFunc(func(context.Context, string, string, string, uint64) (SiteContext, error) {
			calls++
			if calls == 1 {
				return site, nil
			}
			changed := site
			changed.ConfigRevision++
			return changed, nil
		})
		carrier, _ := NewCarrier(cache05ExecutorFunc(func(_ context.Context, input Task) (Result, error) {
			return cache05Result(input), nil
		}), resolver)
		if _, err := carrier.Execute(context.Background(), task); !errors.Is(err, ErrCarrierActiveRevision) {
			t.Fatalf("revision change error = %v", err)
		}
	})
	t.Run("receipt identity mismatch", func(t *testing.T) {
		carrier, _ := NewCarrier(cache05ExecutorFunc(func(_ context.Context, input Task) (Result, error) {
			result := cache05Result(input)
			result.SiteID = "site-b"
			return result, nil
		}), cache05ResolverFunc(func(context.Context, string, string, string, uint64) (SiteContext, error) {
			return site, nil
		}))
		if _, err := carrier.Execute(context.Background(), task); !errors.Is(err, ErrCarrierReceiptMismatch) {
			t.Fatalf("receipt mismatch error = %v", err)
		}
	})
}

type cache05ExecutorFunc func(context.Context, Task) (Result, error)

func (execute cache05ExecutorFunc) Execute(ctx context.Context, task Task) (Result, error) {
	return execute(ctx, task)
}

type cache05ResolverFunc func(context.Context, string, string, string, uint64) (SiteContext, error)

func (resolve cache05ResolverFunc) ResolveSite(
	ctx context.Context,
	tenantID, siteID, versionID string,
	revision uint64,
) (SiteContext, error) {
	return resolve(ctx, tenantID, siteID, versionID, revision)
}

func cache05Task(site SiteContext) Task {
	return Task{
		SchemaVersion: SchemaVersion, TaskID: "cache-task-01", OperationID: "cache-operation-01",
		TenantID: site.TenantID, SiteID: site.SiteID, Scope: ScopeURL,
		ConfigVersionID: site.ConfigVersionID, ConfigRevision: site.ConfigRevision,
		DeliveryAttempt: 1, Deadline: time.Date(2026, 8, 8, 1, 0, 0, 0, time.UTC),
		Action: ActionPrewarm, Targets: []string{"https://cache.example.test/a.js"},
	}
}

func cache05Result(task Task) Result {
	completed := time.Date(2026, 8, 8, 0, 1, 0, 0, time.UTC)
	return Result{
		SchemaVersion: SchemaVersion, TaskID: task.TaskID, OperationID: task.OperationID,
		TenantID: task.TenantID, SiteID: task.SiteID, Scope: task.Scope,
		ConfigVersionID: task.ConfigVersionID, ConfigRevision: task.ConfigRevision,
		Digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		State:  StateSucceeded, Attempt: 1, DeliveryAttempt: task.DeliveryAttempt,
		Progress:  Progress{Total: 1, Completed: 1, Succeeded: 1},
		Items:     []ItemResult{{Index: 0, Status: ItemSuccess, Code: CodePrewarmed, Attempts: 1, CompletedAt: completed}},
		StartedAt: completed.Add(-time.Second), CompletedAt: completed,
	}
}
