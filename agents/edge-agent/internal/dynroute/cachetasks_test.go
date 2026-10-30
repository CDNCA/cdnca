package dynroute

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/cachetask"
)

func TestCacheTasksRejectInvalidAndUnknownSites(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	tasks := CacheTasks{Runtime: runtime}
	base := cachetask.Task{SchemaVersion: cachetask.SchemaVersion, TaskID: "t", OperationID: "t", TenantID: "a", SiteID: "b",
		DeliveryAttempt: 1, Action: cachetask.ActionPurgeSite, Scope: cachetask.ScopeSite}
	if _, err := tasks.Execute(context.Background(), base); !errors.Is(err, cachetask.ErrSiteNotFound) {
		t.Fatalf("unknown site: %v", err)
	}
	bad := base
	bad.Action = "purge_everything"
	if _, err := tasks.Execute(context.Background(), bad); !errors.Is(err, cachetask.ErrInvalidTask) {
		t.Fatalf("unknown action: %v", err)
	}
	empty := base
	empty.Action = cachetask.ActionPurgeExact
	if _, err := tasks.Execute(context.Background(), empty); !errors.Is(err, cachetask.ErrInvalidTask) {
		t.Fatalf("exact without targets: %v", err)
	}
	if _, err := (CacheTasks{}).Execute(context.Background(), base); !errors.Is(err, cachetask.ErrInvalidTask) {
		t.Fatalf("no runtime: %v", err)
	}
}

func TestResultDigestBindsItems(t *testing.T) {
	result := cachetask.Result{TaskID: "t", Items: []cachetask.ItemResult{{Index: 0, Affected: 1}}}
	first, _ := resultDigest(result)
	result.Items[0].Affected = 2
	second, _ := resultDigest(result)
	if first == second || len(first) != 64 {
		t.Fatalf("%s %s", first, second)
	}
}

// CACHE-ADD-07: a task whose context is cancelled (CacheControlCancel) runs
// none of its remaining targets; each is TASK_CANCELLED and the task is
// cancelled.
func TestCacheTasksStopTargetsAfterCancel(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	tasks := CacheTasks{Runtime: runtime}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, action := range []cachetask.Action{cachetask.ActionPurgeExact, cachetask.ActionPrewarm, cachetask.ActionPurgeSite} {
		task := cachetask.Task{SchemaVersion: cachetask.SchemaVersion, TaskID: "t", OperationID: "t", TenantID: "a", SiteID: "b",
			DeliveryAttempt: 1, Action: action, Scope: cachetask.ScopeURL,
			Targets: []string{"http://a.example/1", "http://a.example/2"}}
		want := 2
		if action == cachetask.ActionPurgeSite {
			task.Scope, task.Targets, want = cachetask.ScopeSite, nil, 1
		}
		result, err := tasks.Execute(ctx, task)
		if err != nil || result.State != cachetask.StateCancelled || len(result.Items) != want || result.Progress.Failed != want {
			t.Fatalf("%s: result=%+v err=%v", action, result, err)
		}
		for _, item := range result.Items {
			if item.Status != cachetask.ItemFailed || item.Code != cachetask.CodeTaskCancelled {
				t.Fatalf("%s: item=%+v", action, item)
			}
		}
	}
}
