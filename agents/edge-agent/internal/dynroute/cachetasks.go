package dynroute

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/cachetask"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
)

// CacheTasks executes cachecontrol tasks (purge_exact, purge_prefix,
// purge_site, prewarm) on the dynamic routing cache: the gateway client's
// CacheTaskManager. A task names its site by tenant and site ID; the
// config version it was claimed against does not select a cache namespace
// (the dynamic routing cache key carries none, D8), so a task of an older
// config version still empties the site's current objects.
type CacheTasks struct {
	Runtime *Runtime
	Now     func() time.Time
	// Sleep waits for the task's request rate (tests inject a clock).
	Sleep func(context.Context, time.Duration) error
	// RequestTimeout bounds one prewarm request (node cache_task
	// prewarm_request_timeout; 0 keeps the prewarmer's).
	RequestTimeout time.Duration
}

// prewarmCodes: the node's stable result codes for the prewarmer's
// outcomes (the console maps these, i18n cacheOperations failures).
var prewarmCodes = map[string]string{
	"PREWARMED": cachetask.CodePrewarmed, "ALREADY_CACHED": cachetask.CodeAlreadyCached,
	"NOT_CACHEABLE": cachetask.CodePrewarmNotCacheable, "STATUS": cachetask.CodePrewarmStatus, "REDIRECT": cachetask.CodePrewarmRedirect,
	"UPSTREAM": cachetask.CodePrewarmUpstream, "TIMEOUT": cachetask.CodePrewarmTimeout,
	"TOO_LARGE": cachetask.CodePrewarmResponseTooLarge, "TASK_BYTES": cachetask.CodePrewarmTaskBytesExceeded,
	"SITE_MISMATCH": cachetask.CodeSiteContextStale,
}

// prewarmBudget is the task's budget (CACHEFLOW-E02: the node's cache_task
// limits, gatewayclient localCacheBudgetFor) as the prewarmer spends it:
// one byte allowance for the whole task and a token bucket every request
// (the verifying one too) waits on.
func (tasks CacheTasks) prewarmBudget(budget cachetask.ResourceBudget, now func() time.Time) dyncache.PrewarmBudget {
	sleep := tasks.Sleep
	if sleep == nil {
		sleep = func(ctx context.Context, value time.Duration) error {
			timer := time.NewTimer(value)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	result := dyncache.PrewarmBudget{MaxObjectBytes: budget.MaxResourceBytes, Timeout: tasks.RequestTimeout}
	if budget.MaxTotalBytes > 0 {
		remaining := budget.MaxTotalBytes
		result.Remaining = &remaining
	}
	if budget.RequestsPerSecond > 0 && budget.Burst > 0 {
		tokens, last := float64(budget.Burst), now()
		result.Wait = func(ctx context.Context) error {
			current := now()
			tokens = min(float64(budget.Burst), tokens+current.Sub(last).Seconds()*budget.RequestsPerSecond)
			last = current
			if tokens < 1 {
				wait := time.Duration((1 - tokens) / budget.RequestsPerSecond * float64(time.Second))
				if err := sleep(ctx, wait); err != nil {
					return err
				}
				last = last.Add(wait)
				tokens = 1
			}
			tokens--
			return nil
		}
	}
	return result
}

// Execute runs one task to completion; a site the node does not serve (or
// serves without a cache) is cachetask.ErrSiteNotFound.
func (tasks CacheTasks) Execute(ctx context.Context, task cachetask.Task) (cachetask.Result, error) {
	now := time.Now
	if tasks.Now != nil {
		now = tasks.Now
	}
	if tasks.Runtime == nil || task.SchemaVersion != cachetask.SchemaVersion || task.TaskID == "" || task.SiteID == "" || task.TenantID == "" {
		return cachetask.Result{}, cachetask.ErrInvalidTask
	}
	started := now().UTC()
	result := cachetask.Result{SchemaVersion: cachetask.SchemaVersion, TaskID: task.TaskID, OperationID: task.OperationID,
		TenantID: task.TenantID, SiteID: task.SiteID, Scope: task.Scope, ConfigVersionID: task.ConfigVersionID,
		ConfigRevision: task.ConfigRevision, DeliveryAttempt: task.DeliveryAttempt, Attempt: 1, StartedAt: started}
	item := func(index int, target string, digest string, status cachetask.ItemStatus, code string, affected int, bytes int64) cachetask.ItemResult {
		return cachetask.ItemResult{Index: index, Target: target, TargetDigest: digest, Status: status, Code: code,
			Affected: affected, Bytes: bytes, Attempts: 1, CompletedAt: now().UTC()}
	}
	// CACHEFLOW-E03: the task's deadline bounds its whole run, queueing
	// included: a task already past it runs nothing, and the I/O in flight
	// stops when it passes (a restart or reconnect does not renew it).
	run := ctx
	expired := !task.Deadline.IsZero() && !now().Before(task.Deadline)
	if !task.Deadline.IsZero() {
		var cancel context.CancelFunc
		run, cancel = context.WithDeadline(ctx, task.Deadline)
		defer cancel()
	}
	stopped := func() bool { return expired || run.Err() != nil }
	// CACHE-ADD-07: targets run one at a time and a cancelled context
	// (CacheControlCancel) or the deadline stops the one in flight and the
	// ones not run yet; a target already run keeps its result.
	stop := func(index int, targets []string) {
		code := cachetask.CodeTaskCancelled
		if ctx.Err() == nil {
			code = cachetask.CodeTaskDeadlineExceeded
		}
		for ; index < len(targets); index++ {
			result.Items = append(result.Items, item(index, targets[index], targetDigest(targets[index]), cachetask.ItemFailed,
				code, 0, 0))
		}
	}
	switch task.Action {
	case cachetask.ActionPurgeSite:
		root := "/*"
		if stopped() {
			stop(0, []string{root})
			break
		}
		_, purged, err := tasks.Runtime.PurgeSite(run, task.TenantID, task.SiteID)
		if err != nil && stopped() {
			stop(0, []string{root})
			break
		}
		if err != nil {
			return cachetask.Result{}, siteError(err)
		}
		result.Items = []cachetask.ItemResult{item(0, root, targetDigest(root), cachetask.ItemSuccess, "PURGED", purged.Affected, purged.Bytes)}
	case cachetask.ActionPurgeExact, cachetask.ActionPurgePrefix:
		if len(task.Targets) == 0 {
			return cachetask.Result{}, cachetask.ErrInvalidTask
		}
		for index, target := range task.Targets {
			if stopped() {
				stop(index, task.Targets)
				break
			}
			purged, err := tasks.Runtime.Purge(run, task.TenantID, task.SiteID, []string{target}, task.Action == cachetask.ActionPurgePrefix)
			if err != nil && stopped() {
				stop(index, task.Targets)
				break
			}
			if err != nil {
				if errors.Is(err, dyncache.ErrInvalid) {
					return cachetask.Result{}, cachetask.ErrInvalidTask
				}
				return cachetask.Result{}, siteError(err)
			}
			result.Items = append(result.Items, item(index, target, targetDigest(target), cachetask.ItemSuccess, "PURGED",
				purged[0].Affected, purged[0].Bytes))
		}
	case cachetask.ActionPrewarm:
		if len(task.Targets) == 0 {
			return cachetask.Result{}, cachetask.ErrInvalidTask
		}
		budget := tasks.prewarmBudget(task.Budget, now)
		for index, target := range task.Targets {
			if stopped() {
				stop(index, task.Targets)
				break
			}
			warmed, err := tasks.Runtime.Prewarm(run, task.TenantID, task.SiteID, []string{target}, budget)
			if err != nil {
				if errors.Is(err, dyncache.ErrInvalid) {
					return cachetask.Result{}, cachetask.ErrInvalidTask
				}
				return cachetask.Result{}, siteError(err)
			}
			status := cachetask.ItemFailed
			if slices.Contains([]string{"PREWARMED", "ALREADY_CACHED"}, warmed[0].Code) {
				status = cachetask.ItemSuccess
			} else if warmed[0].Code == "NOT_CACHEABLE" {
				status = cachetask.ItemSkipped
			}
			if status != cachetask.ItemSuccess && stopped() {
				// the request failed because the task was cancelled or
				// ran out of time, not because of the origin
				stop(index, task.Targets)
				break
			}
			code, known := prewarmCodes[warmed[0].Code]
			if !known {
				code = cachetask.CodePrewarmUpstream
			}
			result.Items = append(result.Items, item(index, target, targetDigest(target), status, code, 0, warmed[0].Bytes))
		}
	default:
		return cachetask.Result{}, cachetask.ErrInvalidTask
	}
	result.Progress = progressOf(result.Items)
	result.State = cachetask.StateSucceeded
	switch {
	case ctx.Err() != nil && slices.ContainsFunc(result.Items, func(item cachetask.ItemResult) bool {
		return item.Code == cachetask.CodeTaskCancelled
	}):
		result.State = cachetask.StateCancelled
	case result.Progress.Failed == len(result.Items):
		result.State = cachetask.StateFailed
	case result.Progress.Failed > 0:
		result.State = cachetask.StatePartialFailed
	}
	result.CompletedAt = now().UTC()
	digest, err := resultDigest(result)
	if err != nil {
		return cachetask.Result{}, err
	}
	result.Digest = digest
	return result, nil
}

func siteError(err error) error {
	if errors.Is(err, ErrSiteNotServed) {
		return cachetask.ErrSiteNotFound
	}
	return err
}

// targetDigest is the control plane's target digest (SHA-256 of the
// canonical URL, cachecontrolruntime command.go).
func targetDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func progressOf(items []cachetask.ItemResult) cachetask.Progress {
	progress := cachetask.Progress{Total: len(items), Completed: len(items)}
	for _, item := range items {
		switch item.Status {
		case cachetask.ItemSuccess:
			progress.Succeeded++
		case cachetask.ItemSkipped:
			progress.Skipped++
		case cachetask.ItemFailed:
			progress.Failed++
		}
		progress.Bytes += item.Bytes
	}
	return progress
}

// resultDigest binds the result's identity and items (the receipt digest).
func resultDigest(result cachetask.Result) (string, error) {
	value := result
	value.Digest = ""
	raw, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("cache task result digest: %w", err)
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}
