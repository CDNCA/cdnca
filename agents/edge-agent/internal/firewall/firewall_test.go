package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var errInjected = errors.New("injected runner failure containing raw task data")

func testStateRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "firewall-state")
}

type fakeRunner struct {
	mu             sync.Mutex
	checkCalls     int
	applyCalls     int
	statusCalls    int
	failCheck      bool
	failApply      bool
	failStatus     int
	activeComment  string
	batches        []string
	checkStarted   chan struct{}
	releaseCheck   chan struct{}
	checkStartOnce sync.Once
}

func (f *fakeRunner) Run(ctx context.Context, arguments ...string) ([]byte, error) {
	switch {
	case len(arguments) == 3 && arguments[0] == "--check" && arguments[1] == "--file":
		batch, err := os.ReadFile(arguments[2])
		if err != nil {
			return nil, err
		}
		f.mu.Lock()
		f.checkCalls++
		fail := f.failCheck
		if fail {
			f.failCheck = false
		}
		started, release := f.checkStarted, f.releaseCheck
		f.mu.Unlock()
		if started != nil {
			f.checkStartOnce.Do(func() { close(started) })
		}
		if release != nil {
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if fail {
			return nil, errInjected
		}
		_ = batch
		return nil, nil
	case len(arguments) == 2 && arguments[0] == "--file":
		batch, err := os.ReadFile(arguments[1])
		if err != nil {
			return nil, err
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.applyCalls++
		if f.failApply {
			f.failApply = false
			return nil, errInjected
		}
		text := string(batch)
		f.batches = append(f.batches, text)
		f.activeComment = batchComment(text)
		return nil, nil
	case len(arguments) == 5 && arguments[0] == "--json" && arguments[1] == "list" && arguments[2] == "table":
		f.mu.Lock()
		defer f.mu.Unlock()
		f.statusCalls++
		if f.failStatus > 0 {
			f.failStatus--
			return nil, errInjected
		}
		if f.activeComment == "" {
			return nil, errInjected
		}
		return json.Marshal(map[string]any{"nftables": []any{
			map[string]any{"metainfo": map[string]any{"json_schema_version": 1}},
			map[string]any{"table": map[string]any{"family": TableFamily, "name": TableName, "comment": f.activeComment}},
		}})
	default:
		return nil, fmt.Errorf("unexpected runner arguments")
	}
}

func (f *fakeRunner) counts() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checkCalls, f.applyCalls, f.statusCalls
}

func (f *fakeRunner) lastBatch() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.batches) == 0 {
		return ""
	}
	return f.batches[len(f.batches)-1]
}

func batchComment(batch string) string {
	const prefix = `comment "`
	start := strings.Index(batch, prefix)
	if start < 0 {
		return ""
	}
	start += len(prefix)
	end := strings.Index(batch[start:], `"`)
	if end < 0 {
		return ""
	}
	return batch[start : start+end]
}

func fixedTime() time.Time {
	return time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
}

func validVersion(taskID, versionID string) FirewallVersion {
	return FirewallVersion{
		TaskID: taskID, VersionID: versionID,
		Entries: []Entry{{
			Action: ActionDeny, Network: "198.51.100.7", Source: "manual", Reason: "abuse",
		}},
	}
}

func newTestManager(t *testing.T, root string, runner Runner, now func() time.Time) *Manager {
	t.Helper()
	manager, err := NewManagerWithDependencies(root, runner, now)
	if err != nil {
		t.Fatalf("NewManagerWithDependencies() error = %v", err)
	}
	manager.admitAllTenants = true
	return manager
}

func TestCompileIsDeterministicAndUsesOwnedSets(t *testing.T) {
	expires := fixedTime().Add(24 * time.Hour)
	version := FirewallVersion{TaskID: "task-v1", VersionID: "fw-v1", Entries: []Entry{
		{Action: ActionDeny, Network: "2001:0DB8:1::1/48", Source: "feed", Reason: "v6", ExpiresAt: &expires},
		{Action: ActionAllow, Network: "192.0.2.10", Source: "manual", Reason: "trusted"},
		{Action: ActionDeny, Network: "198.51.100.129/24", Source: "feed", Reason: "v4"},
		{Action: ActionAllow, Network: "192.0.2.10/32", Source: "manual", Reason: "trusted"},
	}}
	first, err := Compile(version)
	if err != nil {
		t.Fatalf("Compile(first) error = %v", err)
	}
	reversed := version
	reversed.Entries = append([]Entry(nil), version.Entries...)
	for left, right := 0, len(reversed.Entries)-1; left < right; left, right = left+1, right-1 {
		reversed.Entries[left], reversed.Entries[right] = reversed.Entries[right], reversed.Entries[left]
	}
	second, err := Compile(reversed)
	if err != nil {
		t.Fatalf("Compile(reversed) error = %v", err)
	}
	if first.Digest != second.Digest || !reflect.DeepEqual(first.Version, second.Version) || string(first.Batch) != string(second.Batch) {
		t.Fatal("equivalent firewall entries produced different output")
	}
	if len(first.Version.Entries) != 3 {
		t.Fatalf("normalized entry count = %d, want 3", len(first.Version.Entries))
	}
	batch := string(first.Batch)
	for _, fragment := range []string{
		"destroy table inet cdnca_firewall",
		"add table inet cdnca_firewall",
		"add set inet cdnca_firewall allow_v4",
		"add set inet cdnca_firewall allow_v6",
		"add set inet cdnca_firewall deny_v4",
		"add set inet cdnca_firewall deny_v6",
		"flags interval; auto-merge;",
		"192.0.2.10/32",
		"198.51.100.0/24",
		"2001:db8:1::/48",
		"ip saddr @allow_v4 accept",
		"ip6 saddr @allow_v6 accept",
		"ip saddr @deny_v4 counter limit name \"cdnca_drop_log\" log prefix \"cdnca-fw ipset\" drop",
		"ip6 saddr @deny_v6 counter limit name \"cdnca_drop_log\" log prefix \"cdnca-fw ipset\" drop",
		"cdnca version=fw-v1 digest=" + first.Digest,
	} {
		if !strings.Contains(batch, fragment) {
			t.Errorf("compiled batch missing %q:\n%s", fragment, batch)
		}
	}
	if strings.Contains(batch, "flush ruleset") || strings.Contains(batch, "manual") || strings.Contains(batch, "trusted") || strings.Contains(batch, "abuse") {
		t.Fatalf("compiled batch contains a forbidden global operation or metadata:\n%s", batch)
	}
	allow := strings.Index(batch, "ip saddr @allow_v4 accept")
	deny := strings.Index(batch, "ip saddr @deny_v4 counter limit name \"cdnca_drop_log\" log prefix \"cdnca-fw ipset\" drop")
	if allow < 0 || deny <= allow {
		t.Fatalf("allow precedence is not deterministic:\n%s", batch)
	}
}

func TestCompileRejectsInvalidFirewallVersion(t *testing.T) {
	tests := map[string]func(*FirewallVersion){
		"missing task":       func(version *FirewallVersion) { version.TaskID = "" },
		"task injection":     func(version *FirewallVersion) { version.TaskID = "task/escape" },
		"missing version":    func(version *FirewallVersion) { version.VersionID = "" },
		"version injection":  func(version *FirewallVersion) { version.VersionID = "fw; flush ruleset" },
		"unknown action":     func(version *FirewallVersion) { version.Entries[0].Action = "reject" },
		"missing network":    func(version *FirewallVersion) { version.Entries[0].Network = "" },
		"all IPv4":           func(version *FirewallVersion) { version.Entries[0].Network = "0.0.0.0/0" },
		"all IPv6":           func(version *FirewallVersion) { version.Entries[0].Network = "::/0" },
		"noncanonical all":   func(version *FirewallVersion) { version.Entries[0].Network = "192.0.2.1/0" },
		"IPv4 multicast":     func(version *FirewallVersion) { version.Entries[0].Network = "224.0.0.0/4" },
		"IPv6 multicast":     func(version *FirewallVersion) { version.Entries[0].Network = "ff00::/8" },
		"IPv4 link local":    func(version *FirewallVersion) { version.Entries[0].Network = "169.254.1.1" },
		"IPv4 overlaps link": func(version *FirewallVersion) { version.Entries[0].Network = "169.0.0.0/8" },
		"IPv6 link local":    func(version *FirewallVersion) { version.Entries[0].Network = "fe80::/10" },
		"mapped IPv6":        func(version *FirewallVersion) { version.Entries[0].Network = "::ffff:192.0.2.1/128" },
		"zoned IPv6":         func(version *FirewallVersion) { version.Entries[0].Network = "fe80::1%eth0" },
		"unspecified IP":     func(version *FirewallVersion) { version.Entries[0].Network = "0.0.0.0" },
		"missing source":     func(version *FirewallVersion) { version.Entries[0].Source = "" },
		"source too long":    func(version *FirewallVersion) { version.Entries[0].Source = strings.Repeat("a", 65) },
		"source control":     func(version *FirewallVersion) { version.Entries[0].Source = "feed\nsecret" },
		"missing reason":     func(version *FirewallVersion) { version.Entries[0].Reason = "" },
		"reason too long":    func(version *FirewallVersion) { version.Entries[0].Reason = strings.Repeat("a", 257) },
		"reason control":     func(version *FirewallVersion) { version.Entries[0].Reason = "bad\rvalue" },
		"zero expiration": func(version *FirewallVersion) {
			zero := time.Time{}
			version.Entries[0].ExpiresAt = &zero
		},
		"duplicate metadata conflict": func(version *FirewallVersion) {
			duplicate := version.Entries[0]
			duplicate.Reason = "different"
			version.Entries = append(version.Entries, duplicate)
		},
		"too many entries": func(version *FirewallVersion) {
			version.Entries = make([]Entry, 10001)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			version := validVersion("task-v1", "fw-v1")
			mutate(&version)
			if _, err := Compile(version); !errors.Is(err, ErrInvalidVersion) {
				t.Fatalf("Compile() error = %v, want ErrInvalidVersion", err)
			}
		})
	}
}

func TestCompileAllowsOverlappingAllowAndDenyWithAllowPrecedence(t *testing.T) {
	version := validVersion("task-v1", "fw-v1")
	version.Entries = []Entry{
		{Action: ActionDeny, Network: "203.0.113.0/24", Source: "feed", Reason: "network"},
		{Action: ActionAllow, Network: "203.0.113.7", Source: "manual", Reason: "exception"},
	}
	if _, err := Compile(version); err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
}

func TestApplyIsIdempotentAndRecoversAcrossRestart(t *testing.T) {
	root := testStateRoot(t)
	runner := &fakeRunner{}
	manager := newTestManager(t, root, runner, fixedTime)
	version := validVersion("task-v1", "fw-v1")

	first, err := manager.Apply(context.Background(), version)
	if err != nil {
		t.Fatalf("Apply(first) error = %v", err)
	}
	if first.State != StateApplied || first.ActiveVersionID != "fw-v1" || first.RunningVersionUnchanged {
		t.Fatalf("first result = %+v", first)
	}
	beforeCheck, beforeApply, beforeStatus := runner.counts()
	second, err := manager.Apply(context.Background(), version)
	if err != nil {
		t.Fatalf("Apply(replay) error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("replayed result differs\nfirst=%+v\nsecond=%+v", first, second)
	}
	afterCheck, afterApply, afterStatus := runner.counts()
	if beforeCheck != afterCheck || beforeApply != afterApply || beforeStatus != afterStatus {
		t.Fatalf("replay reran nft: before=%d/%d/%d after=%d/%d/%d", beforeCheck, beforeApply, beforeStatus, afterCheck, afterApply, afterStatus)
	}

	conflict := version
	conflict.Entries = append([]Entry(nil), version.Entries...)
	conflict.Entries[0].Reason = "different payload"
	if _, err := manager.Apply(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("Apply(task conflict) error = %v, want ErrConflict", err)
	}
	reusedVersion := validVersion("task-v2", "fw-v1")
	reusedVersion.Entries[0].Network = "203.0.113.9"
	if _, err := manager.Apply(context.Background(), reusedVersion); !errors.Is(err, ErrConflict) {
		t.Fatalf("Apply(version conflict) error = %v, want ErrConflict", err)
	}
	sameVersion := version
	sameVersion.TaskID = "task-v3"
	if result, err := manager.Apply(context.Background(), sameVersion); err != nil || result.State != StateApplied || result.VersionID != version.VersionID {
		t.Fatalf("Apply(same version and payload) result=%+v error=%v", result, err)
	}

	restarted := newTestManager(t, root, runner, fixedTime)
	status, err := restarted.Status(context.Background())
	if err != nil {
		t.Fatalf("Status(restarted) error = %v", err)
	}
	if !status.Active || !status.Healthy || status.VersionID != "fw-v1" || status.Digest != first.Digest || status.EntryCount != 1 {
		t.Fatalf("restarted status = %+v", status)
	}
}

func TestPersistedFirewallMetadataIsOwnerOnly(t *testing.T) {
	root := testStateRoot(t)
	manager := newTestManager(t, root, &fakeRunner{}, fixedTime)
	version := validVersion("task-v1", "fw-v1")
	if result, err := manager.Apply(context.Background(), version); err != nil || result.State != StateApplied {
		t.Fatalf("Apply() result=%+v error=%v", result, err)
	}
	for _, path := range []string{
		filepath.Join(root, "active.json"),
		filepath.Join(root, "versions", "fw-v1.json"),
		filepath.Join(root, "tasks", "task-v1.json"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat(%q) error=%v", path, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("state file %q mode=%#o, want 0600", path, info.Mode().Perm())
		}
	}
	content, err := os.ReadFile(filepath.Join(root, "versions", "fw-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `"source":"manual"`) || !strings.Contains(string(content), `"reason":"abuse"`) {
		t.Fatalf("version state omitted firewall metadata: %s", content)
	}
}

func TestManagerRejectsStateWritableOrReadableByOtherAccounts(t *testing.T) {
	t.Run("state root", func(t *testing.T) {
		root := testStateRoot(t)
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := NewManagerWithDependencies(root, &fakeRunner{}, fixedTime); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("NewManagerWithDependencies() error=%v, want ErrInvalidPath", err)
		}
	})

	t.Run("state file after restart", func(t *testing.T) {
		root := testStateRoot(t)
		manager := newTestManager(t, root, &fakeRunner{}, fixedTime)
		if result, err := manager.Apply(context.Background(), validVersion("task-v1", "fw-v1")); err != nil || result.State != StateApplied {
			t.Fatalf("Apply() result=%+v error=%v", result, err)
		}
		if err := os.Chmod(filepath.Join(root, "active.json"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Status(context.Background()); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("Status() error=%v, want ErrCorruptState", err)
		}
	})
}

func TestApplyFailuresKeepPreviousVersion(t *testing.T) {
	for _, failure := range []string{"check", "apply", "status"} {
		t.Run(failure, func(t *testing.T) {
			root := testStateRoot(t)
			runner := &fakeRunner{}
			manager := newTestManager(t, root, runner, fixedTime)
			if result, err := manager.Apply(context.Background(), validVersion("task-v1", "fw-v1")); err != nil || result.State != StateApplied {
				t.Fatalf("Apply(v1) result=%+v error=%v", result, err)
			}
			switch failure {
			case "check":
				runner.failCheck = true
			case "apply":
				runner.failApply = true
			case "status":
				runner.failStatus = 1
			}
			candidate := validVersion("task-v2", "fw-v2")
			candidate.Entries[0].Network = "203.0.113.8"
			result, err := manager.Apply(context.Background(), candidate)
			if err != nil {
				t.Fatalf("Apply(v2) error = %v", err)
			}
			wantCode := map[string]string{"check": "CHECK_FAILED", "apply": "APPLY_FAILED", "status": "HEALTH_FAILED"}[failure]
			if result.State != StateFailed || result.ErrorCode != wantCode || result.ActiveVersionID != "fw-v1" || !result.RunningVersionUnchanged {
				t.Fatalf("Apply(v2) result = %+v", result)
			}
			status, err := manager.Status(context.Background())
			if err != nil || !status.Healthy || status.VersionID != "fw-v1" {
				t.Fatalf("Status() = %+v error=%v", status, err)
			}
			checks, applies, statuses := runner.counts()
			replayed, err := manager.Apply(context.Background(), candidate)
			if err != nil || !reflect.DeepEqual(result, replayed) {
				t.Fatalf("failed task replay result=%+v error=%v", replayed, err)
			}
			if gotCheck, gotApply, gotStatus := runner.counts(); gotCheck != checks || gotApply != applies || gotStatus != statuses {
				t.Fatalf("failed replay reran nft: before=%d/%d/%d after=%d/%d/%d", checks, applies, statuses, gotCheck, gotApply, gotStatus)
			}
		})
	}
}

func TestSaveActiveFailureReportsRollbackFailure(t *testing.T) {
	root := testStateRoot(t)
	runner := &fakeRunner{}
	manager := newTestManager(t, root, runner, fixedTime)
	if result, err := manager.Apply(context.Background(), validVersion("task-v1", "fw-v1")); err != nil || result.State != StateApplied {
		t.Fatalf("Apply(v1) result=%+v error=%v", result, err)
	}
	manager.saveActive = func(activeRecord) error {
		runner.failCheck = true
		return errInjected
	}
	candidate := validVersion("task-v2", "fw-v2")
	candidate.Entries[0].Network = "203.0.113.8"
	result, err := manager.Apply(context.Background(), candidate)
	if err != nil {
		t.Fatalf("Apply(v2) error = %v", err)
	}
	if result.State != StateRollbackFailed || result.ErrorCode != "ROLLBACK_FAILED" || result.RunningVersionUnchanged {
		t.Fatalf("Apply(v2) result = %+v", result)
	}
}

func TestConcurrentManagersSerializeApply(t *testing.T) {
	root := testStateRoot(t)
	runner := &fakeRunner{checkStarted: make(chan struct{}), releaseCheck: make(chan struct{})}
	firstManager := newTestManager(t, root, runner, fixedTime)
	secondManager := newTestManager(t, root, runner, fixedTime)
	type outcome struct {
		result Result
		err    error
	}
	firstDone := make(chan outcome, 1)
	secondDone := make(chan outcome, 1)
	go func() {
		result, err := firstManager.Apply(context.Background(), validVersion("task-v1", "fw-v1"))
		firstDone <- outcome{result: result, err: err}
	}()
	<-runner.checkStarted
	secondStarted := make(chan struct{})
	go func() {
		close(secondStarted)
		result, err := secondManager.Apply(context.Background(), validVersion("task-v2", "fw-v2"))
		secondDone <- outcome{result: result, err: err}
	}()
	<-secondStarted
	time.Sleep(30 * time.Millisecond)
	checks, _, _ := runner.counts()
	if checks != 1 {
		t.Fatalf("concurrent apply entered runner before lock release: checks=%d", checks)
	}
	close(runner.releaseCheck)
	first, second := <-firstDone, <-secondDone
	if first.err != nil || second.err != nil || first.result.State != StateApplied || second.result.State != StateApplied {
		t.Fatalf("concurrent results: first=%+v/%v second=%+v/%v", first.result, first.err, second.result, second.err)
	}
	status, err := firstManager.Status(context.Background())
	if err != nil || status.VersionID != "fw-v2" || !status.Healthy {
		t.Fatalf("final Status() = %+v error=%v", status, err)
	}
}

func TestManagerConstructionDoesNotDeleteInFlightTransaction(t *testing.T) {
	root := testStateRoot(t)
	runner := &fakeRunner{checkStarted: make(chan struct{}), releaseCheck: make(chan struct{})}
	manager := newTestManager(t, root, runner, fixedTime)
	type outcome struct {
		result Result
		err    error
	}
	applyDone := make(chan outcome, 1)
	go func() {
		result, err := manager.Apply(context.Background(), validVersion("task-v1", "fw-v1"))
		applyDone <- outcome{result: result, err: err}
	}()
	<-runner.checkStarted

	constructionDone := make(chan error, 1)
	go func() {
		_, err := NewManagerWithDependencies(root, runner, fixedTime)
		constructionDone <- err
	}()
	select {
	case err := <-constructionDone:
		t.Fatalf("manager construction bypassed in-flight publication lock: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	close(runner.releaseCheck)
	result := <-applyDone
	if result.err != nil || result.result.State != StateApplied {
		t.Fatalf("in-flight Apply() result=%+v error=%v", result.result, result.err)
	}
	if err := <-constructionDone; err != nil {
		t.Fatalf("NewManagerWithDependencies() error=%v", err)
	}
}

func TestExpireBuildsAndAppliesNewImmutableVersion(t *testing.T) {
	root := testStateRoot(t)
	runner := &fakeRunner{}
	now := fixedTime()
	manager := newTestManager(t, root, runner, func() time.Time { return now })
	expires := now.Add(time.Hour)
	version := validVersion("task-v1", "fw-v1")
	version.Entries = []Entry{
		{Action: ActionDeny, Network: "198.51.100.7", Source: "feed", Reason: "temporary", ExpiresAt: &expires},
		{Action: ActionDeny, Network: "203.0.113.8", Source: "manual", Reason: "persistent"},
	}
	first, err := manager.Apply(context.Background(), version)
	if err != nil || first.State != StateApplied {
		t.Fatalf("Apply(v1) result=%+v error=%v", first, err)
	}
	now = expires.Add(time.Second)
	second, err := manager.Expire(context.Background(), "task-expire-v2", "fw-v2")
	if err != nil || second.State != StateApplied || second.ActiveVersionID != "fw-v2" {
		t.Fatalf("Expire() result=%+v error=%v", second, err)
	}
	batch := runner.lastBatch()
	if strings.Contains(batch, "198.51.100.7/32") || !strings.Contains(batch, "203.0.113.8/32") {
		t.Fatalf("expiration batch did not remove only expired entry:\n%s", batch)
	}
	status, err := manager.Status(context.Background())
	if err != nil || status.VersionID != "fw-v2" || status.EntryCount != 1 {
		t.Fatalf("Status()=%+v error=%v", status, err)
	}
	originalPath := filepath.Join(root, "versions", "fw-v1.json")
	content, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatalf("ReadFile(original version) error = %v", err)
	}
	if !strings.Contains(string(content), "198.51.100.7/32") {
		t.Fatalf("expiration mutated original version: %s", content)
	}
	if replayed, err := manager.Apply(context.Background(), version); err != nil || !reflect.DeepEqual(first, replayed) {
		t.Fatalf("expired original task did not replay exactly: result=%+v error=%v", replayed, err)
	}
	newTask := version
	newTask.TaskID = "task-reapply-expired"
	if _, err := manager.Apply(context.Background(), newTask); !errors.Is(err, ErrExpiredEntry) {
		t.Fatalf("new task with expired entry error=%v, want ErrExpiredEntry", err)
	}
}

func TestExpireScopedAggregatePreservesOwnerAndPolicyState(t *testing.T) {
	root := testStateRoot(t)
	runner := &fakeRunner{}
	now := fixedTime()
	manager := newTestManager(t, root, runner, func() time.Time { return now })
	tenantA, siteA := "77777777-7777-4777-8777-777777777777", "44444444-4444-4444-8444-444444444444"
	tenantB, siteB := "88888888-8888-4888-8888-888888888888", "55555555-5555-4555-8555-555555555555"
	expires := now.Add(time.Minute)
	later := now.Add(time.Hour)
	shared := "198.51.100.0/24"
	uniqueExpired := "2001:db8:1::/48"
	permanent := "203.0.113.0/24"

	ownerA := scopedVersion("task-a-1", "11111111-1111-4111-8111-111111111111", tenantA, siteA, 1, 0, shared)
	ownerA.Entries = []Entry{
		{TenantID: tenantA, SiteID: siteA, Action: ActionDeny, Network: shared, Source: "automatic", Reason: "ttl", ExpiresAt: &expires},
		{TenantID: tenantA, SiteID: siteA, Action: ActionDeny, Network: uniqueExpired, Source: "automatic", Reason: "ttl", ExpiresAt: &expires},
		{TenantID: tenantA, SiteID: siteA, Action: ActionAllow, Network: permanent, Source: "manual", Reason: "trusted"},
	}
	ownerB := scopedVersion("task-b-1", "22222222-2222-4222-8222-222222222222", tenantB, siteB, 1, 0, shared)
	ownerB.Entries = []Entry{
		{TenantID: tenantB, SiteID: siteB, Action: ActionDeny, Network: shared, Source: "automatic", Reason: "ttl", ExpiresAt: &later},
		{TenantID: tenantB, SiteID: siteB, Action: ActionDeny, Network: "2001:db8:2::/48", Source: "manual", Reason: "persistent"},
	}
	for _, version := range []FirewallVersion{ownerA, ownerB} {
		if result, err := manager.Apply(context.Background(), version); err != nil || result.State != StateApplied {
			t.Fatalf("Apply(%s) result=%+v error=%v", version.TaskID, result, err)
		}
	}
	before, err := manager.store.loadActive()
	if err != nil || before == nil {
		t.Fatalf("loadActive(before)=%+v error=%v", before, err)
	}
	now = expires.Add(time.Second)
	result, err := manager.Expire(context.Background(), "ttl-expire-1767323100", "ttl-runtime-1767323100")
	if err != nil || result.State != StateApplied || result.ActiveVersionID != "ttl-runtime-1767323100" {
		t.Fatalf("Expire() result=%+v error=%v", result, err)
	}
	batch := runner.lastBatch()
	if !strings.Contains(batch, shared) || strings.Contains(batch, uniqueExpired) || !strings.Contains(batch, permanent) {
		t.Fatalf("expiration did not preserve aggregate ownership:\n%s", batch)
	}
	for _, expected := range []struct {
		tenant, site string
		entries      int
	}{
		{tenantA, siteA, 1},
		{tenantB, siteB, 2},
	} {
		status, statusErr := manager.ScopeStatus(context.Background(), expected.tenant, expected.site)
		if statusErr != nil || status.PolicyVersion != 1 || status.TaskRevision != 1 || status.EntryCount != expected.entries {
			t.Fatalf("ScopeStatus(%s)=%+v error=%v", expected.tenant, status, statusErr)
		}
	}
	after, err := manager.store.loadActive()
	if err != nil || after == nil || len(after.Scopes) != len(before.Scopes) {
		t.Fatalf("loadActive(after)=%+v error=%v", after, err)
	}
	for index := range before.Scopes {
		if before.Scopes[index].TenantID != after.Scopes[index].TenantID ||
			before.Scopes[index].SiteID != after.Scopes[index].SiteID ||
			before.Scopes[index].PolicyVersion != after.Scopes[index].PolicyVersion ||
			before.Scopes[index].TaskRevision != after.Scopes[index].TaskRevision ||
			before.Scopes[index].IdempotencyKey != after.Scopes[index].IdempotencyKey ||
			before.Scopes[index].CommandDigest != after.Scopes[index].CommandDigest {
			t.Fatalf("scope metadata changed: before=%+v after=%+v", before.Scopes[index], after.Scopes[index])
		}
	}

	restarted := newTestManager(t, root, runner, func() time.Time { return now })
	checks, applies, statuses := runner.counts()
	replayed, err := restarted.Expire(context.Background(), "ttl-expire-1767323100", "ttl-runtime-1767323100")
	if err != nil || !reflect.DeepEqual(result, replayed) {
		t.Fatalf("Expire(replay) result=%+v error=%v", replayed, err)
	}
	if gotChecks, gotApplies, gotStatuses := runner.counts(); gotChecks != checks || gotApplies != applies || gotStatuses != statuses {
		t.Fatalf("expiry replay called nft: before=%d/%d/%d after=%d/%d/%d", checks, applies, statuses, gotChecks, gotApplies, gotStatuses)
	}
	if _, err := restarted.Expire(context.Background(), "ttl-expire-1767323160", "ttl-runtime-1767323160"); !errors.Is(err, ErrNoExpiredEntry) {
		t.Fatalf("Expire(no expired) error=%v, want ErrNoExpiredEntry", err)
	}
	if gotChecks, gotApplies, gotStatuses := runner.counts(); gotChecks != checks || gotApplies != applies || gotStatuses != statuses {
		t.Fatalf("no-op expiry called nft: before=%d/%d/%d after=%d/%d/%d", checks, applies, statuses, gotChecks, gotApplies, gotStatuses)
	}
}

func TestExpireScopedAggregateFailuresPreserveLKG(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Manager, *fakeRunner)
		state     ApplyState
		code      string
	}{
		{name: "check", configure: func(_ *Manager, runner *fakeRunner) { runner.failCheck = true }, state: StateFailed, code: "CHECK_FAILED"},
		{name: "apply", configure: func(_ *Manager, runner *fakeRunner) { runner.failApply = true }, state: StateRolledBack, code: "APPLY_FAILED"},
		{name: "health", configure: func(_ *Manager, runner *fakeRunner) { runner.failStatus = 1 }, state: StateRolledBack, code: "HEALTH_FAILED"},
		{name: "state commit", configure: func(manager *Manager, _ *fakeRunner) {
			manager.saveActive = func(activeRecord) error { return errInjected }
		}, state: StateRolledBack, code: "STATE_COMMIT_FAILED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := testStateRoot(t)
			runner := &fakeRunner{}
			now := fixedTime()
			manager := newTestManager(t, root, runner, func() time.Time { return now })
			tenant, site := "77777777-7777-4777-8777-777777777777", "44444444-4444-4444-8444-444444444444"
			expires := now.Add(time.Minute)
			version := scopedVersion("task-a-1", "11111111-1111-4111-8111-111111111111", tenant, site, 1, 0, "198.51.100.0/24")
			version.Entries[0].ExpiresAt = &expires
			if _, err := manager.Apply(context.Background(), version); err != nil {
				t.Fatal(err)
			}
			before, err := manager.store.loadActive()
			if err != nil || before == nil {
				t.Fatalf("loadActive(before)=%+v error=%v", before, err)
			}
			now = expires.Add(time.Second)
			test.configure(manager, runner)
			result, err := manager.Expire(context.Background(), "ttl-expire-failure", "ttl-runtime-failure")
			if err != nil || result.State != test.state || result.ErrorCode != test.code || !result.RunningVersionUnchanged {
				t.Fatalf("Expire() result=%+v error=%v", result, err)
			}
			after, err := manager.store.loadActive()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("expiry failure changed LKG: before=%+v after=%+v error=%v", before, after, err)
			}
			if _, err := os.Stat(manager.store.inflightPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("settled expiry retained journal: %v", err)
			}
			checks, applies, statuses := runner.counts()
			replayed, err := manager.Expire(context.Background(), "ttl-expire-failure", "ttl-runtime-failure")
			if err != nil || !reflect.DeepEqual(result, replayed) {
				t.Fatalf("Expire(replay) result=%+v error=%v", replayed, err)
			}
			if gotChecks, gotApplies, gotStatuses := runner.counts(); gotChecks != checks || gotApplies != applies || gotStatuses != statuses {
				t.Fatalf("failure replay called nft: before=%d/%d/%d after=%d/%d/%d", checks, applies, statuses, gotChecks, gotApplies, gotStatuses)
			}
		})
	}
}

func TestApplyRejectsAlreadyExpiredEntryWithoutCallingNft(t *testing.T) {
	runner := &fakeRunner{}
	manager := newTestManager(t, testStateRoot(t), runner, fixedTime)
	expires := fixedTime()
	version := validVersion("task-expired", "fw-expired")
	version.Entries[0].ExpiresAt = &expires
	if _, err := manager.Apply(context.Background(), version); !errors.Is(err, ErrExpiredEntry) {
		t.Fatalf("Apply() error=%v, want ErrExpiredEntry", err)
	}
	if checks, applies, statuses := runner.counts(); checks != 0 || applies != 0 || statuses != 0 {
		t.Fatalf("expired entry called nft: %d/%d/%d", checks, applies, statuses)
	}
}

func TestScopedApplyEnforcesCASIdempotencyAndOwnerIsolation(t *testing.T) {
	root := testStateRoot(t)
	runner := &fakeRunner{}
	manager := newTestManager(t, root, runner, fixedTime)
	tenantA, siteA := "77777777-7777-4777-8777-777777777777", "44444444-4444-4444-8444-444444444444"
	tenantB, siteB := "88888888-8888-4888-8888-888888888888", "55555555-5555-4555-8555-555555555555"
	network := "198.51.100.0/24"

	firstA := scopedVersion("task-a-1", "11111111-1111-4111-8111-111111111111", tenantA, siteA, 1, 0, network)
	firstB := scopedVersion("task-b-1", "22222222-2222-4222-8222-222222222222", tenantB, siteB, 1, 0, network)
	for _, version := range []FirewallVersion{firstA, firstB} {
		if result, err := manager.Apply(context.Background(), version); err != nil || result.State != StateApplied {
			t.Fatalf("Apply(%s) result=%+v error=%v", version.TaskID, result, err)
		}
	}

	removeA := scopedVersion("task-a-2", "33333333-3333-4333-8333-333333333333", tenantA, siteA, 2, 1, "")
	if result, err := manager.Apply(context.Background(), removeA); err != nil || result.State != StateApplied {
		t.Fatalf("remove owner A result=%+v error=%v", result, err)
	}
	if !strings.Contains(runner.lastBatch(), network) {
		t.Fatalf("removing owner A also removed owner B CIDR:\n%s", runner.lastBatch())
	}
	statusA, err := manager.ScopeStatus(context.Background(), tenantA, siteA)
	if err != nil || statusA.PolicyVersion != 2 || statusA.EntryCount != 0 {
		t.Fatalf("owner A status=%+v error=%v", statusA, err)
	}
	statusB, err := manager.ScopeStatus(context.Background(), tenantB, siteB)
	if err != nil || statusB.PolicyVersion != 1 || statusB.EntryCount != 1 {
		t.Fatalf("owner B status=%+v error=%v", statusB, err)
	}

	stale := scopedVersion("task-a-stale", "44444444-4444-4444-8444-444444444444", tenantA, siteA, 3, 1, network)
	if _, err := manager.Apply(context.Background(), stale); !errors.Is(err, ErrActiveVersionConflict) {
		t.Fatalf("stale CAS error=%v, want ErrActiveVersionConflict", err)
	}
	regressed := scopedVersion("task-a-regress", "55555555-5555-4555-8555-555555555555", tenantA, siteA, 2, 2, network)
	if _, err := manager.Apply(context.Background(), regressed); !errors.Is(err, ErrPolicyVersionRegression) {
		t.Fatalf("policy regression error=%v, want ErrPolicyVersionRegression", err)
	}
	reusedIdempotency := scopedVersion("task-a-reused-key", firstA.IdempotencyKey, tenantA, siteA, 3, 2, network)
	if _, err := manager.Apply(context.Background(), reusedIdempotency); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused idempotency error=%v, want ErrConflict", err)
	}

	removeB := scopedVersion("task-b-2", "66666666-6666-4666-8666-666666666666", tenantB, siteB, 2, 1, "")
	if result, err := manager.Apply(context.Background(), removeB); err != nil || result.State != StateApplied {
		t.Fatalf("remove owner B result=%+v error=%v", result, err)
	}
	if strings.Contains(runner.lastBatch(), network) {
		t.Fatalf("CIDR remained after its final owner was removed:\n%s", runner.lastBatch())
	}
}

func TestScopedCompileFailurePreservesEveryActiveScope(t *testing.T) {
	runner := &fakeRunner{}
	manager := newTestManager(t, testStateRoot(t), runner, fixedTime)
	tenantA, siteA := "77777777-7777-4777-8777-777777777777", "44444444-4444-4444-8444-444444444444"
	tenantB, siteB := "88888888-8888-4888-8888-888888888888", "55555555-5555-4555-8555-555555555555"
	for _, version := range []FirewallVersion{
		scopedVersion("task-a-1", "11111111-1111-4111-8111-111111111111", tenantA, siteA, 1, 0, "198.51.100.0/24"),
		scopedVersion("task-b-1", "22222222-2222-4222-8222-222222222222", tenantB, siteB, 1, 0, "203.0.113.0/24"),
	} {
		if _, err := manager.Apply(context.Background(), version); err != nil {
			t.Fatal(err)
		}
	}
	beforeChecks, beforeApplies, beforeStatuses := runner.counts()
	invalid := scopedVersion("task-a-2", "33333333-3333-4333-8333-333333333333", tenantA, siteA, 2, 1, "0.0.0.0/0")
	if _, err := manager.Apply(context.Background(), invalid); !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("invalid scope error=%v, want ErrInvalidVersion", err)
	}
	if checks, applies, statuses := runner.counts(); checks != beforeChecks || applies != beforeApplies || statuses != beforeStatuses {
		t.Fatalf("invalid scope reached nft: before=%d/%d/%d after=%d/%d/%d", beforeChecks, beforeApplies, beforeStatuses, checks, applies, statuses)
	}
	for _, expected := range []struct {
		tenant, site string
	}{
		{tenantA, siteA}, {tenantB, siteB},
	} {
		status, err := manager.ScopeStatus(context.Background(), expected.tenant, expected.site)
		if err != nil || status.PolicyVersion != 1 || status.EntryCount != 1 {
			t.Fatalf("preserved scope status=%+v error=%v", status, err)
		}
	}
}

func TestScopedCrashRecoveryUsesAppliedDigestWithoutBlindReplay(t *testing.T) {
	root := testStateRoot(t)
	runner := &fakeRunner{}
	manager := newTestManager(t, root, runner, fixedTime)
	tenant, site := "77777777-7777-4777-8777-777777777777", "44444444-4444-4444-8444-444444444444"
	first := scopedVersion("task-1", "11111111-1111-4111-8111-111111111111", tenant, site, 1, 0, "198.51.100.0/24")
	if _, err := manager.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	candidate := scopedVersion("task-2", "22222222-2222-4222-8222-222222222222", tenant, site, 2, 1, "203.0.113.0/24")
	manager.afterKernelApply = func() error { return errInjected }
	if _, err := manager.Apply(context.Background(), candidate); !errors.Is(err, errInjected) {
		t.Fatalf("crash injection error=%v, want injected", err)
	}
	if _, err := os.Stat(manager.store.inflightPath); err != nil {
		t.Fatalf("in-flight journal was not durable after crash: %v", err)
	}
	_, appliesBeforeRecovery, _ := runner.counts()
	restarted := newTestManager(t, root, runner, fixedTime)
	_, appliesAfterRecovery, _ := runner.counts()
	if appliesAfterRecovery != appliesBeforeRecovery {
		t.Fatalf("recovery blindly replayed nft apply: before=%d after=%d", appliesBeforeRecovery, appliesAfterRecovery)
	}
	status, err := restarted.ScopeStatus(context.Background(), tenant, site)
	if err != nil || status.PolicyVersion != 2 || status.EntryCount != 1 {
		t.Fatalf("recovered scope status=%+v error=%v", status, err)
	}
	if _, err := os.Stat(restarted.store.inflightPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("in-flight journal remained after recovery: %v", err)
	}
	if result, err := restarted.Apply(context.Background(), candidate); err != nil || result.State != StateApplied {
		t.Fatalf("recovered task replay result=%+v error=%v", result, err)
	}
}

func TestScopedCrashRecoveryRollsBackUnappliedJournal(t *testing.T) {
	root := testStateRoot(t)
	runner := &fakeRunner{}
	manager := newTestManager(t, root, runner, fixedTime)
	tenant, site := "77777777-7777-4777-8777-777777777777", "44444444-4444-4444-8444-444444444444"
	first := scopedVersion("task-1", "11111111-1111-4111-8111-111111111111", tenant, site, 1, 0, "198.51.100.0/24")
	if _, err := manager.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	candidate := scopedVersion("task-2", "22222222-2222-4222-8222-222222222222", tenant, site, 2, 1, "203.0.113.0/24")
	manager.afterJournalSync = func() error { return errInjected }
	if _, err := manager.Apply(context.Background(), candidate); !errors.Is(err, errInjected) {
		t.Fatalf("journal crash injection error=%v, want injected", err)
	}
	restarted := newTestManager(t, root, runner, fixedTime)
	status, err := restarted.ScopeStatus(context.Background(), tenant, site)
	if err != nil || status.PolicyVersion != 1 || status.EntryCount != 1 {
		t.Fatalf("unapplied recovery changed active scope: status=%+v error=%v", status, err)
	}
	result, err := restarted.Apply(context.Background(), candidate)
	if err != nil || result.State != StateFailed || result.ErrorCode != "RECOVERY_NOT_APPLIED" || !result.RunningVersionUnchanged {
		t.Fatalf("unapplied recovered task result=%+v error=%v", result, err)
	}
}

func TestScopedRollbackFailureJournalRecoversAppliedDigest(t *testing.T) {
	root := testStateRoot(t)
	runner := &fakeRunner{}
	manager := newTestManager(t, root, runner, fixedTime)
	tenant, site := "77777777-7777-4777-8777-777777777777", "44444444-4444-4444-8444-444444444444"
	first := scopedVersion("task-1", "11111111-1111-4111-8111-111111111111", tenant, site, 1, 0, "198.51.100.0/24")
	if _, err := manager.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	candidate := scopedVersion("task-2", "22222222-2222-4222-8222-222222222222", tenant, site, 2, 1, "203.0.113.0/24")
	manager.saveActive = func(activeRecord) error {
		runner.failCheck = true
		return errInjected
	}
	result, err := manager.Apply(context.Background(), candidate)
	if err != nil || result.State != StateRollbackFailed {
		t.Fatalf("rollback failure result=%+v error=%v", result, err)
	}
	if _, err := os.Stat(manager.store.inflightPath); err != nil {
		t.Fatalf("rollback failure removed recovery journal: %v", err)
	}
	_, appliesBeforeRecovery, _ := runner.counts()
	restarted := newTestManager(t, root, runner, fixedTime)
	_, appliesAfterRecovery, _ := runner.counts()
	if appliesAfterRecovery != appliesBeforeRecovery {
		t.Fatalf("recovery replayed nft apply: before=%d after=%d", appliesBeforeRecovery, appliesAfterRecovery)
	}
	status, err := restarted.ScopeStatus(context.Background(), tenant, site)
	if err != nil || status.PolicyVersion != 2 || status.EntryCount != 1 {
		t.Fatalf("recovered scope status=%+v error=%v", status, err)
	}
	if _, err := os.Stat(restarted.store.inflightPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery journal remained after deterministic recovery: %v", err)
	}
	if result, err := restarted.Apply(context.Background(), candidate); err != nil || result.State != StateApplied {
		t.Fatalf("reconciled task result=%+v error=%v", result, err)
	}
}

func scopedVersion(taskID, idempotencyKey, tenantID, siteID string, policyVersion, expectedActive uint64, network string) FirewallVersion {
	version := FirewallVersion{
		TaskID: taskID, TaskRevision: policyVersion, IdempotencyKey: idempotencyKey,
		TenantID: tenantID, SiteID: siteID, PolicyKind: "acl", PolicyID: siteID,
		PolicyVersion: policyVersion, ExpectedActivePolicyVersion: expectedActive,
		Operation: OperationApply, RecoveryReason: RecoveryReasonNotApplicable,
		CommandDigest: strings.Repeat("a", 64), VersionID: "runtime-" + idempotencyKey,
	}
	if network != "" {
		version.Entries = []Entry{{
			TenantID: tenantID, SiteID: siteID, Action: ActionDeny, Network: network, Source: "manual", Reason: "abuse",
		}}
	}
	return version
}

// nftables refuses table comments over 128 bytes: a scoped version
// ("runtime-" + UUID) is named by a fixed-length hash, other comments keep
// their text (tables already applied still match).
func TestTableVersionCommentFitsNFTables(t *testing.T) {
	digest := strings.Repeat("a", 64)
	if got := tableVersionComment("fw-v1", digest); got != "cdnca version=fw-v1 digest="+digest {
		t.Fatalf("short comment changed: %q", got)
	}
	scoped := tableVersionComment("runtime-6c9431f1-28af-52f0-9107-54d3d3ac21f7", digest)
	if len(scoped) > maxTableComment || !strings.HasPrefix(scoped, "cdnca version-digest=") {
		t.Fatalf("scoped comment %q (%d bytes)", scoped, len(scoped))
	}
	if scoped == tableVersionComment("runtime-6c9431f1-28af-52f0-9107-54d3d3ac21f8", digest) ||
		scoped == tableVersionComment("runtime-6c9431f1-28af-52f0-9107-54d3d3ac21f7", strings.Repeat("b", 64)) {
		t.Fatal("hashed comments do not tell versions apart")
	}
	for _, id := range []string{strings.Repeat("v", 128), "runtime-" + strings.Repeat("0", 36)} {
		compiled := compileNormalized(FirewallVersion{TaskID: "t", VersionID: id, Aggregate: true}, digest)
		comment := batchComment(string(compiled.Batch))
		if len(comment) > maxTableComment {
			t.Fatalf("batch comment for %q is %d bytes", id, len(comment))
		}
	}
}
