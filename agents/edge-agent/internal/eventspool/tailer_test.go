package eventspool

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func newTailHarness(t *testing.T) (string, *Spool, TailConfig) {
	t.Helper()
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	source := filepath.Join(root, "access.jsonl")
	if err := os.WriteFile(source, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	spoolConfig := testConfig(filepath.Join(root, "spool"))
	spoolConfig.SoftLimitBytes = 1 << 20
	spoolConfig.HardLimitBytes = 2 << 20
	spoolConfig.MaxTenantBytes = 1 << 20
	spool := newTestSpool(t, spoolConfig)
	tailConfig := TailConfig{
		SourcePath: source, StateDir: filepath.Join(root, "tail-state"),
		Identity: TrustedIdentity{
			EnrollmentNodeID: nodeOne, TenantID: tenantOne, SiteID: siteOne, ConfigVersionID: "cfg-1",
		},
		MaxLineBytes: 16 << 10, MaxBatchEvents: 10, MaxQuarantineBytes: 1 << 20,
	}
	return source, spool, tailConfig
}

func appendSource(t *testing.T, path string, event Envelope, newline bool) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload := sourceLine(t, event)
	if newline {
		payload = append(payload, '\n')
	}
	if _, err := file.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func newRetiredTailHarness(t *testing.T) (string, *Spool, TailConfig, *Tailer, tailCheckpoint) {
	t.Helper()
	source, spool, config := newTailHarness(t)
	first := sourceAccess(tenantOne)
	first.RequestID = "a-initial"
	appendSource(t, source, first, true)
	tailer, err := NewTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tailer.TailOnce(context.Background(), spool); err != nil {
		t.Fatal(err)
	}
	aPending := sourceAccess(tenantOne)
	aPending.RequestID = "a-pending"
	appendSource(t, source, aPending, true)
	if err := os.Rename(source, source+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	bInitial := sourceAccess(tenantOne)
	bInitial.RequestID = "b-initial"
	appendSource(t, source, bInitial, true)
	result, err := tailer.TailOnce(context.Background(), spool)
	if err != nil || result.AppendedEvents != 2 || result.RotationFilesHashed != 1 || result.RotationBytesHashed == 0 {
		t.Fatalf("prepare retired source = %#v, %v", result, err)
	}
	checkpoint, exists, err := tailer.loadCheckpoint()
	if err != nil || !exists || len(checkpoint.RetiredSources) != 1 || !canonicalSHA256(checkpoint.RetiredSources[0].Digest) {
		t.Fatalf("retired checkpoint = %#v, %t, %v", checkpoint, exists, err)
	}
	return source, spool, config, tailer, checkpoint
}

func TestTailerPartialMalformedAndRestart(t *testing.T) {
	source, spool, config := newTailHarness(t)
	appendSource(t, source, sourceAccess(tenantOne), true)
	file, err := os.OpenFile(source, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte("{\"password\":\"source-secret\"\n"))
	_ = file.Close()
	partial := sourceAccess(tenantOne)
	partial.RequestID = "partial"
	appendSource(t, source, partial, false)

	tailer, err := NewTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := tailer.TailOnce(context.Background(), spool)
	if err != nil {
		t.Fatal(err)
	}
	if result.CompletedLines != 2 || result.AppendedEvents != 1 || result.QuarantinedLines != 1 || len(result.Issues) != 1 || result.Issues[0].Code != "TAIL_INVALID_JSON" {
		t.Fatalf("first tail = %#v", result)
	}
	quarantined, err := os.ReadDir(filepath.Join(config.StateDir, "quarantine"))
	if err != nil || len(quarantined) != 1 {
		t.Fatalf("quarantine entries = %d, %v", len(quarantined), err)
	}
	metadata, err := os.ReadFile(filepath.Join(config.StateDir, "quarantine", quarantined[0].Name()))
	if err != nil || bytes.Contains(metadata, []byte("source-secret")) || bytes.Contains(metadata, []byte("password")) {
		t.Fatalf("quarantine metadata leaked source content: %q, %v", metadata, err)
	}
	file, _ = os.OpenFile(source, os.O_WRONLY|os.O_APPEND, 0)
	_, _ = file.Write([]byte("\n"))
	_ = file.Close()
	restarted, err := NewTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err = restarted.TailOnce(context.Background(), spool)
	if err != nil || result.CompletedLines != 1 || result.AppendedEvents != 1 {
		t.Fatalf("restart tail = %#v, %v", result, err)
	}
	stats, _ := spool.Stats()
	if stats.PendingEvents != 2 {
		t.Fatalf("pending = %d", stats.PendingEvents)
	}
}

func TestTailerRenameRotationAndCopytruncate(t *testing.T) {
	t.Run("rename", func(t *testing.T) {
		source, spool, config := newTailHarness(t)
		first := sourceAccess(tenantOne)
		first.RequestID = "first"
		appendSource(t, source, first, true)
		tailer, _ := NewTailer(config)
		if _, err := tailer.TailOnce(context.Background(), spool); err != nil {
			t.Fatal(err)
		}
		second := sourceAccess(tenantOne)
		second.RequestID = "rotated"
		appendSource(t, source, second, true)
		rotated := source + ".1"
		if err := os.Rename(source, rotated); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		third := sourceAccess(tenantOne)
		third.RequestID = "new"
		appendSource(t, source, third, true)
		result, err := tailer.TailOnce(context.Background(), spool)
		if err != nil || result.AppendedEvents != 2 {
			t.Fatalf("rotation tail = %#v, %v", result, err)
		}
		stats, _ := spool.Stats()
		if stats.PendingEvents != 3 {
			t.Fatalf("pending = %d", stats.PendingEvents)
		}
	})

	t.Run("copytruncate", func(t *testing.T) {
		source, spool, config := newTailHarness(t)
		first := sourceAccess(tenantOne)
		first.RequestID = "before"
		appendSource(t, source, first, true)
		tailer, _ := NewTailer(config)
		if _, err := tailer.TailOnce(context.Background(), spool); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(source, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			t.Fatal(err)
		}
		after := sourceAccess(tenantOne)
		after.RequestID = "after-copytruncate-with-longer-content"
		payload := append(sourceLine(t, after), '\n')
		if _, err := file.Write(payload); err != nil {
			t.Fatal(err)
		}
		_ = file.Sync()
		_ = file.Close()
		result, err := tailer.TailOnce(context.Background(), spool)
		if err != nil || result.AppendedEvents != 1 || len(result.Issues) == 0 || result.Issues[0].Code != "TAIL_COPYTRUNCATE" {
			t.Fatalf("copytruncate tail = %#v, %v", result, err)
		}
	})
}

func TestTailerRenameRotationPartialFailsClosed(t *testing.T) {
	source, spool, config := newTailHarness(t)
	first := sourceAccess(tenantOne)
	first.RequestID = "first"
	appendSource(t, source, first, true)
	tailer, err := NewTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tailer.TailOnce(context.Background(), spool); err != nil {
		t.Fatal(err)
	}
	initial, exists, err := tailer.loadCheckpoint()
	if err != nil || !exists {
		t.Fatalf("initial checkpoint = %#v, %t, %v", initial, exists, err)
	}

	expectedBlockedOffset := initial.Offset
	for _, requestID := range []string{"rotated-complete-1", "rotated-complete-2"} {
		event := sourceAccess(tenantOne)
		event.RequestID = requestID
		expectedBlockedOffset += int64(len(sourceLine(t, event)) + 1)
		appendSource(t, source, event, true)
	}
	partial := sourceAccess(tenantOne)
	partial.RequestID = "rotated-partial"
	appendSource(t, source, partial, false)
	rotated := source + ".1"
	if err := os.Rename(source, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	active := sourceAccess(tenantOne)
	active.RequestID = "new-active"
	appendSource(t, source, active, true)

	result, err := tailer.TailOnce(context.Background(), spool)
	if !errors.Is(err, ErrTailRotatedPartial) {
		t.Fatalf("partial rotation error = %v", err)
	}
	if result.CompletedLines != 2 || result.AppendedEvents != 2 || len(result.Issues) != 1 || result.Issues[0].Code != "TAIL_ROTATED_PARTIAL" {
		t.Fatalf("partial rotation result = %#v", result)
	}
	blocked, exists, err := tailer.loadCheckpoint()
	if err != nil || !exists {
		t.Fatalf("blocked checkpoint = %#v, %t, %v", blocked, exists, err)
	}
	if blocked.Device != initial.Device || blocked.Inode != initial.Inode || blocked.Generation != initial.Generation || blocked.Offset != expectedBlockedOffset ||
		result.Issues[0].Generation != blocked.Generation || result.Issues[0].Offset != blocked.Offset {
		t.Fatalf("checkpoint advanced across partial rotation: initial=%#v blocked=%#v issue=%#v", initial, blocked, result.Issues[0])
	}
	stats, err := spool.Stats()
	if err != nil || stats.PendingEvents != 3 {
		t.Fatalf("pending after first block = %d, %v", stats.PendingEvents, err)
	}

	result, err = tailer.TailOnce(context.Background(), spool)
	if !errors.Is(err, ErrTailRotatedPartial) || result.CompletedLines != 0 || result.AppendedEvents != 0 || len(result.Issues) != 1 ||
		result.Issues[0].Code != "TAIL_ROTATED_PARTIAL" {
		t.Fatalf("unresolved partial retry = %#v, %v", result, err)
	}
	retried, exists, err := tailer.loadCheckpoint()
	if err != nil || !exists || !reflect.DeepEqual(retried, blocked) {
		t.Fatalf("retry checkpoint = %#v, %t, %v; want %#v", retried, exists, err, blocked)
	}
	stats, err = spool.Stats()
	if err != nil || stats.PendingEvents != 3 {
		t.Fatalf("pending after blocked retry = %d, %v", stats.PendingEvents, err)
	}

	oldFile, err := os.OpenFile(rotated, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oldFile.Write([]byte("\n")); err != nil {
		_ = oldFile.Close()
		t.Fatal(err)
	}
	if err := oldFile.Sync(); err != nil {
		_ = oldFile.Close()
		t.Fatal(err)
	}
	if err := oldFile.Close(); err != nil {
		t.Fatal(err)
	}
	result, err = tailer.TailOnce(context.Background(), spool)
	if err != nil || result.CompletedLines != 2 || result.AppendedEvents != 2 || result.DuplicateEvents != 0 || len(result.Issues) != 0 {
		t.Fatalf("completed partial rotation = %#v, %v", result, err)
	}
	completed, exists, err := tailer.loadCheckpoint()
	if err != nil || !exists || completed.Generation != initial.Generation+1 || completed.Device == initial.Device && completed.Inode == initial.Inode {
		t.Fatalf("completed checkpoint = %#v, %t, %v", completed, exists, err)
	}
	stats, err = spool.Stats()
	if err != nil || stats.PendingEvents != 5 {
		t.Fatalf("pending after recovery = %d, %v", stats.PendingEvents, err)
	}
}

func TestTailerMultipleRenameFailsClosed(t *testing.T) {
	source, spool, config := newTailHarness(t)
	initialEvent := sourceAccess(tenantOne)
	initialEvent.RequestID = "initial"
	appendSource(t, source, initialEvent, true)
	tailer, err := NewTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tailer.TailOnce(context.Background(), spool); err != nil {
		t.Fatal(err)
	}
	initial, exists, err := tailer.loadCheckpoint()
	if err != nil || !exists {
		t.Fatalf("initial checkpoint = %#v, %t, %v", initial, exists, err)
	}

	aEvent := sourceAccess(tenantOne)
	aEvent.RequestID = "a-complete"
	appendSource(t, source, aEvent, true)
	expectedOffset := initial.Offset + int64(len(sourceLine(t, aEvent))+1)
	if err := os.Rename(source, source+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	bComplete := sourceAccess(tenantOne)
	bComplete.RequestID = "b-complete"
	appendSource(t, source, bComplete, true)
	bPartial := sourceAccess(tenantOne)
	bPartial.RequestID = "b-partial"
	appendSource(t, source, bPartial, false)
	if err := os.Rename(source, source+".2"); err != nil {
		t.Fatal(err)
	}
	bInfo, err := os.Stat(source + ".2")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cEvent := sourceAccess(tenantOne)
	cEvent.RequestID = "c-active"
	appendSource(t, source, cEvent, true)

	result, err := tailer.TailOnce(context.Background(), spool)
	if !errors.Is(err, ErrTailRotationAmbiguous) {
		t.Fatalf("multiple rotation error = %v", err)
	}
	if result.CompletedLines != 1 || result.AppendedEvents != 1 || result.DuplicateEvents != 0 || len(result.Issues) != 1 ||
		result.Issues[0].Code != "TAIL_ROTATION_AMBIGUOUS" {
		t.Fatalf("multiple rotation result = %#v", result)
	}
	blocked, exists, err := tailer.loadCheckpoint()
	if err != nil || !exists || blocked.Device != initial.Device || blocked.Inode != initial.Inode || blocked.Generation != initial.Generation ||
		blocked.Offset != expectedOffset || len(blocked.RetiredSources) != 0 {
		t.Fatalf("blocked checkpoint = %#v, %t, %v; initial=%#v", blocked, exists, err, initial)
	}
	stats, err := spool.Stats()
	if err != nil || stats.PendingEvents != 2 {
		t.Fatalf("pending after ambiguity = %d, %v", stats.PendingEvents, err)
	}

	restarted, err := NewTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err = restarted.TailOnce(context.Background(), spool)
	if !errors.Is(err, ErrTailRotationAmbiguous) || result.CompletedLines != 0 || result.AppendedEvents != 0 || result.DuplicateEvents != 0 ||
		len(result.Issues) != 1 || result.Issues[0].Code != "TAIL_ROTATION_AMBIGUOUS" {
		t.Fatalf("ambiguity restart = %#v, %v", result, err)
	}
	retried, exists, err := restarted.loadCheckpoint()
	if err != nil || !exists || !reflect.DeepEqual(retried, blocked) {
		t.Fatalf("restart checkpoint = %#v, %t, %v; want %#v", retried, exists, err, blocked)
	}
	stats, err = spool.Stats()
	if err != nil || stats.PendingEvents != 2 {
		t.Fatalf("pending after ambiguity restart = %d, %v", stats.PendingEvents, err)
	}
	bAfter, err := os.Stat(source + ".2")
	if err != nil || bAfter.Size() != bInfo.Size() {
		t.Fatalf("intermediate B changed: before=%d after=%d, %v", bInfo.Size(), bAfter.Size(), err)
	}

	stagedC := filepath.Join(filepath.Dir(source), "staged-active")
	if err := os.Rename(source, stagedC); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(source+".2", source); err != nil {
		t.Fatal(err)
	}
	bFile, err := os.OpenFile(source, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bFile.Write([]byte("\n")); err != nil {
		_ = bFile.Close()
		t.Fatal(err)
	}
	if err := bFile.Sync(); err != nil {
		_ = bFile.Close()
		t.Fatal(err)
	}
	if err := bFile.Close(); err != nil {
		t.Fatal(err)
	}
	result, err = restarted.TailOnce(context.Background(), spool)
	if err != nil || result.CompletedLines != 2 || result.AppendedEvents != 2 || result.DuplicateEvents != 0 {
		t.Fatalf("recover intermediate B = %#v, %v", result, err)
	}
	if err := os.Rename(source, source+".2"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(stagedC, source); err != nil {
		t.Fatal(err)
	}
	result, err = restarted.TailOnce(context.Background(), spool)
	if err != nil || result.CompletedLines != 1 || result.AppendedEvents != 1 || result.DuplicateEvents != 0 {
		t.Fatalf("recover active C = %#v, %v", result, err)
	}
	recovered, exists, err := restarted.loadCheckpoint()
	if err != nil || !exists || recovered.Generation != initial.Generation+2 || len(recovered.RetiredSources) != 2 {
		t.Fatalf("recovered checkpoint = %#v, %t, %v", recovered, exists, err)
	}
	stats, err = spool.Stats()
	if err != nil || stats.PendingEvents != 5 {
		t.Fatalf("pending after ordered recovery = %d, %v", stats.PendingEvents, err)
	}
}

func TestTailerRetiredRotationResidualIsIgnored(t *testing.T) {
	source, spool, _, tailer, checkpoint := newRetiredTailHarness(t)

	bPending := sourceAccess(tenantOne)
	bPending.RequestID = "b-pending"
	appendSource(t, source, bPending, true)
	if err := os.Rename(source, source+".2"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cInitial := sourceAccess(tenantOne)
	cInitial.RequestID = "c-initial"
	appendSource(t, source, cInitial, true)
	result, err := tailer.TailOnce(context.Background(), spool)
	if err != nil || result.AppendedEvents != 2 || result.RotationFilesHashed != 2 || result.RotationBytesHashed == 0 ||
		len(result.Issues) != 1 || result.Issues[0].Code != "TAIL_RETIRED_DIGEST_SCAN" {
		t.Fatalf("rotation with retired residual = %#v, %v", result, err)
	}
	checkpoint, exists, err := tailer.loadCheckpoint()
	if err != nil || !exists || len(checkpoint.RetiredSources) != 2 {
		t.Fatalf("second retired checkpoint = %#v, %t, %v", checkpoint, exists, err)
	}
	stats, err := spool.Stats()
	if err != nil || stats.PendingEvents != 5 {
		t.Fatalf("pending with residuals = %d, %v", stats.PendingEvents, err)
	}
}

func TestTailerRetiredFullDigestDetectsFrontRewrite(t *testing.T) {
	source, spool, _, tailer, checkpoint := newRetiredTailHarness(t)
	retiredPath := source + ".1"
	retired, err := os.OpenFile(retiredPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	info, err := retired.Stat()
	if err != nil || info.Size() <= fingerprintBytes {
		_ = retired.Close()
		t.Fatalf("retired size = %d, %v", info.Size(), err)
	}
	tailBefore := make([]byte, fingerprintBytes)
	if _, err := retired.ReadAt(tailBefore, info.Size()-fingerprintBytes); err != nil {
		_ = retired.Close()
		t.Fatal(err)
	}
	if _, err := retired.WriteAt([]byte("XXXXXXXX"), 0); err != nil {
		_ = retired.Close()
		t.Fatal(err)
	}
	if err := retired.Sync(); err != nil {
		_ = retired.Close()
		t.Fatal(err)
	}
	tailAfter := make([]byte, fingerprintBytes)
	if _, err := retired.ReadAt(tailAfter, info.Size()-fingerprintBytes); err != nil {
		_ = retired.Close()
		t.Fatal(err)
	}
	if err := retired.Close(); err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(retiredPath)
	if err != nil || afterInfo.Size() != info.Size() || !bytes.Equal(tailBefore, tailAfter) {
		t.Fatalf("rewrite changed size/tail: before=%d after=%d equal=%t, %v", info.Size(), afterInfo.Size(), bytes.Equal(tailBefore, tailAfter), err)
	}

	bPending := sourceAccess(tenantOne)
	bPending.RequestID = "b-before-rewrite-detection"
	appendSource(t, source, bPending, true)
	expectedOffset := checkpoint.Offset + int64(len(sourceLine(t, bPending))+1)
	if err := os.Rename(source, source+".2"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, append(sourceLine(t, sourceAccess(tenantOne)), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := tailer.TailOnce(context.Background(), spool)
	if !errors.Is(err, ErrTailRotationAmbiguous) || result.CompletedLines != 1 || result.AppendedEvents != 1 || result.RotationFilesHashed != 1 ||
		len(result.Issues) != 2 || result.Issues[0].Code != "TAIL_RETIRED_DIGEST_SCAN" || result.Issues[1].Code != "TAIL_ROTATION_AMBIGUOUS" {
		t.Fatalf("front rewrite result = %#v, %v", result, err)
	}
	blocked, exists, err := tailer.loadCheckpoint()
	if err != nil || !exists || blocked.Device != checkpoint.Device || blocked.Inode != checkpoint.Inode || blocked.Generation != checkpoint.Generation ||
		blocked.Offset != expectedOffset || !reflect.DeepEqual(blocked.RetiredSources, checkpoint.RetiredSources) {
		t.Fatalf("front rewrite checkpoint = %#v, %t, %v; want %#v", blocked, exists, err, checkpoint)
	}
}

func TestTailerDigestScanChangeFailsClosed(t *testing.T) {
	source, spool, _, tailer, checkpoint := newRetiredTailHarness(t)
	appendSource(t, source, sourceAccess(tenantOne), true)
	if err := os.Rename(source, source+".2"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, append(sourceLine(t, sourceAccess(tenantOne)), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var hookErr error
	var hookRead int64
	tailer.hashHook = func(file *os.File, read int64) {
		hookRead = read
		info, err := file.Stat()
		if err != nil {
			hookErr = err
			return
		}
		hookErr = os.Truncate(file.Name(), info.Size()-1)
	}
	result, err := tailer.TailOnce(context.Background(), spool)
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if hookRead <= 0 || !errors.Is(err, ErrTailRotationAmbiguous) || result.CompletedLines != 0 || result.AppendedEvents != 0 || result.RotationFilesHashed != 1 ||
		len(result.Issues) != 2 || result.Issues[0].Code != "TAIL_RETIRED_DIGEST_SCAN" || result.Issues[1].Code != "TAIL_ROTATION_AMBIGUOUS" {
		t.Fatalf("digest race result = %#v, %v", result, err)
	}
	blocked, exists, err := tailer.loadCheckpoint()
	if err != nil || !exists || !reflect.DeepEqual(blocked, checkpoint) {
		t.Fatalf("digest race checkpoint = %#v, %t, %v; want %#v", blocked, exists, err, checkpoint)
	}
}

func TestTailerDigestScanSameSizeRewriteAfterReadFailsClosed(t *testing.T) {
	source, spool, _, tailer, checkpoint := newRetiredTailHarness(t)
	retiredPath := source + ".1"
	retired, err := os.Open(retiredPath)
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, err := checkedOpenSourceState(retired)
	if err != nil || stateBefore.identity.size <= fingerprintBytes {
		_ = retired.Close()
		t.Fatalf("retired state = %#v, %v", stateBefore, err)
	}
	originalPrefix := make([]byte, 8)
	if _, err := retired.ReadAt(originalPrefix, 0); err != nil {
		_ = retired.Close()
		t.Fatal(err)
	}
	tailBefore := make([]byte, fingerprintBytes)
	if _, err := retired.ReadAt(tailBefore, stateBefore.identity.size-fingerprintBytes); err != nil {
		_ = retired.Close()
		t.Fatal(err)
	}
	originalModTime := time.Unix(stateBefore.modifiedSec, stateBefore.modifiedNSec)
	if err := retired.Close(); err != nil {
		t.Fatal(err)
	}

	appendSource(t, source, sourceAccess(tenantOne), true)
	if err := os.Rename(source, source+".2"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, append(sourceLine(t, sourceAccess(tenantOne)), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	var hookErr error
	var hookRead int64
	tailer.hashHook = func(file *os.File, read int64) {
		hookRead = read
		writer, err := os.OpenFile(file.Name(), os.O_WRONLY, 0)
		if err != nil {
			hookErr = err
			return
		}
		changed := append([]byte(nil), originalPrefix...)
		changed[0] ^= 0xff
		if _, err := writer.WriteAt(changed, 0); err != nil {
			hookErr = err
			_ = writer.Close()
			return
		}
		if err := writer.Sync(); err != nil {
			hookErr = err
			_ = writer.Close()
			return
		}
		if _, err := writer.WriteAt(originalPrefix, 0); err != nil {
			hookErr = err
			_ = writer.Close()
			return
		}
		if err := writer.Sync(); err != nil {
			hookErr = err
			_ = writer.Close()
			return
		}
		if err := writer.Close(); err != nil {
			hookErr = err
			return
		}
		hookErr = os.Chtimes(file.Name(), originalModTime, originalModTime)
	}
	result, err := tailer.TailOnce(context.Background(), spool)
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if hookRead <= 0 || !errors.Is(err, ErrTailRotationAmbiguous) || result.CompletedLines != 0 || result.AppendedEvents != 0 ||
		result.RotationFilesHashed != 1 || len(result.Issues) != 2 || result.Issues[0].Code != "TAIL_RETIRED_DIGEST_SCAN" ||
		result.Issues[1].Code != "TAIL_ROTATION_AMBIGUOUS" {
		t.Fatalf("same-size digest race result = %#v, read=%d, %v", result, hookRead, err)
	}
	afterFile, err := os.Open(retiredPath)
	if err != nil {
		t.Fatal(err)
	}
	stateAfter, err := checkedOpenSourceState(afterFile)
	if err != nil {
		_ = afterFile.Close()
		t.Fatal(err)
	}
	prefixAfter := make([]byte, len(originalPrefix))
	if _, err := afterFile.ReadAt(prefixAfter, 0); err != nil {
		_ = afterFile.Close()
		t.Fatal(err)
	}
	tailAfter := make([]byte, fingerprintBytes)
	if _, err := afterFile.ReadAt(tailAfter, stateAfter.identity.size-fingerprintBytes); err != nil {
		_ = afterFile.Close()
		t.Fatal(err)
	}
	if err := afterFile.Close(); err != nil {
		t.Fatal(err)
	}
	if stateAfter.identity.size != stateBefore.identity.size || stateAfter.mode != stateBefore.mode || stateAfter.nlink != stateBefore.nlink ||
		stateAfter.modifiedSec != stateBefore.modifiedSec || stateAfter.modifiedNSec != stateBefore.modifiedNSec ||
		!bytes.Equal(prefixAfter, originalPrefix) || !bytes.Equal(tailAfter, tailBefore) ||
		stateAfter.changedSec == stateBefore.changedSec && stateAfter.changedNSec == stateBefore.changedNSec {
		t.Fatalf("restored rewrite state: before=%#v after=%#v prefix=%t tail=%t", stateBefore, stateAfter,
			bytes.Equal(prefixAfter, originalPrefix), bytes.Equal(tailAfter, tailBefore))
	}
	blocked, exists, err := tailer.loadCheckpoint()
	if err != nil || !exists || !reflect.DeepEqual(blocked, checkpoint) {
		t.Fatalf("same-size digest race checkpoint = %#v, %t, %v; want %#v", blocked, exists, err, checkpoint)
	}
}

func TestTailerCheckpointDigestAndFingerprintValidation(t *testing.T) {
	t.Run("valid-but-wrong-retired-digest", func(t *testing.T) {
		source, spool, _, tailer, checkpoint := newRetiredTailHarness(t)
		checkpoint.RetiredSources[0].Digest = strings.Repeat("0", sha256.Size*2)
		if err := tailer.saveCheckpoint(checkpoint); err != nil {
			t.Fatal(err)
		}
		appendSource(t, source, sourceAccess(tenantOne), true)
		if err := os.Rename(source, source+".2"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source, append(sourceLine(t, sourceAccess(tenantOne)), '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := tailer.TailOnce(context.Background(), spool)
		if !errors.Is(err, ErrTailRotationAmbiguous) || result.RotationFilesHashed != 1 {
			t.Fatalf("tampered digest result = %#v, %v", result, err)
		}
	})

	for _, testCase := range []struct {
		name        string
		fingerprint string
	}{
		{name: "non-hex", fingerprint: strings.Repeat("g", sha256.Size*2)},
		{name: "uppercase", fingerprint: strings.Repeat("A", sha256.Size*2)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			source, spool, config := newTailHarness(t)
			appendSource(t, source, sourceAccess(tenantOne), true)
			tailer, err := NewTailer(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tailer.TailOnce(context.Background(), spool); err != nil {
				t.Fatal(err)
			}
			checkpoint, exists, err := tailer.loadCheckpoint()
			if err != nil || !exists {
				t.Fatalf("checkpoint = %#v, %t, %v", checkpoint, exists, err)
			}
			checkpoint.Fingerprint = testCase.fingerprint
			if err := tailer.saveCheckpoint(checkpoint); err != nil {
				t.Fatal(err)
			}
			if _, err := tailer.TailOnce(context.Background(), spool); !errors.Is(err, ErrCorruptState) {
				t.Fatalf("%s fingerprint error = %v", testCase.name, err)
			}
		})
	}
}

func TestTailerRotationCandidateFiltering(t *testing.T) {
	t.Run("non-source-prefix-is-ignored", func(t *testing.T) {
		source, spool, config := newTailHarness(t)
		appendSource(t, source, sourceAccess(tenantOne), true)
		tailer, err := NewTailer(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tailer.TailOnce(context.Background(), spool); err != nil {
			t.Fatal(err)
		}
		pending := sourceAccess(tenantOne)
		pending.RequestID = "old-pending"
		appendSource(t, source, pending, true)
		if err := os.Rename(source, source+".1"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(source+".1", filepath.Join(filepath.Dir(source), "unrelated-link")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		appendSource(t, source, sourceAccess(tenantOne), true)
		result, err := tailer.TailOnce(context.Background(), spool)
		if err != nil || result.AppendedEvents != 2 {
			t.Fatalf("non-prefix candidate = %#v, %v", result, err)
		}
	})

	for _, candidateType := range []string{"symlink", "hardlink", "permission"} {
		t.Run(candidateType+"-fails-closed", func(t *testing.T) {
			source, spool, config := newTailHarness(t)
			appendSource(t, source, sourceAccess(tenantOne), true)
			tailer, err := NewTailer(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tailer.TailOnce(context.Background(), spool); err != nil {
				t.Fatal(err)
			}
			initial, exists, err := tailer.loadCheckpoint()
			if err != nil || !exists {
				t.Fatalf("initial checkpoint = %#v, %t, %v", initial, exists, err)
			}
			appendSource(t, source, sourceAccess(tenantOne), true)
			if err := os.Rename(source, source+".1"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(source, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			appendSource(t, source, sourceAccess(tenantOne), true)
			candidate := source + ".2"
			target := filepath.Join(filepath.Dir(source), "candidate-target")
			switch candidateType {
			case "symlink":
				if err := os.WriteFile(target, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, candidate); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.WriteFile(target, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(target, candidate); err != nil {
					t.Fatal(err)
				}
			case "permission":
				if err := os.WriteFile(candidate, nil, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(candidate, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tailer.TailOnce(context.Background(), spool); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("unsafe candidate error = %v", err)
			}
			blocked, exists, err := tailer.loadCheckpoint()
			if err != nil || !exists || !reflect.DeepEqual(blocked, initial) {
				t.Fatalf("unsafe candidate checkpoint = %#v, %t, %v; want %#v", blocked, exists, err, initial)
			}
			stats, err := spool.Stats()
			if err != nil || stats.PendingEvents != 1 {
				t.Fatalf("unsafe candidate pending = %d, %v", stats.PendingEvents, err)
			}
		})
	}
}

type appendThenFailSink struct {
	spool *Spool
	used  bool
}

func (sink *appendThenFailSink) AppendBatch(ctx context.Context, events []Envelope) ([]AppendResult, error) {
	results, err := sink.spool.AppendBatch(ctx, events)
	if err != nil {
		return nil, err
	}
	if !sink.used {
		sink.used = true
		return nil, errors.New("simulated process death before checkpoint")
	}
	return results, nil
}

func TestTailerDeterministicReplayAfterCrash(t *testing.T) {
	source, spool, config := newTailHarness(t)
	appendSource(t, source, sourceAccess(tenantOne), true)
	tailer, _ := NewTailer(config)
	if _, err := tailer.TailOnce(context.Background(), &appendThenFailSink{spool: spool}); err == nil {
		t.Fatal("expected injected checkpoint gap")
	}
	restarted, _ := NewTailer(config)
	result, err := restarted.TailOnce(context.Background(), spool)
	if err != nil || result.DuplicateEvents != 1 || result.AppendedEvents != 0 {
		t.Fatalf("replay = %#v, %v", result, err)
	}
	stats, _ := spool.Stats()
	if stats.PendingEvents != 1 {
		t.Fatalf("pending = %d", stats.PendingEvents)
	}
}

func TestTailerRejectsUnsafeFilesAndReportsRotationGap(t *testing.T) {
	t.Run("world-readable-source", func(t *testing.T) {
		source, spool, config := newTailHarness(t)
		if err := os.Chmod(source, 0o644); err != nil {
			t.Fatal(err)
		}
		tailer, _ := NewTailer(config)
		if _, err := tailer.TailOnce(context.Background(), spool); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("source mode error = %v", err)
		}
	})

	t.Run("symlink-parent", func(t *testing.T) {
		root := t.TempDir()
		root, _ = filepath.EvalSymlinks(root)
		realDirectory := filepath.Join(root, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		source := filepath.Join(realDirectory, "access.jsonl")
		if err := os.WriteFile(source, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		linkedDirectory := filepath.Join(root, "linked")
		if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
			t.Fatal(err)
		}
		_, err := NewTailer(TailConfig{
			SourcePath: filepath.Join(linkedDirectory, "access.jsonl"), StateDir: filepath.Join(root, "state"),
			Identity: TrustedIdentity{
				EnrollmentNodeID: nodeOne, TenantID: tenantOne, SiteID: siteOne, ConfigVersionID: "cfg-1",
			},
			MaxLineBytes: 1024, MaxBatchEvents: 1, MaxQuarantineBytes: 1 << 20,
		})
		if !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("symlink parent error = %v", err)
		}
	})

	t.Run("hardlink-source", func(t *testing.T) {
		source, spool, config := newTailHarness(t)
		if err := os.Link(source, source+".hardlink"); err != nil {
			t.Fatal(err)
		}
		tailer, _ := NewTailer(config)
		if _, err := tailer.TailOnce(context.Background(), spool); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("hardlink error = %v", err)
		}
	})

	t.Run("state-symlink", func(t *testing.T) {
		root := t.TempDir()
		root, _ = filepath.EvalSymlinks(root)
		source := filepath.Join(root, "access.jsonl")
		_ = os.WriteFile(source, nil, 0o600)
		target := filepath.Join(root, "target")
		_ = os.Mkdir(target, 0o700)
		state := filepath.Join(root, "state")
		_ = os.Symlink(target, state)
		_, err := NewTailer(TailConfig{
			SourcePath: source, StateDir: state,
			Identity: TrustedIdentity{
				EnrollmentNodeID: nodeOne, TenantID: tenantOne, SiteID: siteOne, ConfigVersionID: "cfg-1",
			},
			MaxLineBytes: 1024, MaxBatchEvents: 1, MaxQuarantineBytes: 1 << 20,
		})
		if !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("state symlink error = %v", err)
		}
	})

	t.Run("rotation-gap", func(t *testing.T) {
		source, spool, config := newTailHarness(t)
		appendSource(t, source, sourceAccess(tenantOne), true)
		tailer, _ := NewTailer(config)
		if _, err := tailer.TailOnce(context.Background(), spool); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(source); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source, append(sourceLine(t, sourceAccess(tenantOne)), '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := tailer.TailOnce(context.Background(), spool); !errors.Is(err, ErrTailGap) {
			t.Fatalf("rotation gap error = %v", err)
		}
	})
}

func TestTailerQuarantineLimitFailsClosed(t *testing.T) {
	source, spool, config := newTailHarness(t)
	config.MaxQuarantineBytes = 64 << 10
	var malformed bytes.Buffer
	for index := 0; index < 1000; index++ {
		_, _ = fmt.Fprintf(&malformed, "{\"password\":\"source-secret-%d\"\n", index)
	}
	if err := os.WriteFile(source, malformed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	tailer, err := NewTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tailer.TailOnce(context.Background(), spool); !errors.Is(err, ErrQuarantineLimit) {
		t.Fatalf("quarantine limit error = %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(config.StateDir, "quarantine"))
	if err != nil || len(entries) == 0 || len(entries) >= 1000 {
		t.Fatalf("quarantine entries = %d, %v", len(entries), err)
	}
	var total int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
		content, err := os.ReadFile(filepath.Join(config.StateDir, "quarantine", entry.Name()))
		if err != nil || bytes.Contains(content, []byte("source-secret")) || bytes.Contains(content, []byte("password")) {
			t.Fatalf("quarantine content leaked at capacity: %q, %v", content, err)
		}
	}
	if total > config.MaxQuarantineBytes {
		t.Fatalf("quarantine bytes = %d, limit = %d", total, config.MaxQuarantineBytes)
	}
	if _, err := tailer.TailOnce(context.Background(), spool); !errors.Is(err, ErrQuarantineLimit) {
		t.Fatalf("quarantine retry did not remain fail closed: %v", err)
	}
}
