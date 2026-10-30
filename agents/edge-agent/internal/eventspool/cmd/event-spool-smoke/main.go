package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

const (
	eventCount = 100_000
	tenantA    = "11111111-1111-4111-8111-111111111111"
	tenantB    = "22222222-2222-4222-8222-222222222222"
	siteID     = "33333333-3333-4333-8333-333333333333"
	nodeID     = "44444444-4444-4444-8444-444444444444"
)

type evidence struct {
	SchemaVersion          string `json:"schema_version"`
	GeneratedEvents        int    `json:"generated_events"`
	PublishedEvents        int    `json:"published_events"`
	UniqueEventIDs         int    `json:"unique_event_ids"`
	CrashReplayDuplicates  int    `json:"crash_replay_duplicates"`
	RenameRotationEvents   int    `json:"rename_rotation_events"`
	RotationFilesHashed    int    `json:"rotation_files_hashed"`
	RotationBytesHashed    int64  `json:"rotation_bytes_hashed"`
	CopytruncateEvents     int    `json:"copytruncate_events"`
	PublisherFailures      int    `json:"publisher_failures"`
	PartialAcknowledgments int    `json:"partial_acknowledgments"`
	DuplicateDeliveries    int    `json:"duplicate_deliveries"`
	BackoffSteps           int    `json:"backoff_steps"`
	QuarantinedLines       int    `json:"quarantined_lines"`
	HardLimitFailClosed    bool   `json:"hard_limit_fail_closed"`
	PeakSpoolBytes         int64  `json:"peak_spool_bytes"`
	FinalSpoolBytes        int64  `json:"final_spool_bytes"`
	FinalPendingEvents     int    `json:"final_pending_events"`
	ContiguousSequenceLast uint64 `json:"contiguous_sequence_last"`
}

func main() {
	mode := flag.String("mode", "run", "run or tail-block")
	root := flag.String("root", "", "task-owned absolute work directory")
	marker := flag.String("marker", "", "tail-block marker path")
	flag.Parse()
	if *root == "" || !filepath.IsAbs(*root) || filepath.Clean(*root) != *root {
		fatal("invalid smoke root")
	}
	var err error
	switch *mode {
	case "run":
		err = run(*root)
	case "tail-block":
		err = tailBlock(*root, *marker)
	default:
		err = errors.New("invalid smoke mode")
	}
	if err != nil {
		fatal(err.Error())
	}
}

func run(root string) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return err
	}
	source := filepath.Join(root, "access.jsonl")
	if err := writeEvents(source, 0, 25_000, false); err != nil {
		return err
	}
	if err := appendMalformed(source); err != nil {
		return err
	}
	spool, err := newSpool(root)
	if err != nil {
		return err
	}

	marker := filepath.Join(root, "append-before-checkpoint.marker")
	child := exec.Command(os.Args[0], "-mode", "tail-block", "-root", root, "-marker", marker)
	child.Stdout = os.Stderr
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		return err
	}
	if err := waitForMarker(marker, child); err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		return err
	}
	if err := child.Process.Kill(); err != nil {
		return err
	}
	if err := child.Wait(); err == nil {
		return errors.New("tail-block child was not killed")
	}

	tailer, err := newTailer(root, source)
	if err != nil {
		return err
	}
	crashReplay, err := tailer.TailOnce(context.Background(), spool)
	if err != nil {
		return fmt.Errorf("tail after SIGKILL: %w", err)
	}
	if crashReplay.AppendedEvents+crashReplay.DuplicateEvents != 25_000 || crashReplay.DuplicateEvents == 0 {
		return fmt.Errorf("unexpected crash replay counts: %#v", crashReplay)
	}

	if err := writeEvents(source, 25_000, 50_000, false); err != nil {
		return err
	}
	if err := os.Rename(source, source+".1"); err != nil {
		return err
	}
	if err := writeEvents(source, 50_000, 75_000, false); err != nil {
		return err
	}
	rotation, err := tailer.TailOnce(context.Background(), spool)
	if err != nil {
		return fmt.Errorf("tail rename rotation: %w", err)
	}
	if rotation.AppendedEvents != 50_000 || rotation.RotationFilesHashed != 1 || rotation.RotationBytesHashed <= 0 {
		return fmt.Errorf("rename rotation appended %d events and hashed %d files/%d bytes",
			rotation.AppendedEvents, rotation.RotationFilesHashed, rotation.RotationBytesHashed)
	}

	if err := writeEvents(source, 75_000, eventCount, true); err != nil {
		return err
	}
	copytruncate, err := tailer.TailOnce(context.Background(), spool)
	if err != nil {
		return fmt.Errorf("tail copytruncate: %w", err)
	}
	if copytruncate.AppendedEvents != 25_000 || !hasIssue(copytruncate.Issues, "TAIL_COPYTRUNCATE") {
		return fmt.Errorf("unexpected copytruncate result: %#v", copytruncate)
	}

	beforePublish, err := spool.Stats()
	if err != nil {
		return err
	}
	if beforePublish.PendingEvents != eventCount {
		return fmt.Errorf("spool contains %d events, want %d", beforePublish.PendingEvents, eventCount)
	}
	publisher := &verifyingPublisher{
		failures: 3, partial: true, ids: make(map[string]struct{}, eventCount),
		messages: make(map[string][]byte),
	}
	var backoffs []time.Duration
	publishResult, err := spool.Drain(context.Background(), publisher, 10_000, eventspool.RetryConfig{
		InitialBackoff: 10 * time.Millisecond, MaximumBackoff: 40 * time.Millisecond, MaximumAttempts: 6,
		Sleep: func(_ context.Context, delay time.Duration) error {
			backoffs = append(backoffs, delay)
			return nil
		},
	})
	if err != nil {
		return fmt.Errorf("drain spool: %w", err)
	}
	finalStats, err := spool.Stats()
	if err != nil {
		return err
	}
	if publisher.count != eventCount || len(publisher.ids) != eventCount || publisher.lastSequence != eventCount ||
		finalStats.PendingEvents != 0 || finalStats.SegmentBytes != 0 || publisher.failuresSeen != 3 ||
		publisher.partialAcks != 1 || publisher.duplicateDeliveries == 0 || len(backoffs) != 4 || publishResult.Published != eventCount {
		return fmt.Errorf("final verification failed: published=%d unique=%d sequence=%d stats=%#v failures=%d partial=%d duplicates=%d backoffs=%v",
			publisher.count, len(publisher.ids), publisher.lastSequence, finalStats, publisher.failuresSeen,
			publisher.partialAcks, publisher.duplicateDeliveries, backoffs)
	}
	if err := scanForSecret(filepath.Join(root, "spool"), []byte("source-secret")); err != nil {
		return err
	}
	if err := scanForSecret(filepath.Join(root, "tail-state"), []byte("source-secret")); err != nil {
		return err
	}
	hardLimit, err := verifyHardLimit(filepath.Join(root, "hard-limit"))
	if err != nil {
		return err
	}
	result := evidence{
		SchemaVersion: "cdnca.edge.event-spool-smoke/v1", GeneratedEvents: eventCount,
		PublishedEvents: publisher.count, UniqueEventIDs: len(publisher.ids),
		CrashReplayDuplicates: crashReplay.DuplicateEvents, RenameRotationEvents: rotation.AppendedEvents,
		RotationFilesHashed: rotation.RotationFilesHashed, RotationBytesHashed: rotation.RotationBytesHashed,
		CopytruncateEvents: copytruncate.AppendedEvents, PublisherFailures: publisher.failuresSeen,
		PartialAcknowledgments: publisher.partialAcks, DuplicateDeliveries: publisher.duplicateDeliveries,
		BackoffSteps: len(backoffs), QuarantinedLines: crashReplay.QuarantinedLines,
		HardLimitFailClosed: hardLimit,
		PeakSpoolBytes:      beforePublish.PeakBytes, FinalSpoolBytes: finalStats.SegmentBytes,
		FinalPendingEvents: finalStats.PendingEvents, ContiguousSequenceLast: publisher.lastSequence,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func tailBlock(root, marker string) error {
	if marker == "" || !filepath.IsAbs(marker) || filepath.Dir(marker) != root {
		return errors.New("invalid marker path")
	}
	source := filepath.Join(root, "access.jsonl")
	spool, err := newSpool(root)
	if err != nil {
		return err
	}
	tailer, err := newTailer(root, source)
	if err != nil {
		return err
	}
	_, err = tailer.TailOnce(context.Background(), &blockingSink{spool: spool, marker: marker})
	return err
}

type blockingSink struct {
	spool  *eventspool.Spool
	marker string
	once   sync.Once
}

func (sink *blockingSink) AppendBatch(ctx context.Context, events []eventspool.Envelope) ([]eventspool.AppendResult, error) {
	results, err := sink.spool.AppendBatch(ctx, events)
	if err != nil {
		return nil, err
	}
	sink.once.Do(func() {
		if err := os.WriteFile(sink.marker, []byte("appended\n"), 0o600); err != nil {
			fatal("write crash marker: " + err.Error())
		}
		if err := syncDirectory(filepath.Dir(sink.marker)); err != nil {
			fatal("sync crash marker: " + err.Error())
		}
		for {
			time.Sleep(time.Hour)
		}
	})
	return results, nil
}

type verifyingPublisher struct {
	failures            int
	failuresSeen        int
	partial             bool
	partialAcks         int
	duplicateDeliveries int
	count               int
	lastSequence        uint64
	ids                 map[string]struct{}
	messages            map[string][]byte
}

func (publisher *verifyingPublisher) Publish(_ context.Context, publications []eventspool.Publication) (eventspool.PublishAck, error) {
	if publisher.failures > 0 {
		publisher.failures--
		publisher.failuresSeen++
		return eventspool.PublishAck{}, errors.New("injected temporary durable publisher failure")
	}
	for _, publication := range publications {
		var envelope struct {
			SchemaVersion uint16 `json:"schema_version"`
			MessageID     string `json:"message_id"`
			NodeID        string `json:"node_id"`
			Events        []struct {
				EventID string `json:"event_id"`
			} `json:"events"`
		}
		if bytes.Contains(publication.Payload, []byte("source-secret")) || json.Unmarshal(publication.Payload, &envelope) != nil ||
			envelope.SchemaVersion != 1 || envelope.MessageID != publication.MessageID || envelope.NodeID != nodeID ||
			publication.Subject != "cdnca.analytics.ingest.v1."+nodeID || len(envelope.Events) != publication.EventCount {
			return eventspool.PublishAck{}, errors.New("published analytics envelope is invalid or leaked a source secret")
		}
		if previous, duplicate := publisher.messages[publication.MessageID]; duplicate {
			if !bytes.Equal(previous, publication.Payload) {
				return eventspool.PublishAck{}, errors.New("duplicate message ID changed payload")
			}
			publisher.duplicateDeliveries += publication.EventCount
			continue
		}
		if publication.FirstSequence != publisher.lastSequence+1 {
			return eventspool.PublishAck{}, fmt.Errorf("non-contiguous sequence %d after %d", publication.FirstSequence, publisher.lastSequence)
		}
		publisher.messages[publication.MessageID] = append([]byte(nil), publication.Payload...)
		for _, event := range envelope.Events {
			if _, duplicate := publisher.ids[event.EventID]; duplicate {
				return eventspool.PublishAck{}, fmt.Errorf("duplicate event ID %s", event.EventID)
			}
			publisher.ids[event.EventID] = struct{}{}
			publisher.count++
		}
		publisher.lastSequence = publication.LastSequence
	}
	if publisher.partial && len(publications) > 1 {
		publisher.partial = false
		publisher.partialAcks++
		return eventspool.PublishAck{Acknowledged: len(publications) / 2}, errors.New("injected disconnect after partial durable acknowledgement")
	}
	return eventspool.PublishAck{Acknowledged: len(publications)}, nil
}

func newSpool(root string) (*eventspool.Spool, error) {
	return eventspool.New(eventspool.Config{
		Root: filepath.Join(root, "spool"), MaxEventBytes: 16 << 10, MaxSegmentBytes: 1 << 20,
		SoftLimitBytes: 96 << 20, HardLimitBytes: 128 << 20, MaxTenantBytes: 80 << 20,
		MaxBatchEvents: 10_000, PressureMode: eventspool.PressureBackpressure,
		SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC().Add(time.Hour) },
	})
}

func newTailer(root, source string) (*eventspool.Tailer, error) {
	return eventspool.NewTailer(eventspool.TailConfig{
		SourcePath: source, StateDir: filepath.Join(root, "tail-state"),
		Identity: eventspool.TrustedIdentity{
			EnrollmentNodeID: nodeID, TenantID: tenantA, SiteID: siteID, ConfigVersionID: "cfg-smoke-v1",
		},
		MaxLineBytes: 16 << 10, MaxBatchEvents: 10_000, MaxQuarantineBytes: 8 << 20,
	})
}

func writeEvents(path string, start, end int, truncate bool) error {
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if truncate {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	for index := start; index < end; index++ {
		if err := encoder.Encode(smokeEvent(index)); err != nil {
			_ = file.Close()
			return err
		}
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func appendMalformed(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	if _, err := file.Write([]byte("{\"password\":\"source-secret\"\n")); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func scanForSecret(root string, secret []byte) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(content, secret) {
			return fmt.Errorf("sensitive marker found in collector-owned file %s", filepath.Base(path))
		}
		return nil
	})
}

func verifyHardLimit(root string) (bool, error) {
	spool, err := eventspool.New(eventspool.Config{
		Root: root, MaxEventBytes: 16 << 10, MaxSegmentBytes: 20 << 10,
		SoftLimitBytes: 20 << 10, HardLimitBytes: 24 << 10, MaxTenantBytes: 24 << 10,
		MaxBatchEvents: 1000, PressureMode: eventspool.PressureSample,
		AccessSampleEvery: 1, SecuritySampleEvery: 1,
		SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC().Add(time.Hour) },
	})
	if err != nil {
		return false, err
	}
	for index := 0; index < 1000; index++ {
		event := smokeEvent(index)
		event.TenantID = tenantA
		event.NodeID = nodeID
		event.EventID = fmt.Sprintf("hard-%06d", index)
		before, err := spool.Stats()
		if err != nil {
			return false, err
		}
		_, err = spool.AppendBatch(context.Background(), []eventspool.Envelope{event})
		if errors.Is(err, eventspool.ErrHardLimit) {
			after, statsErr := spool.Stats()
			if statsErr != nil {
				return false, statsErr
			}
			if before.PendingEvents != after.PendingEvents || after.SegmentBytes > 24<<10 || after.LastAlertCode != "SPOOL_HARD_WATERMARK" {
				return false, errors.New("hard limit changed durable pending records")
			}
			return true, nil
		}
		if err != nil {
			return false, err
		}
	}
	return false, errors.New("hard limit was not reached")
}

func smokeEvent(index int) eventspool.Envelope {
	tenant := tenantA
	if index%2 == 1 {
		tenant = tenantB
	}
	event := eventspool.Envelope{
		SchemaVersion: eventspool.SchemaVersion, Type: eventspool.EventAccess,
		OccurredAt: time.Unix(1_700_000_000, int64(index)*1000).UTC(),
		TenantID:   tenant, SiteID: siteID, NodeID: nodeID, ConfigVersionID: "cfg-smoke-v1",
		RequestID: fmt.Sprintf("request-%06d", index), TraceID: fmt.Sprintf("trace-%06d", index),
		Host: "smoke.example.test", Path: fmt.Sprintf("/event/%d?token=source-secret", index),
		ClientIP: "2001:db8::1", Method: "GET", Protocol: "HTTP/2", CacheStatus: "MISS",
		StatusCode: 200, RequestBytes: 100, ResponseBytes: 200,
		RequestHeaders: map[string]string{"Authorization": "Bearer source-secret"},
		RequestBody:    map[string]any{"password": "source-secret"},
	}
	if index >= eventCount*9/10 {
		event.Type = eventspool.EventSecurity
		event.Method, event.Protocol, event.CacheStatus = "", "", ""
		event.StatusCode = 403
		event.SecurityType, event.Action, event.Severity, event.RuleID = "waf", "block", "high", "smoke-rule"
	}
	return event
}

func waitForMarker(marker string, child *exec.Cmd) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			return nil
		}
		if child.ProcessState != nil && child.ProcessState.Exited() {
			return errors.New("tail-block child exited before marker")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("timed out waiting for append-before-checkpoint marker")
}

func hasIssue(issues []eventspool.Issue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
