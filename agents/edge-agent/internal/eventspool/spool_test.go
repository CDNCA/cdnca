package eventspool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"testing"
	"time"
)

func testConfig(root string) Config {
	_ = os.Chmod(root, 0o700)
	if info, err := os.Lstat(root); err == nil && info.Mode()&os.ModeSymlink == 0 {
		if resolved, resolveErr := filepath.EvalSymlinks(root); resolveErr == nil {
			root = resolved
		}
	} else if resolved, resolveErr := filepath.EvalSymlinks(filepath.Dir(root)); resolveErr == nil {
		root = filepath.Join(resolved, filepath.Base(root))
	}
	return Config{
		Root: root, MaxEventBytes: 2048, MaxSegmentBytes: 4096,
		SoftLimitBytes: 32 << 10, HardLimitBytes: 64 << 10, MaxTenantBytes: 48 << 10,
		MaxBatchEvents: 1000, PressureMode: PressureBackpressure,
		SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC().Add(time.Hour) },
	}
}

func newTestSpool(t *testing.T, config Config) *Spool {
	t.Helper()
	spool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return spool
}

type collectingPublisher struct {
	mu       sync.Mutex
	failures int
	ids      []string
}

func (p *collectingPublisher) Publish(_ context.Context, publications []Publication) (PublishAck, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failures > 0 {
		p.failures--
		return PublishAck{}, errors.New("temporary publisher failure")
	}
	for _, publication := range publications {
		var envelope struct {
			Events []struct {
				EventID string `json:"event_id"`
			} `json:"events"`
		}
		if err := json.Unmarshal(publication.Payload, &envelope); err != nil {
			return PublishAck{}, err
		}
		for _, event := range envelope.Events {
			p.ids = append(p.ids, event.EventID)
		}
	}
	return PublishAck{Acknowledged: len(publications)}, nil
}

func TestSpoolRestartDuplicateAckAndPublisherBoundary(t *testing.T) {
	config := testConfig(t.TempDir())
	spool := newTestSpool(t, config)
	values := []Envelope{pendingAccess("evt-1", tenantOne), pendingAccess("evt-2", tenantOne)}
	results, err := spool.AppendBatch(context.Background(), values)
	if err != nil || results[0].Sequence != 1 || results[1].Sequence != 2 {
		t.Fatalf("append = %#v, %v", results, err)
	}
	duplicate, err := spool.AppendBatch(context.Background(), []Envelope{values[0]})
	if err != nil || !duplicate[0].Duplicate || duplicate[0].Sequence != 1 {
		t.Fatalf("duplicate = %#v, %v", duplicate, err)
	}
	conflict := values[0]
	conflict.StatusCode = 201
	if _, err := spool.AppendBatch(context.Background(), []Envelope{conflict}); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict error = %v", err)
	}

	restarted := newTestSpool(t, config)
	if err := restarted.Ack(2, "evt-2"); !errors.Is(err, ErrAckOrder) {
		t.Fatalf("out-of-order ack error = %v", err)
	}
	if err := restarted.Ack(1, "evt-1"); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Ack(1, "evt-1"); err != nil {
		t.Fatalf("duplicate ack: %v", err)
	}
	if err := restarted.Ack(1, "wrong"); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting duplicate ack = %v", err)
	}

	publisher := &collectingPublisher{failures: 1}
	if _, err := restarted.Flush(context.Background(), publisher, 100); err == nil {
		t.Fatal("publisher failure must not acknowledge records")
	}
	stats, err := restarted.Stats()
	if err != nil || stats.AckedSequence != 1 || stats.PendingEvents != 1 {
		t.Fatalf("stats after failed publish = %#v, %v", stats, err)
	}
	if result, err := restarted.Flush(context.Background(), publisher, 100); err != nil || result.Published != 1 || result.LastSequence != 2 {
		t.Fatalf("flush = %#v, %v", result, err)
	}
	stats, err = restarted.Stats()
	if err != nil || stats.PendingEvents != 0 || stats.SegmentBytes != 0 || stats.AckedSequence != 2 {
		t.Fatalf("reclaimed stats = %#v, %v", stats, err)
	}
}

func TestSpoolRecoversIncompleteOpenAndRejectsCorruptSealed(t *testing.T) {
	t.Run("incomplete-open", func(t *testing.T) {
		config := testConfig(t.TempDir())
		spool := newTestSpool(t, config)
		if _, err := spool.AppendBatch(context.Background(), []Envelope{pendingAccess("evt-open", tenantOne)}); err != nil {
			t.Fatal(err)
		}
		matches, _ := filepath.Glob(filepath.Join(config.Root, "segments", "*.open"))
		file, err := os.OpenFile(matches[0], os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = file.Write([]byte{0, 0, 1})
		_ = file.Sync()
		_ = file.Close()
		restarted := newTestSpool(t, config)
		stats, err := restarted.Stats()
		if err != nil || stats.PendingEvents != 1 {
			t.Fatalf("recovered stats = %#v, %v", stats, err)
		}
	})

	t.Run("corrupt-sealed", func(t *testing.T) {
		config := testConfig(t.TempDir())
		spool := newTestSpool(t, config)
		for index := 0; index < 20; index++ {
			if _, err := spool.AppendBatch(context.Background(), []Envelope{pendingAccess(fmtID(index), tenantOne)}); err != nil {
				t.Fatal(err)
			}
		}
		matches, _ := filepath.Glob(filepath.Join(config.Root, "segments", "*.seg"))
		if len(matches) == 0 {
			t.Fatal("test did not seal a segment")
		}
		file, err := os.OpenFile(matches[0], os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteAt([]byte{0xff}, segmentHeaderSize+recordHeaderSize+4); err != nil {
			t.Fatal(err)
		}
		_ = file.Close()
		if _, err := New(config); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("corrupt segment error = %v", err)
		}
	})
}

func TestSpoolPressureTenantFairnessAndDiskFullCode(t *testing.T) {
	t.Run("disk-full", func(t *testing.T) {
		config := testConfig(t.TempDir())
		spool := newTestSpool(t, config)
		spool.testWriteError = func() error { return syscall.ENOSPC }
		if _, err := spool.AppendBatch(context.Background(), []Envelope{pendingAccess("evt-disk-full", tenantOne)}); !errors.Is(err, syscall.ENOSPC) {
			t.Fatalf("disk full error = %v", err)
		}
		spool.testWriteError = nil
		stats, err := spool.Stats()
		if err != nil || stats.PendingEvents != 0 || stats.LastAlertCode != "SPOOL_DISK_FULL" {
			t.Fatalf("disk full stats = %#v, %v", stats, err)
		}
	})

	t.Run("backpressure", func(t *testing.T) {
		config := testConfig(t.TempDir())
		config.SoftLimitBytes = config.MaxSegmentBytes
		config.HardLimitBytes = 16 << 10
		config.MaxTenantBytes = config.HardLimitBytes
		spool := newTestSpool(t, config)
		var got error
		for index := 0; index < 100; index++ {
			_, got = spool.AppendBatch(context.Background(), []Envelope{pendingAccess(fmtID(index), tenantOne)})
			if got != nil {
				break
			}
		}
		if !errors.Is(got, ErrBackpressure) {
			t.Fatalf("pressure error = %v", got)
		}
	})

	t.Run("hard-watermark", func(t *testing.T) {
		config := testConfig(t.TempDir())
		config.SoftLimitBytes = config.MaxSegmentBytes
		config.HardLimitBytes = config.MaxSegmentBytes + 1024
		config.MaxTenantBytes = config.HardLimitBytes
		config.PressureMode = PressureSample
		config.AccessSampleEvery, config.SecuritySampleEvery = 1, 1
		spool := newTestSpool(t, config)
		var got error
		for index := 0; index < 100; index++ {
			_, got = spool.AppendBatch(context.Background(), []Envelope{pendingAccess(fmtID(index), tenantOne)})
			if got != nil {
				break
			}
		}
		if !errors.Is(got, ErrHardLimit) {
			t.Fatalf("hard limit error = %v", got)
		}
		stats, _ := spool.Stats()
		if stats.LastAlertCode != "SPOOL_HARD_WATERMARK" {
			t.Fatalf("alert = %q", stats.LastAlertCode)
		}
		if safeErrorCode(syscall.ENOSPC) != "SPOOL_DISK_FULL" {
			t.Fatal("ENOSPC must map to stable non-payload alert")
		}
	})

	t.Run("tenant-isolation", func(t *testing.T) {
		config := testConfig(t.TempDir())
		config.SoftLimitBytes = 24 << 10
		config.HardLimitBytes = 32 << 10
		config.MaxTenantBytes = config.MaxSegmentBytes
		spool := newTestSpool(t, config)
		var got error
		for index := 0; index < 100; index++ {
			_, got = spool.AppendBatch(context.Background(), []Envelope{pendingAccess(fmtID(index), tenantOne)})
			if got != nil {
				break
			}
		}
		if !errors.Is(got, ErrTenantLimit) {
			t.Fatalf("tenant limit error = %v", got)
		}
		if _, err := spool.AppendBatch(context.Background(), []Envelope{pendingAccess("evt-other", tenantTwo)}); err != nil {
			t.Fatalf("other tenant was blocked: %v", err)
		}
	})

	t.Run("sampling", func(t *testing.T) {
		config := testConfig(t.TempDir())
		config.SoftLimitBytes = config.MaxSegmentBytes
		config.HardLimitBytes = 32 << 10
		config.MaxTenantBytes = config.HardLimitBytes
		config.PressureMode = PressureSample
		config.AccessSampleEvery, config.SecuritySampleEvery = 2, 2
		spool := newTestSpool(t, config)
		seenSample := false
		for index := 0; index < 100 && !seenSample; index++ {
			result, err := spool.AppendBatch(context.Background(), []Envelope{pendingAccess(fmtID(index), tenantOne)})
			if err != nil {
				t.Fatal(err)
			}
			seenSample = result[0].Sampled
		}
		if !seenSample {
			t.Fatal("explicit sampling policy was not applied")
		}
	})
}

func TestSpoolRejectsSymlinkAndHardlink(t *testing.T) {
	target := t.TempDir()
	symlink := filepath.Join(t.TempDir(), "spool")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	config := testConfig(symlink)
	if _, err := New(config); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink root error = %v", err)
	}

	config = testConfig(t.TempDir())
	spool := newTestSpool(t, config)
	if _, err := spool.AppendBatch(context.Background(), []Envelope{pendingAccess("evt-link", tenantOne)}); err != nil {
		t.Fatal(err)
	}
	segment, _ := filepath.Glob(filepath.Join(config.Root, "segments", "*.open"))
	if err := os.Link(segment[0], filepath.Join(config.Root, "segment-hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("hardlink segment error = %v", err)
	}
}

func TestSpoolRejectsTraversalAndCrossFilesystemIdentity(t *testing.T) {
	root := t.TempDir()
	config := testConfig(filepath.Join(root, "spool"))
	config.Root = root + "/child/../spool"
	if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("traversal error = %v", err)
	}
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(private)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if err := ensureOwnerDirectory(private, uint64(stat.Dev)+1); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("cross-filesystem identity error = %v", err)
	}
}

func TestConcurrentWriterReader(t *testing.T) {
	config := testConfig(t.TempDir())
	config.SoftLimitBytes = 16 << 20
	config.HardLimitBytes = 32 << 20
	config.MaxTenantBytes = 24 << 20
	spool := newTestSpool(t, config)
	publisher := &collectingPublisher{}
	var writers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		writers.Add(1)
		go func(worker int) {
			defer writers.Done()
			for index := 0; index < 50; index++ {
				if _, err := spool.AppendBatch(context.Background(), []Envelope{pendingAccess(fmtID(worker*1000+index), tenantOne)}); err != nil {
					t.Errorf("append: %v", err)
					return
				}
			}
		}(worker)
	}
	readers := sync.WaitGroup{}
	for index := 0; index < 2; index++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				_, err := spool.Flush(context.Background(), publisher, 20)
				if err != nil {
					t.Errorf("flush: %v", err)
					return
				}
				stats, err := spool.Stats()
				if err != nil {
					t.Errorf("stats: %v", err)
					return
				}
				if stats.PendingEvents == 0 {
					return
				}
			}
		}()
	}
	writers.Wait()
	readers.Wait()
	for {
		stats, _ := spool.Stats()
		if stats.PendingEvents == 0 {
			break
		}
		if _, err := spool.Flush(context.Background(), publisher, 20); err != nil {
			t.Fatal(err)
		}
	}
	publisher.mu.Lock()
	ids := append([]string(nil), publisher.ids...)
	publisher.mu.Unlock()
	sort.Strings(ids)
	if len(ids) != 200 {
		t.Fatalf("published %d events", len(ids))
	}
	for index := 1; index < len(ids); index++ {
		if ids[index] == ids[index-1] {
			t.Fatalf("duplicate published ID %q", ids[index])
		}
	}
}

func fmtID(index int) string {
	return fmt.Sprintf("evt-%06d", index)
}
