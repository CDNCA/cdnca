package eventspool

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Quarantine records older than quarantineRetention are removed when a line
// is quarantined: their lines are past the spool hard age limit, and the
// directory otherwise grew without bound until the limit stopped the tail
// (one node held 49 842 records).
func TestTailerQuarantineRetention(t *testing.T) {
	source, spool, config := newTailHarness(t)
	config.MaxQuarantineBytes = 64 << 10
	now := time.Date(2026, 11, 19, 5, 0, 0, 0, time.UTC)
	config.Now = func() time.Time { return now }
	tailer, err := NewTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(config.StateDir, "quarantine")
	write := func(name string, age time.Duration) string {
		path := filepath.Join(directory, fmt.Sprintf("line-%064x.json", name))
		record, _ := json.Marshal(quarantinedLine{SchemaVersion: SchemaVersion, Code: "TAIL_INVALID_JSON", Generation: 1, Bytes: 1,
			SourceDevice: 1, SourceInode: 1, ContentSHA256: fmt.Sprintf("%064x", 1), ObservedAt: now.Add(-age)})
		if err := os.WriteFile(path, append(record, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// old records alone fill the limit
	var old []string
	for index := 0; index < 400; index++ {
		old = append(old, write(fmt.Sprintf("a%d", index), quarantineRetention+time.Hour))
	}
	recent := write("b", time.Hour)
	if err := os.WriteFile(source, []byte("{\"password\":\"source-secret\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := tailer.TailOnce(context.Background(), spool)
	if err != nil || result.QuarantinedLines != 1 {
		t.Fatalf("tail = %#v, %v", result, err)
	}
	for _, path := range old {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("expired record kept: %s %v", path, err)
		}
	}
	entries, err := os.ReadDir(directory)
	if _, statErr := os.Lstat(recent); err != nil || statErr != nil || len(entries) != 2 {
		t.Fatalf("entries %d %v, recent %v", len(entries), err, statErr)
	}
}
