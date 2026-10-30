package sched302runtime

import (
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
)

const node = "00000000-0000-4000-8000-0000000000a0"

func table(t *testing.T, revision uint64, nodeID string) (sched302.Table, []byte) {
	t.Helper()
	value := sched302.Table{Schema: sched302.TableSchema, NodeID: nodeID, Revision: revision, GeneratedAt: time.Now().Unix(),
		Sites: []sched302.TableSite{{SiteID: "11111111-1111-4111-8111-111111111111", Hosts: []string{"dl.example.test"},
			Key: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Candidates: []sched302.Candidate{}}}}
	encoded, err := sched302.Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	return value, encoded
}

func TestApplyInstallsNewerTablesOnly(t *testing.T) {
	root := t.TempDir()
	runtime, err := New(root, node)
	if err != nil {
		t.Fatal(err)
	}
	second, encoded := table(t, 2, node)
	if err := runtime.Apply(second, encoded); err != nil {
		t.Fatal(err)
	}
	first, older := table(t, 1, node)
	if err := runtime.Apply(first, older); err != nil || runtime.Revision() != 2 {
		t.Fatalf("older table: %v revision %d", err, runtime.Revision())
	}
	raw, err := os.ReadFile(runtime.Path())
	if err != nil || string(raw) != string(encoded) {
		t.Fatalf("installed %q %v", raw, err)
	}
	info, _ := os.Stat(runtime.Path())
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", info.Mode())
	}
	// A restarted agent keeps the installed revision.
	restarted, err := New(root, node)
	if err != nil || restarted.Revision() != 2 {
		t.Fatalf("restart: %v %d", err, restarted.Revision())
	}
	other, foreign := table(t, 9, "00000000-0000-4000-8000-0000000000b0")
	if err := runtime.Apply(other, foreign); err == nil {
		t.Fatal("foreign table installed")
	}
	third, _ := table(t, 3, node)
	if err := runtime.Apply(third, append(encoded, ' ')); err == nil {
		t.Fatal("non-canonical bytes installed")
	}
	entries, _ := os.ReadDir(root + "/schedule302")
	if len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
}
