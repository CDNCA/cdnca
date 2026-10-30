package diskguard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDeleteCandidateWritesDurableIntentBeforeRename(t *testing.T) {
	root := mustRealPathForTest(t.TempDir())
	candidatePath := filepath.Join(root, "candidate.tmp")
	writeOldFile(t, candidatePath, "candidate", 2*time.Hour)
	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", root)),
		&sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	var observed string
	guard.hooks.beforeQuarantine = func(directory *openDirectory, item candidate) {
		observed = activationJournalPath(directory.path, item.name)
		if _, err := os.Stat(observed); err != nil {
			t.Errorf("journal was not durable before rename: %v", err)
		}
	}
	if _, err := guard.Evaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if observed == "" {
		t.Fatal("before-quarantine hook did not run")
	}
}

func TestRecoveryDeletesOnlyExactQuarantinedCandidate(t *testing.T) {
	root := mustRealPathForTest(t.TempDir())
	candidatePath := filepath.Join(root, "candidate.tmp")
	writeOldFile(t, candidatePath, "candidate", 2*time.Hour)
	directory, err := secureOpenDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := directory.metadata("candidate.tmp")
	if err != nil {
		directory.close()
		t.Fatal(err)
	}
	privateRoot, err := openPrivateQuarantineRoot(directory)
	if err != nil {
		directory.close()
		t.Fatal(err)
	}
	namespace, name, err := createPrivateQuarantine(privateRoot)
	if err != nil {
		privateRoot.close()
		directory.close()
		t.Fatal(err)
	}
	if err := unixRenameForTest(directory, namespace, "candidate.tmp"); err != nil {
		t.Fatal(err)
	}
	intent := quarantineIntent{
		SchemaVersion: ConfigSchemaVersion, ConfigID: "test-disk-guard", ConfigRevision: 1,
		DirectoryID: "cache", DirectoryDevice: directory.identity.device, DirectoryInode: directory.identity.inode,
		PrivateRootDevice: privateRoot.identity.device, PrivateRootInode: privateRoot.identity.inode,
		NamespaceName: name, NamespaceDevice: namespace.identity.device, NamespaceInode: namespace.identity.inode,
		CandidateName: "candidate.tmp", CandidateDevice: metadata.identity.device, CandidateInode: metadata.identity.inode,
		CandidateLinks: metadata.identity.links, CandidateSize: metadata.size, CandidateAllocated: metadata.allocatedBytes,
		CandidateMtimeSeconds: metadata.modified.seconds, CandidateMtimeNanos: metadata.modified.nanoseconds, Renamed: true,
	}
	if err := writeQuarantineIntent(privateRoot, intent); err != nil {
		t.Fatal(err)
	}
	namespace.close()
	privateRoot.close()
	directory.close()

	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", root)), &sequenceUsage{values: []filesystemUsage{basisPoints(5000)}})
	if _, err := guard.Evaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(candidatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("candidate remained after recovery: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, quarantineRootName))
	if err != nil || len(entries) != 0 {
		t.Fatalf("private root was not empty after recovery: entries=%v err=%v", entries, err)
	}
}

func TestRecoveryKeepsMutatedCandidateAndEvidence(t *testing.T) {
	root := mustRealPathForTest(t.TempDir())
	candidatePath := filepath.Join(root, "candidate.tmp")
	writeOldFile(t, candidatePath, "candidate", 2*time.Hour)
	directory, err := secureOpenDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := directory.metadata("candidate.tmp")
	if err != nil {
		directory.close()
		t.Fatal(err)
	}
	privateRoot, err := openPrivateQuarantineRoot(directory)
	if err != nil {
		directory.close()
		t.Fatal(err)
	}
	namespace, name, err := createPrivateQuarantine(privateRoot)
	if err != nil {
		privateRoot.close()
		directory.close()
		t.Fatal(err)
	}
	if err := unixRenameForTest(directory, namespace, "candidate.tmp"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(namespace.path, "candidate.tmp"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	intent := quarantineIntent{
		SchemaVersion: ConfigSchemaVersion, ConfigID: "test-disk-guard", ConfigRevision: 1,
		DirectoryID: "cache", DirectoryDevice: directory.identity.device, DirectoryInode: directory.identity.inode,
		PrivateRootDevice: privateRoot.identity.device, PrivateRootInode: privateRoot.identity.inode,
		NamespaceName: name, NamespaceDevice: namespace.identity.device, NamespaceInode: namespace.identity.inode,
		CandidateName: "candidate.tmp", CandidateDevice: metadata.identity.device, CandidateInode: metadata.identity.inode,
		CandidateLinks: metadata.identity.links, CandidateSize: metadata.size, CandidateAllocated: metadata.allocatedBytes,
		CandidateMtimeSeconds: metadata.modified.seconds, CandidateMtimeNanos: metadata.modified.nanoseconds, Renamed: true,
	}
	if err := writeQuarantineIntent(privateRoot, intent); err != nil {
		t.Fatal(err)
	}
	namespace.close()
	privateRoot.close()
	directory.close()

	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", root)), &sequenceUsage{values: []filesystemUsage{basisPoints(5000)}})
	report, err := guard.Evaluate(context.Background())
	if err == nil || report.Metrics.FailureReason != FailureCandidateChanged {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	if _, err := os.Stat(candidatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original candidate unexpectedly changed: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, quarantineRootName))
	if err != nil || len(entries) == 0 {
		t.Fatalf("mutation evidence not retained: entries=%v err=%v", entries, err)
	}
}

func unixRenameForTest(from, to *openDirectory, name string) error {
	return unix.Renameat(from.fd, name, to.fd, name)
}
