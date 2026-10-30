package waf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublisherRejectsSymlinkAncestorBeforeCreatingState(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}

	direct := filepath.Join(target, "direct")
	directPublisher, err := NewPublisher(direct)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := directPublisher.PublishJSON(policyWithVersion(t, 1, "/direct")); err != nil {
		t.Fatalf("PublishJSON(direct root) error = %v", err)
	}

	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(link, "escaped", "waf")
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(policyWithVersion(t, 2, "/escaped")); err == nil {
		t.Fatal("PublishJSON() accepted a publication root below a symlink ancestor")
	}
	if _, err := os.Lstat(filepath.Join(target, "escaped")); !os.IsNotExist(err) {
		t.Fatalf("publication state was created through a symlink ancestor: %v", err)
	}
}
