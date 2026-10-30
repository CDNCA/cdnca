package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaintenanceBuildFactsUseEmbeddedProvenanceAndActualExecutable(t *testing.T) {
	file := filepath.Join(t.TempDir(), "control-api")
	content := []byte("actual-running-binary")
	if err := os.WriteFile(file, content, 0o500); err != nil {
		t.Fatal(err)
	}
	facts := maintenanceBuildFacts(strings.Repeat("a", 40), strings.Repeat("b", 40), "2026-10-08T01:02:03Z", file)
	if facts.SourceCommit == nil || *facts.SourceCommit != strings.Repeat("a", 40) ||
		facts.SourceTree == nil || *facts.SourceTree != strings.Repeat("b", 40) ||
		facts.BuiltAt == nil || facts.BuiltAt.Format("2006-01-02T15:04:05Z07:00") != "2026-10-08T01:02:03Z" ||
		facts.BinarySHA256 == nil || *facts.BinarySHA256 != fmt.Sprintf("%x", sha256.Sum256(content)) {
		t.Fatalf("build facts = %+v", facts)
	}
}

func TestMaintenanceBuildFactsRejectUnrecordedOrMalformedMetadata(t *testing.T) {
	for _, input := range []struct{ commit, tree, built string }{
		{"", "", ""},
		{"main", "latest", "yesterday"},
		{strings.Repeat("A", 40), strings.Repeat("b", 39), "2026-10-08"},
	} {
		facts := maintenanceBuildFacts(input.commit, input.tree, input.built, "/no/such/upgrade-test-binary")
		if facts.SourceCommit != nil || facts.SourceTree != nil || facts.BuiltAt != nil || facts.BinarySHA256 != nil {
			t.Fatalf("unverified metadata accepted: %+v", facts)
		}
	}
	if facts := maintenanceBuildFacts("", "", "", t.TempDir()); facts.BinarySHA256 != nil {
		t.Fatal("directory hashed as a binary")
	}
}
