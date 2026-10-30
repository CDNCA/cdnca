package deployment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoredReleaseManifestRejectsAmbiguousJSON(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(string) string
	}{
		{name: "unknown field", mutate: func(content string) string {
			return strings.TrimSuffix(strings.TrimSpace(content), "}") + `,"future_security_policy":true}`
		}},
		{name: "duplicate files field", mutate: func(content string) string {
			return strings.Replace(content, `{"files":`, `{"files":[],"files":`, 1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager, _ := newTestManager(t, &fakePrechecker{failFor: map[string]error{}},
				&fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
			command := testCommand(t, "stored-manifest-"+strings.ReplaceAll(test.name, " ", "-"), 1,
				"cfg-v1", "", map[string][]byte{"site.conf": []byte("server {}")})
			normalized, _, err := validateAndDigest(command)
			if err != nil {
				t.Fatalf("validateAndDigest() error = %v", err)
			}
			releasePath, err := manager.store.stage(command, normalized)
			if err != nil {
				t.Fatalf("stage() error = %v", err)
			}
			if err := manager.store.verifyRelease(releasePath, normalized, command.Bundle.ManifestSHA256); err != nil {
				t.Fatalf("canonical verifyRelease() error = %v", err)
			}
			manifestPath := filepath.Join(releasePath, releaseManifestFile)
			content, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatalf("ReadFile(manifest) error = %v", err)
			}
			makeTreeWritable(releasePath)
			if err := os.Chmod(manifestPath, 0o600); err != nil {
				t.Fatalf("Chmod(manifest) error = %v", err)
			}
			if err := os.WriteFile(manifestPath, []byte(test.mutate(string(content))), 0o600); err != nil {
				t.Fatalf("WriteFile(manifest) error = %v", err)
			}
			if err := manager.store.verifyRelease(releasePath, normalized, command.Bundle.ManifestSHA256); err == nil {
				t.Fatal("ambiguous stored manifest was accepted")
			}
		})
	}
}
