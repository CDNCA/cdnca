//go:build integration && !windows

package controlplaneupgrade

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The Python bootstrap tests supply exactly the same valid/adversarial archives
// to this existing Go validator. This does not run a runner or touch a database.
func TestNativeBaselineArchiveCrossValidation(t *testing.T) {
	directory := os.Getenv("NATIVE_BASELINE_ARCHIVE_FIXTURES")
	if directory == "" {
		t.Skip("set NATIVE_BASELINE_ARCHIVE_FIXTURES to the isolated fixture directory")
	}
	var keys map[string]ed25519.PublicKey
	if filename := os.Getenv("NATIVE_BASELINE_ARTIFACT_TRUST_FILE"); filename != "" {
		encoded, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		keys, err = DecodeNativeArtifactTrust(encoded)
		if err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := os.ReadFile(filepath.Join(directory, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Digest  string `json:"digest"`
		Size    int64  `json:"size"`
		Accept  bool   `json:"accept"`
	}
	if err := json.Unmarshal(encoded, &cases); err != nil || len(cases) < 10 {
		t.Fatalf("expected nonempty adversarial fixture suite: count=%d err=%v", len(cases), err)
	}
	name := regexp.MustCompile(`^[a-z0-9_-]+$`)
	for _, test := range cases {
		if !name.MatchString(test.Name) {
			t.Fatal("invalid fixture name")
		}
		t.Run(test.Name, func(t *testing.T) {
			filename := filepath.Join(directory, test.Name+".tar")
			artifact := Artifact{Version: test.Version, Digest: test.Digest, Size: test.Size}
			platform := NativePlatform{OS: "linux", Arch: "amd64"}
			var err error
			if keys == nil {
				_, err = ValidateNativeReleaseArchive(filename, artifact, platform)
			} else {
				_, err = ValidateSignedNativeReleaseArchive(filename, artifact, platform, keys)
			}
			if (err == nil) != test.Accept {
				t.Fatalf("Go archive acceptance=%t, expected=%t: %v", err == nil, test.Accept, err)
			}
		})
	}
	t.Logf("executed %d native baseline archive fixtures", len(cases))
}
