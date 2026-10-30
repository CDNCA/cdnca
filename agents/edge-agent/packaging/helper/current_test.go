package helper

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

func TestInspectInstalledRejectsCurrentAndReleaseTamper(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, fixture *serviceFixture)
	}{
		{
			name: "current target escape",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				current := filepath.Join(fixture.paths.ReleaseRoot, "current")
				if err := os.Remove(current); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("../outside", current); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "current hardlink",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				current := filepath.Join(fixture.paths.ReleaseRoot, "current")
				if err := os.Link(current, filepath.Join(fixture.paths.ReleaseRoot, "current-copy")); err != nil {
					if runtime.GOOS != "linux" {
						t.Skip("platform does not permit hard-linking a symlink")
					}
					t.Fatal(err)
				}
			},
		},
		{
			name: "manifest symlink",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				path := filepath.Join(fixture.paths.ReleaseRoot, "versions", "1.0.0", "manifest")
				target := path + ".target"
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "manifest signature tamper",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				path := filepath.Join(fixture.paths.ReleaseRoot, "versions", "1.0.0", "manifest.sig")
				content, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				content[0] ^= 1
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, content, 0o444); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o444); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "executable tamper",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				path := filepath.Join(fixture.paths.ReleaseRoot, "versions", "1.0.0", "edge-agent")
				if err := os.Chmod(path, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("tampered"), 0o555); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o555); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "accepted manifest corrupt",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				if err := os.WriteFile(fixture.paths.AcceptedManifest, []byte("not-a-manifest"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			if _, err := InspectInstalled(fixture.paths, fixture.packagePublic, fixture.uid, fixture.gid); err != nil {
				t.Fatalf("baseline facts: %v", err)
			}
			test.mutate(t, fixture)
			if _, err := InspectInstalled(fixture.paths, fixture.packagePublic, fixture.uid, fixture.gid); !errors.Is(err, ErrCurrentFacts) {
				t.Fatalf("tamper error = %v", err)
			}
			request := protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationCurrent}
			response := fixture.handle(request, nil)
			if response.OK || response.ErrorCode != protocol.ErrorCurrentUnavailable {
				t.Fatalf("current after tamper = %#v", response)
			}
		})
	}
}

func TestInspectInstalledReconstructsCanonicalOuterDigest(t *testing.T) {
	fixture := newServiceFixture(t)
	release := fixture.release(1, "1.0.0")
	facts, err := InspectInstalled(fixture.paths, fixture.packagePublic, fixture.uid, fixture.gid)
	if err != nil {
		t.Fatal(err)
	}
	if facts.OuterArtifactSHA256 != digestOf(release.bundle) || facts.OuterArtifactSHA256 == facts.ExecutableSHA256 {
		t.Fatalf("outer=%s executable=%s want=%s", facts.OuterArtifactSHA256, facts.ExecutableSHA256, digestOf(release.bundle))
	}
}

func TestCurrentStoreFailsClosedAndRepairsCanonicalCorruption(t *testing.T) {
	fixture := newServiceFixture(t)
	receipt := fixture.current()
	store, err := NewCurrentStore(fixture.paths.StateDirectory, fixture.uid, fixture.gid)
	if err != nil {
		t.Fatal(err)
	}
	loaded, digest, err := store.Load()
	if err != nil || !sameReceipt(loaded, receipt) || !validHelperDigest(digest) {
		t.Fatalf("load = (%+v, %s, %v)", loaded, digest, err)
	}
	path := filepath.Join(fixture.paths.StateDirectory, "current.json")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(); !errors.Is(err, ErrCurrentFacts) {
		t.Fatalf("wide current mode error = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(); !errors.Is(err, ErrCurrentFacts) {
		t.Fatalf("hardlink current error = %v", err)
	}
}

func TestServiceRepairsInvalidCurrentReceiptSignatureFromInstalledFacts(t *testing.T) {
	fixture := newServiceFixture(t)
	original := fixture.current()
	path := filepath.Join(fixture.paths.StateDirectory, "current.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record currentRecord
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatal(err)
	}
	record.Receipt.Signature.Value = base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	content, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeTestProtectedFile(t, path, journalMode, content)
	repaired := fixture.current()
	if repaired.Signature.Value == record.Receipt.Signature.Value || repaired.Signature.Value != original.Signature.Value {
		t.Fatalf("repaired receipt = %+v", repaired)
	}
}
