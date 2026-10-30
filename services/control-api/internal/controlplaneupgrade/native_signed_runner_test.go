//go:build !windows

package controlplaneupgrade

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeSignedRunnerWithoutGit(t *testing.T) {
	t.Run("controlled v1 to v2 transition keeps Git rollback", func(t *testing.T) {
		fixture := newNativeFixture(t)
		private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x37}, ed25519.SeedSize))
		fixture.runner.executor.config.ArtifactPublicKeys = map[string]ed25519.PublicKey{"release-test": private.Public().(ed25519.PublicKey)}
		manifest, files := fixture.manifests[fixture.next.Digest], fixture.contents[fixture.next.Digest]
		manifest.Schema, manifest.KeyID = NativeManifestSignedSchema, "release-test"
		raw, _ := json.Marshal(manifest)
		signature := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(NativeManifestSignedSchema+"\n"), raw...))))
		filename, candidate := nativeSignedReleaseArchiveFixture(t, raw, signature, 0o644, files)
		encoded, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture.runner.executor.config.ReleaseRoot, "artifacts", candidate.Digest+".tar"), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		fixture.next = candidate
		fixture.manifests[candidate.Digest], fixture.contents[candidate.Digest] = manifest, files
		fixture.bundle = nativeSignedBundle(t, fixture.bundle, fixture.old, candidate)
		// A v2 candidate must not require its source object on a legacy customer.
		if err := os.Remove(filepath.Join(fixture.runner.executor.config.SourceGitDirectory, "objects", manifest.Source.Commit[:2], manifest.Source.Commit[2:])); err != nil {
			t.Fatal(err)
		}
		fixture.commands.failHealth = candidate.Digest
		if receipt, err := fixture.runner.Run(t.Context(), fixture.bundle); !errors.Is(err, ErrRolledBack) || receipt.Result != ResultRolledBack {
			t.Fatalf("controlled migration rollback: %+v %v", receipt, err)
		}
		fixture.assertLinks(t, fixture.old.Digest, fixture.old.Digest)
	})
	t.Run("apply restart expired plan and status", func(t *testing.T) {
		fixture := newNativeSignedFixture(t)
		if status, err := fixture.runner.Probe(t.Context()); err != nil || !status.Ready || status.ArtifactFormat != NativeManifestSignedSchema {
			t.Fatalf("signed baseline: %+v %v", status, err)
		}
		if receipt, err := fixture.runner.Run(t.Context(), fixture.bundle); err != nil || receipt.Result != ResultApplied {
			t.Fatalf("signed apply: %+v %v", receipt, err)
		}
		fixture.assertLinks(t, fixture.next.Digest, fixture.old.Digest)
		config, trust, store := fixture.runner.executor.config, fixture.runner.runner.trust, fixture.runner.runner.store
		later := fixture.runner.runner.now().Add(30 * 24 * time.Hour)
		if err := fixture.runner.Close(); err != nil {
			t.Fatal(err)
		}
		runner, err := newNativeStandaloneRunner(config, trust, store, func() time.Time { return later }, uint32(os.Getuid()), fixture.commands, fixture.commands.inspect)
		if err != nil {
			t.Fatal(err)
		}
		fixture.runner = runner
		if status, err := runner.Probe(t.Context()); err != nil || !status.Ready {
			t.Fatalf("proof must survive plan expiry and restart: %+v %v", status, err)
		}
		if _, err := runner.Run(t.Context(), fixture.bundle); err == nil {
			t.Fatal("expired authorization accepted for execution")
		}
		filename := filepath.Join(config.ReleaseRoot, "signed-status.json")
		if err := runner.PublishStatus(t.Context(), filename); err != nil {
			t.Fatal(err)
		}
		if status, err := readNativeStandaloneStatus(filename, fixture.installationID(), later, uint32(os.Getuid()), fixture.commands.inspect); err != nil || status.ArtifactFormat != NativeManifestSignedSchema {
			t.Fatalf("v2 status reader: %+v %v", status, err)
		}
		state, err := readNativeStandaloneState(filename+".state.json", uint32(os.Getuid()))
		if err != nil {
			t.Fatal(err)
		}
		history, err := readNativeStandaloneHistory(filename+".history.json", uint32(os.Getuid()))
		if err != nil || history.PlanID != state.PlanID || history.Sequence != state.Sequence ||
			history.Entries[0].Phase != PhaseVerified || history.Entries[len(history.Entries)-1].Phase != PhaseCompleted {
			t.Fatalf("published history: %+v %v", history, err)
		}
	})
	t.Run("whole release rollback", func(t *testing.T) {
		fixture := newNativeSignedFixture(t)
		fixture.commands.failHealth = fixture.next.Digest
		if receipt, err := fixture.runner.Run(t.Context(), fixture.bundle); !errors.Is(err, ErrRolledBack) || receipt.Result != ResultRolledBack {
			t.Fatalf("signed rollback: %+v %v", receipt, err)
		}
		fixture.assertLinks(t, fixture.old.Digest, fixture.old.Digest)
		if status, err := fixture.runner.Probe(t.Context()); err != nil || !status.Ready {
			t.Fatalf("rolled back proof: %+v %v", status, err)
		}
	})
	for _, change := range []string{"directory signature", "directory manifest whitespace", "directory signature mode", "missing trust", "v1 without git", "v2 to v1", "unsigned v2 target", "signature before rollback"} {
		t.Run(change, func(t *testing.T) {
			fixture := newNativeSignedFixture(t)
			executor := fixture.runner.executor
			current := executor.release(fixture.old)
			switch change {
			case "directory signature", "signature before rollback":
				if err := os.WriteFile(filepath.Join(current, NativeSignatureFilename), []byte("invalid"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "directory manifest whitespace":
				filename := filepath.Join(current, NativeManifestFilename)
				encoded, err := os.ReadFile(filename)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filename, append(encoded, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
			case "directory signature mode":
				if err := os.Chmod(filepath.Join(current, NativeSignatureFilename), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing trust":
				executor.config.ArtifactPublicKeys = nil
			case "v1 without git":
				legacy := newNativeFixture(t)
				legacy.runner.executor.config.SourceGitDirectory = ""
				legacy.runner.executor.config.ArtifactPublicKeys = executor.config.ArtifactPublicKeys
				if status, err := legacy.runner.Probe(t.Context()); err == nil || status.Ready {
					t.Fatalf("legacy bypassed Git: %+v %v", status, err)
				}
				return
			case "v2 to v1":
				manifest := fixture.manifests[fixture.next.Digest]
				manifest.Schema, manifest.KeyID = NativeManifestSchema, ""
				fixture.replaceCandidate(t, manifest, fixture.contents[fixture.next.Digest])
				if _, err := fixture.runner.Run(t.Context(), fixture.bundle); err == nil || fixture.commands.restarts != 0 {
					t.Fatalf("v2 provenance downgrade accepted: %v", err)
				}
				return
			case "unsigned v2 target":
				fixture.replaceCandidate(t, fixture.manifests[fixture.next.Digest], fixture.contents[fixture.next.Digest])
				if _, err := fixture.runner.Run(t.Context(), fixture.bundle); err == nil || fixture.commands.restarts != 0 {
					t.Fatalf("plan signature replaced missing artifact signature: %v", err)
				}
				return
			}
			if change == "signature before rollback" {
				if err := executor.Rollback(t.Context(), Plan{Rollback: fixture.old}); err == nil || fixture.commands.restarts != 0 {
					t.Fatalf("rollback trusted tampered proof: %v", err)
				}
				return
			}
			if status, err := fixture.runner.Probe(t.Context()); err == nil || status.Ready {
				t.Fatalf("tampered signed provenance accepted: %+v %v", status, err)
			}
		})
	}
	t.Run("constructor rejects missing provenance and does not borrow keys", func(t *testing.T) {
		fixture := newNativeSignedFixture(t)
		config, trust, store, now := fixture.runner.executor.config, fixture.runner.runner.trust, fixture.runner.runner.store, fixture.runner.runner.now
		if err := fixture.runner.Close(); err != nil {
			t.Fatal(err)
		}
		original := config.ArtifactPublicKeys
		for _, keys := range []map[string]ed25519.PublicKey{nil, {"release-test": {}}, {"invalid key": original["release-test"]}} {
			config.ArtifactPublicKeys = keys
			if runner, err := newNativeStandaloneRunner(config, trust, store, now, uint32(os.Getuid()), fixture.commands, fixture.commands.inspect); err == nil {
				_ = runner.Close()
				t.Fatal("constructor accepted untrusted provenance")
			}
		}
		config.ArtifactPublicKeys = original
		runner, err := newNativeStandaloneRunner(config, trust, store, now, uint32(os.Getuid()), fixture.commands, fixture.commands.inspect)
		if err != nil {
			t.Fatal(err)
		}
		fixture.runner = runner
		delete(original, "release-test")
		if status, err := runner.Probe(t.Context()); err != nil || !status.Ready {
			t.Fatalf("constructor borrowed mutable caller trust: %+v %v", status, err)
		}
		legacy := newNativeFixture(t)
		config = legacy.runner.executor.config
		config.SourceGitDirectory, config.ArtifactPublicKeys = "", runner.executor.config.ArtifactPublicKeys
		if err := legacy.runner.Close(); err != nil {
			t.Fatal(err)
		}
		if rejected, err := newNativeStandaloneRunner(config, legacy.runner.runner.trust, legacy.runner.runner.store, now, uint32(os.Getuid()), legacy.commands, legacy.commands.inspect); err == nil {
			_ = rejected.Close()
			t.Fatal("v1 baseline accepted solely because artifact keys exist")
		}
	})
	t.Run("resume activation checkpoint", func(t *testing.T) {
		fixture := newNativeSignedFixture(t)
		plan, err := fixture.runner.runner.verifyBundle(fixture.bundle)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range []func(context.Context, Plan) error{fixture.runner.executor.Expand, fixture.runner.executor.Preflight, fixture.runner.executor.Drain, fixture.runner.executor.Activate} {
			if err := step(t.Context(), plan); err != nil {
				t.Fatal(err)
			}
		}
		if err := fixture.runner.runner.store.Save(State{Schema: StateSchema, PlanID: plan.ID, BundleSHA256: plan.BundleSHA256, Sequence: plan.Sequence, Phase: PhaseDrained, PreviousDigest: fixture.old.Digest, TargetDigest: fixture.next.Digest}); err != nil {
			t.Fatal(err)
		}
		if receipt, err := fixture.runner.Run(t.Context(), fixture.bundle); err != nil || receipt.Result != ResultApplied {
			t.Fatalf("signed recovery: %+v %v", receipt, err)
		}
	})
	t.Run("stage fsync failure", func(t *testing.T) {
		fixture := newNativeSignedFixture(t)
		fixture.runner.executor.syncDir = func(string) error { return errors.New("injected sync failure") }
		if _, err := fixture.runner.Run(t.Context(), fixture.bundle); err == nil || fixture.commands.restarts != 0 {
			t.Fatalf("unsigned durable stage accepted: %v", err)
		}
	})
}

func newNativeSignedFixture(t *testing.T) *nativeFixture {
	t.Helper()
	fixture := newNativeFixture(t)
	config, trust, store, now := fixture.runner.executor.config, fixture.runner.runner.trust, fixture.runner.runner.store, fixture.runner.runner.now
	if err := fixture.runner.Close(); err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x37}, ed25519.SeedSize))
	config.ArtifactPublicKeys = map[string]ed25519.PublicKey{"release-test": private.Public().(ed25519.PublicKey)}
	// These are this fixture's private temporary Git objects, never production.
	if err := os.RemoveAll(filepath.Dir(config.SourceGitDirectory)); err != nil {
		t.Fatal(err)
	}
	config.SourceGitDirectory = ""
	for index, artifact := range []Artifact{fixture.old, fixture.next} {
		manifest, files := fixture.manifests[artifact.Digest], fixture.contents[artifact.Digest]
		manifest.Schema, manifest.KeyID = NativeManifestSignedSchema, "release-test"
		raw, _ := json.Marshal(manifest)
		signature := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(NativeManifestSignedSchema+"\n"), raw...))))
		filename, signed := nativeSignedReleaseArchiveFixture(t, raw, signature, 0o644, files)
		signed.Sequence = artifact.Sequence
		encoded, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(config.ReleaseRoot, "artifacts", signed.Digest+".tar"), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		fixture.manifests[signed.Digest], fixture.contents[signed.Digest] = manifest, files
		if index == 0 {
			fixture.old = signed
			release := filepath.Join(config.ReleaseRoot, "releases", signed.Digest)
			reader := tar.NewReader(bytes.NewReader(encoded))
			for {
				header, err := reader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(reader)
				if err != nil {
					t.Fatal(err)
				}
				if err := nativeStageFile(release, header.Name, body, uint32(header.Mode)); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(filepath.Join(config.ReleaseRoot, "current")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(release, filepath.Join(config.ReleaseRoot, "current")); err != nil {
				t.Fatal(err)
			}
			fixture.commands.active = signed.Digest
		} else {
			fixture.next = signed
		}
	}
	var err error
	fixture.runner, err = newNativeStandaloneRunner(config, trust, store, now, uint32(os.Getuid()), fixture.commands, fixture.commands.inspect)
	if err != nil {
		t.Fatal(err)
	}
	fixture.bundle = nativeSignedBundle(t, fixture.bundle, fixture.old, fixture.next)
	return fixture
}
