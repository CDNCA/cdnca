package cc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestPublisherKeepsLastKnownGoodOnRejectedCandidate(t *testing.T) {
	publisher, err := NewPublisher(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	first, err := publisher.PublishJSON(policyVersion(t, 1, "/v1"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(first.CurrentPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON([]byte(`{"schema_version":"bad"}`)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("bad candidate error = %v", err)
	}
	if _, err := publisher.PublishJSON(policyVersion(t, 1, "/changed")); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("reused version error = %v", err)
	}
	second, err := publisher.PublishJSON(policyVersion(t, 2, "/v2"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(policyVersion(t, 1, "/v1")); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("older version error = %v", err)
	}
	after, err := os.ReadFile(second.CurrentPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) || !bytes.Contains(after, []byte(`"policy_version":2`)) {
		t.Fatal("current policy did not advance to version 2")
	}
	if _, err := publisher.PublishJSON(policyVersion(t, 2, "/v2")); err != nil {
		t.Fatalf("idempotent publish: %v", err)
	}
}

func TestPublisherAtomicReadersAndConcurrentIdempotency(t *testing.T) {
	publisher, err := NewPublisher(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	publication, err := publisher.PublishJSON(policyVersion(t, 1, "/v1"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	errorsChannel := make(chan error, 16)
	var readers sync.WaitGroup
	for index := 0; index < 4; index++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				raw, err := os.ReadFile(publication.CurrentPath)
				var value CompiledPolicy
				if err != nil || json.Unmarshal(raw, &value) != nil || value.PolicyVersion == 0 {
					errorsChannel <- fmt.Errorf("reader observed invalid current policy: %w", err)
					return
				}
			}
		}()
	}
	for version := uint64(2); version <= 20; version++ {
		if _, err := publisher.PublishJSON(policyVersion(t, version, fmt.Sprintf("/v%d", version))); err != nil {
			t.Fatal(err)
		}
	}
	close(done)
	readers.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatal(err)
	}

	last := policyVersion(t, 20, "/v20")
	var publishers sync.WaitGroup
	publishErrors := make(chan error, 8)
	for index := 0; index < 8; index++ {
		publishers.Add(1)
		go func() {
			defer publishers.Done()
			if _, err := publisher.PublishJSON(last); err != nil {
				publishErrors <- err
			}
		}()
	}
	publishers.Wait()
	close(publishErrors)
	for err := range publishErrors {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(publication.CurrentPath), "versions"))
	if err != nil || len(entries) != 20 {
		t.Fatalf("version entries = %d, error = %v", len(entries), err)
	}
}

func TestIndependentPublishersCannotRegressCurrentVersion(t *testing.T) {
	root := privateTempDir(t)
	first, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errorsChannel := make(chan error, 2)
	var publishers sync.WaitGroup
	for _, candidate := range []struct {
		publisher *Publisher
		version   uint64
	}{
		{publisher: first, version: 1},
		{publisher: second, version: 2},
	} {
		publishers.Add(1)
		go func() {
			defer publishers.Done()
			<-start
			_, err := candidate.publisher.PublishJSON(policyVersion(t, candidate.version, fmt.Sprintf("/v%d", candidate.version)))
			if err != nil && !errors.Is(err, ErrInvalidPolicy) {
				errorsChannel <- err
			}
		}()
	}
	close(start)
	publishers.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	var current CompiledPolicy
	if err := json.Unmarshal(raw, &current); err != nil || current.PolicyVersion != 2 {
		t.Fatalf("current policy version = %d, error = %v", current.PolicyVersion, err)
	}
}

func TestNewPublisherRejectsUnsafeRoot(t *testing.T) {
	if _, err := NewPublisher("relative"); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("relative root error = %v", err)
	}
	target := canonicalTempDir(t)
	link := filepath.Join(canonicalTempDir(t), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPublisher(link); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("symlink root error = %v", err)
	}
}

func TestPublisherRejectsUnsafeFilesystemState(t *testing.T) {
	policy := policyVersion(t, 1, "/v1")

	t.Run("broad root permissions", func(t *testing.T) {
		root := filepath.Join(canonicalTempDir(t), "root")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o750); err != nil {
			t.Fatal(err)
		}
		publisher, err := NewPublisher(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.PublishJSON(policy); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("broad root error = %v", err)
		}
	})

	t.Run("symlink versions directory", func(t *testing.T) {
		root := filepath.Join(canonicalTempDir(t), "root")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		outside := canonicalTempDir(t)
		if err := os.Symlink(outside, filepath.Join(root, "versions")); err != nil {
			t.Fatal(err)
		}
		publisher, err := NewPublisher(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.PublishJSON(policy); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("symlink versions error = %v", err)
		}
	})

	t.Run("symlink immutable version", func(t *testing.T) {
		root := filepath.Join(canonicalTempDir(t), "root")
		versions := filepath.Join(root, "versions")
		if err := os.MkdirAll(versions, 0o700); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(canonicalTempDir(t), "outside.json")
		if err := os.WriteFile(outside, policy, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(versions, versionFilename(1))); err != nil {
			t.Fatal(err)
		}
		publisher, err := NewPublisher(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.PublishJSON(policy); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("symlink version error = %v", err)
		}
	})

	t.Run("hardlinked immutable version", func(t *testing.T) {
		root := filepath.Join(canonicalTempDir(t), "root")
		versions := filepath.Join(root, "versions")
		if err := os.MkdirAll(versions, 0o700); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(canonicalTempDir(t), "outside.json")
		if err := os.WriteFile(outside, policy, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(outside, filepath.Join(versions, versionFilename(1))); err != nil {
			t.Fatal(err)
		}
		publisher, err := NewPublisher(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.PublishJSON(policy); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("hardlinked version error = %v", err)
		}
	})
}

func TestPublisherMaintainsValidatedDurableFallback(t *testing.T) {
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	versionOne := policyVersion(t, 1, "/v1")
	publication, err := publisher.PublishJSON(versionOne)
	if err != nil {
		t.Fatal(err)
	}
	canonicalOne := canonicalPolicy(t, versionOne)
	fallback := filepath.Join(root, "fallback.json")
	assertCCFileEquals(t, fallback, canonicalOne)
	assertCCPrivateFile(t, fallback)

	versionTwo := policyVersion(t, 2, "/v2")
	if _, err := publisher.PublishJSON(versionTwo); err != nil {
		t.Fatal(err)
	}
	canonicalTwo := canonicalPolicy(t, versionTwo)
	assertCCFileEquals(t, fallback, canonicalOne)

	versionThree := policyVersion(t, 3, "/v3")
	if _, err := publisher.PublishJSON(versionThree); err != nil {
		t.Fatal(err)
	}
	canonicalThree := canonicalPolicy(t, versionThree)
	assertCCFileEquals(t, fallback, canonicalTwo)
	assertCCFileEquals(t, publication.CurrentPath, canonicalThree)

	if _, err := publisher.PublishJSON(policyVersion(t, 3, "/conflict")); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("same-version conflict error = %v", err)
	}
	if _, err := publisher.PublishJSON(versionOne); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("regressed policy error = %v", err)
	}
	assertCCFileEquals(t, fallback, canonicalTwo)
	assertCCFileEquals(t, publication.CurrentPath, canonicalThree)
}

func TestPublisherNeverAdvancesFallbackFromInvalidCurrent(t *testing.T) {
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	versionOne := policyVersion(t, 1, "/v1")
	publication, err := publisher.PublishJSON(versionOne)
	if err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(root, "fallback.json")
	wantFallback := canonicalPolicy(t, versionOne)
	if err := os.WriteFile(publication.CurrentPath, []byte("bad policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	versionTwo := policyVersion(t, 2, "/v2")
	if _, err := publisher.PublishJSON(versionTwo); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("publication with corrupt current error = %v", err)
	}
	assertCCFileEquals(t, fallback, wantFallback)
	if _, err := os.Stat(filepath.Join(root, "versions", versionFilename(2))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt current persisted candidate version: %v", err)
	}
	if _, err := publisher.PublishJSON(versionOne); err != nil {
		t.Fatalf("idempotent current repair failed: %v", err)
	}
	assertCCFileEquals(t, publication.CurrentPath, wantFallback)
	assertCCFileEquals(t, fallback, wantFallback)

	if err := os.Chmod(publication.CurrentPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(versionTwo); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("publication with unsafe current error = %v", err)
	}
	assertCCFileEquals(t, fallback, wantFallback)
}

func TestPublisherRecoversPastPoisonedHighestVersionFromValidatedFallback(t *testing.T) {
	tests := []struct {
		name   string
		poison func(*testing.T, string) func(*testing.T)
	}{
		{
			name: "corrupt content",
			poison: func(t *testing.T, path string) func(*testing.T) {
				t.Helper()
				poisoned := []byte("corrupt sealed policy\n")
				if err := os.WriteFile(path, poisoned, 0o600); err != nil {
					t.Fatal(err)
				}
				return func(t *testing.T) { assertCCFileEquals(t, path, poisoned) }
			},
		},
		{
			name: "owner unreadable",
			poison: func(t *testing.T, path string) func(*testing.T) {
				t.Helper()
				before, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o200); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
				if _, err := readPrivateRegular(path); err == nil {
					t.Skip("filesystem permits reading an owner-unreadable file")
				}
				return func(t *testing.T) {
					after, err := os.Lstat(path)
					if err != nil {
						t.Fatal(err)
					}
					if !os.SameFile(before, after) || after.Mode().Perm() != 0o200 || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
						t.Fatal("publisher mutated the unreadable poisoned version")
					}
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publisher, root, current, fallback, highest, fallbackBefore := newCCSealedRecoveryFixture(t)
			assertPoisonUnchanged := test.poison(t, highest)

			if _, err := publisher.PublishJSON(policyVersion(t, 2, "/v2")); err == nil {
				t.Fatalf("same-version poisoned publication error = %v", err)
			}
			assertPoisonUnchanged(t)

			versionThree := policyVersion(t, 3, "/v3")
			publication, err := publisher.PublishJSON(versionThree)
			if err != nil {
				t.Fatalf("publish past poisoned highest version: %v", err)
			}
			canonicalThree := canonicalPolicy(t, versionThree)
			assertCCFileEquals(t, publication.CurrentPath, canonicalThree)
			assertCCFileEquals(t, current, canonicalThree)
			assertCCFileEquals(t, filepath.Join(root, "versions", versionFilename(3)), canonicalThree)
			assertCCFileEquals(t, fallback, fallbackBefore)
			assertPoisonUnchanged(t)
		})
	}

	t.Run("requires validated fallback", testPublisherPoisonedHighestRecoveryRequiresValidatedFallback)
}

func testPublisherPoisonedHighestRecoveryRequiresValidatedFallback(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string, []byte) func(*testing.T)
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, fallback string, _ []byte) func(*testing.T) {
				t.Helper()
				if err := os.Remove(fallback); err != nil {
					t.Fatal(err)
				}
				return func(t *testing.T) {
					if _, err := os.Lstat(fallback); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("missing fallback changed: %v", err)
					}
				}
			},
		},
		{
			name: "invalid",
			mutate: func(t *testing.T, fallback string, _ []byte) func(*testing.T) {
				t.Helper()
				invalid := []byte("invalid fallback\n")
				if err := os.WriteFile(fallback, invalid, 0o600); err != nil {
					t.Fatal(err)
				}
				return func(t *testing.T) { assertCCFileEquals(t, fallback, invalid) }
			},
		},
		{
			name: "immutable mismatch",
			mutate: func(t *testing.T, fallback string, _ []byte) func(*testing.T) {
				t.Helper()
				mismatch := canonicalPolicy(t, policyVersion(t, 1, "/mismatch"))
				if err := os.WriteFile(fallback, mismatch, 0o600); err != nil {
					t.Fatal(err)
				}
				return func(t *testing.T) { assertCCFileEquals(t, fallback, mismatch) }
			},
		},
		{
			name: "symlink",
			mutate: func(t *testing.T, fallback string, baseline []byte) func(*testing.T) {
				t.Helper()
				if err := os.Remove(fallback); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(canonicalTempDir(t), "fallback.json")
				if err := os.WriteFile(outside, baseline, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, fallback); err != nil {
					t.Fatal(err)
				}
				return func(t *testing.T) {
					target, err := os.Readlink(fallback)
					if err != nil || target != outside {
						t.Fatalf("fallback symlink changed: target=%q error=%v", target, err)
					}
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publisher, root, current, fallback, highest, fallbackBefore := newCCSealedRecoveryFixture(t)
			poisoned := []byte("corrupt sealed policy\n")
			if err := os.WriteFile(highest, poisoned, 0o600); err != nil {
				t.Fatal(err)
			}
			assertFallbackUnchanged := test.mutate(t, fallback, fallbackBefore)
			currentBefore, err := os.ReadFile(current)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := publisher.PublishJSON(policyVersion(t, 3, "/v3")); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("publish with unverified fallback error = %v", err)
			}
			assertCCFileEquals(t, current, currentBefore)
			assertCCFileEquals(t, highest, poisoned)
			assertFallbackUnchanged(t)
			if _, err := os.Lstat(filepath.Join(root, "versions", versionFilename(3))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected recovery persisted version 3: %v", err)
			}
		})
	}
}

func TestPublisherFallbackFailureDoesNotCommitCurrent(t *testing.T) {
	root := privateTempDir(t)
	fallback := filepath.Join(root, "fallback.json")
	if err := os.Mkdir(fallback, 0o700); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	raw := policyVersion(t, 1, "/v1")
	if _, err := publisher.PublishJSON(raw); err == nil {
		t.Fatal("fallback write failure unexpectedly published current")
	}
	if _, err := os.Stat(filepath.Join(root, "current.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed publication committed current: %v", err)
	}
	if err := os.Remove(fallback); err != nil {
		t.Fatal(err)
	}
	publication, err := publisher.PublishJSON(raw)
	if err != nil {
		t.Fatalf("idempotent retry failed: %v", err)
	}
	canonical := canonicalPolicy(t, raw)
	assertCCFileEquals(t, fallback, canonical)
	assertCCFileEquals(t, publication.CurrentPath, canonical)
}

func TestOpenRestyColdStartFallbackContract(t *testing.T) {
	enginePath := filepath.Join("..", "..", "..", "..", "edge", "openresty", "cc", "engine.lua")
	engine, err := os.ReadFile(enginePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"local fallback_path",
		"local function read_candidate(path)",
		"read_candidate(policy_path)",
		"read_candidate(fallback_path)",
		"if not candidate and not current_policy",
		`fallback_path = policy_path:match("^(.*)/[^/]+$") .. "/fallback.json"`,
	} {
		if !bytes.Contains(engine, []byte(required)) {
			t.Errorf("engine is missing cold-start fallback contract %q", required)
		}
	}

	smokePath := filepath.Join("..", "..", "..", "..", "scripts", "edge-cc-smoke.sh")
	smoke, err := os.ReadFile(smokePath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(smoke)
	badCurrent := strings.Index(text, `mv "${workdir}/policy/current.bad" "${workdir}/policy/current.json"`)
	hup := strings.Index(text, `docker kill --signal HUP "${container}"`)
	restart := strings.Index(text, `docker restart "${container}"`)
	repair := strings.Index(text, `publish_policy 2 "${trusted_json}" "${allowlist_json}" >"${workdir}/repair-v2.log"`)
	if badCurrent < 0 || hup <= badCurrent || restart <= hup || repair <= restart {
		t.Fatalf("smoke does not exercise invalid-current HUP/restart before repair: bad=%d hup=%d restart=%d repair=%d", badCurrent, hup, restart, repair)
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	root := canonicalTempDir(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func newCCSealedRecoveryFixture(t *testing.T) (*Publisher, string, string, string, string, []byte) {
	t.Helper()
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	versionOne := policyVersion(t, 1, "/v1")
	publication, err := publisher.PublishJSON(versionOne)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(policyVersion(t, 2, "/v2")); err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(root, "fallback.json")
	fallbackBefore := canonicalPolicy(t, versionOne)
	assertCCFileEquals(t, fallback, fallbackBefore)
	return publisher, root, publication.CurrentPath, fallback,
		filepath.Join(root, "versions", versionFilename(2)), fallbackBefore
}

func policyVersion(t *testing.T, version uint64, path string) []byte {
	t.Helper()
	policy := validPolicy()
	policy.PolicyVersion = version
	policy.Rules[0].Match.Path.Value = path
	return marshalPolicy(t, policy)
}

func canonicalPolicy(t *testing.T, raw []byte) []byte {
	t.Helper()
	canonical, _, err := CompileJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func assertCCFileEquals(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s does not contain expected canonical policy", path)
	}
}

func assertCCPrivateFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("%s mode = %v, want private regular file", path, info.Mode())
	}
}
