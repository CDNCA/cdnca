package waf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPublisherRejectsBadOrReusedVersionWithoutChangingCurrent(t *testing.T) {
	publisher, err := NewPublisher(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	baseline := policyWithVersion(t, 1, "/v1")
	publication, err := publisher.PublishJSON(baseline)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(publication.CurrentPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON([]byte(`{"schema_version":"broken"}`)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("bad candidate error = %v", err)
	}
	if _, err := publisher.PublishJSON(policyWithVersion(t, 1, "/different")); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("reused version error = %v", err)
	}
	after, err := os.ReadFile(publication.CurrentPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected candidate changed current.json")
	}
	if _, err := publisher.PublishJSON(baseline); err != nil {
		t.Fatalf("idempotent publication failed: %v", err)
	}
}

func TestPublisherAtomicReadersAndConcurrentIdempotency(t *testing.T) {
	publisher, err := NewPublisher(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	first, err := publisher.PublishJSON(policyWithVersion(t, 1, "/v1"))
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	errorsChannel := make(chan error, 32)
	var readers sync.WaitGroup
	for index := 0; index < 8; index++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				raw, err := os.ReadFile(first.CurrentPath)
				if err != nil {
					errorsChannel <- err
					return
				}
				var policy CompiledPolicy
				if err := json.Unmarshal(raw, &policy); err != nil || policy.SchemaVersion != SchemaVersion || policy.PolicyVersion == 0 {
					errorsChannel <- fmt.Errorf("reader observed invalid policy version=%d: %w", policy.PolicyVersion, err)
					return
				}
			}
		}()
	}
	for version := uint64(2); version <= 30; version++ {
		if _, err := publisher.PublishJSON(policyWithVersion(t, version, fmt.Sprintf("/v%d", version))); err != nil {
			t.Fatal(err)
		}
	}
	close(done)
	readers.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatal(err)
	}

	last := policyWithVersion(t, 30, "/v30")
	publishErrors := make(chan error, 8)
	var publishers sync.WaitGroup
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
	if entries, err := os.ReadDir(filepath.Join(filepath.Dir(first.CurrentPath), "versions")); err != nil || len(entries) != 30 {
		t.Fatalf("versions entries=%d error=%v, want 30", len(entries), err)
	}
}

func TestNewPublisherRejectsUnsafeRoot(t *testing.T) {
	if _, err := NewPublisher("relative/path"); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("NewPublisher() error = %v", err)
	}
}

func TestPublisherRejectsUnsafeFilesystemState(t *testing.T) {
	policy := policyWithVersion(t, 1, "/blocked")
	t.Run("symlink root", func(t *testing.T) {
		parent := t.TempDir()
		target := filepath.Join(parent, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(parent, "root")
		if err := os.Symlink(target, root); err != nil {
			t.Fatal(err)
		}
		publisher, err := NewPublisher(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.PublishJSON(policy); err == nil {
			t.Fatal("publisher accepted a symlink state root")
		}
	})

	t.Run("broad root permissions", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "root")
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
		if _, err := publisher.PublishJSON(policy); err == nil {
			t.Fatal("publisher accepted a group-accessible state root")
		}
	})

	t.Run("symlink lock", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "root")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("sentinel"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "publish.lock")); err != nil {
			t.Fatal(err)
		}
		publisher, err := NewPublisher(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.PublishJSON(policy); err == nil {
			t.Fatal("publisher followed a symlink lock file")
		}
	})

	t.Run("symlink immutable version", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "root")
		versions := filepath.Join(root, "versions")
		if err := os.MkdirAll(versions, 0o700); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "outside.json")
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
		if _, err := publisher.PublishJSON(policy); err == nil {
			t.Fatal("publisher followed a symlink immutable version")
		}
	})
}

func TestIndependentPublishersSerializeMonotonicVersions(t *testing.T) {
	root := privateTempDir(t)
	first, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.PublishJSON(policyWithVersion(t, 1, "/v1")); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	version2 := policyWithVersion(t, 2, "/v2")
	version3 := policyWithVersion(t, 3, "/v3")
	var wait sync.WaitGroup
	for _, candidate := range []struct {
		publisher *Publisher
		policy    []byte
	}{{first, version2}, {second, version3}} {
		wait.Add(1)
		go func(publisher *Publisher, policy []byte) {
			defer wait.Done()
			<-start
			_, err := publisher.PublishJSON(policy)
			if err != nil && !errors.Is(err, ErrInvalidPolicy) {
				results <- err
			}
		}(candidate.publisher, candidate.policy)
	}
	close(start)
	wait.Wait()
	close(results)
	for err := range results {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	var current CompiledPolicy
	if err := json.Unmarshal(raw, &current); err != nil {
		t.Fatal(err)
	}
	if current.PolicyVersion != 3 {
		t.Fatalf("current policy_version = %d, want 3", current.PolicyVersion)
	}
}

func TestPublisherMaintainsValidatedDurableFallback(t *testing.T) {
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	versionOne := policyWithVersion(t, 1, "/v1")
	publication, err := publisher.PublishJSON(versionOne)
	if err != nil {
		t.Fatal(err)
	}
	canonicalOne := canonicalWAFPolicy(t, versionOne)
	fallback := filepath.Join(root, "fallback.json")
	assertWAFFileEquals(t, fallback, canonicalOne)
	assertWAFPrivateFile(t, fallback)

	versionTwo := policyWithVersion(t, 2, "/v2")
	if _, err := publisher.PublishJSON(versionTwo); err != nil {
		t.Fatal(err)
	}
	canonicalTwo := canonicalWAFPolicy(t, versionTwo)
	assertWAFFileEquals(t, fallback, canonicalOne)

	versionThree := policyWithVersion(t, 3, "/v3")
	if _, err := publisher.PublishJSON(versionThree); err != nil {
		t.Fatal(err)
	}
	canonicalThree := canonicalWAFPolicy(t, versionThree)
	assertWAFFileEquals(t, fallback, canonicalTwo)
	assertWAFFileEquals(t, publication.CurrentPath, canonicalThree)

	if _, err := publisher.PublishJSON(policyWithVersion(t, 3, "/conflict")); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("same-version conflict error = %v", err)
	}
	if _, err := publisher.PublishJSON(versionOne); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("regressed policy error = %v", err)
	}
	assertWAFFileEquals(t, fallback, canonicalTwo)
	assertWAFFileEquals(t, publication.CurrentPath, canonicalThree)
}

func TestPublisherReadsSealedCompiledCIDRPolicyOnUpgrade(t *testing.T) {
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	versionOne := marshalPolicy(t, Policy{
		SchemaVersion: SchemaVersionV1,
		PolicyVersion: 1,
		Rules: []Rule{{
			RuleID: "cidr-v1", Priority: 1, Action: ActionBlock, Flow: FlowStop,
			Match: Match{SourceCIDR: "127.0.0.0/8"},
		}},
	})
	publication, err := publisher.PublishJSON(versionOne)
	if err != nil {
		t.Fatal(err)
	}
	canonicalOne := canonicalWAFPolicy(t, versionOne)
	versionTwo := policyWithVersion(t, 2, "/v2")
	if _, err := publisher.PublishJSON(versionTwo); err != nil {
		t.Fatalf("upgrade from compiled CIDR policy: %v", err)
	}
	assertWAFFileEquals(t, filepath.Join(root, "fallback.json"), canonicalOne)
	assertWAFFileEquals(t, publication.CurrentPath, canonicalWAFPolicy(t, versionTwo))
}

func TestPublisherNeverAdvancesFallbackFromInvalidCurrent(t *testing.T) {
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	versionOne := policyWithVersion(t, 1, "/v1")
	publication, err := publisher.PublishJSON(versionOne)
	if err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(root, "fallback.json")
	wantFallback := canonicalWAFPolicy(t, versionOne)
	invalidCurrent := []byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":2,"policy_version":3,"rules":[]}`)
	if err := os.WriteFile(publication.CurrentPath, invalidCurrent, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON([]byte(`{"schema_version":"bad"}`)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid candidate error = %v", err)
	}
	assertWAFFileEquals(t, publication.CurrentPath, invalidCurrent)
	assertWAFFileEquals(t, fallback, wantFallback)

	versionTwo := policyWithVersion(t, 2, "/v2")
	if _, err := publisher.PublishJSON(versionTwo); err != nil {
		t.Fatalf("publication from sealed fallback failed: %v", err)
	}
	assertWAFFileEquals(t, fallback, wantFallback)
	assertWAFFileEquals(t, publication.CurrentPath, canonicalWAFPolicy(t, versionTwo))

	if err := os.WriteFile(publication.CurrentPath, invalidCurrent, 0o600); err != nil {
		t.Fatal(err)
	}
	versionThree := policyWithVersion(t, 3, "/v3")
	if _, err := publisher.PublishJSON(versionThree); err != nil {
		t.Fatalf("higher publication from sealed fallback failed: %v", err)
	}
	assertWAFFileEquals(t, fallback, wantFallback)
	assertWAFFileEquals(t, publication.CurrentPath, canonicalWAFPolicy(t, versionThree))
}

func TestPublisherFailsClosedWithoutSealedFallback(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, root, fallback string, baseline []byte)
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, _, fallback string, _ []byte) {
				t.Helper()
				if err := os.Remove(fallback); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "invalid",
			mutate: func(t *testing.T, _, fallback string, _ []byte) {
				t.Helper()
				if err := os.WriteFile(fallback, []byte("invalid fallback\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "immutable digest mismatch",
			mutate: func(t *testing.T, _, fallback string, _ []byte) {
				t.Helper()
				mismatch := canonicalWAFPolicy(t, policyWithVersion(t, 1, "/different"))
				if err := os.WriteFile(fallback, mismatch, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink scope escape",
			mutate: func(t *testing.T, root, fallback string, baseline []byte) {
				t.Helper()
				if err := os.Remove(fallback); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(filepath.Dir(root), "outside-fallback.json")
				if err := os.WriteFile(outside, baseline, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, fallback); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := privateTempDir(t)
			publisher, err := NewPublisher(root)
			if err != nil {
				t.Fatal(err)
			}
			versionOne := policyWithVersion(t, 1, "/v1")
			publication, err := publisher.PublishJSON(versionOne)
			if err != nil {
				t.Fatal(err)
			}
			fallback := filepath.Join(root, "fallback.json")
			baseline := canonicalWAFPolicy(t, versionOne)
			badCurrent := []byte("bad current\n")
			if err := os.WriteFile(publication.CurrentPath, badCurrent, 0o600); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, root, fallback, baseline)
			fallbackInfo, fallbackErr := os.Lstat(fallback)
			var fallbackBefore []byte
			if fallbackErr == nil && fallbackInfo.Mode().IsRegular() {
				fallbackBefore, err = os.ReadFile(fallback)
				if err != nil {
					t.Fatal(err)
				}
			}

			if _, err := publisher.PublishJSON(policyWithVersion(t, 2, "/v2")); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("publication without sealed fallback error = %v", err)
			}
			assertWAFFileEquals(t, publication.CurrentPath, badCurrent)
			if fallbackBefore != nil {
				assertWAFFileEquals(t, fallback, fallbackBefore)
			} else if after, err := os.Lstat(fallback); (fallbackErr == nil) != (err == nil) || err == nil && after.Mode() != fallbackInfo.Mode() {
				t.Fatalf("fallback filesystem state changed: before=%v after=%v", fallbackErr, err)
			}
			if _, err := os.Stat(filepath.Join(root, "versions", versionFilename(2))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed publication persisted candidate version: %v", err)
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
	raw := policyWithVersion(t, 1, "/v1")
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
	canonical := canonicalWAFPolicy(t, raw)
	assertWAFFileEquals(t, fallback, canonical)
	assertWAFFileEquals(t, publication.CurrentPath, canonical)
}

func TestOpenRestyColdStartFallbackContract(t *testing.T) {
	enginePath := filepath.Join("..", "..", "..", "..", "edge", "openresty", "lua", "cdnca_waf.lua")
	engine, err := os.ReadFile(enginePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("local function read_sealed_fallback(path)"),
		[]byte("read_sealed_fallback(path)"),
		[]byte(`.. "/fallback.json"`),
		[]byte(`.. "/versions/"`),
		[]byte("if not candidate and not state.policy then"),
	} {
		if !bytes.Contains(engine, required) {
			t.Errorf("engine is missing cold-start fallback contract %q", required)
		}
	}

	smokePath := filepath.Join("..", "..", "..", "..", "scripts", "edge-waf-smoke.sh")
	smoke, err := os.ReadFile(smokePath)
	if err != nil {
		t.Fatal(err)
	}
	badCurrent := bytes.Index(smoke, []byte(`mv "${workdir}/policy/.corrupt.json" "${workdir}/policy/current.json"`))
	hup := bytes.Index(smoke, []byte(`docker kill --signal HUP "${container}"`))
	missingCurrent := bytes.Index(smoke, []byte(`rm -f "${workdir}/policy/current.json"`))
	restart := bytes.Index(smoke, []byte(`docker restart "${container}"`))
	repair := bytes.Index(smoke, []byte(`publish_waf repair-v2 "${workdir}/policy-v2.json" "${workdir}/repair-v2.txt" "${workdir}/policy"`))
	if badCurrent < 0 || hup <= badCurrent || missingCurrent <= hup || restart <= missingCurrent || repair <= restart {
		t.Fatalf("smoke does not exercise invalid/missing-current HUP/restart before repair: bad=%d hup=%d missing=%d restart=%d repair=%d", badCurrent, hup, missingCurrent, restart, repair)
	}
}

func policyWithVersion(t *testing.T, version uint64, path string) []byte {
	t.Helper()
	return marshalPolicy(t, Policy{
		SchemaVersion: SchemaVersion, PolicyVersion: version,
		Rules: []Rule{{RuleID: "rule", Priority: 1, Action: ActionBlock, Flow: FlowStop, Match: Match{Path: &PathMatch{Kind: PathExact, Value: path}}}},
	})
}

func canonicalWAFPolicy(t *testing.T, raw []byte) []byte {
	t.Helper()
	canonical, _, err := CompileJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func assertWAFFileEquals(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s does not contain expected canonical policy", path)
	}
}

func assertWAFPrivateFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("%s mode = %v, want private regular file", path, info.Mode())
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}
