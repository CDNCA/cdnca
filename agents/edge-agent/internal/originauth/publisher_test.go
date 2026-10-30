package originauth

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestPublisherIsMonotonicIdempotentAndAtomic(t *testing.T) {
	directory := testSecretDirectory(t)
	credentialPath := writeTestCredential(t, directory, "credential.json", ProviderS3, "access", "secret", "", 0, 4102444800)
	rule := testRule(ProviderS3, credentialPath)
	root := filepath.Join(t.TempDir(), "published")
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}

	versionOne := mustPolicyJSON(t, rule)
	publication, err := publisher.PublishJSON(versionOne)
	if err != nil {
		t.Fatal(err)
	}
	canonicalOne, _, err := CompileJSON(versionOne)
	if err != nil {
		t.Fatal(err)
	}
	assertFileEquals(t, publication.CurrentPath, canonicalOne)
	assertPrivateFile(t, publication.CurrentPath)
	assertPrivateFile(t, filepath.Join(root, "versions", versionFilename(1)))

	if _, err := publisher.PublishJSON(versionOne); err != nil {
		t.Fatalf("idempotent publication failed: %v", err)
	}
	conflicting := rule
	conflicting.SignatureTTLSeconds++
	if _, err := publisher.PublishJSON(mustPolicyJSON(t, conflicting)); err == nil || rejectionCode(t, err) != "POLICY_VERSION_CONFLICT" {
		t.Fatalf("same-version conflict error = %v", err)
	}
	assertFileEquals(t, publication.CurrentPath, canonicalOne)

	versionTwoRaw := mustPolicyJSON(t, rule)
	versionTwoRaw = bytes.Replace(versionTwoRaw, []byte(`"policy_version":1`), []byte(`"policy_version":2`), 1)
	publication, err = publisher.PublishJSON(versionTwoRaw)
	if err != nil {
		t.Fatal(err)
	}
	canonicalTwo, _, err := CompileJSON(versionTwoRaw)
	if err != nil {
		t.Fatal(err)
	}
	assertFileEquals(t, publication.CurrentPath, canonicalTwo)

	if _, err := publisher.PublishJSON(versionOne); err == nil || rejectionCode(t, err) != "POLICY_VERSION_REGRESSED" {
		t.Fatalf("regressed publication error = %v", err)
	}
	assertFileEquals(t, publication.CurrentPath, canonicalTwo)
}

func TestPublisherRestoresCurrentFromImmutableVersion(t *testing.T) {
	directory := testSecretDirectory(t)
	credentialPath := writeTestCredential(t, directory, "credential.json", ProviderS3, "access", "secret", "", 0, 4102444800)
	raw := mustPolicyJSON(t, testRule(ProviderS3, credentialPath))
	root := filepath.Join(t.TempDir(), "published")
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := publisher.PublishJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publication.CurrentPath, []byte("bad policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(raw); err != nil {
		t.Fatalf("idempotent republish did not restore current: %v", err)
	}
	canonical, _, err := CompileJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	assertFileEquals(t, publication.CurrentPath, canonical)
}

func TestPublisherMaintainsValidatedDurableFallback(t *testing.T) {
	directory := testSecretDirectory(t)
	credentialPath := writeTestCredential(t, directory, "credential.json", ProviderS3, "access", "secret-material", "session-material", 0, 4102444800)
	rule := testRule(ProviderS3, credentialPath)
	root := filepath.Join(t.TempDir(), "published")
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}

	versionOne := mustPolicyJSON(t, rule)
	publication, err := publisher.PublishJSON(versionOne)
	if err != nil {
		t.Fatal(err)
	}
	canonicalOne, _, err := CompileJSON(versionOne)
	if err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(root, "fallback.json")
	assertFileEquals(t, fallback, canonicalOne)
	assertPrivateFile(t, fallback)
	fallbackRaw, err := os.ReadFile(fallback)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-material", "session-material", "access"} {
		if bytes.Contains(fallbackRaw, []byte(secret)) {
			t.Fatalf("fallback contains credential material %q", secret)
		}
	}

	versionTwo := bytes.Replace(versionOne, []byte(`"policy_version":1`), []byte(`"policy_version":2`), 1)
	if _, err := publisher.PublishJSON(versionTwo); err != nil {
		t.Fatal(err)
	}
	assertFileEquals(t, fallback, canonicalOne)
	canonicalTwo, _, err := CompileJSON(versionTwo)
	if err != nil {
		t.Fatal(err)
	}

	versionThree := bytes.Replace(versionOne, []byte(`"policy_version":1`), []byte(`"policy_version":3`), 1)
	if _, err := publisher.PublishJSON(versionThree); err != nil {
		t.Fatal(err)
	}
	assertFileEquals(t, fallback, canonicalTwo)

	conflicting := bytes.Replace(versionThree, []byte(`"signature_ttl_seconds":600`), []byte(`"signature_ttl_seconds":601`), 1)
	if _, err := publisher.PublishJSON(conflicting); err == nil || rejectionCode(t, err) != "POLICY_VERSION_CONFLICT" {
		t.Fatalf("same-version conflict error = %v", err)
	}
	assertFileEquals(t, fallback, canonicalTwo)
	if _, err := publisher.PublishJSON(versionOne); err == nil || rejectionCode(t, err) != "POLICY_VERSION_REGRESSED" {
		t.Fatalf("regressed publication error = %v", err)
	}
	assertFileEquals(t, fallback, canonicalTwo)
	assertFileEquals(t, publication.CurrentPath, mustCompilePolicy(t, versionThree))
}

func TestPublisherNeverAdvancesFallbackFromInvalidCurrent(t *testing.T) {
	directory := testSecretDirectory(t)
	credentialPath := writeTestCredential(t, directory, "credential.json", ProviderS3, "access", "secret", "", 0, 4102444800)
	rule := testRule(ProviderS3, credentialPath)
	root := filepath.Join(t.TempDir(), "published")
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	versionOne := mustPolicyJSON(t, rule)
	publication, err := publisher.PublishJSON(versionOne)
	if err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(root, "fallback.json")
	wantFallback, err := os.ReadFile(fallback)
	if err != nil {
		t.Fatal(err)
	}
	versionTwo := bytes.Replace(versionOne, []byte(`"policy_version":1`), []byte(`"policy_version":2`), 1)

	if err := os.WriteFile(publication.CurrentPath, []byte("bad policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(versionTwo); err == nil || rejectionCode(t, err) != "PUBLISH_CURRENT_INVALID" {
		t.Fatalf("publication with corrupt current error = %v", err)
	}
	assertFileEquals(t, fallback, wantFallback)
	if _, err := os.Stat(filepath.Join(root, "versions", versionFilename(2))); !os.IsNotExist(err) {
		t.Fatalf("corrupt current allowed candidate version persistence: %v", err)
	}

	if _, err := publisher.PublishJSON(versionOne); err != nil {
		t.Fatalf("idempotent repair failed: %v", err)
	}
	assertFileEquals(t, fallback, wantFallback)
	assertFileEquals(t, publication.CurrentPath, wantFallback)
	if err := os.Chmod(publication.CurrentPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(versionTwo); err == nil || rejectionCode(t, err) != "PUBLISH_CURRENT_INVALID" {
		t.Fatalf("publication with unsafe current error = %v", err)
	}
	assertFileEquals(t, fallback, wantFallback)
}

func TestPublisherFallbackFailureIsNotCommittedAndRetryIsIdempotent(t *testing.T) {
	directory := testSecretDirectory(t)
	credentialPath := writeTestCredential(t, directory, "credential.json", ProviderS3, "access", "secret", "", 0, 4102444800)
	raw := mustPolicyJSON(t, testRule(ProviderS3, credentialPath))
	root := filepath.Join(t.TempDir(), "published")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(root, "fallback.json")
	if err := os.Mkdir(fallback, 0o700); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(raw); err == nil || rejectionCode(t, err) != "PUBLISH_WRITE_FAILED" {
		t.Fatalf("fallback write failure error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "current.json")); !os.IsNotExist(err) {
		t.Fatalf("failed publication committed current: %v", err)
	}
	if err := os.Remove(fallback); err != nil {
		t.Fatal(err)
	}
	publication, err := publisher.PublishJSON(raw)
	if err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	canonical := mustCompilePolicy(t, raw)
	assertFileEquals(t, publication.CurrentPath, canonical)
	assertFileEquals(t, fallback, canonical)
	if _, err := publisher.PublishJSON(raw); err != nil {
		t.Fatalf("idempotent retry failed: %v", err)
	}
}

func TestOpenRestyColdStartFallbackContract(t *testing.T) {
	enginePath := filepath.Join("..", "..", "..", "..", "edge", "openresty", "originauth", "engine.lua")
	engine, err := os.ReadFile(enginePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"local fallback_path",
		"local function read_candidate(path)",
		"secure_read(path, MAX_POLICY_BYTES)",
		"read_candidate(fallback_path)",
		"if not candidate and not current_policy",
		`fallback_path = policy_path:match("^(.*)/[^/]+$") .. "/fallback.json"`,
	} {
		if !bytes.Contains(engine, []byte(required)) {
			t.Errorf("engine is missing cold-start fallback contract %q", required)
		}
	}

	smokePath := filepath.Join("..", "..", "..", "..", "scripts", "edge-origin-auth-smoke.sh")
	smoke, err := os.ReadFile(smokePath)
	if err != nil {
		t.Fatal(err)
	}
	badCurrent := strings.Index(string(smoke), `mv "${workdir}/policy/current.bad" "${workdir}/policy/current.json"`)
	hup := strings.Index(string(smoke), `docker kill --signal HUP "${container}"`)
	restart := strings.Index(string(smoke), `docker restart "${container}"`)
	restore := strings.Index(string(smoke), `publish_policy 1 >"${workdir}/restore-v1.log"`)
	if badCurrent < 0 || hup <= badCurrent || restart <= hup || restore <= restart {
		t.Fatalf("smoke does not exercise HUP and restart while current is invalid: bad=%d hup=%d restart=%d restore=%d", badCurrent, hup, restart, restore)
	}
}

func TestConcurrentIdempotentPublication(t *testing.T) {
	directory := testSecretDirectory(t)
	credentialPath := writeTestCredential(t, directory, "credential.json", ProviderS3, "access", "secret", "", 0, 4102444800)
	raw := mustPolicyJSON(t, testRule(ProviderS3, credentialPath))
	publisher, err := NewPublisher(filepath.Join(t.TempDir(), "published"))
	if err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	errors := make(chan error, 32)
	for index := 0; index < cap(errors); index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := publisher.PublishJSON(raw)
			if err != nil {
				errors <- err
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

func TestPublisherRejectsUnsafeRoot(t *testing.T) {
	parent := t.TempDir()
	permissive := filepath.Join(parent, "permissive")
	if err := os.Mkdir(permissive, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPublisher(permissive); err == nil || rejectionCode(t, err) != "PUBLISH_ROOT_UNSAFE" {
		t.Fatalf("permissive root error = %v", err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(permissive, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPublisher(link); err == nil || rejectionCode(t, err) != "PUBLISH_ROOT_UNSAFE" {
		t.Fatalf("symlink root error = %v", err)
	}
	if _, err := NewPublisher("relative"); err == nil || rejectionCode(t, err) != "PUBLISH_ROOT_INVALID" {
		t.Fatalf("relative root error = %v", err)
	}
}

func assertFileEquals(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch\n got: %s\nwant: %s", path, got, want)
	}
}

func assertPrivateFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := infoSys(info)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		t.Fatalf("%s metadata is unsafe: mode=%v stat=%#v", path, info.Mode(), stat)
	}
}

func mustCompilePolicy(t *testing.T, raw []byte) []byte {
	t.Helper()
	canonical, _, err := CompileJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}
