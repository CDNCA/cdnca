package http3runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var errInjectedRuntime = errors.New("injected runtime failure")

type fakeRuntime struct {
	mu             sync.Mutex
	precheckCalls  []string
	activateCalls  []string
	healthCalls    []string
	stopCalls      []string
	failPrecheck   bool
	failActivation int
	failHealth     int
	onPrecheck     func(string) error
	onActivate     func(string) error
}

func (r *fakeRuntime) Precheck(_ context.Context, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.precheckCalls = append(r.precheckCalls, path)
	if r.failPrecheck {
		r.failPrecheck = false
		return errInjectedRuntime
	}
	if r.onPrecheck != nil {
		return r.onPrecheck(path)
	}
	return nil
}

func (r *fakeRuntime) Activate(_ context.Context, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.activateCalls = append(r.activateCalls, currentTarget(path))
	if r.failActivation > 0 {
		r.failActivation--
		return errInjectedRuntime
	}
	if r.onActivate != nil {
		return r.onActivate(path)
	}
	return nil
}

func (r *fakeRuntime) Healthy(_ context.Context, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.healthCalls = append(r.healthCalls, currentTarget(path))
	if r.failHealth > 0 {
		r.failHealth--
		return errInjectedRuntime
	}
	return nil
}

func (r *fakeRuntime) Stop(_ context.Context, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopCalls = append(r.stopCalls, path)
	return nil
}

func currentTarget(path string) string {
	target, _ := os.Readlink(path)
	return filepath.Base(target)
}

func fixedTime() time.Time {
	return time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
}

func testManager(t *testing.T, runtime Runtime) (*Manager, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "http3")
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	manager, err := newManager(root, runtime, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	return manager, root
}

type managerTLSFixture struct {
	policy          Policy
	certificate     []byte
	privateKey      []byte
	certificatePath string
	privateKeyPath  string
}

func newManagerTLSFixture(t *testing.T, versionID string) managerTLSFixture {
	t.Helper()
	source := t.TempDir()
	certificate := []byte("certificate-" + versionID + "\n")
	privateKey := []byte("private-key-" + versionID + "\n")
	certificatePath := filepath.Join(source, "server.crt")
	privateKeyPath := filepath.Join(source, "server.key")
	if err := os.WriteFile(certificatePath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyPath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	certificateDigest := sha256.Sum256(certificate)
	privateKeyDigest := sha256.Sum256(privateKey)
	policy := validPolicy(versionID)
	policy.TLS.CertificateFile = certificatePath
	policy.TLS.CertificateSHA256 = hex.EncodeToString(certificateDigest[:])
	policy.TLS.PrivateKeyFile = privateKeyPath
	policy.TLS.PrivateKeySHA256 = hex.EncodeToString(privateKeyDigest[:])
	return managerTLSFixture{
		policy: policy, certificate: certificate, privateKey: privateKey,
		certificatePath: certificatePath, privateKeyPath: privateKeyPath,
	}
}

func assertSealedTLS(t *testing.T, versionPath string, fixture managerTLSFixture) {
	t.Helper()
	tlsPath := filepath.Join(versionPath, "tls")
	info, err := os.Stat(tlsPath)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o500 {
		t.Fatalf("sealed TLS directory mode=%v err=%v", modePerm(info), err)
	}
	for name, expected := range map[string][]byte{
		"server.crt": fixture.certificate,
		"server.key": fixture.privateKey,
	} {
		path := filepath.Join(tlsPath, name)
		content, readErr := os.ReadFile(path)
		fileInfo, statErr := os.Stat(path)
		if readErr != nil || statErr != nil || fileInfo.Mode().Perm() != 0o400 || string(content) != string(expected) {
			t.Fatalf("sealed %s mode=%v read=%v stat=%v content=%q", name, modePerm(fileInfo), readErr, statErr, content)
		}
	}
	nginx, err := os.ReadFile(filepath.Join(versionPath, "nginx.conf"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(nginx)
	if !strings.Contains(text, "ssl_certificate tls/server.crt;") ||
		!strings.Contains(text, "ssl_certificate_key tls/server.key;") ||
		strings.Contains(text, fixture.certificatePath) || strings.Contains(text, fixture.privateKeyPath) {
		t.Fatalf("Nginx does not exclusively reference sealed TLS assets:\n%s", text)
	}
}

func modePerm(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode().Perm()
}

func TestManagerStagesPrechecksActivatesAndHealthGates(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	fixture := newManagerTLSFixture(t, "http3-v1")
	result, err := manager.Apply(context.Background(), fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != StateApplied || result.ActiveVersionID != "http3-v1" || result.Digest == "" || !result.AppliedAt.Equal(fixedTime()) {
		t.Fatalf("Apply() = %+v", result)
	}
	target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || filepath.Base(target) != "http3-v1-"+result.Digest {
		t.Fatalf("current = %q, %v", target, err)
	}
	for _, name := range []string{"policy.json", "nginx.conf"} {
		info, err := os.Stat(filepath.Join(root, target, name))
		if err != nil || modePerm(info) != 0o400 {
			t.Fatalf("%s mode=%v err=%v", name, modePerm(info), err)
		}
	}
	assertSealedTLS(t, filepath.Join(root, target), fixture)
	if len(runtime.precheckCalls) != 1 || len(runtime.activateCalls) != 1 || len(runtime.healthCalls) != 1 {
		t.Fatalf("runtime calls precheck=%v activate=%v health=%v", runtime.precheckCalls, runtime.activateCalls, runtime.healthCalls)
	}
	status, err := manager.Status()
	if err != nil || !status.Active || status.VersionID != "http3-v1" || status.Digest != result.Digest {
		t.Fatalf("Status() = %+v, %v", status, err)
	}
}

func TestManagerPrecheckFailurePreservesLastKnownGood(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	firstFixture := newManagerTLSFixture(t, "http3-v1")
	first, err := manager.Apply(context.Background(), firstFixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	runtime.failPrecheck = true
	secondFixture := newManagerTLSFixture(t, "http3-v2")
	failed, err := manager.Apply(context.Background(), secondFixture.policy)
	if !errors.Is(err, ErrPrecheck) || failed.ErrorCode != "PRECHECK_FAILED" || !failed.RunningVersionUnchanged || failed.ActiveVersionID != "http3-v1" {
		t.Fatalf("Apply(v2) = %+v, %v", failed, err)
	}
	target, _ := os.Readlink(filepath.Join(root, "current"))
	if filepath.Base(target) != "http3-v1-"+first.Digest || len(runtime.activateCalls) != 1 {
		t.Fatalf("precheck changed active runtime: %q calls=%v", target, runtime.activateCalls)
	}
}

func TestManagerInvalidCandidateAssetReturnsPrecheckAndPreservesLastKnownGood(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	firstFixture := newManagerTLSFixture(t, "http3-v1")
	first, err := manager.Apply(context.Background(), firstFixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	secondFixture := newManagerTLSFixture(t, "http3-v2")
	secondFixture.policy.TLS.CertificateSHA256 = strings.Repeat("0", 64)
	failed, err := manager.Apply(context.Background(), secondFixture.policy)
	if !errors.Is(err, ErrPrecheck) || errors.Is(err, ErrCorruptState) || failed.ErrorCode != "PRECHECK_FAILED" ||
		!failed.RunningVersionUnchanged || failed.ActiveVersionID != "http3-v1" || failed.VersionID != "http3-v2" {
		t.Fatalf("Apply(v2 bad asset) = %+v, %v", failed, err)
	}
	if target := currentTarget(filepath.Join(root, "current")); target != "http3-v1-"+first.Digest ||
		len(runtime.precheckCalls) != 1 || len(runtime.activateCalls) != 1 || len(runtime.healthCalls) != 1 {
		t.Fatalf("bad asset changed LKG: current=%q precheck=%v activate=%v health=%v",
			target, runtime.precheckCalls, runtime.activateCalls, runtime.healthCalls)
	}
	entries, err := os.ReadDir(manager.store.temporaryDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("bad asset left temporary state: entries=%v error=%v", entries, err)
	}
}

func TestManagerRejectsInvalidTLSSourcesBeforePointerSwitch(t *testing.T) {
	tests := map[string]func(*testing.T, *managerTLSFixture){
		"wrong certificate digest": func(_ *testing.T, fixture *managerTLSFixture) {
			fixture.policy.TLS.CertificateSHA256 = strings.Repeat("0", 64)
		},
		"missing private key": func(t *testing.T, fixture *managerTLSFixture) {
			if err := os.Remove(fixture.privateKeyPath); err != nil {
				t.Fatal(err)
			}
		},
		"symlink certificate": func(t *testing.T, fixture *managerTLSFixture) {
			target := fixture.certificatePath + ".target"
			if err := os.Rename(fixture.certificatePath, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, fixture.certificatePath); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			runtime := &fakeRuntime{}
			manager, root := testManager(t, runtime)
			fixture := newManagerTLSFixture(t, "http3-v1")
			mutate(t, &fixture)
			if _, err := manager.Apply(context.Background(), fixture.policy); err == nil {
				t.Fatal("invalid TLS source was accepted")
			}
			if _, err := os.Lstat(filepath.Join(root, "current")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid TLS source switched current pointer: %v", err)
			}
			versions, err := os.ReadDir(filepath.Join(root, "versions"))
			if err != nil || len(versions) != 0 || len(runtime.precheckCalls) != 0 || len(runtime.activateCalls) != 0 {
				t.Fatalf("invalid source escaped stage: versions=%v read=%v precheck=%v activate=%v", versions, err, runtime.precheckCalls, runtime.activateCalls)
			}
		})
	}
}

func TestManagerSealsTLSBeforePrecheckAndIgnoresSourceReplacement(t *testing.T) {
	fixture := newManagerTLSFixture(t, "http3-v1")
	runtime := &fakeRuntime{}
	runtime.onPrecheck = func(stagePath string) error {
		certificate, certErr := os.ReadFile(filepath.Join(stagePath, "tls", "server.crt"))
		privateKey, keyErr := os.ReadFile(filepath.Join(stagePath, "tls", "server.key"))
		if certErr != nil || keyErr != nil || string(certificate) != string(fixture.certificate) || string(privateKey) != string(fixture.privateKey) {
			return errors.New("precheck did not receive the canonical sealed TLS bytes")
		}
		if err := os.WriteFile(fixture.certificatePath, []byte("replacement certificate\n"), 0o600); err != nil {
			return err
		}
		return os.WriteFile(fixture.privateKeyPath, []byte("replacement private key\n"), 0o600)
	}
	manager, root := testManager(t, runtime)
	result, err := manager.Apply(context.Background(), fixture.policy)
	if err != nil {
		t.Fatalf("Apply()=%v", err)
	}
	assertSealedTLS(t, filepath.Join(root, "versions", "http3-v1-"+result.Digest), fixture)
}

func TestManagerRejectsSealedAssetTamperAndPreservesLKG(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	firstFixture := newManagerTLSFixture(t, "http3-v1")
	first, err := manager.Apply(context.Background(), firstFixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	secondFixture := newManagerTLSFixture(t, "http3-v2")
	runtime.onPrecheck = func(stagePath string) error {
		path := filepath.Join(stagePath, "tls", "server.crt")
		if _, err := os.Stat(path); err != nil {
			return errors.New("sealed certificate was missing before tamper injection")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("tampered sealed certificate\n"), 0o600)
	}
	if _, err := manager.Apply(context.Background(), secondFixture.policy); err == nil {
		t.Fatal("tampered sealed certificate was activated")
	} else if errors.Is(err, ErrPrecheck) {
		t.Fatalf("tamper fixture failed before the post-Precheck integrity gate: %v", err)
	}
	if target := currentTarget(filepath.Join(root, "current")); target != "http3-v1-"+first.Digest || len(runtime.activateCalls) != 1 {
		t.Fatalf("sealed tamper changed LKG: current=%q activate=%v", target, runtime.activateCalls)
	}
	assertSealedTLS(t, filepath.Join(root, "versions", "http3-v1-"+first.Digest), firstFixture)
}

func TestManagerHealthFailureRestoresAndRechecksLastKnownGood(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	firstFixture := newManagerTLSFixture(t, "http3-v1")
	first, err := manager.Apply(context.Background(), firstFixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	runtime.failHealth = 1
	secondFixture := newManagerTLSFixture(t, "http3-v2")
	failed, err := manager.Apply(context.Background(), secondFixture.policy)
	if !errors.Is(err, ErrActivation) || failed.ErrorCode != "HEALTH_FAILED" || !failed.RunningVersionUnchanged || failed.ActiveVersionID != "http3-v1" {
		t.Fatalf("Apply(v2) = %+v, %v", failed, err)
	}
	target, _ := os.Readlink(filepath.Join(root, "current"))
	if filepath.Base(target) != "http3-v1-"+first.Digest {
		t.Fatalf("health rollback current=%q", target)
	}
	if len(runtime.activateCalls) != 3 || len(runtime.healthCalls) != 3 || runtime.healthCalls[2] != filepath.Base(target) {
		t.Fatalf("activate=%v health=%v", runtime.activateCalls, runtime.healthCalls)
	}
}

func TestManagerRetryExistingCandidateRemovesSealedStage(t *testing.T) {
	tests := map[string]bool{
		"retry health succeeds": false,
		"retry health fails":    true,
	}
	for name, failRetryHealth := range tests {
		t.Run(name, func(t *testing.T) {
			runtime := &fakeRuntime{}
			manager, root := testManager(t, runtime)
			firstFixture := newManagerTLSFixture(t, "http3-v1")
			first, err := manager.Apply(context.Background(), firstFixture.policy)
			if err != nil {
				t.Fatal(err)
			}
			secondFixture := newManagerTLSFixture(t, "http3-v2")
			runtime.failHealth = 1
			failed, err := manager.Apply(context.Background(), secondFixture.policy)
			if !errors.Is(err, ErrActivation) || failed.ErrorCode != "HEALTH_FAILED" ||
				!failed.RunningVersionUnchanged || failed.ActiveVersionID != "http3-v1" ||
				currentTarget(filepath.Join(root, "current")) != "http3-v1-"+first.Digest {
				t.Fatalf("initial v2 failure=%+v, %v current=%q", failed, err, currentTarget(filepath.Join(root, "current")))
			}
			second, err := Compile(secondFixture.policy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(root, "versions", "http3-v2-"+second.Digest, "tls", "server.key")); err != nil {
				t.Fatalf("failed v2 did not retain its sealed release for exact retry: %v", err)
			}
			if failRetryHealth {
				runtime.failHealth = 1
			}
			retry, retryErr := manager.Apply(context.Background(), secondFixture.policy)
			status, statusErr := manager.Status()
			if failRetryHealth {
				if !errors.Is(retryErr, ErrActivation) || retry.ErrorCode != "HEALTH_FAILED" ||
					!retry.RunningVersionUnchanged || retry.ActiveVersionID != "http3-v1" || statusErr != nil ||
					status.VersionID != "http3-v1" || currentTarget(filepath.Join(root, "current")) != "http3-v1-"+first.Digest {
					t.Fatalf("failed retry=%+v, %v status=%+v/%v current=%q", retry, retryErr, status, statusErr, currentTarget(filepath.Join(root, "current")))
				}
			} else if retryErr != nil || retry.State != StateApplied || retry.ActiveVersionID != "http3-v2" ||
				statusErr != nil || status.VersionID != "http3-v2" ||
				currentTarget(filepath.Join(root, "current")) != "http3-v2-"+second.Digest {
				t.Fatalf("successful retry=%+v, %v status=%+v/%v current=%q", retry, retryErr, status, statusErr, currentTarget(filepath.Join(root, "current")))
			}
			entries, err := os.ReadDir(manager.store.temporaryDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				leakedKey := filepath.Join(manager.store.temporaryDir, entries[0].Name(), "tls", "server.key")
				if _, err := os.Stat(leakedKey); err != nil {
					t.Fatalf("retry left unexpected temporary entries without the diagnostic sealed key: entries=%v key=%v", entries, err)
				}
				t.Fatalf("retry of exact existing v2 leaked sealed stage %s", leakedKey)
			}
		})
	}
}

func TestManagerRollbackUsesSealedLKGAfterSourcesAreDeleted(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	firstFixture := newManagerTLSFixture(t, "http3-v1")
	first, err := manager.Apply(context.Background(), firstFixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(firstFixture.certificatePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(firstFixture.privateKeyPath); err != nil {
		t.Fatal(err)
	}
	runtime.onActivate = func(currentPath string) error {
		if !strings.HasPrefix(currentTarget(currentPath), "http3-v1-") {
			return nil
		}
		certificate, certErr := os.ReadFile(filepath.Join(currentPath, "tls", "server.crt"))
		privateKey, keyErr := os.ReadFile(filepath.Join(currentPath, "tls", "server.key"))
		if certErr != nil || keyErr != nil || string(certificate) != string(firstFixture.certificate) || string(privateKey) != string(firstFixture.privateKey) {
			return errors.New("rollback did not consume sealed LKG TLS bytes")
		}
		return nil
	}
	runtime.failHealth = 1
	secondFixture := newManagerTLSFixture(t, "http3-v2")
	failed, err := manager.Apply(context.Background(), secondFixture.policy)
	if !errors.Is(err, ErrActivation) || failed.ErrorCode != "HEALTH_FAILED" || !failed.RunningVersionUnchanged || failed.ActiveVersionID != "http3-v1" {
		t.Fatalf("Apply(v2)=%+v, %v", failed, err)
	}
	if target := currentTarget(filepath.Join(root, "current")); target != "http3-v1-"+first.Digest {
		t.Fatalf("rollback current=%q", target)
	}
	assertSealedTLS(t, filepath.Join(root, "versions", "http3-v1-"+first.Digest), firstFixture)
}

func TestManagerInitialHealthFailureStopsCandidate(t *testing.T) {
	runtime := &fakeRuntime{failHealth: 1}
	manager, root := testManager(t, runtime)
	fixture := newManagerTLSFixture(t, "http3-v1")
	failed, err := manager.Apply(context.Background(), fixture.policy)
	if !errors.Is(err, ErrActivation) || failed.ErrorCode != "HEALTH_FAILED" || !failed.RunningVersionUnchanged || failed.ActiveVersionID != "" {
		t.Fatalf("Apply() = %+v, %v", failed, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "current")); !errors.Is(err, os.ErrNotExist) || len(runtime.stopCalls) != 1 {
		t.Fatalf("initial failure current=%v stops=%v", err, runtime.stopCalls)
	}
}

func TestManagerIsIdempotentSerialAndRejectsVersionConflict(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	fixture := newManagerTLSFixture(t, "http3-v1")
	const workers = 12
	results := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := manager.Apply(context.Background(), fixture.policy)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(runtime.precheckCalls) != 1 || len(runtime.activateCalls) != 1 || len(runtime.healthCalls) != 1 {
		t.Fatalf("idempotent calls=%d/%d/%d", len(runtime.precheckCalls), len(runtime.activateCalls), len(runtime.healthCalls))
	}
	compiled, err := Compile(fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	assertSealedTLS(t, filepath.Join(root, "versions", "http3-v1-"+compiled.Digest), fixture)
	if err := os.Remove(fixture.certificatePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture.privateKeyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), fixture.policy); err != nil {
		t.Fatalf("idempotent apply consulted deleted TLS sources: %v", err)
	}
	conflict := fixture.policy
	conflict.Limits.IdleTimeoutMS++
	if _, err := manager.Apply(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict error=%v", err)
	}
}

func TestManagerRejectsUnsafeRootAndTamperedLKG(t *testing.T) {
	for _, path := range []string{"relative", "/"} {
		if _, err := NewManager(path, &fakeRuntime{}); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("NewManager(%q)=%v", path, err)
		}
	}
	manager, root := testManager(t, &fakeRuntime{})
	fixture := newManagerTLSFixture(t, "http3-v1")
	result, err := manager.Apply(context.Background(), fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(root, "versions", "http3-v1-"+result.Digest, "policy.json")
	if err := os.Chmod(policyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Status(); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("Status()=%v, want ErrCorruptState", err)
	}
}
