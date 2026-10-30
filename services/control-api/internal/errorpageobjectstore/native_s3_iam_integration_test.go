//go:build integration && (darwin || linux)

package errorpageobjectstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/google/uuid"
)

// Uses only an isolated local process/data directory. It never installs a unit,
// account, system CA, or application credential. SHA256 checks precede execution.
func TestNativeS3RestrictedIAMIntegration(t *testing.T) {
	if os.Getenv("ERRORPAGE_OBJECTSTORE_NATIVE_IAM_SMOKE") != "1" {
		t.Skip("set ERRORPAGE_OBJECTSTORE_NATIVE_IAM_SMOKE=1 with verified native binary and helper")
	}
	binary := nativeIAMVerifiedFile(t, "ERRORPAGE_OBJECTSTORE_NATIVE_S3_BINARY", "ERRORPAGE_OBJECTSTORE_NATIVE_S3_SHA256")
	helper := nativeIAMVerifiedFile(t, "ERRORPAGE_OBJECTSTORE_NATIVE_IAM_HELPER", "ERRORPAGE_OBJECTSTORE_NATIVE_IAM_HELPER_SHA256")
	version := exec.CommandContext(t.Context(), binary, "-V")
	version.Env = []string{"PATH=/usr/bin:/bin"}
	if output, err := version.Output(); err != nil || strings.TrimSpace(string(output)) != "rustfs 1.0.1" {
		t.Fatal("integration requires verified RustFS 1.0.1")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	access, secret := nativeS3SmokeCredentials(t)
	for name, value := range map[string]string{"root-access-key": access, "root-secret-key": secret} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	nativeIAMHelper(t, helper, root, "", "tls")
	certificate, err := os.ReadFile(filepath.Join(root, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	endpoint := "https://" + address
	process, done := startNativeIAMProcess(t, binary, address, root)
	t.Cleanup(func() {
		if process != nil {
			stopNativeS3Smoke(t, process, done)
		}
	})
	provider := func(key, value string) aws.CredentialsProvider {
		return credentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: key, SecretAccessKey: value}, nil
		})
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certificate) {
		t.Fatal("load isolated TLS trust")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	defer transport.CloseIdleConnections()
	client := newSmokeS3Client(endpoint, provider(access, secret), &http.Client{
		Transport: transport, Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	})
	waitReady := func() {
		t.Helper()
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-done:
				t.Fatal("isolated TLS process exited before readiness")
			default:
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			_, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
			cancel()
			if err == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("isolated TLS readiness deadline exceeded")
	}
	waitReady()
	response, err := (&http.Client{Timeout: time.Second}).Get("http://" + address + "/")
	if err == nil {
		_ = response.Body.Close()
		if response.StatusCode < 400 {
			t.Fatal("TLS-only listener unexpectedly accepted plaintext HTTP")
		}
	}
	nativeIAMHelper(t, helper, root, endpoint, "iam")
	encoded, err := os.ReadFile(filepath.Join(root, "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	var runtime struct {
		Users map[string]struct {
			AccessKey string `json:"access_key"`
			SecretKey string `json:"secret_key"`
		} `json:"users"`
	}
	if err := json.Unmarshal(encoded, &runtime); err != nil || len(runtime.Users) != 2 {
		t.Fatal("decode private runtime identities")
	}
	t.Cleanup(func() { cleanupSmokeBucket(t, client, "cdnca-assets") })
	stores := make(map[string]*Store)
	for _, prefix := range []string{"brand-assets", "error-pages"} {
		user := runtime.Users[prefix]
		if user.AccessKey == "" || user.SecretKey == "" || user.AccessKey == access || user.SecretKey == secret {
			t.Fatal("runtime identity was not isolated from administrator")
		}
		config := validConfig(endpoint)
		config.Region, config.Bucket, config.Prefix = "us-east-1", "cdnca-assets", prefix
		config.CACertificatePEM, config.MaxAttempts = certificate, 1
		config.Credentials = provider(user.AccessKey, user.SecretKey)
		store, err := New(t.Context(), config)
		if err != nil {
			t.Fatalf("restricted identity adapter readiness: %v", err)
		}
		stores[prefix] = store
		assertNoSmokeObjectVersions(t, client, config.Bucket, prefix+"/")
		wrong := config
		wrong.Credentials = provider(user.AccessKey, user.SecretKey+"wrong")
		if candidate, err := New(t.Context(), wrong); candidate != nil || !errors.Is(err, errorpagecontrol.ErrUnavailable) {
			t.Fatal("adapter accepted wrong runtime secret")
		}
		wrong = config
		wrong.CACertificatePEM = nil
		if candidate, err := New(t.Context(), wrong); candidate != nil || !errors.Is(err, errorpagecontrol.ErrUnavailable) {
			t.Fatal("adapter accepted untrusted isolated certificate")
		}
		wrong = config
		if prefix == "brand-assets" {
			wrong.Prefix = "error-pages"
		} else {
			wrong.Prefix = "brand-assets"
		}
		if candidate, err := New(t.Context(), wrong); candidate != nil || !errors.Is(err, errorpagecontrol.ErrUnavailable) {
			t.Fatal("adapter accepted cross-prefix identity")
		}
	}
	nativeIAMHelper(t, helper, root, endpoint, "probe")
	t.Log("trusted TLS and restricted identities passed real Ready; plaintext, untrusted CA, wrong secret, cross-prefix, bucket administration and IAM administration refused")
	tenant, scope := uuid.New(), uuid.New()
	ref := func(key string) errorpagecontrol.ObjectRef {
		return errorpagecontrol.ObjectRef{TenantID: &tenant, ScopeID: scope, LogicalKey: key}
	}
	staging, final := ref("staging/persistent"), ref("objects/persistent")
	body := []byte("restricted TLS restart persistence")
	store := stores["error-pages"]
	info, err := store.PutStaging(t.Context(), staging, body, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Finalize(t.Context(), staging, final, info); err != nil {
		t.Fatal(err)
	}
	before, err := store.stat(t.Context(), final)
	if err != nil {
		t.Fatal(err)
	}
	foreignKey, err := store.canonicalKey(final)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := stores["brand-assets"].getBoundObject(t.Context(), foreignKey, before, "cross-prefix read"); output != nil || !errors.Is(err, errorpagecontrol.ErrUnavailable) {
		if output != nil && output.Body != nil {
			_ = output.Body.Close()
		}
		t.Fatal("restricted adapter could read another prefix's real object/version")
	}
	_, err = stores["brand-assets"].client.DeleteObject(t.Context(), &s3.DeleteObjectInput{
		Bucket: aws.String("cdnca-assets"), Key: aws.String(foreignKey), VersionId: aws.String(before.versionID),
	})
	var deniedHTTP interface{ HTTPStatusCode() int }
	if !errors.As(err, &deniedHTTP) || deniedHTTP.HTTPStatusCode() != http.StatusForbidden {
		t.Fatal("restricted identity must receive 403 deleting another prefix's version")
	}
	t.Log("cross-prefix GET and exact-version DELETE of a real object were denied")
	stopNativeS3Smoke(t, process, done)
	process = nil
	if err := store.Ready(t.Context()); !errors.Is(err, errorpagecontrol.ErrUnavailable) {
		t.Fatal("stopped TLS dependency did not fail closed")
	}
	process, done = startNativeIAMProcess(t, binary, address, root)
	waitReady()
	for _, current := range stores {
		if err := current.Ready(t.Context()); err != nil {
			t.Fatalf("persisted restricted IAM readiness: %v", err)
		}
	}
	nativeIAMHelper(t, helper, root, endpoint, "probe")
	if after, err := store.stat(t.Context(), final); err != nil || after != before {
		t.Fatal("restart changed immutable version or metadata")
	}
	reader, err := store.Open(t.Context(), final, info.ImmutableToken)
	if err != nil {
		t.Fatal(err)
	}
	actual, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(actual, body) {
		t.Fatal("restart changed persisted object bytes")
	}
	t.Log("restart preserved TLS, IAM users/policies and exact object version/bytes without re-provisioning")
}

func nativeIAMVerifiedFile(t *testing.T, pathVariable, digestVariable string) string {
	t.Helper()
	path, expected := os.Getenv(pathVariable), os.Getenv(digestVariable)
	info, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || !info.Mode().IsRegular() || !digestPattern.MatchString(expected) {
		t.Fatal("integration requires absolute regular input files and exact SHA256")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("open verified input")
	}
	digest := sha256.New()
	_, readErr := io.Copy(digest, file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || hex.EncodeToString(digest.Sum(nil)) != expected {
		t.Fatal("integration input SHA256 mismatch; refusing execution")
	}
	return path
}

func nativeIAMHelper(t *testing.T, helper, root, endpoint, action string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for official Admin API helper integration")
	}
	code := `import importlib.util,json,os,sys,traceback
from pathlib import Path
os.umask(0o077)
spec=importlib.util.spec_from_file_location("native_rustfs",sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.COMMAND_ENV["PATH"]=os.environ["PATH"]
directory,endpoint,action=Path(sys.argv[2]),sys.argv[3],sys.argv[4]
try:
 if action=="tls":m.create_tls(directory)
 elif action=="iam":m.provision_iam(directory,endpoint)
 elif action=="probe":m.probe_runtime(directory)
 else:raise ValueError("unknown test action")
except Exception as error:
 print(json.dumps({"line":traceback.extract_tb(error.__traceback__)[-1].lineno}))
 sys.exit(1)`
	command := exec.CommandContext(t.Context(), python, "-c", code, helper, root, endpoint, action)
	command.Env = []string{"PATH=/opt/homebrew/opt/openssl@3/bin:/opt/homebrew/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Stderr = io.Discard
	if output, err := command.Output(); err != nil {
		var diagnostic struct{ Line int }
		_ = json.Unmarshal(output, &diagnostic)
		t.Fatalf("isolated native helper %s failed at line %d (sensitive output suppressed): %v", action, diagnostic.Line, err)
	}
}

func startNativeIAMProcess(t *testing.T, binary, address, root string) (*exec.Cmd, <-chan error) {
	t.Helper()
	for _, name := range []string{"data", "logs"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command(binary, "server", filepath.Join(root, "data"))
	command.Dir = root
	command.Env = []string{
		"PATH=/usr/bin:/bin", "RUSTFS_ADDRESS=" + address, "RUSTFS_REGION=us-east-1",
		"RUSTFS_ACCESS_KEY_FILE=" + filepath.Join(root, "root-access-key"), "RUSTFS_SECRET_KEY_FILE=" + filepath.Join(root, "root-secret-key"),
		"RUSTFS_TLS_PATH=" + root, "RUSTFS_CONSOLE_ENABLE=false", "RUSTFS_CONSOLE_ADDRESS=127.0.0.1:0", "RUSTFS_CHECK_UPDATE=false",
		"RUSTFS_OBS_ENDPOINT=", "RUSTFS_OBS_TRACES_EXPORT_ENABLED=false", "RUSTFS_OBS_METRICS_EXPORT_ENABLED=false",
		"RUSTFS_OBS_LOGS_EXPORT_ENABLED=false", "RUSTFS_OBS_PROFILING_EXPORT_ENABLED=false", "RUSTFS_OBS_LOG_STDOUT_ENABLED=false",
		"RUSTFS_OBS_LOGGER_LEVEL=off", "RUSTFS_OBS_LOG_DIRECTORY=" + filepath.Join(root, "logs"), "RUSTFS_RUNTIME_DIAL9_ENABLED=false",
	}
	for _, value := range command.Env {
		if strings.HasPrefix(value, "RUSTFS_SECRET_KEY=") {
			t.Fatal("secret value must not be in service environment")
		}
	}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		t.Fatal("start isolated TLS process")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait(); close(done) }()
	t.Logf("isolated TLS RustFS started pid=%d loopback=%s", command.Process.Pid, address)
	return command, done
}
