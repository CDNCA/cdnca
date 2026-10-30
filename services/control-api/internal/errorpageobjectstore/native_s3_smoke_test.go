//go:build darwin || linux

package errorpageobjectstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/google/uuid"
)

// This opt-in qualification uses a separately downloaded and verified RustFS 1.0.1
// binary. It neither downloads software nor changes the production adapter.
func TestNativeS3ObjectStoreSmoke(t *testing.T) {
	if os.Getenv("ERRORPAGE_OBJECTSTORE_NATIVE_S3_SMOKE") != "1" {
		t.Skip("set ERRORPAGE_OBJECTSTORE_NATIVE_S3_SMOKE=1 with a verified RustFS binary and its SHA256")
	}
	binary := os.Getenv("ERRORPAGE_OBJECTSTORE_NATIVE_S3_BINARY")
	wantDigest := os.Getenv("ERRORPAGE_OBJECTSTORE_NATIVE_S3_SHA256")
	info, err := os.Lstat(binary)
	if err != nil || !filepath.IsAbs(binary) || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || !digestPattern.MatchString(wantDigest) {
		t.Fatal("native smoke requires an absolute regular executable and its exact SHA256")
	}
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal("open verified native smoke executable")
	}
	digest := sha256.New()
	_, hashErr := io.Copy(digest, file)
	closeErr := file.Close()
	if hashErr != nil || closeErr != nil || hex.EncodeToString(digest.Sum(nil)) != wantDigest {
		t.Fatal("native smoke executable SHA256 mismatch; refusing to execute")
	}
	version := exec.CommandContext(t.Context(), binary, "-V")
	version.Env = []string{"PATH=/usr/bin:/bin"}
	versionOutput, err := version.Output()
	if err != nil || strings.TrimSpace(string(versionOutput)) != "rustfs 1.0.1" {
		t.Fatal("native smoke requires RustFS 1.0.1")
	}
	t.Logf("verified native binary: version=1.0.1 sha256=%s", wantDigest)

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	accessKey, secretKey := nativeS3SmokeCredentials(t)
	provider := credentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}, nil
	})
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := newSmokeS3Client("http://"+address, provider, &http.Client{
		Transport: transport, Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	})
	root := t.TempDir()
	process, done := startNativeS3Smoke(t, binary, address, root, accessKey, secretKey)
	t.Cleanup(func() {
		if process != nil {
			stopNativeS3Smoke(t, process, done)
		}
	})
	waitReady := func() {
		t.Helper()
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-done:
				t.Fatal("isolated native S3 process exited before authenticated readiness")
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
		t.Fatal("isolated native S3 did not reach authenticated readiness within 45 seconds")
	}
	waitReady()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	bucket := "cdnca-native-smoke-" + suffix[:20]
	if _, err := client.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("create native smoke bucket: %v", err)
	}
	t.Cleanup(func() { cleanupSmokeBucket(t, client, bucket) })
	config := validConfig("http://" + address)
	config.Region, config.Bucket, config.Prefix = "us-east-1", bucket, "native-smoke/"+suffix[:16]
	config.Credentials, config.MaxAttempts = provider, 1
	config.RequestTimeout = 5 * time.Second
	if store, err := New(t.Context(), config); store != nil || !errors.Is(err, errorpagecontrol.ErrUnavailable) {
		t.Fatalf("unversioned bucket must fail closed: store=%t error=%v", store != nil, err)
	}
	setVersioning := func(status types.BucketVersioningStatus) {
		t.Helper()
		if _, err := client.PutBucketVersioning(t.Context(), &s3.PutBucketVersioningInput{
			Bucket: aws.String(bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: status},
		}); err != nil {
			t.Fatalf("set native bucket versioning %s: %v", status, err)
		}
	}
	setVersioning(types.BucketVersioningStatusEnabled)
	wrongConfig := config
	wrongConfig.Credentials = credentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey + "wrong"}, nil
	})
	if store, err := New(t.Context(), wrongConfig); store != nil || !errors.Is(err, errorpagecontrol.ErrUnavailable) {
		t.Fatalf("wrong credentials must fail closed: store=%t error=%v", store != nil, err)
	}
	store, err := New(t.Context(), config)
	if err != nil {
		t.Fatalf("real native S3 readiness contract: %v", err)
	}
	assertNoSmokeObjectVersions(t, client, bucket, config.Prefix+"/")
	t.Log("real Ready probe passed conditional PUT/finalize, source identity, exact-version/ETag rejection, concurrent single winner, and exact-version cleanup")
	tenantID, scopeID := uuid.New(), uuid.New()
	ref := func(name string) errorpagecontrol.ObjectRef {
		return errorpagecontrol.ObjectRef{TenantID: &tenantID, ScopeID: scopeID, LogicalKey: "error-pages/" + name}
	}
	staging, final, missing := ref("staging/"+suffix), ref("objects/"+suffix), ref("missing/"+suffix)
	body := []byte("native S3 error page smoke")
	wantSHA := sha256.Sum256(body)
	token := "sha256:" + hex.EncodeToString(wantSHA[:])
	if _, err := store.Stat(t.Context(), missing); !errors.Is(err, errorpagecontrol.ErrObjectNotFound) {
		t.Fatalf("missing object Stat: %v", err)
	}
	if reader, err := store.Open(t.Context(), missing, token); !errors.Is(err, errorpagecontrol.ErrObjectNotFound) || reader != nil {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("missing object Open: %v", err)
	}
	staged, err := store.PutStaging(t.Context(), staging, body, "text/plain")
	if err != nil || staged.Size != int64(len(body)) || staged.SHA256 != hex.EncodeToString(wantSHA[:]) || staged.ImmutableToken != token {
		t.Fatalf("native immutable staging metadata: info=%+v error=%v", staged, err)
	}
	before, err := store.stat(t.Context(), staging)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := store.PutStaging(t.Context(), staging, body, "text/plain"); err != nil || replay != staged {
		t.Fatalf("native staging replay: %v", err)
	}
	if _, err := store.PutStaging(t.Context(), staging, []byte("different"), "text/plain"); !errors.Is(err, errorpagecontrol.ErrConflict) {
		t.Fatalf("native staging conflict: %v", err)
	}
	if after, err := store.stat(t.Context(), staging); err != nil || after != before {
		t.Fatalf("native replay/conflict changed staging version: %v", err)
	}
	if finalized, err := store.Finalize(t.Context(), staging, final, staged); err != nil || finalized != staged {
		t.Fatalf("native finalize: %v", err)
	}
	finalState, err := store.stat(t.Context(), final)
	if err != nil {
		t.Fatal(err)
	}
	readFinal := func() {
		t.Helper()
		reader, err := store.Open(t.Context(), final, token)
		if err != nil {
			t.Fatalf("native immutable Open: %v", err)
		}
		opened, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || !bytes.Equal(opened, body) {
			t.Fatalf("native immutable bytes: read=%v close=%v equal=%t", readErr, closeErr, bytes.Equal(opened, body))
		}
	}
	readFinal()

	// A newer version must not redirect an exact-version read to the current body.
	protocolKey := "protocol/" + suffix
	first, err := client.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(protocolKey), Body: bytes.NewReader(body)})
	if err != nil || aws.ToString(first.VersionId) == "" || aws.ToString(first.VersionId) == "null" {
		t.Fatalf("put first protocol version: %v", err)
	}
	second, err := client.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(protocolKey), Body: strings.NewReader("newer body")})
	if err != nil || aws.ToString(second.VersionId) == aws.ToString(first.VersionId) {
		t.Fatalf("put distinct second protocol version: %v", err)
	}
	oldState := objectState{versionID: aws.ToString(first.VersionId), etag: aws.ToString(first.ETag)}
	old, err := store.getBoundObject(t.Context(), protocolKey, oldState, "read older version")
	if err != nil {
		t.Fatal(err)
	}
	oldBody, readErr := io.ReadAll(old.Body)
	closeErr = old.Body.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(oldBody, body) {
		t.Fatal("exact-version read did not preserve the older body")
	}
	if _, err := client.DeleteObject(t.Context(), &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(protocolKey), VersionId: first.VersionId}); err != nil {
		t.Fatalf("delete exact old version: %v", err)
	}
	if output, err := store.getBoundObject(t.Context(), protocolKey, oldState, "read deleted version"); !errors.Is(err, errorpagecontrol.ErrObjectNotFound) || output != nil {
		if output != nil && output.Body != nil {
			_ = output.Body.Close()
		}
		t.Fatal("deleted exact version remained readable")
	}
	if current, err := client.HeadObject(t.Context(), &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(protocolKey)}); err != nil || aws.ToString(current.VersionId) != aws.ToString(second.VersionId) {
		t.Fatalf("exact old-version deletion changed the current version: %v", err)
	}

	setVersioning(types.BucketVersioningStatusSuspended)
	if err := store.Ready(t.Context()); !errors.Is(err, errorpagecontrol.ErrUnavailable) || store.Capabilities() != (errorpagecontrol.ObjectStoreCapabilities{}) {
		t.Fatalf("suspended versioning must revoke capabilities: %v", err)
	}
	if _, err := store.PutStaging(t.Context(), missing, body, "text/plain"); !errors.Is(err, errorpagecontrol.ErrUnavailable) {
		t.Fatalf("write while not ready: %v", err)
	}
	setVersioning(types.BucketVersioningStatusEnabled)
	if err := store.Ready(t.Context()); err != nil {
		t.Fatalf("restore versioning readiness: %v", err)
	}
	t.Log("negative versioning, credentials, missing object, immutable replay/conflict, older-version read/delete passed")

	stopNativeS3Smoke(t, process, done)
	process = nil
	if err := store.Ready(t.Context()); !errors.Is(err, errorpagecontrol.ErrUnavailable) || store.Capabilities() != (errorpagecontrol.ObjectStoreCapabilities{}) {
		t.Fatalf("stopped dependency must revoke capabilities: %v", err)
	}
	if _, err := store.PutStaging(t.Context(), missing, body, "text/plain"); !errors.Is(err, errorpagecontrol.ErrUnavailable) {
		t.Fatalf("write while dependency is stopped: %v", err)
	}
	process, done = startNativeS3Smoke(t, binary, address, root, accessKey, secretKey)
	waitReady()
	if err := store.Ready(t.Context()); err != nil {
		t.Fatalf("restart readiness: %v", err)
	}
	if restarted, err := store.stat(t.Context(), final); err != nil || restarted != finalState {
		t.Fatalf("restart changed persisted object metadata/version: %v", err)
	}
	readFinal()
	for _, object := range []errorpagecontrol.ObjectRef{final, staging} {
		if err := store.Delete(t.Context(), object); err != nil {
			t.Fatalf("native logical delete: %v", err)
		}
		if _, err := store.Stat(t.Context(), object); !errors.Is(err, errorpagecontrol.ErrObjectNotFound) {
			t.Fatalf("native deleted object remained visible: %v", err)
		}
	}
	t.Log("restart preserved exact object version and bytes; dependency outage failed closed; logical delete passed")
}

func nativeS3SmokeCredentials(t *testing.T) (string, string) {
	t.Helper()
	value := make([]byte, 40)
	if _, err := rand.Read(value); err != nil {
		t.Fatal("generate native smoke credentials")
	}
	return "smoke" + hex.EncodeToString(value[:8]), hex.EncodeToString(value[8:])
}

func startNativeS3Smoke(t *testing.T, binary, address, root, accessKey, secretKey string) (*exec.Cmd, <-chan error) {
	t.Helper()
	for _, directory := range []string{"data", "logs"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command(binary, "server", filepath.Join(root, "data"))
	command.Dir = root
	// RustFS 1.0.1 tag: ServerOpts, init_update_check and observability export flags.
	// Do not inherit cloud profiles, production credentials, proxy or telemetry env.
	command.Env = []string{
		"PATH=/usr/bin:/bin", "RUSTFS_ADDRESS=" + address, "RUSTFS_REGION=us-east-1",
		"RUSTFS_ACCESS_KEY=" + accessKey, "RUSTFS_SECRET_KEY=" + secretKey,
		"RUSTFS_CONSOLE_ENABLE=false", "RUSTFS_CONSOLE_ADDRESS=127.0.0.1:0", "RUSTFS_CHECK_UPDATE=false",
		"RUSTFS_OBS_ENDPOINT=", "RUSTFS_OBS_TRACES_EXPORT_ENABLED=false", "RUSTFS_OBS_METRICS_EXPORT_ENABLED=false",
		"RUSTFS_OBS_LOGS_EXPORT_ENABLED=false", "RUSTFS_OBS_PROFILING_EXPORT_ENABLED=false",
		"RUSTFS_OBS_LOG_STDOUT_ENABLED=false", "RUSTFS_OBS_LOGGER_LEVEL=off",
		"RUSTFS_OBS_LOG_DIRECTORY=" + filepath.Join(root, "logs"), "RUSTFS_RUNTIME_DIAL9_ENABLED=false",
	}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		t.Fatalf("start isolated native S3: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
		close(done)
	}()
	t.Logf("isolated native S3 started pid=%d address=%s; console/update/exporters disabled", command.Process.Pid, address)
	return command, done
}

func stopNativeS3Smoke(t *testing.T, command *exec.Cmd, done <-chan error) {
	t.Helper()
	if err := command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("stop isolated native S3 pid=%d: %v", command.Process.Pid, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("isolated native S3 pid=%d did not exit cleanly: %v", command.Process.Pid, err)
		}
	case <-time.After(15 * time.Second):
		_ = command.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("isolated native S3 pid=%d did not reap after kill", command.Process.Pid)
			return
		}
		t.Errorf("isolated native S3 pid=%d exceeded graceful shutdown deadline", command.Process.Pid)
	}
	t.Logf("isolated native S3 reaped pid=%d", command.Process.Pid)
}
