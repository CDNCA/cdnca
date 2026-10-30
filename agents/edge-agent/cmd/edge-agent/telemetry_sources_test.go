package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

const (
	telemetryTestTenantID = "11111111-1111-4111-8111-111111111111"
	telemetryTestSiteID   = "33333333-3333-4333-8333-333333333333"
	telemetryTestNodeID   = "44444444-4444-4444-8444-444444444444"
)

type precheckFunc func(context.Context, string, string) error

func (f precheckFunc) Precheck(ctx context.Context, versionID, releasePath string) error {
	return f(ctx, versionID, releasePath)
}

type capturePublication struct {
	publications []eventspool.Publication
}

func (p *capturePublication) Publish(_ context.Context, publications []eventspool.Publication) (eventspool.PublishAck, error) {
	p.publications = append(p.publications, publications...)
	accepted := 0
	for _, publication := range publications {
		accepted += publication.EventCount
	}
	return eventspool.PublishAck{Acknowledged: accepted}, nil
}

func TestTelemetryPrecheckCreatesPrivateSignedLogSourcesBeforeOpenResty(t *testing.T) {
	root := telemetrySecureRoot(t)
	bundle := telemetryBundle(t, root, "cfg-v1")
	release := filepath.Join(root, "releases", bundle.ManifestSHA256)
	writeTelemetryRelease(t, release, bundle)

	called := false
	delegate := precheckFunc(func(_ context.Context, versionID, releasePath string) error {
		called = true
		if versionID != "cfg-v1" || releasePath != release {
			t.Fatalf("delegate input = %q, %q", versionID, releasePath)
		}
		manifest, err := edgeconfig.ParseTelemetryIdentityManifest(bundle.Files[edgeconfig.TelemetryIdentityManifestPath])
		if err != nil {
			t.Fatal(err)
		}
		for _, site := range manifest.Sites {
			for _, path := range []string{site.AccessLogPath, site.SecurityLogPath} {
				info, err := os.Lstat(path)
				if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
					t.Fatalf("telemetry source %q is not private: %v, %v", path, info, err)
				}
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
					t.Fatalf("telemetry source %q ownership/link count = %#v", path, stat)
				}
				if directory, err := os.Stat(filepath.Dir(path)); err != nil || !directory.IsDir() || directory.Mode().Perm() != 0o700 {
					t.Fatalf("telemetry directory %q is not private: %v, %v", filepath.Dir(path), directory, err)
				}
			}
		}
		return nil
	})
	prechecker, err := newTelemetryPrechecker(root, delegate)
	if err != nil {
		t.Fatal(err)
	}
	if err := prechecker.Precheck(context.Background(), "cfg-v1", release); err != nil {
		t.Fatalf("Precheck() error = %v", err)
	}
	if !called {
		t.Fatal("OpenResty precheck was not called")
	}
}

func TestL4TelemetrySourcePathUsesLegacyOnlyForSingleListener(t *testing.T) {
	root := telemetrySecureRoot(t)
	stream := l4runtime.StreamRuntimeSpecV2{
		SchemaVersion: l4runtime.SchemaVersionV2, TenantID: telemetryTestTenantID,
		StreamID: "55555555-5555-4555-8555-555555555555", Revision: 1,
		Listener: l4runtime.ListenerSocketV2{Protocol: l4runtime.ProtocolTCP, Address: "0.0.0.0", Port: 18080},
	}
	// v12: a stream is its own telemetry partition (no website).
	legacy := l4runtime.L4TelemetryLogPath(root, "cfg-v1", stream.StreamID, stream.Listener.Port)
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := l4TelemetrySourcePath(root, "cfg-v1", stream, map[string]int{stream.StreamID: 1})
	if err != nil || path != legacy {
		t.Fatalf("single-listener legacy path = %q, error=%v", path, err)
	}
	stream.StreamID = "66666666-6666-4666-8666-666666666666"
	newPath, err := l4runtime.L4TelemetryLogPathForRuntimeStream(root, "cfg-v1", stream)
	if err != nil {
		t.Fatal(err)
	}
	path, err = l4TelemetrySourcePath(root, "cfg-v1", stream, map[string]int{stream.StreamID: 2})
	if err != nil || path == legacy || path != newPath {
		t.Fatalf("multi-listener identity path = %q, want new=%q legacy=%q error=%v", path, newPath, legacy, err)
	}
	identity := eventspool.TrustedIdentity{EnrollmentNodeID: telemetryTestNodeID, TenantID: telemetryTestTenantID,
		SiteID: stream.StreamID, ConfigVersionID: "cfg-v1", StreamID: stream.StreamID, ListenerID: stream.StreamID,
		ConfigRevision: 1}
	if err := validateTelemetryRegistration(telemetrySourceConfig{DeploymentRoot: root, EnrollmentNodeID: telemetryTestNodeID}, telemetrySourceRegistration{
		SourcePath: path, Identity: identity, EventType: eventspool.EventL4Session,
	}); err != nil {
		t.Fatalf("identity-aware L4 path rejected: %v path=%q prefix=%q", err, path,
			l4runtime.L4TelemetryPathIdentityPrefix(identity.StreamID, identity.ListenerID))
	}
}

func TestTelemetryPrecheckPreservesSameSiteMultiPortSourcesAndPolicies(t *testing.T) {
	root := telemetrySecureRoot(t)
	bundle := telemetryMultiPortBundle(t, root, "cfg-v1")
	release := filepath.Join(root, "releases", bundle.ManifestSHA256)
	writeTelemetryRelease(t, release, bundle)
	called := false
	prechecker, err := newTelemetryPrechecker(root, precheckFunc(func(context.Context, string, string) error {
		called = true
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := prechecker.Precheck(context.Background(), "cfg-v1", release); err != nil {
		t.Fatalf("Precheck() error = %v", err)
	}
	if !called {
		t.Fatal("OpenResty delegate was not called")
	}
	manifest, err := edgeconfig.ParseTelemetryIdentityManifest(bundle.Files[edgeconfig.TelemetryIdentityManifestPath])
	if err != nil || len(manifest.Sites) != 2 || len(manifest.CapturePolicy.Sites) != 2 {
		t.Fatalf("same-site multi-port manifest = %+v, error=%v", manifest, err)
	}
	paths := map[string]struct{}{}
	for _, site := range manifest.Sites {
		for _, path := range []string{site.AccessLogPath, site.SecurityLogPath} {
			if _, duplicate := paths[path]; duplicate {
				t.Fatalf("same-site listener source path was reused: %q", path)
			}
			paths[path] = struct{}{}
			if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("same-site listener source %q = %v, %v", path, info, err)
			}
		}
	}
	if got := manifest.CapturePolicy.Sites; len(got[0].RequestHeaderAllowlist) != 1 ||
		len(got[1].RequestBodyFieldAllowlist) != 1 {
		t.Fatalf("same-site listener capture policies = %+v", got)
	}
}

func TestEnsurePrivateTelemetrySourceRejectsSpecialFilesPromptly(t *testing.T) {
	root := telemetrySecureRoot(t)
	directory := filepath.Join(root, "shared", "telemetry", "cfg-v1", telemetryTestSiteID, "18081")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Geteuid(), os.Getegid()
	rejectPromptly := func(t *testing.T, sourceRoot, path string) {
		t.Helper()
		result := make(chan error, 1)
		go func() { result <- ensurePrivateTelemetrySource(sourceRoot, path, uid, gid) }()
		select {
		case err := <-result:
			if err == nil {
				t.Fatalf("special telemetry source %q was accepted", path)
			}
		case <-time.After(250 * time.Millisecond):
			t.Fatalf("special telemetry source %q blocked", path)
		}
	}

	t.Run("fifo without reader", func(t *testing.T) {
		path := filepath.Join(directory, "fifo.jsonl")
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		rejectPromptly(t, root, path)
	})

	t.Run("unix socket", func(t *testing.T) {
		shortRoot, err := os.MkdirTemp("/tmp", "t")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(shortRoot) })
		shortDirectory := filepath.Join(shortRoot, "shared", "telemetry", "cfg-v1", telemetryTestSiteID, "18081")
		if err := os.MkdirAll(shortDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(shortDirectory, "source.sock")
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		rejectPromptly(t, shortRoot, path)
	})

	t.Run("device descriptor", func(t *testing.T) {
		file, err := os.OpenFile("/dev/null", os.O_WRONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := validatePrivateTelemetrySourceFile(file, uid, gid); err == nil {
			t.Fatal("device telemetry source descriptor was accepted")
		}
	})

	t.Run("device info", func(t *testing.T) {
		info, err := os.Stat("/dev/null")
		if err != nil {
			t.Fatal(err)
		}
		if err := validatePrivateTelemetrySourceInfo(info, uid, gid); err == nil {
			t.Fatal("device telemetry source was accepted")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		target := filepath.Join(directory, "symlink-target.jsonl")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "symlink.jsonl")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := ensurePrivateTelemetrySource(root, path, uid, gid); err == nil {
			t.Fatal("symlink telemetry source was accepted")
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		target := filepath.Join(directory, "hardlink-target.jsonl")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "hardlink.jsonl")
		if err := os.Link(target, path); err != nil {
			t.Fatal(err)
		}
		if err := ensurePrivateTelemetrySource(root, path, uid, gid); err == nil {
			t.Fatal("hardlink telemetry source was accepted")
		}
	})

	t.Run("wrong mode", func(t *testing.T) {
		path := filepath.Join(directory, "mode.jsonl")
		if err := os.WriteFile(path, nil, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := ensurePrivateTelemetrySource(root, path, uid, gid); err == nil {
			t.Fatal("wrong-mode telemetry source was accepted")
		}
	})

	t.Run("wrong owner", func(t *testing.T) {
		path := filepath.Join(directory, "owner.jsonl")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ensurePrivateTelemetrySource(root, path, uid+1, gid); err == nil {
			t.Fatal("wrong-owner telemetry source was accepted")
		}
	})

	t.Run("regular file", func(t *testing.T) {
		path := filepath.Join(directory, "regular.jsonl")
		if err := ensurePrivateTelemetrySource(root, path, uid, gid); err != nil {
			t.Fatalf("regular telemetry source error = %v", err)
		}
	})
}

func TestReadPrivateFileRejectsSpecialFilesPromptly(t *testing.T) {
	rejectPromptly := func(t *testing.T, path string) {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			_, _, err := readPrivateFile(path, 1<<20)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("special private file %q was accepted", path)
			}
		case <-time.After(250 * time.Millisecond):
			t.Fatalf("special private file %q blocked", path)
		}
	}

	root, err := os.MkdirTemp("/tmp", "cdnca-telemetry-read-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	t.Run("fifo replacement", func(t *testing.T) {
		path := filepath.Join(root, "manifest.json")
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		originalOpen := readPrivateOpen
		t.Cleanup(func() { readPrivateOpen = originalOpen })
		validated, open := make(chan struct{}), make(chan struct{})
		readPrivateOpen = func(path string, flag int, perm os.FileMode) (*os.File, error) {
			close(validated)
			<-open
			return os.OpenFile(path, flag, perm)
		}
		done := make(chan error, 1)
		go func() {
			_, _, err := readPrivateFile(path, 1<<20)
			done <- err
		}()
		<-validated
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		close(open)
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("post-validation FIFO replacement was accepted")
			}
		case <-time.After(250 * time.Millisecond):
			t.Fatal("post-validation FIFO replacement blocked descriptor open")
		}
	})
	t.Run("unix socket", func(t *testing.T) {
		path := filepath.Join(root, "manifest.sock")
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		rejectPromptly(t, path)
	})
	t.Run("device", func(t *testing.T) { rejectPromptly(t, "/dev/null") })
}

func TestTelemetryPrecheckRejectsCacheIdentityMismatchBeforeCreatingSources(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(edgeconfig.Bundle, map[string]any)
	}{
		{name: "tenant", mutate: func(_ edgeconfig.Bundle, manifest map[string]any) {
			manifest["tenant_id"] = "44444444-4444-4444-8444-444444444444"
		}},
		{name: "domain", mutate: func(_ edgeconfig.Bundle, manifest map[string]any) {
			manifest["sites"].([]any)[0].(map[string]any)["domain"] = "other.example.test"
		}},
		{name: "listen port", mutate: func(_ edgeconfig.Bundle, manifest map[string]any) {
			manifest["sites"].([]any)[0].(map[string]any)["listen_port"] = float64(18082)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := telemetrySecureRoot(t)
			bundle := telemetryBundle(t, root, "cfg-v1")
			bundle.Files = cloneTelemetryFiles(bundle.Files)
			original, err := edgeconfig.ParseTelemetryIdentityManifest(bundle.Files[edgeconfig.TelemetryIdentityManifestPath])
			if err != nil {
				t.Fatal(err)
			}
			var manifest map[string]any
			if err := json.Unmarshal(bundle.Files[edgeconfig.TelemetryIdentityManifestPath], &manifest); err != nil {
				t.Fatal(err)
			}
			test.mutate(bundle, manifest)
			content, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			bundle.Files[edgeconfig.TelemetryIdentityManifestPath] = append(content, '\n')
			release := filepath.Join(root, "releases", bundle.ManifestSHA256)
			writeTelemetryRelease(t, release, bundle)
			called := false
			prechecker, err := newTelemetryPrechecker(root, precheckFunc(func(context.Context, string, string) error {
				called = true
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if err := prechecker.Precheck(context.Background(), "cfg-v1", release); err == nil {
				t.Fatal("mismatched telemetry/cache identity was accepted")
			}
			if called {
				t.Fatal("OpenResty delegate ran after telemetry/cache identity rejection")
			}
			for _, site := range original.Sites {
				for _, path := range []string{site.AccessLogPath, site.SecurityLogPath} {
					if _, err := os.Lstat(path); !os.IsNotExist(err) {
						t.Fatalf("telemetry source was created before identity rejection: %v", err)
					}
				}
			}
		})
	}
}

func TestTelemetryPrecheckRejectsUnexpectedRuntimeOwnerBeforeCreatingSources(t *testing.T) {
	root := telemetrySecureRoot(t)
	bundle := telemetryBundle(t, root, "cfg-v1")
	release := filepath.Join(root, "releases", bundle.ManifestSHA256)
	writeTelemetryRelease(t, release, bundle)
	manifest, err := edgeconfig.ParseTelemetryIdentityManifest(bundle.Files[edgeconfig.TelemetryIdentityManifestPath])
	if err != nil {
		t.Fatal(err)
	}
	called := false
	prechecker, err := newTelemetryPrechecker(root, precheckFunc(func(context.Context, string, string) error {
		called = true
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	prechecker.ownerUID++
	if err := prechecker.Precheck(context.Background(), "cfg-v1", release); err == nil {
		t.Fatal("unexpected production runtime owner was accepted")
	}
	if called {
		t.Fatal("OpenResty delegate ran after runtime owner rejection")
	}
	for _, site := range manifest.Sites {
		for _, path := range []string{site.AccessLogPath, site.SecurityLogPath} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("telemetry source was created before owner rejection: %v", err)
			}
		}
	}
}

func TestTelemetrySourceRunnerTrustsOnlyActiveManifestAndOverwritesSourceIdentity(t *testing.T) {
	root := telemetrySecureRoot(t)
	spoolRoot := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(spoolRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	spoolRoot, err := filepath.EvalSymlinks(spoolRoot)
	if err != nil {
		t.Fatal(err)
	}
	bundle := telemetryBundle(t, root, "cfg-v1")
	release := filepath.Join(root, "releases", bundle.ManifestSHA256)
	writeTelemetryRelease(t, release, bundle)
	prechecker, err := newTelemetryPrechecker(root, precheckFunc(func(context.Context, string, string) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	if err := prechecker.Precheck(context.Background(), "cfg-v1", release); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("releases", bundle.ManifestSHA256), filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}

	spool, err := eventspool.New(eventspool.Config{
		Root: spoolRoot, MaxEventBytes: 64 << 10, MaxSegmentBytes: 1 << 20,
		SoftLimitBytes: 8 << 20, HardLimitBytes: 16 << 20, MaxTenantBytes: 12 << 20,
		MaxBatchEvents: 100, PressureMode: eventspool.PressureBackpressure,
		SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	runner, err := newTelemetrySourceRunner(telemetrySourceConfig{
		DeploymentRoot: root, SpoolRoot: spoolRoot, EnrollmentNodeID: telemetryTestNodeID,
		PollInterval: time.Millisecond, MaxLineBytes: 64 << 10, MaxBatchEvents: 100,
		MaxQuarantineBytes: 1 << 20,
	}, spool)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.syncOnce(context.Background()); err != nil {
		t.Fatalf("initial source sync error = %v", err)
	}

	manifest, err := edgeconfig.ParseTelemetryIdentityManifest(bundle.Files[edgeconfig.TelemetryIdentityManifestPath])
	if err != nil {
		t.Fatal(err)
	}
	line := map[string]any{
		"schema_version": 1, "type": "access.v1", "occurred_at": time.Now().UTC().Format(time.RFC3339Nano),
		"tenant_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "site_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		"node_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "config_version_id": "forged-config",
		"host": "www.example.test", "path": "/identity", "client_ip": "192.0.2.10",
		"method": "GET", "protocol": "HTTP/1.1", "cache_status": "MISS", "status_code": 200,
		"request_bytes": 10, "response_bytes": 20,
	}
	encoded, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eventspool.ParseSourceLineBound(encoded, eventspool.CapturePolicy{}, eventspool.TrustedIdentity{
		EnrollmentNodeID: telemetryTestNodeID, TenantID: telemetryTestTenantID,
		SiteID: telemetryTestSiteID, ConfigVersionID: "cfg-v1",
	}); err != nil {
		t.Fatalf("source fixture is invalid: %v: %s", err, encoded)
	}
	file, err := os.OpenFile(manifest.Sites[0].AccessLogPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runner.syncOnce(context.Background()); err != nil {
		t.Fatalf("tail source error = %v", err)
	}

	publisher := &capturePublication{}
	result, err := spool.Flush(context.Background(), publisher, 100)
	if err != nil || result.Published != 1 || len(publisher.publications) != 1 {
		t.Fatalf("Flush() = %+v, publications=%d, error=%v", result, len(publisher.publications), err)
	}
	var publication struct {
		TenantID string `json:"tenant_id"`
		NodeID   string `json:"node_id"`
		Events   []struct {
			TenantID      string `json:"tenant_id"`
			SiteID        string `json:"site_id"`
			NodeID        string `json:"node_id"`
			ConfigVersion string `json:"config_version_id"`
		} `json:"events"`
	}
	if err := json.Unmarshal(publisher.publications[0].Payload, &publication); err != nil {
		t.Fatal(err)
	}
	if publication.TenantID != telemetryTestTenantID || publication.NodeID != telemetryTestNodeID || len(publication.Events) != 1 ||
		publication.Events[0].TenantID != telemetryTestTenantID || publication.Events[0].SiteID != telemetryTestSiteID ||
		publication.Events[0].NodeID != telemetryTestNodeID || publication.Events[0].ConfigVersion != "cfg-v1" {
		t.Fatalf("authoritative publication identity = %+v", publication)
	}
	if _, err := os.Stat(filepath.Join(spoolRoot, "state", telemetrySourceRegistryName)); err != nil {
		t.Fatalf("active source registry was not persisted: %v", err)
	}
}

func telemetrySecureRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "deployments")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func telemetryBundle(t *testing.T, root, versionID string) edgeconfig.Bundle {
	return telemetryBundleWithRevision(t, root, versionID, 7)
}

// telemetryListener is one site listener of a telemetry fixture release.
type telemetryListener struct {
	domain  string
	port    uint16
	capture edgeconfig.TelemetryCapturePolicy
}

// telemetryBundleWithRevision is a site runtime release of one plain cached
// site (www.example.test:18081) as the node derives it: the signed telemetry
// identity control-api publishes and the cache identity the node compiles.
func telemetryBundleWithRevision(t *testing.T, root, versionID string, revision uint64) edgeconfig.Bundle {
	t.Helper()
	return telemetryReleaseBundle(t, root, versionID, revision, uuid.Nil.String(), telemetryListener{domain: "www.example.test", port: 18081})
}

// telemetryMultiPortBundle: the same site on two ports, each with its own
// capture policy.
func telemetryMultiPortBundle(t *testing.T, root, versionID string) edgeconfig.Bundle {
	t.Helper()
	return telemetryReleaseBundle(t, root, versionID, 7, uuid.Nil.String(),
		telemetryListener{domain: "www.example.test", port: 18081, capture: edgeconfig.TelemetryCapturePolicy{
			SchemaVersion: 1, Enabled: true, RequestHeaderAllowlist: []string{"X-First-Listener"}}},
		telemetryListener{domain: "www.example.test", port: 18082, capture: edgeconfig.TelemetryCapturePolicy{
			SchemaVersion: 1, Enabled: true, RequestBodyFieldAllowlist: []string{"clientSecret"}}})
}

// telemetryReleaseBundle builds the release files of telemetryTestSiteID's
// listeners; installationID "" or the nil UUID publishes none.
func telemetryReleaseBundle(t *testing.T, root, versionID string, revision uint64, installationID string,
	listeners ...telemetryListener) edgeconfig.Bundle {
	t.Helper()
	if installationID == uuid.Nil.String() {
		installationID = ""
	}
	nginx := []byte("# site runtime release " + versionID + "\n")
	manifest := edgeconfig.TelemetryIdentityManifest{
		SchemaVersion: 1, ConfigVersionID: versionID, ConfigRevision: revision, TenantID: telemetryTestTenantID,
		InstallationID:     installationID,
		CapturePolicy:      edgeconfig.TelemetryCapturePolicyManifest{SchemaVersion: 1},
		SourceCapabilities: edgeconfig.TelemetrySourceCapabilities{SchemaVersion: 1},
	}
	var cacheListeners []edgeconfig.CacheListenerPolicy
	for _, listener := range listeners {
		access, security := edgeconfig.TelemetryLogPaths(root, versionID, telemetryTestSiteID, listener.port)
		manifest.Sites = append(manifest.Sites, edgeconfig.TelemetrySiteIdentity{
			SiteID: telemetryTestSiteID, Domain: listener.domain, ListenPort: listener.port,
			NamespaceID:   edgeconfig.CacheSiteNamespaceID(telemetryTestTenantID, telemetryTestSiteID),
			AccessLogPath: access, SecurityLogPath: security,
		})
		capture := listener.capture
		policy := edgeconfig.TelemetrySiteCapturePolicy{SiteID: telemetryTestSiteID, Domain: listener.domain, ListenPort: listener.port,
			Revision: capture.Revision, EvidenceDigest: capture.EvidenceDigest, Enabled: capture.Enabled,
			Methods: []string{}, URIPrefixes: []string{}, RequestHeaderAllowlist: []string{}, ResponseHeaderAllowlist: []string{},
			RequestBodyFieldAllowlist: []string{}, ResponseBodyFieldAllowlist: []string{},
			MaxValueBytes: 4096, MaxBodyBytes: 64 << 10, MaxEventBytes: 1 << 20}
		policy.RequestHeaderAllowlist = append(policy.RequestHeaderAllowlist, capture.RequestHeaderAllowlist...)
		policy.RequestBodyFieldAllowlist = append(policy.RequestBodyFieldAllowlist, capture.RequestBodyFieldAllowlist...)
		manifest.CapturePolicy.Sites = append(manifest.CapturePolicy.Sites, policy)
		renderer, err := edgeconfig.NewSiteCacheRenderer(versionID, filepath.Join(root, "shared"), telemetryTestSiteID, 0,
			[]string{listener.domain}, false, edgeconfig.SiteRuntimeCache{TenantID: telemetryTestTenantID, Domain: listener.domain,
				Policy: edgeconfig.CachePolicyDocument{Revision: 1, Mode: edgeconfig.CacheFollowOrigin, QueryMode: edgeconfig.CacheQueryPreserve,
					Rules: []edgeconfig.CacheRuleDocument{}, QueryNames: []string{}, VaryHeaders: []string{}, DiskQuotaBytes: 64 << 20},
				SharedAcrossDomains: true})
		if err != nil {
			t.Fatal(err)
		}
		cacheListeners = append(cacheListeners, renderer.ManifestListener(edgeconfig.SiteRuntimeCacheListener{Port: listener.port}, 18080))
	}
	identity, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	identity = append(identity, '\n')
	if _, err := edgeconfig.ParseTelemetryIdentityManifest(identity); err != nil {
		t.Fatalf("telemetry fixture identity: %v", err)
	}
	files := map[string][]byte{"nginx.conf": nginx, edgeconfig.TelemetryIdentityManifestPath: identity}
	if revision != 0 {
		cache, err := edgeconfig.SiteRuntimeCacheManifest(versionID, revision, telemetryTestTenantID, nginx, cacheListeners)
		if err != nil {
			t.Fatal(err)
		}
		files[edgeconfig.CachePolicyManifestPath] = cache
		files[edgeconfig.CachePolicyKeyModulePath] = edgeconfig.CachePolicyKeyModule()
	}
	// The derived release (what the precheck reads), content addressed.
	manifestFiles := make([]edgeconfig.FileManifest, 0, len(files))
	for path, content := range files {
		digest := sha256.Sum256(content)
		manifestFiles = append(manifestFiles, edgeconfig.FileManifest{Path: path, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])})
	}
	normalized, err := edgeconfig.NormalizeManifest(edgeconfig.Manifest{Files: manifestFiles})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := edgeconfig.ManifestDigest(normalized)
	if err != nil {
		t.Fatal(err)
	}
	return edgeconfig.Bundle{Manifest: normalized, ManifestSHA256: digest, Files: files}
}

func cloneTelemetryFiles(files map[string][]byte) map[string][]byte {
	clone := make(map[string][]byte, len(files))
	for path, content := range files {
		clone[path] = append([]byte(nil), content...)
	}
	return clone
}

func writeTelemetryRelease(t *testing.T, release string, bundle edgeconfig.Bundle) {
	t.Helper()
	if err := os.MkdirAll(release, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, content := range bundle.Files {
		target := filepath.Join(release, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := deployment.ManifestDigest(bundle.Manifest); err != nil {
		t.Fatalf("bundle manifest error = %v", err)
	}
}
