package l4runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type v2LifecycleRuntime struct {
	fakeRuntime
	healthVersions []string
	failHealth     string
}

func (*v2LifecycleRuntime) Healthy(_ context.Context, config Config) error {
	_, err := Compile(config)
	return err
}
func (*v2LifecycleRuntime) Drain(context.Context, time.Duration) error { return nil }
func (r *v2LifecycleRuntime) HealthyV2(_ context.Context, config ConfigV2) error {
	r.healthVersions = append(r.healthVersions, config.VersionID)
	if config.VersionID == r.failHealth {
		return errInjectedRuntime
	}
	_, err := CanonicalV2(config)
	return err
}

func v2LifecycleConfig(t *testing.T, version string, source, resource int64) ConfigV2 {
	t.Helper()
	spec := l403StreamSpec()
	spec.Revision, spec.Geo.Revision = resource, resource
	config, err := AggregateStreamRuntimeSpecsV2(version, source, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestV2SourceAndResourceRevisionsRemainDistinct(t *testing.T) {
	config := v2LifecycleConfig(t, "source-9", 9, 3)
	if config.Revision != 9 || config.Listeners[0].ResourceRevision != 3 || config.Listeners[0].Geo.Revision != 3 {
		t.Fatalf("revisions collapsed: %+v", config)
	}
	compiled, err := CompileV2(config, map[string][]netip.Addr{l403Stream: {netip.MustParseAddr("8.8.8.8")}})
	if err != nil || !bytes.Contains(compiled.GeoJSON, []byte(`"resource_revision":3`)) {
		t.Fatalf("scoped geo config = %s, %v", compiled.GeoJSON, err)
	}
	config.Listeners[0].Geo.Revision = 9
	if _, err := CanonicalV2(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Geo bound to source instead of resource: %v", err)
	}
	legacy := v2LifecycleConfig(t, "legacy", 3, 3)
	before, err := CompileV2(legacy, map[string][]netip.Addr{l403Stream: {netip.MustParseAddr("8.8.8.8")}})
	if err != nil {
		t.Fatal(err)
	}
	legacy.Listeners[0].ResourceRevision = 3
	after, err := CompileV2(legacy, before.ResolvedAddressSets)
	if err != nil || after.Digest != before.Digest || !bytes.Equal(before.GeoJSON, after.GeoJSON) ||
		!bytes.Equal(before.CanonicalJSON, after.CanonicalJSON) || bytes.Contains(after.CanonicalJSON, []byte("resource_revision")) {
		t.Fatalf("equal revision changed legacy canonical bytes: %v", err)
	}
}

func TestV2LegacyCompiledBytesRemainIdentical(t *testing.T) {
	// Captured from f0c2ff341e0935924164abdf90d78242bce0c639 before this change;
	// repinned at tcp/udp v12 (l4-decouple): the stream ID now fills the
	// former site slot (geo, nginx variables, telemetry path). nginx repinned
	// for L4-USAGE-01: every TCP socket tracks live sessions and the log
	// lines carry $pid; canonical, Geo and runtime bytes are unchanged.
	compiled, err := CompileV2(v2LifecycleConfig(t, "legacy", 3, 3), map[string][]netip.Addr{l403Stream: {netip.MustParseAddr("8.8.8.8")}})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := encodeStoredRuntimeV2(compiled)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		bytes []byte
		hash  string
	}{
		{"canonical", compiled.CanonicalJSON, "d3d65b95f9b1fa98d554217ca54826451f382d5a46a73b0e8981fbe082563c5b"},
		{"geo", compiled.GeoJSON, "e41616bca4acd091c1d2fac7fb6591ac97e3e8747b3d2075303fbf8333704d52"},
		// The master-side Geo preload directive is the only addition since then.
		{"nginx", bytes.Replace(compiled.NginxConfig, []byte(geoPreloadDirectiveV2), nil, 1), "efc201a5bfd2a50f571abef908c9be4fd0b457aeb31dc84c6542f88c25327fae"},
		{"nginx-preload", compiled.NginxConfig, "d62a70b8c9badbc78180f8b21322253dd23c03806cc2df6957df3fce9f4298af"},
		{"runtime", stored, "41364e7e4e7865393f0059fc68704eeb8d9a530839f4d695b001e3935e8b6369"},
	} {
		if got := fmt.Sprintf("%x", sha256.Sum256(test.bytes)); got != test.hash {
			t.Fatalf("legacy %s digest changed: %s", test.name, got)
		}
	}
	if compiled.Digest != "4ebd8b1c784d00e82696da93620cb1cbe84b296b75592fbacd34c05dcc37c0a9" {
		t.Fatalf("legacy snapshot digest changed: %s", compiled.Digest)
	}
}

func TestV2ReleaseRecoveryWithNoPreviousRuntime(t *testing.T) {
	runtime := &v2LifecycleRuntime{}
	manager, root := testManager(t, runtime)
	if err := manager.BeginRelease(context.Background(), "initial"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), Config{SchemaVersion: SchemaVersionV1, VersionID: "initial"}); err != nil {
		t.Fatal(err)
	}
	restarted, err := newManager(root, runtime, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	status, err := restarted.Status()
	if err != nil || status.Active || len(runtime.stopCalls) != 1 {
		t.Fatalf("unconfirmed initial release survived: %+v %v stops=%v", status, err, runtime.stopCalls)
	}
	if _, err := os.Lstat(filepath.Join(root, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unconfirmed current retained: %v", err)
	}
}

func TestV2DNSBindsResourceAndFencesSourceRevision(t *testing.T) {
	resolver := &l403Resolver{results: []DNSLookupResult{{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, TTL: time.Minute}}}
	dns, err := NewDNSCoordinator(t.TempDir(), resolver, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []int64{9, 10} {
		config := v2LifecycleConfig(t, "resource-3", source, 3)
		resolved, err := dns.Resolve(context.Background(), config, l403Stream)
		if err != nil || resolved.Revision != 3 {
			t.Fatalf("source %d DNS resource binding = %+v, %v", source, resolved, err)
		}
	}
	for _, config := range []ConfigV2{v2LifecycleConfig(t, "stale-source", 9, 4), v2LifecycleConfig(t, "stale-resource", 11, 2)} {
		if _, err := dns.Resolve(context.Background(), config, l403Stream); !errors.Is(err, ErrConflict) {
			t.Fatalf("DNS accepted stale revision: %+v, %v", config, err)
		}
	}
}

func TestV2ReplayRollbackAndReleaseRecoveryUsePersistedDNSDigest(t *testing.T) {
	ctx := context.Background()
	runtime := &v2LifecycleRuntime{}
	manager, root := testManager(t, runtime)
	now := fixedTime()
	resolver := &l403Resolver{results: []DNSLookupResult{
		{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, TTL: time.Minute},
		{Addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, TTL: time.Minute},
	}}
	dns, err := NewDNSCoordinator(filepath.Join(root, "dns"), resolver, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	firstConfig := v2LifecycleConfig(t, "first", 9, 3)
	first, err := manager.ApplyV2(ctx, firstConfig, dns)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if err := manager.PrecheckV2(ctx, firstConfig, nil); err != nil {
		t.Fatalf("rollback precheck required live DNS: %v", err)
	}
	replay, err := manager.ApplyV2(ctx, firstConfig, dns)
	if err != nil || replay.Digest != first.Digest || resolver.callCount() != 1 {
		t.Fatalf("replay resolved DNS or changed digest: %+v, %v calls=%d", replay, err, resolver.callCount())
	}
	secondConfig := v2LifecycleConfig(t, "second", 10, 4)
	second, err := manager.ApplyV2(ctx, secondConfig, dns)
	if err != nil {
		t.Fatal(err)
	}
	rolledBack, err := manager.Rollback(ctx, first.VersionID, first.Digest)
	if err != nil || rolledBack.Digest != first.Digest || resolver.callCount() != 2 {
		t.Fatalf("v2 rollback failed: %+v, %v calls=%d", rolledBack, err, resolver.callCount())
	}
	if err := manager.BeginRelease(ctx, second.VersionID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApplyV2(ctx, secondConfig, dns); err != nil {
		t.Fatal(err)
	}
	// Crash after L4 activation, before enclosing HTTP health confirmation.
	restarted, err := newManager(root, runtime, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	status, err := restarted.Status()
	if err != nil || status.VersionID != first.VersionID || status.Digest != first.Digest || resolver.callCount() != 2 {
		t.Fatalf("uncertain release did not restore actual baseline: %+v, %v", status, err)
	}
	if err := restarted.FinishRelease(ctx, second.VersionID, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("health certified reverted L4 candidate: %v", err)
	}
	if got := runtime.healthVersions[len(runtime.healthVersions)-1]; got != first.VersionID {
		t.Fatalf("restore did not use v2 health: %v", runtime.healthVersions)
	}
	content, err := os.ReadFile(filepath.Join(root, "current", "nginx.conf"))
	if err != nil || !strings.Contains(string(content), "server 8.8.8.8:443") {
		t.Fatalf("restored DNS differs: %s, %v", content, err)
	}
}

func TestOpenRestyV2HealthVerifiesOwnedWorkersWithoutV1Compilation(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "nginx.pid")
	identity := testProcessIdentity(t, 43)
	writeProcessFixture(t, pidFile, identity)
	runtime := testOpenResty(t, pidFile)
	runtime.openProcess = func(int) (processHandle, error) { return &fakeProcessHandle{alive: []bool{true}}, nil }
	runtime.inspect = func(int) (processIdentity, error) { return identity, nil }
	config := v2LifecycleConfig(t, "source-9", 9, 3)
	if err := runtime.HealthyV2(context.Background(), config); err != nil {
		t.Fatalf("valid V2 owned worker health rejected: %v", err)
	}
	runtime.workerGeneration = func(processIdentity) (workerGeneration, error) { return nil, nil }
	if err := runtime.HealthyV2(context.Background(), config); !errors.Is(err, ErrActivation) {
		t.Fatalf("V2 health accepted missing worker generation: %v", err)
	}
}

func TestV2HealthFailureRestoresV2Baseline(t *testing.T) {
	runtime := &v2LifecycleRuntime{}
	manager, _ := testManager(t, runtime)
	dns, err := NewDNSCoordinator(t.TempDir(), &l403Resolver{results: []DNSLookupResult{{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, TTL: time.Minute}}}, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.ApplyV2(context.Background(), v2LifecycleConfig(t, "healthy", 9, 3), dns)
	if err != nil {
		t.Fatal(err)
	}
	runtime.failHealth = "unhealthy"
	if _, err := manager.ApplyV2(context.Background(), v2LifecycleConfig(t, "unhealthy", 10, 4), dns); !errors.Is(err, ErrActivation) {
		t.Fatalf("unhealthy V2 succeeded: %v", err)
	}
	status, err := manager.Status()
	if err != nil || status.VersionID != first.VersionID || status.Digest != first.Digest {
		t.Fatalf("V2 health failure did not preserve LKG: %+v %v", status, err)
	}
}
