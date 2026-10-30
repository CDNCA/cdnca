package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeo"
)

func TestOBS07AnalyticsGeoArtifactConfigDefaultsDisabledAndRejectsResidue(t *testing.T) {
	fixture := newOBS07GeoRuntimeFixture(t)
	config, err := loadAnalyticsGeoArtifactRuntimeConfigFromEnv(fixture.environment())
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || config.PublisherKeyID != "geo-production-current" ||
		config.PublisherPrivateKeyFile != fixture.privateKeyFile || config.LoaderKeyringFile != fixture.keyringFile ||
		config.SourceCatalogFile != fixture.sourceFile || config.ArtifactDirectory != fixture.artifactDirectory ||
		config.MaxSourceBytes != 1<<20 || config.MaxCatalogs != 4 || config.MaxEntriesPerCatalog != 100 ||
		config.MaxCatalogBytes != 1<<20 || config.MaxArtifactBytes != 2<<20 || config.PollInterval != 10*time.Millisecond {
		t.Fatalf("runtime config = %+v", config)
	}
	disabled, err := loadAnalyticsGeoArtifactRuntimeConfigFromEnv(nil)
	if err != nil || disabled.Enabled {
		t.Fatalf("default config = (%+v, %v)", disabled, err)
	}

	for _, test := range []struct {
		name        string
		environment []string
	}{
		{name: "disabled residue", environment: []string{
			analyticsGeoArtifactEnabledEnv + "=false", analyticsGeoArtifactDirectoryEnv + "=" + fixture.artifactDirectory,
		}},
		{name: "implicit disabled residue", environment: []string{
			analyticsGeoArtifactDirectoryEnv + "=" + fixture.artifactDirectory,
		}},
		{name: "non canonical boolean", environment: []string{analyticsGeoArtifactEnabledEnv + "=TRUE"}},
		{name: "unknown variable", environment: append(fixture.environment(), "ANALYTICS_GEO_ARTIFACT_UNKNOWN=x")},
		{name: "duplicate variable", environment: append(fixture.environment(), analyticsGeoArtifactEnabledEnv+"=true")},
		{name: "relative source", environment: replaceOBS07Environment(fixture.environment(), analyticsGeoArtifactSourceFileEnv, "catalog.json")},
		{name: "non canonical capacity", environment: replaceOBS07Environment(fixture.environment(), analyticsGeoArtifactMaxCatalogsEnv, "04")},
		{name: "unsafe poll", environment: replaceOBS07Environment(fixture.environment(), analyticsGeoArtifactPollIntervalEnv, "1ms")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := loadAnalyticsGeoArtifactRuntimeConfigFromEnv(test.environment); err == nil {
				t.Fatal("invalid runtime configuration was accepted")
			}
		})
	}
}

func TestOBS07AnalyticsGeoArtifactRuntimePublishesPollsAndRetainsLKG(t *testing.T) {
	fixture := newOBS07GeoRuntimeFixture(t)
	config, err := loadAnalyticsGeoArtifactRuntimeConfigFromEnv(fixture.environment())
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := openAnalyticsGeoArtifactRuntime(t.Context(), config,
		analyticsGeoArtifactRuntimeDependencies{Now: fixture.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	reader := runtime.Reader()
	if reader == nil || runtime.Ready() != nil || runtime.BackgroundError() != nil {
		t.Fatalf("initial runtime reader=%v ready=%v background=%v", reader, runtime.Ready(), runtime.BackgroundError())
	}
	initial := lookupOBS07Geo(t, reader, 1, analyticsgeo.AuthorityStateActive, analyticsgeo.AuthorityReasonNone)
	if initial.Attribution.Carrier != "initial-carrier" {
		t.Fatalf("initial lookup = %#v", initial)
	}
	artifactPath := activeOBS07ArtifactPath(t, runtime)
	artifactInfo, err := os.Lstat(artifactPath)
	if err != nil || artifactInfo.Mode().Perm() != 0o600 || !artifactInfo.Mode().IsRegular() {
		t.Fatalf("durable artifact metadata = (%v, %v)", artifactInfo, err)
	}

	fixture.writeSource(2, "upgraded-carrier", fixture.clock.Now().Add(time.Hour))
	waitOBS07GeoRevision(t, runtime, 2, "upgraded-carrier")
	artifactPath = activeOBS07ArtifactPath(t, runtime)
	stableBytes, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	stableDigest := sha256.Sum256(stableBytes)

	fixture.writeSource(1, "rollback-carrier", fixture.clock.Now().Add(time.Hour))
	waitOBS07BackgroundError(t, runtime)
	assertOBS07ArtifactDigest(t, artifactPath, stableDigest)
	lookupOBS07Geo(t, reader, 2, analyticsgeo.AuthorityStateLKG, analyticsgeo.AuthorityReasonArtifactRejected)

	fixture.writeSource(3, "expired-carrier", fixture.clock.Now())
	waitOBS07BackgroundError(t, runtime)
	assertOBS07ArtifactDigest(t, artifactPath, stableDigest)
	lookupOBS07Geo(t, reader, 2, analyticsgeo.AuthorityStateLKG, analyticsgeo.AuthorityReasonArtifactRejected)

	writeOBS07File(t, fixture.sourceFile, []byte("{not-json"), 0o600)
	waitOBS07BackgroundError(t, runtime)
	assertOBS07ArtifactDigest(t, artifactPath, stableDigest)
	lookupOBS07Geo(t, reader, 2, analyticsgeo.AuthorityStateLKG, analyticsgeo.AuthorityReasonArtifactRejected)

	fixture.writeSource(3, "recovered-carrier", fixture.clock.Now().Add(time.Hour))
	waitOBS07GeoRevision(t, runtime, 3, "recovered-carrier")
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if runtime.privateKey != nil || runtime.store != nil || runtime.release != nil || runtime.Ready() == nil {
		t.Fatalf("closed runtime retained state: key=%d store=%v release=%v ready=%v",
			len(runtime.privateKey), runtime.store, runtime.release, runtime.Ready())
	}
	if _, err := reader.Lookup(t.Context(), "geo-current", netip.MustParseAddr("203.0.113.7")); !errors.Is(err, analyticsgeo.ErrAuthorityUnavailable) {
		t.Fatalf("closed reader error = %v", err)
	}
}

func TestOBS07AnalyticsGeoArtifactRuntimeRestartUsesVerifiedDurableLKGAndRejectsUnsafeFiles(t *testing.T) {
	fixture := newOBS07GeoRuntimeFixture(t)
	config, err := loadAnalyticsGeoArtifactRuntimeConfigFromEnv(fixture.environment())
	if err != nil {
		t.Fatal(err)
	}
	first, err := openAnalyticsGeoArtifactRuntime(t.Context(), config,
		analyticsGeoArtifactRuntimeDependencies{Now: fixture.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	writeOBS07File(t, fixture.sourceFile, []byte("corrupt-source"), 0o600)
	restarted, err := openAnalyticsGeoArtifactRuntime(t.Context(), config,
		analyticsGeoArtifactRuntimeDependencies{Now: fixture.clock.Now})
	if err != nil {
		t.Fatalf("restart with durable LKG error = %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if restarted.Ready() != nil || restarted.BackgroundError() == nil {
		t.Fatalf("restart ready=%v background=%v", restarted.Ready(), restarted.BackgroundError())
	}
	lookupOBS07Geo(t, restarted.Reader(), 1, analyticsgeo.AuthorityStateLKG,
		analyticsgeo.AuthorityReasonArtifactRejected)

	unsafeFixture := newOBS07GeoRuntimeFixture(t)
	unsafeConfig, err := loadAnalyticsGeoArtifactRuntimeConfigFromEnv(unsafeFixture.environment())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeFixture.privateKeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openAnalyticsGeoArtifactRuntime(t.Context(), unsafeConfig,
		analyticsGeoArtifactRuntimeDependencies{Now: unsafeFixture.clock.Now}); err == nil {
		t.Fatal("group-readable private key was accepted")
	}
	if err := os.Chmod(unsafeFixture.privateKeyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	realKeyring := unsafeFixture.keyringFile
	linkedKeyring := filepath.Join(filepath.Dir(realKeyring), "linked-keyring.json")
	if err := os.Symlink(realKeyring, linkedKeyring); err != nil {
		t.Fatal(err)
	}
	unsafeConfig.LoaderKeyringFile = linkedKeyring
	if _, err := openAnalyticsGeoArtifactRuntime(t.Context(), unsafeConfig,
		analyticsGeoArtifactRuntimeDependencies{Now: unsafeFixture.clock.Now}); err == nil {
		t.Fatal("symlink keyring was accepted")
	}
}

func TestOBS07AnalyticsGeoArtifactRuntimePersistsReleaseIdentityAndBoundedClose(t *testing.T) {
	fixture := newOBS07GeoRuntimeFixture(t)
	config, err := loadAnalyticsGeoArtifactRuntimeConfigFromEnv(fixture.environment())
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := openAnalyticsGeoArtifactRuntime(t.Context(), config,
		analyticsGeoArtifactRuntimeDependencies{Now: fixture.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	if runtime.store == nil || runtime.release == nil {
		t.Fatal("durable release store/runtime was not mounted")
	}
	state, err := runtime.store.State(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if state.Active.Revision != 1 || state.Active.CatalogVersion != "geo-current" ||
		state.Active.Source.Provider != "local-file" || state.Active.Source.SHA256 == "" || state.LKG != nil {
		t.Fatalf("initial release state = %#v", state)
	}

	fixture.writeSource(2, "upgraded-carrier", fixture.clock.Now().Add(time.Hour))
	waitOBS07GeoRevision(t, runtime, 2, "upgraded-carrier")
	state, err = runtime.store.State(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if state.Active.Revision != 2 || state.LKG == nil || state.LKG.Revision != 1 {
		t.Fatalf("upgraded release state = %#v", state)
	}

	blocked := &analyticsGeoArtifactRuntime{
		cancel:       func() {},
		done:         make(chan struct{}),
		closeTimeout: 10 * time.Millisecond,
	}
	started := time.Now()
	if err := blocked.Close(); !errors.Is(err, errAnalyticsGeoArtifactCloseTimeout) {
		t.Fatalf("bounded Close() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("bounded Close() elapsed = %v", elapsed)
	}
	if err := blocked.Close(); err != nil {
		t.Fatalf("idempotent Close() error = %v", err)
	}
	close(blocked.done)
}

type obs07GeoRuntimeFixture struct {
	clock             *obs07GeoClock
	privateKeyFile    string
	keyringFile       string
	sourceFile        string
	artifactDirectory string
}

func newOBS07GeoRuntimeFixture(t *testing.T) *obs07GeoRuntimeFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	privateKeyFile := filepath.Join(root, "publisher-key.pem")
	keyringFile := filepath.Join(root, "loader-keyring.json")
	sourceFile := filepath.Join(root, "source-catalog.json")
	artifactDirectory := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifactDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPrivate, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	writeOBS07File(t, privateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPrivate}), 0o600)
	keyring, err := json.Marshal(map[string]any{
		"schema": "cdnca.analytics-geo-keyring/v1",
		"current": map[string]any{
			"key_id": "geo-production-current", "public_key_base64": base64.StdEncoding.EncodeToString(publicKey),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeOBS07File(t, keyringFile, keyring, 0o600)
	fixture := &obs07GeoRuntimeFixture{clock: &obs07GeoClock{now: time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)},
		privateKeyFile: privateKeyFile, keyringFile: keyringFile,
		sourceFile: sourceFile, artifactDirectory: artifactDirectory}
	fixture.writeSource(1, "initial-carrier", fixture.clock.Now().Add(time.Hour))
	return fixture
}

func (fixture *obs07GeoRuntimeFixture) environment() []string {
	return []string{
		analyticsGeoArtifactEnabledEnv + "=true",
		analyticsGeoArtifactPublisherKeyIDEnv + "=geo-production-current",
		analyticsGeoArtifactPublisherPrivateKeyFileEnv + "=" + fixture.privateKeyFile,
		analyticsGeoArtifactLoaderKeyringFileEnv + "=" + fixture.keyringFile,
		analyticsGeoArtifactSourceFileEnv + "=" + fixture.sourceFile,
		analyticsGeoArtifactDirectoryEnv + "=" + fixture.artifactDirectory,
		analyticsGeoArtifactMaxSourceBytesEnv + "=1048576",
		analyticsGeoArtifactMaxCatalogsEnv + "=4",
		analyticsGeoArtifactMaxEntriesEnv + "=100",
		analyticsGeoArtifactMaxCatalogBytesEnv + "=1048576",
		analyticsGeoArtifactMaxArtifactBytesEnv + "=2097152",
		analyticsGeoArtifactPollIntervalEnv + "=10ms",
	}
}

func (fixture *obs07GeoRuntimeFixture) writeSource(revision uint64, carrier string, expiresAt time.Time) {
	source, err := json.Marshal(map[string]any{
		"schema":                  "cdnca.analytics-geo-source/v1",
		"revision":                revision,
		"issued_at":               fixture.clock.Now().Format(time.RFC3339Nano),
		"expires_at":              expiresAt.Format(time.RFC3339Nano),
		"current_catalog_version": "geo-current",
		"address_policy":          "allow_non_public",
		"catalogs": []map[string]any{{
			"version": "geo-current",
			"entries": []map[string]any{{
				"prefix": "203.0.113.0/24", "country_code": "CN", "region": "CN-SH",
				"carrier": carrier, "asn": 64512,
			}},
		}},
	})
	if err != nil {
		panic(err)
	}
	writeOBS07File(nil, fixture.sourceFile, source, 0o600)
}

func writeOBS07File(t *testing.T, path string, data []byte, mode os.FileMode) {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, mode); err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	if err := os.Chmod(temporary, mode); err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	if err := os.Rename(temporary, path); err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
}

func replaceOBS07Environment(environment []string, name, value string) []string {
	result := append([]string(nil), environment...)
	for index, entry := range result {
		if strings.HasPrefix(entry, name+"=") {
			result[index] = name + "=" + value
		}
	}
	return result
}

func lookupOBS07Geo(t *testing.T, reader analyticsgeo.AuthorityReader, revision uint64,
	state analyticsgeo.AuthorityState, reason analyticsgeo.AuthorityReason) analyticsgeo.AuthorityLookup {
	t.Helper()
	result, err := reader.Lookup(t.Context(), "geo-current", netip.MustParseAddr("203.0.113.7"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != revision || result.State != state || result.Reason != reason {
		t.Fatalf("geo lookup = %#v", result)
	}
	return result
}

func waitOBS07GeoRevision(t *testing.T, runtime *analyticsGeoArtifactRuntime, revision uint64, carrier string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		result, err := runtime.Reader().Lookup(t.Context(), "geo-current", netip.MustParseAddr("203.0.113.7"))
		if err == nil && result.Revision == revision && result.Attribution.Carrier == carrier &&
			result.State == analyticsgeo.AuthorityStateActive && runtime.BackgroundError() == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("revision %d carrier %q was not installed; background=%v", revision, carrier, runtime.BackgroundError())
}

func waitOBS07BackgroundError(t *testing.T, runtime *analyticsGeoArtifactRuntime) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.BackgroundError() != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("background rejection was not reported")
}

func assertOBS07ArtifactDigest(t *testing.T, path string, want [sha256.Size]byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(data); got != want {
		t.Fatalf("durable artifact digest changed: got=%x want=%x", got, want)
	}
}

func activeOBS07ArtifactPath(t *testing.T, runtime *analyticsGeoArtifactRuntime) string {
	t.Helper()
	state, err := runtime.store.State(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return runtime.store.ArtifactTrigger(state.Active).Path
}

type obs07GeoClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *obs07GeoClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}
