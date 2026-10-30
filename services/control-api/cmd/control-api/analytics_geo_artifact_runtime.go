package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeo"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeoartifact"
	"golang.org/x/sys/unix"
)

const (
	analyticsGeoArtifactEnabledEnv                 = "ANALYTICS_GEO_ARTIFACT_ENABLED"
	analyticsGeoArtifactPublisherKeyIDEnv          = "ANALYTICS_GEO_ARTIFACT_PUBLISHER_KEY_ID"
	analyticsGeoArtifactPublisherPrivateKeyFileEnv = "ANALYTICS_GEO_ARTIFACT_PUBLISHER_PRIVATE_KEY_FILE"
	analyticsGeoArtifactLoaderKeyringFileEnv       = "ANALYTICS_GEO_ARTIFACT_LOADER_KEYRING_FILE"
	analyticsGeoArtifactSourceFileEnv              = "ANALYTICS_GEO_ARTIFACT_SOURCE_CATALOG_FILE"
	analyticsGeoArtifactDirectoryEnv               = "ANALYTICS_GEO_ARTIFACT_DIRECTORY"
	analyticsGeoArtifactMaxSourceBytesEnv          = "ANALYTICS_GEO_ARTIFACT_MAX_SOURCE_BYTES"
	analyticsGeoArtifactMaxCatalogsEnv             = "ANALYTICS_GEO_ARTIFACT_MAX_CATALOGS"
	analyticsGeoArtifactMaxEntriesEnv              = "ANALYTICS_GEO_ARTIFACT_MAX_ENTRIES_PER_CATALOG"
	analyticsGeoArtifactMaxCatalogBytesEnv         = "ANALYTICS_GEO_ARTIFACT_MAX_CATALOG_BYTES"
	analyticsGeoArtifactMaxArtifactBytesEnv        = "ANALYTICS_GEO_ARTIFACT_MAX_ARTIFACT_BYTES"
	analyticsGeoArtifactPollIntervalEnv            = "ANALYTICS_GEO_ARTIFACT_POLL_INTERVAL"

	analyticsGeoArtifactSourceSchema    = "cdnca.analytics-geo-source/v1"
	analyticsGeoArtifactKeyringSchema   = "cdnca.analytics-geo-keyring/v1"
	analyticsGeoArtifactMaximumFile     = 180 << 20
	analyticsGeoArtifactMaximumCatalogs = 16
	analyticsGeoArtifactMaximumEntries  = 100_000
	analyticsGeoArtifactCloseTimeout    = 5 * time.Second
)

var (
	errAnalyticsGeoArtifactConfiguration = errors.New("analytics geo artifact runtime configuration invalid")
	errAnalyticsGeoArtifactSource        = errors.New("analytics geo artifact source rejected")
	errAnalyticsGeoArtifactClosed        = errors.New("analytics geo artifact runtime closed")
	errAnalyticsGeoArtifactCloseTimeout  = errors.New("analytics geo artifact runtime close timed out")
)

type analyticsGeoArtifactRuntimeConfig struct {
	Enabled                 bool
	PublisherKeyID          string
	PublisherPrivateKeyFile string
	LoaderKeyringFile       string
	SourceCatalogFile       string
	ArtifactDirectory       string
	MaxSourceBytes          int
	MaxCatalogs             int
	MaxEntriesPerCatalog    int
	MaxCatalogBytes         int
	MaxArtifactBytes        int
	PollInterval            time.Duration
}

type analyticsGeoArtifactRuntimeDependencies struct {
	Now func() time.Time
}

type analyticsGeoArtifactRuntime struct {
	mu            sync.RWMutex
	refreshMu     sync.Mutex
	config        analyticsGeoArtifactRuntimeConfig
	now           func() time.Time
	privateKey    ed25519.PrivateKey
	compiler      *analyticsgeoartifact.Compiler
	store         *analyticsgeoartifact.ReleaseStore
	release       *analyticsgeoartifact.ReleaseRuntime
	backgroundErr error
	rejected      bool
	expiresAt     time.Time
	cancel        context.CancelFunc
	done          chan struct{}
	closeTimeout  time.Duration
	closed        bool
}

type analyticsGeoArtifactKeyDocument struct {
	Schema   string                            `json:"schema"`
	Current  analyticsGeoArtifactKeyReference  `json:"current"`
	Previous *analyticsGeoArtifactKeyReference `json:"previous,omitempty"`
}

type analyticsGeoArtifactKeyReference struct {
	KeyID           string `json:"key_id"`
	PublicKeyBase64 string `json:"public_key_base64"`
}

type analyticsGeoArtifactSourceDocument struct {
	Schema                string                              `json:"schema"`
	Revision              uint64                              `json:"revision"`
	IssuedAt              string                              `json:"issued_at"`
	ExpiresAt             string                              `json:"expires_at"`
	CurrentCatalogVersion string                              `json:"current_catalog_version"`
	AddressPolicy         analyticsgeoartifact.AddressPolicy  `json:"address_policy"`
	Catalogs              []analyticsGeoArtifactSourceCatalog `json:"catalogs"`
}

type analyticsGeoArtifactSourceCatalog struct {
	Version string                                  `json:"version"`
	Entries []analyticsGeoArtifactSourceCatalogFact `json:"entries"`
}

type analyticsGeoArtifactSourceCatalogFact struct {
	Prefix      string `json:"prefix"`
	CountryCode string `json:"country_code"`
	Region      string `json:"region"`
	Carrier     string `json:"carrier"`
	ASN         uint32 `json:"asn"`
}

func loadAnalyticsGeoArtifactRuntimeConfig() (analyticsGeoArtifactRuntimeConfig, error) {
	return loadAnalyticsGeoArtifactRuntimeConfigFromEnv(os.Environ())
}

func loadAnalyticsGeoArtifactRuntimeConfigFromEnv(environment []string) (analyticsGeoArtifactRuntimeConfig, error) {
	allowed := map[string]struct{}{
		analyticsGeoArtifactEnabledEnv: {}, analyticsGeoArtifactPublisherKeyIDEnv: {},
		analyticsGeoArtifactPublisherPrivateKeyFileEnv: {}, analyticsGeoArtifactLoaderKeyringFileEnv: {},
		analyticsGeoArtifactSourceFileEnv: {}, analyticsGeoArtifactDirectoryEnv: {},
		analyticsGeoArtifactMaxSourceBytesEnv: {}, analyticsGeoArtifactMaxCatalogsEnv: {},
		analyticsGeoArtifactMaxEntriesEnv: {}, analyticsGeoArtifactMaxCatalogBytesEnv: {},
		analyticsGeoArtifactMaxArtifactBytesEnv: {}, analyticsGeoArtifactPollIntervalEnv: {},
	}
	values, err := runtimeEnvEntries(environment, "ANALYTICS_GEO_ARTIFACT_", allowed)
	if err != nil {
		return analyticsGeoArtifactRuntimeConfig{}, err
	}
	enabled, err := strictRuntimeBool(values, analyticsGeoArtifactEnabledEnv)
	if err != nil {
		return analyticsGeoArtifactRuntimeConfig{}, err
	}
	if !enabled {
		if len(values) > 1 || len(values) == 1 && values[analyticsGeoArtifactEnabledEnv] != "false" {
			return analyticsGeoArtifactRuntimeConfig{}, errors.New("analytics geo artifact configuration is invalid while disabled")
		}
		return analyticsGeoArtifactRuntimeConfig{}, nil
	}
	if len(values) != len(allowed) {
		return analyticsGeoArtifactRuntimeConfig{}, errAnalyticsGeoArtifactConfiguration
	}
	paths := []string{
		values[analyticsGeoArtifactPublisherPrivateKeyFileEnv], values[analyticsGeoArtifactLoaderKeyringFileEnv],
		values[analyticsGeoArtifactSourceFileEnv], values[analyticsGeoArtifactDirectoryEnv],
	}
	for _, path := range paths {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return analyticsGeoArtifactRuntimeConfig{}, errAnalyticsGeoArtifactConfiguration
		}
	}
	maxSource, err := analyticsGeoArtifactInteger(values, analyticsGeoArtifactMaxSourceBytesEnv, 1, analyticsGeoArtifactMaximumFile)
	if err != nil {
		return analyticsGeoArtifactRuntimeConfig{}, err
	}
	maxCatalogs, err := analyticsGeoArtifactInteger(values, analyticsGeoArtifactMaxCatalogsEnv, 1, analyticsGeoArtifactMaximumCatalogs)
	if err != nil {
		return analyticsGeoArtifactRuntimeConfig{}, err
	}
	maxEntries, err := analyticsGeoArtifactInteger(values, analyticsGeoArtifactMaxEntriesEnv, 1, analyticsGeoArtifactMaximumEntries)
	if err != nil {
		return analyticsGeoArtifactRuntimeConfig{}, err
	}
	maxCatalogBytes, err := analyticsGeoArtifactInteger(values, analyticsGeoArtifactMaxCatalogBytesEnv, 1, 128<<20)
	if err != nil {
		return analyticsGeoArtifactRuntimeConfig{}, err
	}
	maxArtifactBytes, err := analyticsGeoArtifactInteger(values, analyticsGeoArtifactMaxArtifactBytesEnv, 1, analyticsGeoArtifactMaximumFile)
	if err != nil || maxArtifactBytes < maxCatalogBytes {
		return analyticsGeoArtifactRuntimeConfig{}, errAnalyticsGeoArtifactConfiguration
	}
	pollInterval, err := time.ParseDuration(values[analyticsGeoArtifactPollIntervalEnv])
	if err != nil || pollInterval < 10*time.Millisecond || pollInterval > time.Hour ||
		pollInterval.String() != values[analyticsGeoArtifactPollIntervalEnv] {
		return analyticsGeoArtifactRuntimeConfig{}, errAnalyticsGeoArtifactConfiguration
	}
	keyID := values[analyticsGeoArtifactPublisherKeyIDEnv]
	if keyID == "" || strings.TrimSpace(keyID) != keyID {
		return analyticsGeoArtifactRuntimeConfig{}, errAnalyticsGeoArtifactConfiguration
	}
	return analyticsGeoArtifactRuntimeConfig{
		Enabled: true, PublisherKeyID: keyID,
		PublisherPrivateKeyFile: values[analyticsGeoArtifactPublisherPrivateKeyFileEnv],
		LoaderKeyringFile:       values[analyticsGeoArtifactLoaderKeyringFileEnv],
		SourceCatalogFile:       values[analyticsGeoArtifactSourceFileEnv], ArtifactDirectory: values[analyticsGeoArtifactDirectoryEnv],
		MaxSourceBytes: maxSource, MaxCatalogs: maxCatalogs, MaxEntriesPerCatalog: maxEntries,
		MaxCatalogBytes: maxCatalogBytes, MaxArtifactBytes: maxArtifactBytes, PollInterval: pollInterval,
	}, nil
}

func openAnalyticsGeoArtifactRuntime(ctx context.Context, config analyticsGeoArtifactRuntimeConfig,
	dependencies analyticsGeoArtifactRuntimeDependencies) (*analyticsGeoArtifactRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	if ctx == nil || dependencies.Now == nil || config.PublisherKeyID == "" || config.PollInterval < 10*time.Millisecond ||
		config.MaxSourceBytes <= 0 || config.MaxCatalogs <= 0 || config.MaxEntriesPerCatalog <= 0 ||
		config.MaxCatalogBytes <= 0 || config.MaxArtifactBytes < config.MaxCatalogBytes {
		return nil, errAnalyticsGeoArtifactConfiguration
	}
	if err := analyticsGeoArtifactValidateDirectory(config.ArtifactDirectory); err != nil {
		return nil, err
	}
	privateKey, err := analyticsGeoArtifactLoadPrivateKey(config.PublisherPrivateKeyFile)
	if err != nil {
		return nil, err
	}
	keyring, trustedKeys, currentPublicKey, err := analyticsGeoArtifactLoadKeyring(
		config.LoaderKeyringFile, config.PublisherKeyID,
	)
	if err != nil || !bytes.Equal(privateKey.Public().(ed25519.PublicKey), currentPublicKey) {
		clear(privateKey)
		return nil, errAnalyticsGeoArtifactConfiguration
	}
	compiler, err := analyticsgeoartifact.NewCompiler(analyticsgeoartifact.CompilerConfig{
		KeyID: config.PublisherKeyID, PrivateKey: privateKey, MaxCatalogs: config.MaxCatalogs,
		MaxEntriesPerCatalog: config.MaxEntriesPerCatalog, MaxCatalogBytes: config.MaxCatalogBytes,
		MaxArtifactBytes: config.MaxArtifactBytes,
	})
	if err != nil {
		clear(privateKey)
		return nil, errAnalyticsGeoArtifactConfiguration
	}
	now := func() time.Time { return dependencies.Now().UTC().Truncate(time.Millisecond) }
	store, err := analyticsgeoartifact.NewReleaseStore(analyticsgeoartifact.ReleaseStoreConfig{
		Directory: config.ArtifactDirectory, MaxArtifactBytes: int64(config.MaxArtifactBytes),
		Now: now, TrustedKeys: trustedKeys,
	})
	if err != nil {
		clear(privateKey)
		return nil, err
	}
	loader, err := analyticsgeo.NewSignedFileLoader(analyticsgeo.SignedFileLoaderConfig{
		Keyring: keyring, Now: now, MaxArtifactBytes: int64(config.MaxArtifactBytes),
		MaxAggregateCatalogBytes: config.MaxCatalogBytes,
	})
	if err != nil {
		clear(privateKey)
		return nil, errAnalyticsGeoArtifactConfiguration
	}
	release, err := analyticsgeoartifact.NewReleaseRuntime(store, loader)
	if err != nil {
		clear(privateKey)
		return nil, errAnalyticsGeoArtifactConfiguration
	}
	runtime := &analyticsGeoArtifactRuntime{
		config: config, now: now, privateKey: privateKey, compiler: compiler,
		store: store, release: release, done: make(chan struct{}), closeTimeout: analyticsGeoArtifactCloseTimeout,
	}
	if err := runtime.refresh(ctx); err != nil {
		if fallbackErr := runtime.loadDurableLKG(ctx); fallbackErr != nil {
			runtime.clear()
			return nil, err
		}
		runtime.backgroundErr, runtime.rejected = err, true
	}
	runContext, cancel := context.WithCancel(context.Background())
	runtime.cancel = cancel
	go runtime.run(runContext)
	return runtime, nil
}

func (runtime *analyticsGeoArtifactRuntime) Reader() analyticsgeo.AuthorityReader {
	if runtime == nil {
		return nil
	}
	return runtime
}

func (runtime *analyticsGeoArtifactRuntime) Lookup(ctx context.Context, version string,
	address netip.Addr) (analyticsgeo.AuthorityLookup, error) {
	if runtime == nil || ctx == nil {
		return analyticsgeo.AuthorityLookup{}, analyticsgeo.ErrAuthorityUnavailable
	}
	runtime.mu.RLock()
	if runtime.closed || runtime.release == nil {
		runtime.mu.RUnlock()
		return analyticsgeo.AuthorityLookup{}, analyticsgeo.ErrAuthorityUnavailable
	}
	release, rejected := runtime.release, runtime.rejected
	runtime.mu.RUnlock()
	result, err := release.Lookup(ctx, version, address)
	if err == nil && rejected && result.State == analyticsgeo.AuthorityStateActive {
		result.State, result.Reason = analyticsgeo.AuthorityStateLKG, analyticsgeo.AuthorityReasonArtifactRejected
	}
	return result, err
}

func (runtime *analyticsGeoArtifactRuntime) Ready() error {
	if runtime == nil {
		return errAnalyticsGeoArtifactClosed
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if runtime.closed || runtime.release == nil || runtime.expiresAt.IsZero() || !runtime.now().Before(runtime.expiresAt) {
		return errAnalyticsGeoArtifactClosed
	}
	return nil
}

func (runtime *analyticsGeoArtifactRuntime) BackgroundError() error {
	if runtime == nil {
		return errAnalyticsGeoArtifactClosed
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if runtime.closed {
		return errAnalyticsGeoArtifactClosed
	}
	return runtime.backgroundErr
}

func (runtime *analyticsGeoArtifactRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	if runtime.closed {
		runtime.mu.Unlock()
		return nil
	}
	runtime.closed = true
	cancel, done := runtime.cancel, runtime.done
	runtime.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if cancel == nil {
		runtime.clear()
		return nil
	}
	timeout := runtime.closeTimeout
	if timeout <= 0 {
		timeout = analyticsGeoArtifactCloseTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errAnalyticsGeoArtifactCloseTimeout
	}
}

func (runtime *analyticsGeoArtifactRuntime) run(ctx context.Context) {
	defer func() {
		runtime.clear()
		close(runtime.done)
	}()
	ticker := time.NewTicker(runtime.config.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := runtime.refresh(ctx)
			runtime.mu.Lock()
			if err != nil {
				runtime.backgroundErr, runtime.rejected = err, true
			} else {
				runtime.backgroundErr, runtime.rejected = nil, false
			}
			runtime.mu.Unlock()
		}
	}
}

func (runtime *analyticsGeoArtifactRuntime) refresh(ctx context.Context) error {
	runtime.refreshMu.Lock()
	defer runtime.refreshMu.Unlock()
	request, sourceSHA256, err := analyticsGeoArtifactLoadSource(
		ctx, runtime.config.SourceCatalogFile, runtime.config.MaxSourceBytes,
	)
	if err != nil {
		return errAnalyticsGeoArtifactSource
	}
	now := runtime.now()
	if now.Location() != time.UTC || request.IssuedAt.After(now) || !request.ExpiresAt.After(now) {
		return errAnalyticsGeoArtifactSource
	}
	artifact, err := runtime.compiler.Compile(ctx, request)
	if err != nil {
		return errAnalyticsGeoArtifactSource
	}
	if len(artifact.SHA256) < 16 {
		return errAnalyticsGeoArtifactSource
	}
	state, err := runtime.release.Activate(ctx, analyticsgeoartifact.ReleaseRequest{
		ReleaseID: "geo-" + strconv.FormatUint(artifact.Revision, 10) + "-" + artifact.SHA256[:16],
		Artifact:  artifact,
		Source: analyticsgeoartifact.SourceRef{
			Provider: "local-file", Version: request.CurrentCatalogVersion, SHA256: sourceSHA256,
		},
	})
	if err != nil {
		return errAnalyticsGeoArtifactSource
	}
	runtime.mu.Lock()
	runtime.expiresAt = state.Active.ExpiresAt
	runtime.mu.Unlock()
	return nil
}

func (runtime *analyticsGeoArtifactRuntime) loadDurableLKG(ctx context.Context) error {
	if err := runtime.release.Load(ctx); err != nil {
		return err
	}
	state, err := runtime.store.State(ctx)
	if err != nil {
		return err
	}
	runtime.expiresAt = state.Active.ExpiresAt
	return nil
}

func (runtime *analyticsGeoArtifactRuntime) clear() {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	clear(runtime.privateKey)
	runtime.privateKey = nil
	runtime.compiler = nil
	runtime.store = nil
	runtime.release = nil
	runtime.backgroundErr = nil
	runtime.cancel = nil
}

func analyticsGeoArtifactInteger(values map[string]string, name string, minimum, maximum int) (int, error) {
	raw := values[name]
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum || strconv.Itoa(value) != raw {
		return 0, errAnalyticsGeoArtifactConfiguration
	}
	return value, nil
}

func analyticsGeoArtifactLoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	encoded, err := analyticsGeoArtifactReadOwnerFile(context.Background(), path, 16<<10)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errAnalyticsGeoArtifactConfiguration
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errAnalyticsGeoArtifactConfiguration
	}
	result := bytes.Clone(privateKey)
	clear(privateKey)
	return result, nil
}

func analyticsGeoArtifactLoadKeyring(path, currentKeyID string) (analyticsgeo.TrustedEd25519Keyring,
	map[string]ed25519.PublicKey, ed25519.PublicKey, error) {
	encoded, err := analyticsGeoArtifactReadOwnerFile(context.Background(), path, 16<<10)
	if err != nil {
		return analyticsgeo.TrustedEd25519Keyring{}, nil, nil, err
	}
	if rejectDuplicateJSONKeys(string(encoded)) != nil {
		return analyticsgeo.TrustedEd25519Keyring{}, nil, nil, errAnalyticsGeoArtifactConfiguration
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var document analyticsGeoArtifactKeyDocument
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		document.Schema != analyticsGeoArtifactKeyringSchema || document.Current.KeyID != currentKeyID {
		return analyticsgeo.TrustedEd25519Keyring{}, nil, nil, errAnalyticsGeoArtifactConfiguration
	}
	keys := make(map[string]ed25519.PublicKey, 2)
	current, err := analyticsGeoArtifactDecodePublicKey(document.Current)
	if err != nil {
		return analyticsgeo.TrustedEd25519Keyring{}, nil, nil, err
	}
	keys[document.Current.KeyID] = current
	if document.Previous != nil {
		previous, err := analyticsGeoArtifactDecodePublicKey(*document.Previous)
		if err != nil || document.Previous.KeyID == document.Current.KeyID {
			return analyticsgeo.TrustedEd25519Keyring{}, nil, nil, errAnalyticsGeoArtifactConfiguration
		}
		keys[document.Previous.KeyID] = previous
	}
	keyring, err := analyticsgeo.NewTrustedEd25519Keyring(keys)
	if err != nil {
		return analyticsgeo.TrustedEd25519Keyring{}, nil, nil, errAnalyticsGeoArtifactConfiguration
	}
	return keyring, keys, current, nil
}

func analyticsGeoArtifactDecodePublicKey(reference analyticsGeoArtifactKeyReference) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(reference.PublicKeyBase64)
	if err != nil || len(decoded) != ed25519.PublicKeySize ||
		base64.StdEncoding.EncodeToString(decoded) != reference.PublicKeyBase64 || reference.KeyID == "" {
		return nil, errAnalyticsGeoArtifactConfiguration
	}
	return ed25519.PublicKey(decoded), nil
}

func analyticsGeoArtifactLoadSource(ctx context.Context, path string,
	maximum int) (analyticsgeoartifact.CompileRequest, string, error) {
	encoded, err := analyticsGeoArtifactReadOwnerFile(ctx, path, int64(maximum))
	if err != nil || rejectDuplicateJSONKeys(string(encoded)) != nil {
		return analyticsgeoartifact.CompileRequest{}, "", errAnalyticsGeoArtifactSource
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var document analyticsGeoArtifactSourceDocument
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		document.Schema != analyticsGeoArtifactSourceSchema {
		return analyticsgeoartifact.CompileRequest{}, "", errAnalyticsGeoArtifactSource
	}
	issuedAt, issuedErr := time.Parse(time.RFC3339Nano, document.IssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, document.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || issuedAt.Format(time.RFC3339Nano) != document.IssuedAt ||
		expiresAt.Format(time.RFC3339Nano) != document.ExpiresAt {
		return analyticsgeoartifact.CompileRequest{}, "", errAnalyticsGeoArtifactSource
	}
	catalogs := make([]analyticsgeoartifact.CatalogFacts, len(document.Catalogs))
	for catalogIndex, catalog := range document.Catalogs {
		catalogs[catalogIndex].Version = catalog.Version
		catalogs[catalogIndex].Entries = make([]analyticsgeoartifact.Fact, len(catalog.Entries))
		for factIndex, fact := range catalog.Entries {
			catalogs[catalogIndex].Entries[factIndex] = analyticsgeoartifact.Fact{
				Prefix: fact.Prefix, CountryCode: fact.CountryCode, Region: fact.Region,
				Carrier: fact.Carrier, ASN: fact.ASN,
			}
		}
	}
	digest := sha256.Sum256(encoded)
	return analyticsgeoartifact.CompileRequest{Revision: document.Revision, IssuedAt: issuedAt, ExpiresAt: expiresAt,
		CurrentCatalogVersion: document.CurrentCatalogVersion, AddressPolicy: document.AddressPolicy,
		Catalogs: catalogs}, hex.EncodeToString(digest[:]), nil
}

func analyticsGeoArtifactReadOwnerFile(ctx context.Context, path string, maximum int64) ([]byte, error) {
	if ctx == nil || maximum < 1 || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		analyticsGeoArtifactRejectSymlinks(path) != nil {
		return nil, errAnalyticsGeoArtifactConfiguration
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errAnalyticsGeoArtifactConfiguration
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errAnalyticsGeoArtifactConfiguration
	}
	defer file.Close()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 ||
		before.Uid != uint32(os.Geteuid()) || before.Mode&0o077 != 0 || before.Mode&0o400 == 0 ||
		before.Size < 1 || before.Size > maximum {
		return nil, errAnalyticsGeoArtifactConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		clear(data)
		return nil, errAnalyticsGeoArtifactConfiguration
	}
	var after, pathStat unix.Stat_t
	if unix.Fstat(fd, &after) != nil || unix.Lstat(path, &pathStat) != nil ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Dev != pathStat.Dev || before.Ino != pathStat.Ino {
		clear(data)
		return nil, errAnalyticsGeoArtifactConfiguration
	}
	return data, nil
}

func analyticsGeoArtifactValidateDirectory(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		analyticsGeoArtifactRejectSymlinks(path) != nil {
		return errAnalyticsGeoArtifactConfiguration
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errAnalyticsGeoArtifactConfiguration
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) ||
		stat.Mode&0o077 != 0 {
		return errAnalyticsGeoArtifactConfiguration
	}
	return nil
}

func analyticsGeoArtifactRejectSymlinks(path string) error {
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, current), current) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return errAnalyticsGeoArtifactConfiguration
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if filepath.Dir(current) != string(filepath.Separator) {
				return errAnalyticsGeoArtifactConfiguration
			}
			target, err := os.Stat(current)
			if err != nil || !target.IsDir() {
				return errAnalyticsGeoArtifactConfiguration
			}
		}
	}
	return nil
}
