package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderlive"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

const (
	livePrefix = "CDNCA_DNS_LIVE_"

	envAck              = livePrefix + "MUTATION_ACK"
	envZone             = livePrefix + "ZONE"
	envGuardOwner       = livePrefix + "GUARD_OWNER"
	envGuardSHA256      = livePrefix + "GUARD_SHA256"
	envAuthoritative    = livePrefix + "AUTHORITATIVE_ENDPOINTS_JSON"
	envPublic           = livePrefix + "PUBLIC_RESOLVERS_JSON"
	envTimeout          = livePrefix + "TIMEOUT_SECONDS"
	envCleanupTimeout   = livePrefix + "CLEANUP_TIMEOUT_SECONDS"
	envEvidencePath     = livePrefix + "EVIDENCE_PATH"
	requiredMutationAck = "dedicated-disposable-zone"

	reasonConfigRejected        = "config_rejected"
	reasonCredentialUnavailable = "credential_unavailable"
	reasonEvidenceWriteFailed   = "evidence_write_failed"

	minimumTimeoutSeconds = 60
	maximumTimeoutSeconds = 1800
)

var errConfigRejected = errors.New(reasonConfigRejected)

type providerDefinition struct {
	code string
	env  string
}

var providerDefinitions = [...]providerDefinition{
	{code: "cloudflare", env: "CLOUDFLARE"},
	{code: "aliyun", env: "ALIYUN"},
	{code: "huawei", env: "HUAWEI"},
	{code: "dnspod_cn", env: "DNSPOD_CN"},
	{code: "dns_com", env: "DNS_COM"},
	{code: "dns_la", env: "DNS_LA"},
}

type cliConfig struct {
	run          dnsproviderlive.Config
	provider     providerDefinition
	service      string
	account      string
	evidencePath string
}

type runtimeDependencies struct {
	keychain dnsproviderlive.KeychainReader
	execute  func(context.Context, cliConfig, *dnsproviderlive.CredentialLease) dnsproviderlive.Evidence
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code, reason := run(ctx, os.Args[1:], os.Environ(), runtimeDependencies{
		keychain: dnsproviderlive.ReadKeychain,
		execute:  executeLive,
	})
	_, _ = fmt.Fprintln(os.Stderr, reason)
	return code
}

func run(ctx context.Context, args, environment []string, dependencies runtimeDependencies) (int, string) {
	if ctx == nil || len(args) != 0 || dependencies.keychain == nil || dependencies.execute == nil {
		return 2, reasonConfigRejected
	}
	config, err := parseConfig(environment)
	if err != nil {
		return 2, reasonConfigRejected
	}
	if config.provider.code == "huawei" {
		return 2, reasonConfigRejected
	}
	lease, err := dnsproviderlive.LoadCredential(
		dependencies.keychain, config.provider.code, config.service, config.account,
	)
	if err != nil {
		if writeErr := dnsproviderlive.WriteEvidence(config.evidencePath, failureEvidence(config)); writeErr != nil {
			return 3, reasonEvidenceWriteFailed
		}
		return 3, reasonCredentialUnavailable
	}
	defer lease.Close()

	evidence := dependencies.execute(ctx, config, lease)
	lease.Close()
	verified := evidence.Status == dnsproviderlive.StatusPass &&
		evidence.Reason == dnsproviderlive.ReasonVerified &&
		evidence.Phase == dnsproviderlive.PhaseComplete &&
		evidence.CleanupAttempted && evidence.CleanupComplete
	if evidence.Status == dnsproviderlive.StatusPass && !verified {
		evidence.Status = dnsproviderlive.StatusFail
		evidence.Reason = dnsproviderlive.ReasonInvalidConfig
		evidence.Phase = dnsproviderlive.PhaseConfig
	}
	if err := dnsproviderlive.WriteEvidence(config.evidencePath, evidence); err != nil {
		return 4, reasonEvidenceWriteFailed
	}
	if verified {
		return 0, evidence.Reason
	}
	if evidence.Reason == "" {
		return 1, dnsproviderlive.ReasonInvalidConfig
	}
	return 1, evidence.Reason
}

func parseConfig(environment []string) (cliConfig, error) {
	values, present, err := parseEnvironment(environment)
	if err != nil || values[envAck] != requiredMutationAck {
		return cliConfig{}, errConfigRejected
	}

	var selected *providerDefinition
	for index := range providerDefinitions {
		definition := &providerDefinitions[index]
		enabledName := providerPrefix(definition.env) + "_ENABLED"
		enabled, exists := values[enabledName]
		if exists && enabled != "0" && enabled != "1" {
			return cliConfig{}, errConfigRejected
		}
		if enabled == "1" {
			if selected != nil {
				return cliConfig{}, errConfigRejected
			}
			selected = definition
		}
	}
	if selected == nil {
		return cliConfig{}, errConfigRejected
	}

	serviceName := providerPrefix(selected.env) + "_KEYCHAIN_SERVICE"
	accountName := providerPrefix(selected.env) + "_KEYCHAIN_ACCOUNT"
	service, servicePresent := values[serviceName]
	account, accountPresent := values[accountName]
	if !servicePresent || !accountPresent || !validAlias(service) || !validAlias(account) {
		return cliConfig{}, errConfigRejected
	}
	for _, definition := range providerDefinitions {
		if definition.code == selected.code {
			continue
		}
		if present[providerPrefix(definition.env)+"_KEYCHAIN_SERVICE"] ||
			present[providerPrefix(definition.env)+"_KEYCHAIN_ACCOUNT"] {
			return cliConfig{}, errConfigRejected
		}
	}

	zone := values[envZone]
	guardOwner := values[envGuardOwner]
	if !validDNSName(zone, false, false) || !validDNSName(guardOwner, true, true) ||
		!strings.HasSuffix(guardOwner, "."+zone+".") {
		return cliConfig{}, errConfigRejected
	}
	guardDigest, err := parseDigest(values[envGuardSHA256])
	if err != nil {
		return cliConfig{}, errConfigRejected
	}
	seenEndpoints := make(map[netip.AddrPort]struct{})
	authoritative, err := parseEndpoints(values[envAuthoritative], seenEndpoints)
	if err != nil {
		return cliConfig{}, errConfigRejected
	}
	public, err := parseEndpoints(values[envPublic], seenEndpoints)
	if err != nil {
		return cliConfig{}, errConfigRejected
	}
	timeout, err := parseTimeout(values[envTimeout])
	if err != nil {
		return cliConfig{}, errConfigRejected
	}
	cleanupTimeout, err := parseTimeout(values[envCleanupTimeout])
	if err != nil {
		return cliConfig{}, errConfigRejected
	}
	evidencePath := values[envEvidencePath]
	if !validEvidencePath(evidencePath) {
		return cliConfig{}, errConfigRejected
	}
	for _, required := range []string{
		envZone, envGuardOwner, envGuardSHA256, envAuthoritative, envPublic,
		envTimeout, envCleanupTimeout, envEvidencePath,
	} {
		if !present[required] {
			return cliConfig{}, errConfigRejected
		}
	}
	return cliConfig{
		run: dnsproviderlive.Config{
			ProviderCode: selected.code, Zone: zone, GuardOwner: guardOwner,
			GuardSHA256: guardDigest, Authoritative: authoritative, Public: public,
			Timeout: timeout, CleanupTimeout: cleanupTimeout,
		},
		provider: *selected, service: service, account: account, evidencePath: evidencePath,
	}, nil
}

func parseEnvironment(environment []string) (map[string]string, map[string]bool, error) {
	allowed := map[string]struct{}{
		envAck: {}, envZone: {}, envGuardOwner: {}, envGuardSHA256: {},
		envAuthoritative: {}, envPublic: {}, envTimeout: {}, envCleanupTimeout: {}, envEvidencePath: {},
	}
	for _, definition := range providerDefinitions {
		prefix := providerPrefix(definition.env)
		allowed[prefix+"_ENABLED"] = struct{}{}
		allowed[prefix+"_KEYCHAIN_SERVICE"] = struct{}{}
		allowed[prefix+"_KEYCHAIN_ACCOUNT"] = struct{}{}
	}
	values := make(map[string]string, len(environment))
	present := make(map[string]bool, len(environment))
	for _, item := range environment {
		separator := strings.IndexByte(item, '=')
		if separator <= 0 {
			return nil, nil, errConfigRejected
		}
		name, value := item[:separator], item[separator+1:]
		if present[name] {
			return nil, nil, errConfigRejected
		}
		present[name] = true
		values[name] = value
		if strings.HasPrefix(name, livePrefix) {
			if _, ok := allowed[name]; !ok {
				return nil, nil, errConfigRejected
			}
		}
	}
	return values, present, nil
}

func providerPrefix(provider string) string {
	return livePrefix + provider
}

func parseDigest(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if len(value) != hex.EncodedLen(len(result)) || value != strings.ToLower(value) {
		return result, errConfigRejected
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		zero(decoded)
		return result, errConfigRejected
	}
	copy(result[:], decoded)
	zero(decoded)
	if result == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, errConfigRejected
	}
	return result, nil
}

func parseEndpoints(document string, seen map[netip.AddrPort]struct{}) ([]dnsproviderlive.Endpoint, error) {
	if document == "" || len(document) > 65535 || seen == nil {
		return nil, errConfigRejected
	}
	decoder := json.NewDecoder(bytes.NewBufferString(document))
	var raw []string
	if err := decoder.Decode(&raw); err != nil || len(raw) == 0 || len(raw) > 64 {
		return nil, errConfigRejected
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errConfigRejected
	}
	result := make([]dnsproviderlive.Endpoint, 0, len(raw))
	for _, value := range raw {
		address, err := netip.ParseAddrPort(value)
		if err != nil || address.String() != value || address.Port() == 0 ||
			address.Addr().IsUnspecified() || address.Addr().IsMulticast() {
			return nil, errConfigRejected
		}
		if _, duplicate := seen[address]; duplicate {
			return nil, errConfigRejected
		}
		seen[address] = struct{}{}
		result = append(result, dnsproviderlive.Endpoint{Address: address})
	}
	return result, nil
}

func parseTimeout(value string) (time.Duration, error) {
	seconds, err := strconv.Atoi(value)
	if err != nil || strconv.Itoa(seconds) != value || seconds < minimumTimeoutSeconds || seconds > maximumTimeoutSeconds {
		return 0, errConfigRejected
	}
	return time.Duration(seconds) * time.Second, nil
}

func validEvidencePath(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || containsControl(path) {
		return false
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil || !parent.IsDir() {
		return false
	}
	info, err := os.Lstat(path)
	if err == nil {
		return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
	}
	return errors.Is(err, os.ErrNotExist)
}

func validAlias(value string) bool {
	return value != "" && len(value) <= 256 && value == strings.TrimSpace(value) && utf8.ValidString(value) && !containsControl(value)
}

func validDNSName(value string, trailingDot, allowUnderscore bool) bool {
	if value == "" || value != strings.ToLower(value) || !utf8.ValidString(value) || containsControl(value) {
		return false
	}
	if trailingDot {
		if !strings.HasSuffix(value, ".") {
			return false
		}
		value = strings.TrimSuffix(value, ".")
	} else if strings.HasSuffix(value, ".") {
		return false
	}
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
				character == '-' || (allowUnderscore && character == '_') {
				continue
			}
			return false
		}
	}
	return true
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}

func failureEvidence(config cliConfig) dnsproviderlive.Evidence {
	return dnsproviderlive.Evidence{
		Schema: dnsproviderlive.EvidenceSchema, Status: dnsproviderlive.StatusFail,
		Reason: dnsproviderlive.ReasonInvalidConfig, Phase: dnsproviderlive.PhaseConfig,
		ProviderCode: config.provider.code, AuthoritativeCount: len(config.run.Authoritative),
		PublicCount: len(config.run.Public),
	}
}

func executeLive(ctx context.Context, config cliConfig, lease *dnsproviderlive.CredentialLease) dnsproviderlive.Evidence {
	if lease == nil || len(lease.Values) == 0 {
		return failureEvidence(config)
	}
	tenantID, scopeID, providerID, zoneID, ok := randomLiveAuthority(rand.Reader)
	if !ok {
		return failureEvidence(config)
	}
	config.run.TenantID = tenantID
	config.run.ScopeID = scopeID
	config.run.ProviderID = providerID
	config.run.ZoneID = zoneID
	source := &dedicatedSource{
		tenantID: config.run.TenantID, scopeID: config.run.ScopeID, providerID: config.run.ProviderID,
		zoneID: zoneID, providerCode: config.provider.code, zone: config.run.Zone,
		credentials: cloneCredentialViews(lease.Values),
	}
	defer source.clear()

	handleSecret := make([]byte, sha256.Size)
	if _, err := io.ReadFull(rand.Reader, handleSecret); err != nil {
		zero(handleSecret)
		return failureEvidence(config)
	}
	keyring, err := dnsproviderremote.NewHandleKeyring(dnsproviderremote.HandleKey{
		ID: "dns_live_ephemeral_v1", Secret: handleSecret,
	})
	zero(handleSecret)
	if err != nil {
		return failureEvidence(config)
	}
	provider, err := dnsproviderremote.Open(ctx, source, keyring)
	if err != nil {
		return failureEvidence(config)
	}
	evidence := dnsproviderlive.Run(ctx, config.run, provider, dnsproviderlive.NewWireDNS(), wallClock{}, rand.Reader)
	runtime.KeepAlive(lease)
	return evidence
}

type dedicatedSource struct {
	tenantID     uuid.UUID
	scopeID      uuid.UUID
	providerID   uuid.UUID
	zoneID       uuid.UUID
	providerCode string
	zone         string
	credentials  map[string]string
}

func (s *dedicatedSource) Resolve(ctx context.Context, lookup dnsproviderremote.ProviderLookup) (dnsproviderremote.ProviderConfig, error) {
	if err := ctx.Err(); err != nil {
		return dnsproviderremote.ProviderConfig{}, err
	}
	if s == nil || s.tenantID == uuid.Nil || s.scopeID == uuid.Nil || s.tenantID == s.scopeID ||
		s.providerID == uuid.Nil || s.zoneID == uuid.Nil || lookup.TenantID != s.tenantID || lookup.ScopeID != s.scopeID ||
		lookup.ProviderID != s.providerID || lookup.ZoneID != s.zoneID || !validOwnerForZone(lookup.OwnerName, s.zone) || len(s.credentials) == 0 {
		return dnsproviderremote.ProviderConfig{}, errors.New("dns_live_source_unavailable")
	}
	return dnsproviderremote.ProviderConfig{
		TenantID: s.tenantID, ScopeID: s.scopeID, TenantScopeID: s.scopeID,
		ProviderID: s.providerID, ProviderType: s.providerCode,
		ZoneID: s.zoneID, ZoneName: s.zone, Credentials: s.cloneCredentialViews(),
	}, nil
}

func (*dedicatedSource) OutstandingRemoteTXTHandles(context.Context) ([]acmeworker.ChallengeIdentity, error) {
	return []acmeworker.ChallengeIdentity{}, nil
}

func (s *dedicatedSource) cloneCredentialViews() map[string]string {
	if s == nil {
		return nil
	}
	return cloneCredentialViews(s.credentials)
}

func (s *dedicatedSource) clear() {
	if s != nil {
		clearCredentialViews(s.credentials)
		s.credentials = nil
	}
}

func cloneCredentialViews(credentials map[string]string) map[string]string {
	result := make(map[string]string, len(credentials))
	for name, value := range credentials {
		result[name] = value
	}
	return result
}

func clearCredentialViews(credentials map[string]string) {
	for name := range credentials {
		credentials[name] = ""
		delete(credentials, name)
	}
}

func validOwnerForZone(owner, zone string) bool {
	return validDNSName(owner, true, true) && validDNSName(zone, false, false) &&
		(owner == zone+"." || strings.HasSuffix(owner, "."+zone+"."))
}

func randomLiveAuthority(reader io.Reader) (tenantID, scopeID, providerID, zoneID uuid.UUID, ok bool) {
	tenantID = randomUUID(reader)
	scopeID = randomUUID(reader)
	providerID = randomUUID(reader)
	zoneID = randomUUID(reader)
	ok = tenantID != uuid.Nil && scopeID != uuid.Nil && tenantID != scopeID && providerID != uuid.Nil && zoneID != uuid.Nil
	return
}

func randomUUID(reader io.Reader) uuid.UUID {
	value := make([]byte, 16)
	if _, err := io.ReadFull(reader, value); err != nil {
		zero(value)
		return uuid.Nil
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	result, err := uuid.FromBytes(value)
	zero(value)
	if err != nil {
		return uuid.Nil
	}
	return result
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func (wallClock) Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ dnsproviderremote.StartupSource = (*dedicatedSource)(nil)
var _ dnsproviderlive.Provider = (*dnsproviderremote.Adapter)(nil)
var _ dnsproviderlive.Clock = wallClock{}
