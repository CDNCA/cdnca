package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderlive"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

func TestParseConfigAcceptsExactlyOneOfSixProviders(t *testing.T) {
	providers := []struct {
		code string
		env  string
	}{
		{code: "cloudflare", env: "CLOUDFLARE"},
		{code: "aliyun", env: "ALIYUN"},
		{code: "huawei", env: "HUAWEI"},
		{code: "dnspod_cn", env: "DNSPOD_CN"},
		{code: "dns_com", env: "DNS_COM"},
		{code: "dns_la", env: "DNS_LA"},
	}
	for _, provider := range providers {
		provider := provider
		t.Run(provider.code, func(t *testing.T) {
			environment := validEnvironment(t, provider.env)
			config, err := parseConfig(environment)
			if err != nil {
				t.Fatalf("parseConfig() error=%v", err)
			}
			if config.provider.code != provider.code || config.run.ProviderCode != provider.code ||
				config.service != "service-alias" || config.account != "account-alias" ||
				len(config.run.Authoritative) != 2 || len(config.run.Public) != 2 {
				t.Fatal("parsed config fields differ")
			}
		})
	}
}

func TestParseConfigRejectsAmbiguousOrUnsafeEnvironment(t *testing.T) {
	valid := validEnvironment(t, "CLOUDFLARE")
	unsafeDirectory := t.TempDir()
	unsafeTarget := filepath.Join(unsafeDirectory, "target.json")
	if err := os.WriteFile(unsafeTarget, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsafeLink := filepath.Join(unsafeDirectory, "evidence.json")
	if err := os.Symlink(unsafeTarget, unsafeLink); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func([]string) []string
	}{
		{name: "missing ack", mutate: func(env []string) []string { return withoutKey(env, envAck) }},
		{name: "wrong ack", mutate: func(env []string) []string { return replaceEnv(env, envAck, "yes") }},
		{name: "no provider", mutate: func(env []string) []string { return withoutKey(env, providerPrefix("CLOUDFLARE")+"_ENABLED") }},
		{name: "two providers", mutate: func(env []string) []string { return append(env, providerPrefix("ALIYUN")+"_ENABLED=1") }},
		{name: "invalid enabled", mutate: func(env []string) []string { return replaceEnv(env, providerPrefix("CLOUDFLARE")+"_ENABLED", "true") }},
		{name: "empty enabled", mutate: func(env []string) []string { return replaceEnv(env, providerPrefix("CLOUDFLARE")+"_ENABLED", "") }},
		{name: "missing service", mutate: func(env []string) []string { return withoutKey(env, providerPrefix("CLOUDFLARE")+"_KEYCHAIN_SERVICE") }},
		{name: "unsafe alias", mutate: func(env []string) []string {
			return replaceEnv(env, providerPrefix("CLOUDFLARE")+"_KEYCHAIN_SERVICE", " alias ")
		}},
		{name: "unselected alias", mutate: func(env []string) []string {
			return append(env, providerPrefix("ALIYUN")+"_KEYCHAIN_SERVICE=unexpected")
		}},
		{name: "credential env", mutate: func(env []string) []string { return append(env, providerPrefix("CLOUDFLARE")+"_API_TOKEN=secret") }},
		{name: "unknown live env", mutate: func(env []string) []string { return append(env, "CDNCA_DNS_LIVE_UNKNOWN=1") }},
		{name: "duplicate env", mutate: func(env []string) []string { return append(env, envAck+"=dedicated-disposable-zone") }},
		{name: "hostname endpoint", mutate: func(env []string) []string { return replaceEnv(env, envAuthoritative, `["ns.example.test:53"]`) }},
		{name: "duplicate endpoint", mutate: func(env []string) []string { return replaceEnv(env, envPublic, `["192.0.2.10:53"]`) }},
		{name: "duplicate endpoint in group", mutate: func(env []string) []string {
			return replaceEnv(env, envPublic, `["198.51.100.10:53","198.51.100.10:53"]`)
		}},
		{name: "unspecified endpoint", mutate: func(env []string) []string { return replaceEnv(env, envPublic, `["0.0.0.0:53"]`) }},
		{name: "endpoint trailing json", mutate: func(env []string) []string { return replaceEnv(env, envPublic, `["198.51.100.10:53"] true`) }},
		{name: "timeout low", mutate: func(env []string) []string { return replaceEnv(env, envTimeout, "59") }},
		{name: "cleanup timeout high", mutate: func(env []string) []string { return replaceEnv(env, envCleanupTimeout, "1801") }},
		{name: "bad digest", mutate: func(env []string) []string { return replaceEnv(env, envGuardSHA256, strings.Repeat("A", 64)) }},
		{name: "guard outside zone", mutate: func(env []string) []string { return replaceEnv(env, envGuardOwner, "_guard.other.test.") }},
		{name: "relative evidence", mutate: func(env []string) []string { return replaceEnv(env, envEvidencePath, "evidence.json") }},
		{name: "missing evidence parent", mutate: func(env []string) []string {
			return replaceEnv(env, envEvidencePath, filepath.Join(t.TempDir(), "missing", "evidence.json"))
		}},
		{name: "symlink evidence", mutate: func(env []string) []string { return replaceEnv(env, envEvidencePath, unsafeLink) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseConfig(test.mutate(slices.Clone(valid))); !errors.Is(err, errConfigRejected) {
				t.Fatalf("parseConfig() error=%v", err)
			}
		})
	}
}

func TestRunRejectsArgumentsAndConfigBeforeKeychainOrExecution(t *testing.T) {
	calledKeychain := false
	calledExecute := false
	dependencies := runtimeDependencies{
		keychain: func(string, string) ([]byte, error) {
			calledKeychain = true
			return nil, errors.New("unexpected")
		},
		execute: func(context.Context, cliConfig, *dnsproviderlive.CredentialLease) dnsproviderlive.Evidence {
			calledExecute = true
			return dnsproviderlive.Evidence{}
		},
	}
	for _, test := range []struct {
		name string
		args []string
		env  []string
	}{
		{name: "argument", args: []string{"unexpected"}, env: validEnvironment(t, "CLOUDFLARE")},
		{name: "config", env: withoutKey(validEnvironment(t, "CLOUDFLARE"), envAck)},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, reason := run(t.Context(), test.args, test.env, dependencies)
			if code == 0 || reason != reasonConfigRejected || calledKeychain || calledExecute {
				t.Fatalf("run()=(%d,%q) keychain=%v execute=%v", code, reason, calledKeychain, calledExecute)
			}
		})
	}
}

func TestRunBlocksHuaweiBeforeKeychainOrExecution(t *testing.T) {
	environment := validEnvironment(t, "HUAWEI")
	calledKeychain := false
	calledExecute := false
	code, reason := run(t.Context(), nil, environment, runtimeDependencies{
		keychain: func(string, string) ([]byte, error) {
			calledKeychain = true
			return nil, errors.New("unexpected")
		},
		execute: func(context.Context, cliConfig, *dnsproviderlive.CredentialLease) dnsproviderlive.Evidence {
			calledExecute = true
			return dnsproviderlive.Evidence{Status: dnsproviderlive.StatusPass}
		},
	})
	if code == 0 || reason != reasonConfigRejected || calledKeychain || calledExecute {
		t.Fatalf("run()=(%d,%q) keychain=%v execute=%v", code, reason, calledKeychain, calledExecute)
	}
	if _, err := os.Stat(envValue(environment, envEvidencePath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blocked Huawei run wrote evidence: %v", err)
	}
}

func TestRunLoadsKeychainOnlyAfterGatesWritesRedactedEvidenceAndClearsSecrets(t *testing.T) {
	environment := validEnvironment(t, "CLOUDFLARE")
	raw := []byte(`{"api_token":"SENTINEL-LIVE-SECRET"}`)
	var lease *dnsproviderlive.CredentialLease
	var clonedViews map[string]string
	dependencies := runtimeDependencies{
		keychain: func(service, account string) ([]byte, error) {
			if service != "service-alias" || account != "account-alias" {
				t.Fatal("keychain aliases differ")
			}
			return raw, nil
		},
		execute: func(_ context.Context, config cliConfig, got *dnsproviderlive.CredentialLease) dnsproviderlive.Evidence {
			lease = got
			clonedViews = cloneCredentialViews(got.Values)
			if got.Values["api_token"] != "SENTINEL-LIVE-SECRET" {
				t.Fatal("credential unavailable to executor")
			}
			return dnsproviderlive.Evidence{
				Schema: dnsproviderlive.EvidenceSchema, Status: dnsproviderlive.StatusPass,
				Reason: dnsproviderlive.ReasonVerified, Phase: dnsproviderlive.PhaseComplete,
				ProviderCode: config.provider.code, AuthoritativeCount: len(config.run.Authoritative),
				PublicCount: len(config.run.Public), CleanupAttempted: true, CleanupComplete: true,
			}
		},
	}
	code, reason := run(t.Context(), nil, environment, dependencies)
	if code != 0 || reason != dnsproviderlive.ReasonVerified {
		t.Fatalf("run()=(%d,%q)", code, reason)
	}
	if lease == nil || !allZero(raw) || len(lease.Values) != 0 || !allStringZero(clonedViews["api_token"]) {
		t.Fatal("credential lease and retained views were not zeroed")
	}
	path := envValue(environment, envEvidencePath)
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "SENTINEL-LIVE-SECRET") || strings.Contains(reason, "SENTINEL-LIVE-SECRET") {
		t.Fatal("secret leaked to evidence or output")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("evidence mode=%v error=%v", info.Mode(), err)
	}
}

func TestRunKeychainFailureWritesOnlyStableEvidence(t *testing.T) {
	environment := validEnvironment(t, "DNS_LA")
	sentinel := "SENTINEL-RAW-KEYCHAIN-ERROR"
	code, reason := run(t.Context(), nil, environment, runtimeDependencies{
		keychain: func(string, string) ([]byte, error) { return nil, errors.New(sentinel) },
		execute: func(context.Context, cliConfig, *dnsproviderlive.CredentialLease) dnsproviderlive.Evidence {
			t.Fatal("executor called after keychain failure")
			return dnsproviderlive.Evidence{}
		},
	})
	if code == 0 || reason != reasonCredentialUnavailable || strings.Contains(reason, sentinel) {
		t.Fatalf("run()=(%d,%q)", code, reason)
	}
	encoded, err := os.ReadFile(envValue(environment, envEvidencePath))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), sentinel) || strings.Contains(string(encoded), "service-alias") || strings.Contains(string(encoded), "account-alias") {
		t.Fatalf("unsafe evidence=%s", encoded)
	}
}

func TestRunRejectsInconsistentPassEvidence(t *testing.T) {
	valid := dnsproviderlive.Evidence{
		Schema: dnsproviderlive.EvidenceSchema, Status: dnsproviderlive.StatusPass,
		Reason: dnsproviderlive.ReasonVerified, Phase: dnsproviderlive.PhaseComplete,
		ProviderCode: "cloudflare", AuthoritativeCount: 2, PublicCount: 2,
		CleanupAttempted: true, CleanupComplete: true,
	}
	tests := []struct {
		name   string
		mutate func(*dnsproviderlive.Evidence)
	}{
		{name: "cleanup not attempted", mutate: func(e *dnsproviderlive.Evidence) { e.CleanupAttempted = false }},
		{name: "cleanup incomplete", mutate: func(e *dnsproviderlive.Evidence) { e.CleanupComplete = false }},
		{name: "wrong reason", mutate: func(e *dnsproviderlive.Evidence) { e.Reason = dnsproviderlive.ReasonInvalidConfig }},
		{name: "wrong phase", mutate: func(e *dnsproviderlive.Evidence) { e.Phase = dnsproviderlive.PhaseCleanup }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := valid
			test.mutate(&evidence)
			environment := validEnvironment(t, "CLOUDFLARE")
			code, reason := run(t.Context(), nil, environment, runtimeDependencies{
				keychain: func(string, string) ([]byte, error) { return []byte(`{"api_token":"secret"}`), nil },
				execute: func(context.Context, cliConfig, *dnsproviderlive.CredentialLease) dnsproviderlive.Evidence {
					return evidence
				},
			})
			if code == 0 || reason != dnsproviderlive.ReasonInvalidConfig {
				t.Fatalf("run()=(%d,%q)", code, reason)
			}
			var written dnsproviderlive.Evidence
			encoded, err := os.ReadFile(envValue(environment, envEvidencePath))
			if err != nil || json.Unmarshal(encoded, &written) != nil || written.Status != dnsproviderlive.StatusFail {
				t.Fatalf("written evidence=%+v read error=%v", written, err)
			}
		})
	}
}

func TestDedicatedSourceClonesAndClearsCredentials(t *testing.T) {
	raw := []byte(`{"api_token":"secret"}`)
	lease, err := dnsproviderlive.LoadCredential(
		func(string, string) ([]byte, error) { return raw, nil },
		"cloudflare", "service", "account",
	)
	if err != nil {
		t.Fatalf("LoadCredential() error=%v", err)
	}
	source := &dedicatedSource{
		tenantID:     uuid.MustParse("10000000-0000-4000-8000-000000000001"),
		scopeID:      uuid.MustParse("11000000-0000-4000-8000-000000000001"),
		providerID:   uuid.MustParse("20000000-0000-4000-8000-000000000001"),
		zoneID:       uuid.MustParse("30000000-0000-4000-8000-000000000001"),
		providerCode: "cloudflare", zone: "example.test",
		credentials: cloneCredentialViews(lease.Values),
	}
	validLookup := dnsproviderremote.ProviderLookup{
		TenantID: source.tenantID, ScopeID: source.scopeID, ProviderID: source.providerID, ZoneID: source.zoneID,
		OwnerName: "_cdnca-live-token.example.test.",
	}
	resolved, err := source.Resolve(t.Context(), validLookup)
	if err != nil || resolved.TenantID != source.tenantID || resolved.ScopeID != source.scopeID ||
		resolved.ProviderID != source.providerID || resolved.ZoneID != source.zoneID || resolved.Credentials["api_token"] != "secret" {
		t.Fatalf("Resolve() validation error=%v", err)
	}
	clearCredentialViews(resolved.Credentials)
	wrongID := uuid.MustParse("ffffffff-ffff-4fff-8fff-ffffffffffff")
	for _, test := range []struct {
		name   string
		mutate func(*dnsproviderremote.ProviderLookup)
	}{
		{name: "missing tenant", mutate: func(lookup *dnsproviderremote.ProviderLookup) { lookup.TenantID = uuid.Nil }},
		{name: "wrong tenant", mutate: func(lookup *dnsproviderremote.ProviderLookup) { lookup.TenantID = wrongID }},
		{name: "missing scope", mutate: func(lookup *dnsproviderremote.ProviderLookup) { lookup.ScopeID = uuid.Nil }},
		{name: "wrong scope", mutate: func(lookup *dnsproviderremote.ProviderLookup) { lookup.ScopeID = wrongID }},
		{name: "legacy scope only", mutate: func(lookup *dnsproviderremote.ProviderLookup) {
			lookup.TenantID = uuid.Nil
			lookup.ScopeID = uuid.Nil
			lookup.TenantScopeID = source.scopeID
		}},
		{name: "missing provider", mutate: func(lookup *dnsproviderremote.ProviderLookup) { lookup.ProviderID = uuid.Nil }},
		{name: "wrong provider", mutate: func(lookup *dnsproviderremote.ProviderLookup) { lookup.ProviderID = wrongID }},
		{name: "missing zone", mutate: func(lookup *dnsproviderremote.ProviderLookup) { lookup.ZoneID = uuid.Nil }},
		{name: "wrong zone", mutate: func(lookup *dnsproviderremote.ProviderLookup) { lookup.ZoneID = wrongID }},
		{name: "wrong owner", mutate: func(lookup *dnsproviderremote.ProviderLookup) { lookup.OwnerName = "_cdnca-live-token.other.test." }},
	} {
		t.Run(test.name, func(t *testing.T) {
			lookup := validLookup
			test.mutate(&lookup)
			if config, err := source.Resolve(t.Context(), lookup); err == nil {
				t.Fatalf("Resolve()=(%+v,%v), want unavailable", config, err)
			}
		})
	}
	first := source.cloneCredentialViews()
	first["api_token"] = "changed"
	second := source.cloneCredentialViews()
	if second["api_token"] != "secret" {
		t.Fatal("source returned aliased credential map")
	}
	retainedView := second["api_token"]
	source.clear()
	if len(source.credentials) != 0 || second["api_token"] != "secret" {
		t.Fatal("source clear did not preserve independent clone")
	}
	lease.Close()
	if !allZero(raw) || !allStringZero(retainedView) || !allStringZero(second["api_token"]) {
		t.Fatal("lease close did not zero source clone views")
	}
	clearCredentialViews(first)
	clearCredentialViews(second)
}

func TestRandomLiveAuthorityConsumesFourIndependentIDs(t *testing.T) {
	reader := bytes.NewReader(bytes.Join([][]byte{
		bytes.Repeat([]byte{0x11}, 16),
		bytes.Repeat([]byte{0x22}, 16),
		bytes.Repeat([]byte{0x33}, 16),
		bytes.Repeat([]byte{0x44}, 16),
	}, nil))
	tenantID, scopeID, providerID, zoneID, ok := randomLiveAuthority(reader)
	if !ok || tenantID == uuid.Nil || scopeID == uuid.Nil || providerID == uuid.Nil || zoneID == uuid.Nil ||
		tenantID == scopeID || reader.Len() != 0 {
		t.Fatalf("authority=(%s,%s,%s,%s,%v), remaining=%d", tenantID, scopeID, providerID, zoneID, ok, reader.Len())
	}
}

func validEnvironment(t *testing.T, provider string) []string {
	t.Helper()
	digest := sha256.Sum256([]byte("guard-proof"))
	prefix := providerPrefix(provider)
	return []string{
		envAck + "=dedicated-disposable-zone",
		prefix + "_ENABLED=1",
		prefix + "_KEYCHAIN_SERVICE=service-alias",
		prefix + "_KEYCHAIN_ACCOUNT=account-alias",
		envZone + "=example.test",
		envGuardOwner + "=_cdnca-live-guard.example.test.",
		envGuardSHA256 + "=" + hex.EncodeToString(digest[:]),
		envAuthoritative + `=["192.0.2.10:53","192.0.2.11:53"]`,
		envPublic + `=["198.51.100.10:53","198.51.100.11:53"]`,
		envTimeout + "=60",
		envCleanupTimeout + "=60",
		envEvidencePath + "=" + filepath.Join(t.TempDir(), "evidence.json"),
	}
}

func replaceEnv(environment []string, key, value string) []string {
	for index, item := range environment {
		if strings.HasPrefix(item, key+"=") {
			environment[index] = key + "=" + value
			return environment
		}
	}
	return append(environment, key+"="+value)
}

func withoutKey(environment []string, key string) []string {
	result := environment[:0]
	for _, item := range environment {
		if !strings.HasPrefix(item, key+"=") {
			result = append(result, item)
		}
	}
	return result
}

func envValue(environment []string, key string) string {
	for _, item := range environment {
		if strings.HasPrefix(item, key+"=") {
			return strings.TrimPrefix(item, key+"=")
		}
	}
	return ""
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func allStringZero(value string) bool {
	for index := range len(value) {
		if value[index] != 0 {
			return false
		}
	}
	return true
}
