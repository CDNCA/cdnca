package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOpenACMERuntimeDisabledHasNoDependencies(t *testing.T) {
	runtime, err := openACMERuntime(config.Config{}, nil, acmeRuntimeProviders{})
	if err != nil || runtime != nil {
		t.Fatalf("disabled runtime = (%v, %v)", runtime, err)
	}
	t.Setenv("ACME_DNS_HANDLE_ACTIVE_KEY_ID", "invalid key id")
	t.Setenv("ACME_DNS_HANDLE_ACTIVE_KEY_BASE64", "not-base64")
	t.Setenv("ACME_DNS_HANDLE_VERIFY_ONLY_KEYS_JSON", "not-json")
	runtime, err = openConfiguredACMERuntime(t.Context(), config.Config{}, nil)
	if err != nil || runtime != nil {
		t.Fatalf("disabled configured runtime = (%v, %v)", runtime, err)
	}
}

func TestOpenACMERuntimeFailsClosedForMissingProductionProviders(t *testing.T) {
	cfg := validACMERuntimeConfig()
	secret := string(cfg.ACMEWrappingKey)
	_, err := openACMERuntime(cfg, new(pgxpool.Pool), acmeRuntimeProviders{})
	if err == nil || err.Error() != "ACME runtime HTTP-01 provider is not configured" ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("missing HTTP-01 provider error = %v", err)
	}
	_, err = openACMERuntime(cfg, new(pgxpool.Pool), acmeRuntimeProviders{
		http01: inertHTTP01Provider{},
	})
	if err == nil || err.Error() != "ACME runtime DNS-01 provider is not configured" {
		t.Fatalf("missing DNS-01 provider error = %v", err)
	}
}

func TestOpenACMERuntimeBuildsWithInjectedProviders(t *testing.T) {
	runtime, err := openACMERuntime(validACMERuntimeConfig(), new(pgxpool.Pool), acmeRuntimeProviders{
		http01: inertHTTP01Provider{}, dns01: inertDNS01Provider{},
		issuerOverride: inertIssuer{},
	})
	if err != nil || runtime == nil {
		t.Fatalf("configured runtime = (%v, %v)", runtime, err)
	}
	if err := runtime.Ready(); err == nil {
		t.Fatal("constructed but inactive runtime was ready")
	}
}

func TestACMERenewalSchedulerConfigCarriesRetryMaximum(t *testing.T) {
	cfg := validACMERuntimeConfig()
	schedulerConfig := acmeRenewalSchedulerConfig(cfg)
	if schedulerConfig.RetryMaximum != cfg.ACMERetryMaximum {
		t.Fatalf("renewal retry maximum = %s, want %s", schedulerConfig.RetryMaximum, cfg.ACMERetryMaximum)
	}
}

func TestDNS08CompositionMountsConfiguredCAFailoverIssuer(t *testing.T) {
	cfg := validACMERuntimeConfig()
	cfg.ACMEBackupDirectoryURL = "https://backup.example/directory"
	primary := &dns08CompositionIssuer{}
	backup := &dns08CompositionIssuer{}
	facts := &dns08CompositionFacts{}
	issuer, err := newConfiguredACMEIssuer(
		cfg, primary, backup, facts,
		dns08CompositionProbe{primary: cfg.ACMEDirectoryURL},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := acmeworker.IssueRequest{AccountKeyRef: "acme:v1:tenant-bound-account"}
	if _, err := issuer.Issue(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if primary.calls != 0 || backup.calls != 1 ||
		backup.request.DirectoryURL != cfg.ACMEBackupDirectoryURL ||
		backup.request.AccountKeyRef != request.AccountKeyRef {
		t.Fatalf("failover calls primary=%d backup=%d request=%+v",
			primary.calls, backup.calls, backup.request)
	}
	if len(facts.candidates) != 2 ||
		facts.candidates[0].AccountKeyRef != request.AccountKeyRef ||
		facts.candidates[1].AccountKeyRef != request.AccountKeyRef {
		t.Fatalf("request-bound CA candidates = %+v", facts.candidates)
	}

	cfg.ACMEBackupDirectoryURL = ""
	single, err := newConfiguredACMEIssuer(cfg, primary, nil, nil, nil)
	if err != nil || single != primary {
		t.Fatalf("single CA composition = (%T, %v)", single, err)
	}
}

func TestACMEProcessRuntimeRunsReadiesAndClosesBothLoops(t *testing.T) {
	issuance := newACMETestLoop()
	renewal := newACMETestLoop()
	runtime := &acmeProcessRuntime{issuance: issuance, renewal: renewal}
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	for _, started := range []<-chan struct{}{issuance.started, renewal.started} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("ACME process loop did not start")
		}
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("active process readiness error = %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("closed process error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join both ACME process loops")
	}
	if !issuance.stopped.Load() || !renewal.stopped.Load() {
		t.Fatalf("loop stop state issuance=%t renewal=%t",
			issuance.stopped.Load(), renewal.stopped.Load())
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("idempotent Close error = %v", err)
	}
	if err := runtime.Run(context.Background()); err == nil {
		t.Fatal("closed ACME process runtime restarted")
	}
}

func TestACMEProcessRuntimeCancelsPeerOnLoopFailure(t *testing.T) {
	issuance := newACMETestLoop()
	renewal := newACMETestLoop()
	renewal.runError = errors.New("renewal stopped")
	runtime := &acmeProcessRuntime{issuance: issuance, renewal: renewal}
	err := runtime.Run(context.Background())
	if err == nil || err.Error() != "renewal stopped" || !issuance.stopped.Load() {
		t.Fatalf("process failure=%v issuance-stopped=%t", err, issuance.stopped.Load())
	}
}

func TestNodeAggregateRequiredHTTP01ProviderFailsClosedWithoutRenderingChallenge(t *testing.T) {
	provider := nodeAggregateRequiredHTTP01Provider{}
	challenge := acmeworker.ChallengeIdentity{
		Identifier: "sensitive.example.test", Token: "sensitive-token", ExactValue: "sensitive-value",
	}
	for _, test := range []struct {
		name string
		call func() error
	}{
		{name: "publish", call: func() error { return provider.Publish(t.Context(), challenge) }},
		{name: "delete", call: func() error { return provider.Delete(t.Context(), challenge) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if acmeworker.ErrorCodeOf(err) != acmeworker.CodeHTTP01NodeAggregateRequired ||
				err.Error() != string(acmeworker.CodeHTTP01NodeAggregateRequired) {
				t.Fatalf("capability error = %v", err)
			}
			rendered := fmt.Sprintf("%+v", err)
			for _, secret := range []string{challenge.Identifier, challenge.Token, challenge.ExactValue} {
				if strings.Contains(rendered, secret) {
					t.Fatalf("capability error rendered challenge material: %q", rendered)
				}
			}
		})
	}
}

func TestLoadACMEDNSHandleKeyringAcceptsRotation(t *testing.T) {
	active := bytes.Repeat([]byte{3}, 32)
	old := bytes.Repeat([]byte{4}, 32)
	t.Setenv("ACME_DNS_HANDLE_ACTIVE_KEY_ID", "active_2")
	t.Setenv("ACME_DNS_HANDLE_ACTIVE_KEY_BASE64", base64.StdEncoding.EncodeToString(active))
	t.Setenv("ACME_DNS_HANDLE_VERIFY_ONLY_KEYS_JSON", `[{"id":"old-1","key_base64":"`+
		base64.StdEncoding.EncodeToString(old)+`"}]`)
	keyring, err := loadACMEDNSHandleKeyring()
	if err != nil || keyring == nil {
		t.Fatalf("rotation keyring = (%v, %v)", keyring, err)
	}
}

func TestLoadACMEDNSHandleKeyringAllowsMissingVerifyOnlyEnvironment(t *testing.T) {
	unsetTestEnvironment(t, "ACME_DNS_HANDLE_VERIFY_ONLY_KEYS_JSON")
	t.Setenv("ACME_DNS_HANDLE_ACTIVE_KEY_ID", "active")
	t.Setenv("ACME_DNS_HANDLE_ACTIVE_KEY_BASE64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)))
	keyring, err := loadACMEDNSHandleKeyring()
	if err != nil || keyring == nil {
		t.Fatalf("active-only keyring = (%v, %v)", keyring, err)
	}
}

func TestLoadACMEDNSHandleKeyringRejectsInvalidConfiguration(t *testing.T) {
	canonical := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{6}, 31))
	tooManyKeys := make([]acmeDNSHandleVerificationKey, maximumACMEDNSHandleVerifyOnlyKeys+1)
	for index := range tooManyKeys {
		tooManyKeys[index] = acmeDNSHandleVerificationKey{
			ID: "old-" + string(rune('a'+index)), KeyBase64: canonical,
		}
	}
	tooManyKeysJSON, err := json.Marshal(tooManyKeys)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		activeID   string
		activeKey  string
		verifyOnly *string
	}{
		{name: "missing active id", activeKey: canonical},
		{name: "invalid active id", activeID: "bad id", activeKey: canonical},
		{name: "missing active key", activeID: "active"},
		{name: "short active key", activeID: "active", activeKey: short},
		{name: "noncanonical active key", activeID: "active", activeKey: canonical + "\n"},
		{name: "explicit empty verify JSON", activeID: "active", activeKey: canonical, verifyOnly: stringPointer("")},
		{name: "null verify JSON", activeID: "active", activeKey: canonical, verifyOnly: stringPointer("null")},
		{name: "object verify JSON", activeID: "active", activeKey: canonical, verifyOnly: stringPointer(`{}`)},
		{name: "unknown verify field", activeID: "active", activeKey: canonical, verifyOnly: stringPointer(`[{"id":"old","key_base64":"` + canonical + `","extra":true}]`)},
		{name: "trailing JSON", activeID: "active", activeKey: canonical, verifyOnly: stringPointer(`[] []`)},
		{name: "oversized verify JSON", activeID: "active", activeKey: canonical, verifyOnly: stringPointer(strings.Repeat(" ", maximumACMEDNSHandleVerifyOnlyJSONBytes+1))},
		{name: "too many verify keys", activeID: "active", activeKey: canonical, verifyOnly: stringPointer(string(tooManyKeysJSON))},
		{name: "invalid verify id", activeID: "active", activeKey: canonical, verifyOnly: stringPointer(`[{"id":"bad id","key_base64":"` + canonical + `"}]`)},
		{name: "short verify key", activeID: "active", activeKey: canonical, verifyOnly: stringPointer(`[{"id":"old","key_base64":"` + short + `"}]`)},
		{name: "noncanonical verify key", activeID: "active", activeKey: canonical, verifyOnly: stringPointer(`[{"id":"old","key_base64":"` + canonical + `\n"}]`)},
		{name: "duplicate active id", activeID: "active", activeKey: canonical, verifyOnly: stringPointer(`[{"id":"active","key_base64":"` + canonical + `"}]`)},
		{name: "duplicate verify id", activeID: "active", activeKey: canonical, verifyOnly: stringPointer(`[{"id":"old","key_base64":"` + canonical + `"},{"id":"old","key_base64":"` + canonical + `"}]`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("ACME_DNS_HANDLE_ACTIVE_KEY_ID", test.activeID)
			t.Setenv("ACME_DNS_HANDLE_ACTIVE_KEY_BASE64", test.activeKey)
			if test.verifyOnly == nil {
				unsetTestEnvironment(t, "ACME_DNS_HANDLE_VERIFY_ONLY_KEYS_JSON")
			} else {
				t.Setenv("ACME_DNS_HANDLE_VERIFY_ONLY_KEYS_JSON", *test.verifyOnly)
			}
			_, err := loadACMEDNSHandleKeyring()
			if err == nil || strings.Contains(err.Error(), canonical) || strings.Contains(err.Error(), short) {
				t.Fatalf("invalid keyring error = %v", err)
			}
		})
	}
}

func TestACMEPrivateKeyEnvelopeBindsContext(t *testing.T) {
	enveloper, err := newACMEPrivateKeyEnveloper("acme-kek-v1", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	contextValue := certificateasset.PrivateKeyEnvelopeContext{
		TenantScopeID: uuid.New(), AssetID: uuid.New(), VersionID: uuid.New(), Version: 1,
		CertificateFingerprintSHA256: [32]byte{1}, CertificatePublicKeySHA256: [32]byte{2},
		PrivateKeyReference: "acme:v1:key",
	}
	plaintext := []byte("provider-wrapped-private-key")
	envelope, err := enveloper.SealOpaque(t.Context(), certificateasset.OpaquePrivateKeySealRequest{
		Context: contextValue, WrappedKeyMaterial: plaintext,
		Metadata: json.RawMessage(`{"schema":"source.v1"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(envelope.Ciphertext, plaintext) || bytes.Contains(envelope.Metadata, plaintext) {
		t.Fatal("envelope exposed wrapped key material")
	}
	unsealed, err := enveloper.Unseal(t.Context(), certificateasset.PrivateKeyUnsealRequest{
		Context: contextValue, Envelope: envelope,
	})
	if err != nil || !bytes.Equal(unsealed, plaintext) {
		t.Fatalf("Unseal() = (%q, %v)", unsealed, err)
	}
	tamperedContext := contextValue
	tamperedContext.AssetID = uuid.New()
	if _, err := enveloper.Unseal(t.Context(), certificateasset.PrivateKeyUnsealRequest{
		Context: tamperedContext, Envelope: envelope,
	}); !errors.Is(err, certificateasset.ErrEnvelopeUnavailable) {
		t.Fatalf("tampered context error = %v", err)
	}
}

func validACMERuntimeConfig() config.Config {
	return config.Config{
		DNSCredentialKeyID: "dns-v1", DNSCredentialKey: bytes.Repeat([]byte{8}, 32),
		ACMERuntimeEnabled: true, ACMEDirectoryURL: "https://ca.example/directory",
		ACMEContacts: []string{"mailto:ops@example.test"}, ACMEWrappingKeyID: "acme-kek-v1",
		ACMEWrappingKey: bytes.Repeat([]byte{9}, 32), ACMEPollInterval: time.Second,
		ACMELeaseDuration: 10 * time.Minute, ACMESettleTimeout: 30 * time.Second,
		ACMERetryBase: time.Minute, ACMERetryMaximum: time.Hour, ACMEMaxAttempts: 3,
		ACMEErrorBackoffMin: time.Second, ACMEErrorBackoffMax: 30 * time.Second,
	}
}

type inertHTTP01Provider struct{}

func (inertHTTP01Provider) Publish(context.Context, acmeworker.ChallengeIdentity) error { return nil }
func (inertHTTP01Provider) Delete(context.Context, acmeworker.ChallengeIdentity) error  { return nil }

type inertDNS01Provider struct{}

func (inertDNS01Provider) PresentTXT(context.Context, acmeworker.ChallengeIdentity) (acmeworker.RemoteTXTHandle, error) {
	return acmeworker.RemoteTXTHandle{}, errors.New("not used")
}
func (inertDNS01Provider) ObserveTXT(context.Context, acmeworker.ChallengeIdentity) error {
	return errors.New("not used")
}
func (inertDNS01Provider) DeleteTXT(context.Context, acmeworker.ChallengeIdentity) error {
	return errors.New("not used")
}

type inertIssuer struct{}

func (inertIssuer) Issue(context.Context, acmeworker.IssueRequest) (acmeworker.IssueResult, error) {
	return acmeworker.IssueResult{}, errors.New("not used")
}

var _ acmeruntime.Issuer = inertIssuer{}

type dns08CompositionIssuer struct {
	calls   int
	request acmeworker.IssueRequest
}

func (i *dns08CompositionIssuer) Issue(
	_ context.Context,
	request acmeworker.IssueRequest,
) (acmeworker.IssueResult, error) {
	i.calls++
	i.request = request
	return acmeworker.IssueResult{}, nil
}

type dns08CompositionFacts struct {
	candidates []acmeworker.CAPolicyCandidate
}

func (f *dns08CompositionFacts) LoadCAPolicyFacts(
	_ context.Context,
	_ acmeworker.IssueRequest,
	candidates []acmeworker.CAPolicyCandidate,
	_ time.Time,
	_ time.Duration,
	_ time.Duration,
) (acmeworker.CAPolicyFacts, error) {
	f.candidates = append([]acmeworker.CAPolicyCandidate(nil), candidates...)
	return acmeworker.CAPolicyFacts{
		Usage: make(map[string]acmeworker.CAPolicyUsage, len(candidates)),
	}, nil
}

type dns08CompositionProbe struct{ primary string }

func (p dns08CompositionProbe) Probe(
	_ context.Context,
	directoryURL string,
	_ time.Time,
) acmeworker.CAProbeResult {
	if directoryURL == p.primary {
		return acmeworker.CAProbeResult{
			FailoverSafe: true,
			Failure: &acmeworker.Error{
				Code: acmeworker.CodeDirectoryUnavailable, Temporary: true,
			},
		}
	}
	return acmeworker.CAProbeResult{Available: true}
}

type acmeTestLoop struct {
	started  chan struct{}
	running  atomic.Bool
	stopped  atomic.Bool
	runError error
}

func newACMETestLoop() *acmeTestLoop {
	return &acmeTestLoop{started: make(chan struct{})}
}

func (loop *acmeTestLoop) Run(ctx context.Context) error {
	loop.running.Store(true)
	close(loop.started)
	if loop.runError != nil {
		loop.running.Store(false)
		loop.stopped.Store(true)
		return loop.runError
	}
	<-ctx.Done()
	loop.running.Store(false)
	loop.stopped.Store(true)
	return ctx.Err()
}

func (loop *acmeTestLoop) Ready() error {
	if !loop.running.Load() {
		return errors.New("test ACME loop is not ready")
	}
	return nil
}

func stringPointer(value string) *string { return &value }

func unsetTestEnvironment(t *testing.T, key string) {
	t.Helper()
	value, existed := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var err error
		if existed {
			err = os.Setenv(key, value)
		} else {
			err = os.Unsetenv(key)
		}
		if err != nil {
			t.Errorf("restore %s: %v", key, err)
		}
	})
}
