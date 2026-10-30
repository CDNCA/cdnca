package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverificationhttp"
)

func TestIdentityVerificationRuntimeConfigDefaultsDisabledAndIgnoresSecrets(t *testing.T) {
	config, err := loadIdentityVerificationRuntimeConfigFromEnv([]string{
		identityVerificationCursorKeyBase64Env + "=not-secret-material",
		identityVerificationResolverNameEnv + "=not-used",
	})
	if err != nil || config.Enabled || config.CursorKey != nil || config.ResolverName != "" {
		t.Fatalf("disabled config=(%#v,%v)", config, err)
	}
	runtime, err := openIdentityVerificationProductionRuntime(nil, config,
		identityVerificationProductionDependencies{})
	if err != nil || runtime != nil {
		t.Fatalf("disabled runtime=(%T,%v)", runtime, err)
	}
}

func TestIdentityVerificationRuntimeConfigLoadsStrictProductionValuesAndClearsSecret(t *testing.T) {
	key := bytes.Repeat([]byte{0x61}, identityVerificationCursorKeyMaxBytes)
	config, err := loadIdentityVerificationRuntimeConfigFromEnv(identityVerificationRuntimeEnvironment(key))
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || !config.WorkerEnabled || config.ResolverName != "trusted-kyc" ||
		config.ReviewTTL != 72*time.Hour || config.RetentionPeriod != 6*365*24*time.Hour ||
		config.Settlement.LeaseDuration != time.Minute || config.Settlement.RetryDelay != 2*time.Minute ||
		config.Settlement.MaxAttempts != 9 || config.WorkerIdlePoll != 250*time.Millisecond ||
		config.WorkerErrorBackoff != 2*time.Second || !bytes.Equal(config.CursorKey, key) {
		t.Fatalf("loaded config=%#v", config)
	}
	retained := config.CursorKey
	config.clearSecrets()
	if config.Enabled || config.CursorKey != nil || config.ResolverName != "" || config.WorkerEnabled ||
		config.ReviewTTL != 0 || config.RetentionPeriod != 0 || config.Settlement.Clock != nil ||
		config.Settlement.NewID != nil || config.Settlement.LeaseDuration != 0 ||
		config.Settlement.RetryDelay != 0 || config.Settlement.MaxAttempts != 0 ||
		config.WorkerIdlePoll != 0 || config.WorkerErrorBackoff != 0 ||
		!bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("identity verification runtime config retained secret or settings")
	}
}

func TestIdentityVerificationRuntimeConfigRejectsIncompleteAmbiguousAndSecretInput(t *testing.T) {
	key := bytes.Repeat([]byte{0x62}, identityVerificationCursorKeyMinBytes)
	encoded := base64.StdEncoding.EncodeToString(key)
	valid := identityVerificationRuntimeEnvironment(key)
	tests := []struct {
		name        string
		environment []string
		want        string
	}{
		{"invalid enabled", replaceIdentityVerificationEnv(valid, identityVerificationEnabledEnv, "TRUE"), identityVerificationEnabledEnv},
		{"worker missing", removeIdentityVerificationEnv(valid, identityVerificationWorkerEnabledEnv), identityVerificationWorkerEnabledEnv},
		{"worker disabled", replaceIdentityVerificationEnv(valid, identityVerificationWorkerEnabledEnv, "false"), identityVerificationWorkerEnabledEnv},
		{"resolver missing", removeIdentityVerificationEnv(valid, identityVerificationResolverNameEnv), identityVerificationResolverNameEnv},
		{"resolver invalid", replaceIdentityVerificationEnv(valid, identityVerificationResolverNameEnv, "Trusted KYC"), identityVerificationResolverNameEnv},
		{"cursor missing", removeIdentityVerificationEnv(valid, identityVerificationCursorKeyBase64Env), identityVerificationCursorKeyBase64Env},
		{"cursor malformed", replaceIdentityVerificationEnv(valid, identityVerificationCursorKeyBase64Env, "not-base64"), "canonical padded base64"},
		{"cursor unpadded", replaceIdentityVerificationEnv(valid, identityVerificationCursorKeyBase64Env, base64.RawStdEncoding.EncodeToString(key)), "canonical padded base64"},
		{"cursor short", replaceIdentityVerificationEnv(valid, identityVerificationCursorKeyBase64Env, base64.StdEncoding.EncodeToString(key[:len(key)-1])), "32 to 128"},
		{"review TTL invalid", replaceIdentityVerificationEnv(valid, identityVerificationReviewTTLEnv, "0s"), identityVerificationReviewTTLEnv},
		{"retention invalid", replaceIdentityVerificationEnv(valid, identityVerificationRetentionPeriodEnv, "forever"), identityVerificationRetentionPeriodEnv},
		{"lease invalid", replaceIdentityVerificationEnv(valid, identityVerificationSettlementLeaseDurationEnv, "-1s"), identityVerificationSettlementLeaseDurationEnv},
		{"retry invalid", replaceIdentityVerificationEnv(valid, identityVerificationSettlementRetryDelayEnv, "0s"), identityVerificationSettlementRetryDelayEnv},
		{"attempts invalid", replaceIdentityVerificationEnv(valid, identityVerificationSettlementMaxAttemptsEnv, "0"), identityVerificationSettlementMaxAttemptsEnv},
		{"idle poll invalid", replaceIdentityVerificationEnv(valid, identityVerificationWorkerIdlePollEnv, "0s"), identityVerificationWorkerIdlePollEnv},
		{"error backoff invalid", replaceIdentityVerificationEnv(valid, identityVerificationWorkerErrorBackoffEnv, "bad"), identityVerificationWorkerErrorBackoffEnv},
		{"duplicate enabled", append(append([]string(nil), valid...), identityVerificationEnabledEnv+"=true"), "exactly once"},
		{"unknown setting", append(append([]string(nil), valid...), "IDENTITY_VERIFICATION_RESOLVER_SECRET=secret-value"), "unsupported"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadIdentityVerificationRuntimeConfigFromEnv(test.environment)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
			for _, secret := range []string{encoded, "not-base64", "secret-value"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("configuration error leaked secret input: %v", err)
				}
			}
		})
	}
}

func TestOpenIdentityVerificationProductionRuntimeBindsDurableSourceWorkerAndClearsInput(t *testing.T) {
	configured := configuredRuntimeTestDependencies(t)
	key := bytes.Repeat([]byte{0x63}, 32)
	config, err := loadIdentityVerificationRuntimeConfigFromEnv(identityVerificationRuntimeEnvironment(key))
	if err != nil {
		t.Fatal(err)
	}
	retained := config.CursorKey
	events := make([]string, 0, 3)
	var mu sync.Mutex
	source := &identityVerificationEvidenceSourceStub{onClose: func() {
		mu.Lock()
		events = append(events, "source")
		mu.Unlock()
	}}
	worker := &identityVerificationWorkerRuntimeStub{
		handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusNoContent)
		}),
		onClose: func() error {
			mu.Lock()
			events = append(events, "worker")
			mu.Unlock()
			return nil
		},
	}
	dependencies := identityVerificationProductionDependencies{
		Pool: configured.Pool, Identity: configured.Identity, IAM: configured.IAM, Clock: time.Now,
		NewEvidenceSource: func(_ context.Context, parameters identityVerificationEvidenceSourceParameters) (identityVerificationEvidenceSource, error) {
			if parameters.Config.ResolverName != "trusted-kyc" || len(parameters.Config.IssueTokenKey) != sha256.Size ||
				bytes.Equal(parameters.Config.IssueTokenKey, key) {
				t.Fatal("evidence source issue token key is not domain separated")
			}
			return source, nil
		},
		NewRuntime: func(runtimeConfig identityverificationhttp.ProductionRuntimeConfig,
			runtimeDependencies identityverificationhttp.ProductionRuntimeDependencies,
		) (identityVerificationWorkerRuntime, error) {
			if !runtimeConfig.Runtime.Enabled || runtimeConfig.Evidence.ResolverName != "trusted-kyc" ||
				runtimeConfig.Runtime.Core.ReviewTTL != 72*time.Hour ||
				runtimeConfig.Runtime.Core.RetentionPeriod != 6*365*24*time.Hour ||
				runtimeConfig.Runtime.Settlement.LeaseDuration != time.Minute ||
				runtimeConfig.Runtime.Settlement.RetryDelay != 2*time.Minute ||
				runtimeConfig.Runtime.Settlement.MaxAttempts != 9 ||
				runtimeConfig.Runtime.WorkerIdlePoll != 250*time.Millisecond ||
				runtimeConfig.Runtime.WorkerErrorBackoff != 2*time.Second ||
				!bytes.Equal(runtimeConfig.Runtime.Service.CursorKey, key) ||
				runtimeDependencies.Pool != configured.Pool || runtimeDependencies.Identity != configured.Identity ||
				runtimeDependencies.IAM != configured.IAM || runtimeDependencies.EvidenceSource != source ||
				runtimeDependencies.Clock == nil {
				t.Fatalf("runtime config=%#v dependencies=%#v", runtimeConfig, runtimeDependencies)
			}
			return worker, nil
		},
	}
	runtime, err := openAndClearIdentityVerificationProductionRuntime(t.Context(), &config, dependencies)
	if err != nil || runtime == nil {
		t.Fatalf("open runtime=(%T,%v)", runtime, err)
	}
	if config.Enabled || config.CursorKey != nil || config.ResolverName != "" || config.WorkerEnabled ||
		config.ReviewTTL != 0 || config.RetentionPeriod != 0 || config.Settlement.Clock != nil ||
		config.Settlement.NewID != nil || config.Settlement.LeaseDuration != 0 ||
		config.Settlement.RetryDelay != 0 || config.Settlement.MaxAttempts != 0 ||
		config.WorkerIdlePoll != 0 || config.WorkerErrorBackoff != 0 ||
		!bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("production opener retained identity verification cursor key")
	}
	factory := runtime.HandlerFactory()
	if factory == nil {
		t.Fatal("enabled runtime returned nil handler factory")
	}
	handler, err := factory()
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/identity-verification/cases", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("handler status=%d", response.Code)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	events = append(events, "shared-pool")
	got := append([]string(nil), events...)
	mu.Unlock()
	if strings.Join(got, ",") != "worker,source,shared-pool" {
		t.Fatalf("shutdown order=%v", got)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 3 {
		t.Fatalf("idempotent close repeated shutdown events: %v", events)
	}
}

func TestIdentityVerificationProductionRuntimeFailsClosedAndDoesNotLeakDependencyErrors(t *testing.T) {
	key := bytes.Repeat([]byte{0x64}, 32)
	config, err := loadIdentityVerificationRuntimeConfigFromEnv(identityVerificationRuntimeEnvironment(key))
	if err != nil {
		t.Fatal(err)
	}
	configured := configuredRuntimeTestDependencies(t)
	base := identityVerificationProductionDependencies{
		Pool: configured.Pool, Identity: configured.Identity, IAM: configured.IAM, Clock: time.Now,
	}
	for name, invalidate := range map[string]func(*identityVerificationProductionDependencies){
		"pool":     func(value *identityVerificationProductionDependencies) { value.Pool = nil },
		"identity": func(value *identityVerificationProductionDependencies) { value.Identity = nil },
		"IAM":      func(value *identityVerificationProductionDependencies) { value.IAM = nil },
		"clock":    func(value *identityVerificationProductionDependencies) { value.Clock = nil },
	} {
		t.Run(name, func(t *testing.T) {
			dependencies := base
			invalidate(&dependencies)
			if runtime, err := openIdentityVerificationProductionRuntime(t.Context(), config, dependencies); err == nil || runtime != nil {
				t.Fatalf("incomplete runtime=(%T,%v)", runtime, err)
			}
		})
	}

	source := &identityVerificationEvidenceSourceStub{}
	dependencies := base
	dependencies.NewEvidenceSource = func(context.Context, identityVerificationEvidenceSourceParameters) (identityVerificationEvidenceSource, error) {
		return nil, errors.New("source-secret-value")
	}
	if runtime, err := openIdentityVerificationProductionRuntime(t.Context(), config, dependencies); err == nil || runtime != nil || strings.Contains(err.Error(), "source-secret-value") {
		t.Fatalf("source failure runtime=(%T,%v)", runtime, err)
	}

	dependencies.NewEvidenceSource = func(context.Context, identityVerificationEvidenceSourceParameters) (identityVerificationEvidenceSource, error) {
		return source, nil
	}
	dependencies.NewRuntime = func(identityverificationhttp.ProductionRuntimeConfig,
		identityverificationhttp.ProductionRuntimeDependencies,
	) (identityVerificationWorkerRuntime, error) {
		return nil, errors.New("worker-secret-value")
	}
	if runtime, err := openIdentityVerificationProductionRuntime(t.Context(), config, dependencies); err == nil || runtime != nil || strings.Contains(err.Error(), "worker-secret-value") || source.closeCalls != 1 {
		t.Fatalf("worker failure runtime=(%T,%v) source closes=%d", runtime, err, source.closeCalls)
	}

	events := make([]string, 0, 2)
	source = &identityVerificationEvidenceSourceStub{onClose: func() {
		events = append(events, "source")
	}}
	worker := &identityVerificationWorkerRuntimeStub{onClose: func() error {
		events = append(events, "worker")
		return nil
	}}
	dependencies.NewEvidenceSource = func(context.Context, identityVerificationEvidenceSourceParameters) (identityVerificationEvidenceSource, error) {
		return source, nil
	}
	dependencies.NewRuntime = func(identityverificationhttp.ProductionRuntimeConfig,
		identityverificationhttp.ProductionRuntimeDependencies,
	) (identityVerificationWorkerRuntime, error) {
		return worker, errors.New("worker-secret-value")
	}
	if runtime, err := openIdentityVerificationProductionRuntime(t.Context(), config, dependencies); err == nil || runtime != nil || strings.Contains(err.Error(), "worker-secret-value") || strings.Join(events, ",") != "worker,source" {
		t.Fatalf("partial worker failure runtime=(%T,%v) shutdown=%v", runtime, err, events)
	}
}

func TestIdentityVerificationReadinessFailsBeforeStartOnSourceFailureAndWorkerTermination(t *testing.T) {
	sourceFailure := errors.New("source unavailable")
	workerFailure := errors.New("worker not running")
	source := &identityVerificationEvidenceSourceStub{readyErr: sourceFailure}
	worker := &identityVerificationWorkerRuntimeStub{readyErr: workerFailure}
	runtime := &identityVerificationProductionRuntime{source: source, worker: worker}
	if err := runtime.Ready(); err == nil || source.readyCalls != 1 || worker.readyCalls != 0 {
		t.Fatalf("source readiness=(%v) source calls=%d worker calls=%d", err, source.readyCalls, worker.readyCalls)
	}
	source.readyErr = nil
	if err := runtime.Ready(); err == nil || source.readyCalls != 2 || worker.readyCalls != 1 {
		t.Fatalf("worker readiness=(%v) source calls=%d worker calls=%d", err, source.readyCalls, worker.readyCalls)
	}
	worker.readyErr = nil
	if err := runtime.Ready(); err != nil {
		t.Fatalf("ready runtime error=%v", err)
	}
}

func identityVerificationRuntimeEnvironment(key []byte) []string {
	return []string{
		identityVerificationEnabledEnv + "=true",
		identityVerificationCursorKeyBase64Env + "=" + base64.StdEncoding.EncodeToString(key),
		identityVerificationResolverNameEnv + "=trusted-kyc",
		identityVerificationReviewTTLEnv + "=72h",
		identityVerificationRetentionPeriodEnv + "=52560h",
		identityVerificationWorkerEnabledEnv + "=true",
		identityVerificationSettlementLeaseDurationEnv + "=1m",
		identityVerificationSettlementRetryDelayEnv + "=2m",
		identityVerificationSettlementMaxAttemptsEnv + "=9",
		identityVerificationWorkerIdlePollEnv + "=250ms",
		identityVerificationWorkerErrorBackoffEnv + "=2s",
	}
}

func replaceIdentityVerificationEnv(environment []string, name, value string) []string {
	result := append([]string(nil), environment...)
	for index := range result {
		if strings.HasPrefix(result[index], name+"=") {
			result[index] = name + "=" + value
			return result
		}
	}
	return append(result, name+"="+value)
}

func removeIdentityVerificationEnv(environment []string, name string) []string {
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		if !strings.HasPrefix(entry, name+"=") {
			result = append(result, entry)
		}
	}
	return result
}

type identityVerificationEvidenceSourceStub struct {
	readyErr   error
	readyCalls int
	closeCalls int
	onClose    func()
}

func (source *identityVerificationEvidenceSourceStub) Ready(context.Context) error {
	source.readyCalls++
	return source.readyErr
}

func (source *identityVerificationEvidenceSourceStub) Close() {
	source.closeCalls++
	if source.onClose != nil {
		source.onClose()
	}
}

func (*identityVerificationEvidenceSourceStub) Capabilities() identityverificationhttp.RuntimeEvidenceSourceCapabilities {
	return identityverificationhttp.RuntimeEvidenceSourceCapabilities{
		TrustedFacts: true, DurableReservations: true, ActorRequestBinding: true,
		AtomicTransitions: true, IdempotentTransitions: true,
	}
}

func (*identityVerificationEvidenceSourceStub) Reserve(context.Context,
	identityverificationhttp.RuntimeEvidenceReserveRequest,
) (identityverificationhttp.RuntimeEvidenceReserveResult, error) {
	return identityverificationhttp.RuntimeEvidenceReserveResult{}, errors.New("unexpected reserve")
}

func (*identityVerificationEvidenceSourceStub) Abort(context.Context, string) error {
	return errors.New("unexpected abort")
}

func (*identityVerificationEvidenceSourceStub) Quarantine(context.Context, string) error {
	return errors.New("unexpected quarantine")
}

func (*identityVerificationEvidenceSourceStub) Publish(context.Context,
	identityverificationhttp.RuntimeEvidencePublishRequest,
) error {
	return errors.New("unexpected publish")
}

type identityVerificationWorkerRuntimeStub struct {
	handler    http.Handler
	readyErr   error
	readyCalls int
	run        func(context.Context) error
	onClose    func() error
}

func (runtime *identityVerificationWorkerRuntimeStub) Handler() http.Handler { return runtime.handler }

func (runtime *identityVerificationWorkerRuntimeStub) Ready() error {
	runtime.readyCalls++
	return runtime.readyErr
}

func (runtime *identityVerificationWorkerRuntimeStub) Run(ctx context.Context) error {
	if runtime.run != nil {
		return runtime.run(ctx)
	}
	<-ctx.Done()
	return nil
}

func (runtime *identityVerificationWorkerRuntimeStub) Close() error {
	if runtime.onClose != nil {
		return runtime.onClose()
	}
	return nil
}
