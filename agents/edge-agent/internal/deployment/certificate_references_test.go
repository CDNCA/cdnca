package deployment

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/httppolicy"
)

const (
	testCertificateScope = "018f47a2-5b9c-7d31-8a60-104c9c0b7101"
	testCertificateSite  = "018f47a2-5b9c-7d31-8a60-104c9c0b7103"
	testCertificateV1    = "018f47a2-5b9c-7d31-8a60-104c9c0b7104"
	testCertificateV2    = "018f47a2-5b9c-7d31-8a60-104c9c0b7105"
	testConfigV1         = "018f47a2-5b9c-7d31-8a60-104c9c0b7111"
	testConfigV2         = "018f47a2-5b9c-7d31-8a60-104c9c0b7112"
)

type testCertificateVersionStore struct {
	mu              sync.Mutex
	root            string
	references      certstore.CertificateVersionReferences
	versions        map[string]certstore.ResolvedCertificateVersion
	resolveRequests []certstore.CertificateResolveRequest
	setCalls        []certstore.CertificateVersionReferences
	setFailures     map[int]error
	resolveErr      error
	mutateResolved  func(certstore.ResolvedCertificateVersion) certstore.ResolvedCertificateVersion
}

func newTestCertificateVersionStore(t *testing.T) *testCertificateVersionStore {
	t.Helper()
	root := t.TempDir()
	certificatePath := filepath.Join(root, "versions", "certificate.pem")
	privateKeyPath := filepath.Join(root, "versions", "private-key.pem")
	if err := os.MkdirAll(filepath.Dir(certificatePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certificatePath, []byte("certificate"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyPath, []byte("private-key"), 0o400); err != nil {
		t.Fatal(err)
	}
	versions := make(map[string]certstore.ResolvedCertificateVersion, 2)
	for _, version := range []string{testCertificateV1, testCertificateV2} {
		versions[version] = certstore.ResolvedCertificateVersion{
			TenantScopeID: testCertificateScope, SiteID: testCertificateSite,
			CertificateVersionID: version, Domains: []string{"cdn.example.test", "static.example.test"},
			CertificatePath: certificatePath, PrivateKeyPath: privateKeyPath,
		}
	}
	return &testCertificateVersionStore{root: root, versions: versions}
}

func (store *testCertificateVersionStore) CertificateVersionReferences(context.Context) (certstore.CertificateVersionReferences, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneTestCertificateReferences(store.references), nil
}

func (store *testCertificateVersionStore) SetCertificateVersionReferences(_ context.Context, references certstore.CertificateVersionReferences) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.setCalls = append(store.setCalls, cloneTestCertificateReferences(references))
	if err := store.setFailures[len(store.setCalls)]; err != nil {
		return err
	}
	store.references = cloneTestCertificateReferences(references)
	return nil
}

func (store *testCertificateVersionStore) ResolveCertificateVersion(_ context.Context, request certstore.CertificateResolveRequest) (certstore.ResolvedCertificateVersion, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.resolveRequests = append(store.resolveRequests, request)
	if store.resolveErr != nil {
		return certstore.ResolvedCertificateVersion{}, store.resolveErr
	}
	resolved, exists := store.versions[request.CertificateVersionID]
	if !exists || request.TenantScopeID != resolved.TenantScopeID || request.SiteID != resolved.SiteID ||
		!containsTestString(resolved.Domains, request.Domain) {
		return certstore.ResolvedCertificateVersion{}, certstore.ErrCertificateUnavailable
	}
	if store.mutateResolved != nil {
		resolved = store.mutateResolved(resolved)
	}
	return resolved, nil
}

func cloneTestCertificateReferences(value certstore.CertificateVersionReferences) certstore.CertificateVersionReferences {
	return certstore.CertificateVersionReferences{
		Current: append([]string(nil), value.Current...), Previous: append([]string(nil), value.Previous...),
	}
}

func containsTestString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func newCertificateDeploymentManager(t *testing.T, root string, runtime Runtime, certificates *testCertificateVersionStore) *Manager {
	t.Helper()
	config := DefaultConfig()
	config.HealthTimeout = defaultTestHealthTimeout
	config.HealthInterval = defaultTestHealthInterval
	manager, err := NewManagerWithCertificateVersionStore(
		root, &fakePrechecker{failFor: map[string]error{}}, runtime, config, certificates, certificates.root,
	)
	if err != nil {
		t.Fatalf("NewManagerWithCertificateVersionStore() error = %v", err)
	}
	t.Cleanup(func() { makeTreeWritable(root) })
	return manager
}

const (
	defaultTestHealthTimeout  = 20_000_000
	defaultTestHealthInterval = 1_000_000
)

func certificateRuntimeDocument(t *testing.T, configVersionID, certificateVersionID string) []byte {
	t.Helper()
	document := map[string]any{
		"schema": "cdnca.edge.site-runtime/v2", "configuration_scope_id": testCertificateScope,
		"source_revision": 1, "config_version_id": configVersionID,
		"sites": []any{map[string]any{
			"id": testCertificateSite, "revision": 1,
			"domains": []any{"cdn.example.test", "static.example.test"},
			"listeners": []any{map[string]any{
				"id": "public-443", "position": 0, "address_family": "ipv4", "port": 443,
				"protocols": []any{"http1"}, "tls": map[string]any{"certificate_version_id": certificateVersionID},
			}},
			"origin_pools": []any{map[string]any{
				"id": "primary", "position": 0, "kind": "origin", "algorithm": "round_robin",
				"origins": []any{map[string]any{
					"id": "origin-a", "position": 0, "tier": "origin", "scheme": "http",
					"host": "192.0.2.10", "port": 8080, "weight": 100,
				}},
				"retry": map[string]any{
					"methods": []any{"GET", "HEAD"}, "bodyless_only": true, "response_not_started": true,
					"retry_on":     []any{"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"},
					"max_attempts": 3, "connect_timeout_ms": 3000, "read_timeout_ms": 30000, "total_budget_ms": 60000,
				},
			}},
			"default_pool_id": "primary", "websocket": false, "range": true,
			"l2": map[string]any{
				"enabled": false, "probe_interval_ms": 10000, "failure_threshold": 3,
				"recovery_threshold": 3, "single_half_open_probe": true, "max_hops": 1,
			},
		}},
		"required_capabilities": []any{
			map[string]any{"name": "http1", "api_version": 1},
			map[string]any{"name": "ipv4", "api_version": 1},
			map[string]any{"name": "site_runtime", "api_version": 6},
		},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A release with an HTTP policy binding declares the same v6 baseline.
func TestCertificateReferenceLoaderAcceptsHTTPPolicyRelease(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deployment")
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	certificates := newTestCertificateVersionStore(t)
	manager := newCertificateDeploymentManager(t, root, runtime, certificates)
	raw := certificateRuntimeDocument(t, testConfigV1, testCertificateV1)
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	policyRaw, err := json.Marshal(httppolicy.Policy{
		SchemaVersion: httppolicy.SchemaVersion, PolicyVersion: 1,
		Sites: []httppolicy.SitePolicy{{
			SiteID: testCertificateSite, MaxUploadBytes: 1024,
			RequestHeaders: []httppolicy.HeaderAction{}, ResponseHeaders: []httppolicy.HeaderAction{},
			Rewrites: []httppolicy.RewriteRule{}, RedirectAllowedHosts: []string{}, Redirects: []httppolicy.RedirectRule{},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := httppolicy.CompileJSON(policyRaw)
	if err != nil {
		t.Fatal(err)
	}
	document["sites"].([]any)[0].(map[string]any)["http_policy"] = map[string]any{
		"policy_id": "018f47a2-5b9c-7d31-8a60-104c9c0b7190", "policy_revision": float64(1),
		"artifact_sha256": hex.EncodeToString(policy.Digest[:]),
	}
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	command := testCommand(t, "certificate-v3", 1, testConfigV1, "", map[string][]byte{
		siteRuntimeV2File: raw, "http-policy.v1.json": policy.Canonical,
	})
	result, err := manager.Process(t.Context(), command)
	if err != nil || result.State != StateHealthy {
		t.Fatalf("Process(HTTP policy release) = (%+v, %v)", result, err)
	}
}

func certificateDeploymentCommand(t *testing.T, deploymentID string, attempt uint32, configVersionID, previousVersionID, certificateVersionID string) Command {
	t.Helper()
	return testCommand(t, deploymentID, attempt, configVersionID, previousVersionID, map[string][]byte{
		"site-runtime.v2.json": certificateRuntimeDocument(t, configVersionID, certificateVersionID),
	})
}

func TestCertificateReferencesAdvanceCurrentAndPreviousBeforeReload(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deployment")
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	certificates := newTestCertificateVersionStore(t)
	manager := newCertificateDeploymentManager(t, root, runtime, certificates)

	for _, command := range []Command{
		certificateDeploymentCommand(t, "certificate-v1", 1, testConfigV1, "", testCertificateV1),
		certificateDeploymentCommand(t, "certificate-v2", 1, testConfigV2, testConfigV1, testCertificateV2),
	} {
		result, err := manager.Process(t.Context(), command)
		if err != nil || result.State != StateHealthy {
			t.Fatalf("Process(%s) = (%+v, %v)", command.ConfigVersionID, result, err)
		}
	}

	want := certstore.CertificateVersionReferences{Current: []string{testCertificateV2}, Previous: []string{testCertificateV1}}
	if !reflect.DeepEqual(certificates.references, want) {
		t.Fatalf("references = %+v, want %+v", certificates.references, want)
	}
	wantRequests := []certstore.CertificateResolveRequest{
		{TenantScopeID: testCertificateScope, SiteID: testCertificateSite, CertificateVersionID: testCertificateV1, Domain: "cdn.example.test"},
		{TenantScopeID: testCertificateScope, SiteID: testCertificateSite, CertificateVersionID: testCertificateV1, Domain: "static.example.test"},
		{TenantScopeID: testCertificateScope, SiteID: testCertificateSite, CertificateVersionID: testCertificateV2, Domain: "cdn.example.test"},
		{TenantScopeID: testCertificateScope, SiteID: testCertificateSite, CertificateVersionID: testCertificateV2, Domain: "static.example.test"},
	}
	if !reflect.DeepEqual(certificates.resolveRequests, wantRequests) {
		t.Fatalf("Resolve requests = %+v, want %+v", certificates.resolveRequests, wantRequests)
	}
	if got := runtime.activationList(); !reflect.DeepEqual(got, []string{testConfigV1, testConfigV2}) {
		t.Fatalf("reloads = %v", got)
	}
}

func TestCertificateReferenceFailureIsFailClosedBeforePointerAndReload(t *testing.T) {
	mutations := map[string]func(certstore.ResolvedCertificateVersion) certstore.ResolvedCertificateVersion{
		"scope": func(value certstore.ResolvedCertificateVersion) certstore.ResolvedCertificateVersion {
			value.TenantScopeID = testCertificateV2
			return value
		},
		"site": func(value certstore.ResolvedCertificateVersion) certstore.ResolvedCertificateVersion {
			value.SiteID = testCertificateScope
			return value
		},
		"version": func(value certstore.ResolvedCertificateVersion) certstore.ResolvedCertificateVersion {
			value.CertificateVersionID = testCertificateV2
			return value
		},
		"domain": func(value certstore.ResolvedCertificateVersion) certstore.ResolvedCertificateVersion {
			value.Domains = []string{"other.example.test"}
			return value
		},
		"certificate-path": func(value certstore.ResolvedCertificateVersion) certstore.ResolvedCertificateVersion {
			value.CertificatePath = filepath.Join(t.TempDir(), "outside.pem")
			return value
		},
		"private-key-path": func(value certstore.ResolvedCertificateVersion) certstore.ResolvedCertificateVersion {
			value.PrivateKeyPath = filepath.Join(t.TempDir(), "outside.key")
			return value
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "deployment")
			runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
			certificates := newTestCertificateVersionStore(t)
			certificates.mutateResolved = mutate
			manager := newCertificateDeploymentManager(t, root, runtime, certificates)

			result, err := manager.Process(t.Context(), certificateDeploymentCommand(t, "invalid-resolve-"+name, 1, testConfigV1, "", testCertificateV1))
			if err != nil || result.State != StateFailed || !result.RunningConfigUnchanged {
				t.Fatalf("Process() = (%+v, %v), want unchanged failure", result, err)
			}
			if got := runtime.activationList(); len(got) != 0 {
				t.Fatalf("reloads = %v, want none", got)
			}
			if pointers, pointerErr := manager.Pointers(); pointerErr != nil || pointers != (Pointers{}) {
				t.Fatalf("Pointers() = (%+v, %v)", pointers, pointerErr)
			}
			if !reflect.DeepEqual(certificates.references, certstore.CertificateVersionReferences{}) {
				t.Fatalf("references were not restored: %+v", certificates.references)
			}
		})
	}
}

func TestCertificateReferenceRejectsInvalidDocumentAndNumericVersion(t *testing.T) {
	for _, version := range []string{"7", "018F47A2-5B9C-7D31-8A60-104C9C0B7104", "not-a-uuid"} {
		t.Run(version, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "deployment")
			runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
			certificates := newTestCertificateVersionStore(t)
			manager := newCertificateDeploymentManager(t, root, runtime, certificates)
			result, err := manager.Process(t.Context(), certificateDeploymentCommand(t, "invalid-certificate-version", 1, testConfigV1, "", version))
			if err != nil || result.State != StateFailed || !result.RunningConfigUnchanged {
				t.Fatalf("Process() = (%+v, %v), want unchanged failure", result, err)
			}
			if len(certificates.setCalls) != 0 || len(runtime.activationList()) != 0 {
				t.Fatalf("invalid version caused side effects: sets=%v reloads=%v", certificates.setCalls, runtime.activationList())
			}
		})
	}
}

func TestCertificateResolveFailureRestoresReferencesAndRelease(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deployment")
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	certificates := newTestCertificateVersionStore(t)
	manager := newCertificateDeploymentManager(t, root, runtime, certificates)
	first := certificateDeploymentCommand(t, "resolve-restore-v1", 1, testConfigV1, "", testCertificateV1)
	if result, err := manager.Process(t.Context(), first); err != nil || result.State != StateHealthy {
		t.Fatalf("Process(v1) = (%+v, %v)", result, err)
	}
	before := cloneTestCertificateReferences(certificates.references)
	certificates.resolveErr = errors.New("resolve failed")
	result, err := manager.Process(t.Context(), certificateDeploymentCommand(t, "resolve-restore-v2", 1, testConfigV2, testConfigV1, testCertificateV2))
	if err != nil || result.State != StateFailed || !result.RunningConfigUnchanged {
		t.Fatalf("Process(v2) = (%+v, %v)", result, err)
	}
	if !reflect.DeepEqual(certificates.references, before) {
		t.Fatalf("references = %+v, want restored %+v", certificates.references, before)
	}
	if pointers, pointerErr := manager.Pointers(); pointerErr != nil || pointers.Current != testConfigV1 {
		t.Fatalf("Pointers() = (%+v, %v)", pointers, pointerErr)
	}
	if got := runtime.activationList(); !reflect.DeepEqual(got, []string{testConfigV1}) {
		t.Fatalf("reloads = %v, want only v1", got)
	}
}

func TestCertificateReferenceWriteFailureIsFailClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deployment")
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	certificates := newTestCertificateVersionStore(t)
	certificates.setFailures = map[int]error{1: errors.New("reference write failed")}
	manager := newCertificateDeploymentManager(t, root, runtime, certificates)
	result, err := manager.Process(t.Context(), certificateDeploymentCommand(t, "reference-write-failure", 1, testConfigV1, "", testCertificateV1))
	if err != nil || result.State != StateFailed || !result.RunningConfigUnchanged {
		t.Fatalf("Process() = (%+v, %v), want unchanged failure", result, err)
	}
	if pointers, pointerErr := manager.Pointers(); pointerErr != nil || pointers != (Pointers{}) {
		t.Fatalf("Pointers() = (%+v, %v)", pointers, pointerErr)
	}
	if len(runtime.activationList()) != 0 {
		t.Fatalf("reload occurred after reference write failure: %v", runtime.activationList())
	}
}

func TestCertificateReferenceRestoreFailureIsRollbackFailed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deployment")
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	certificates := newTestCertificateVersionStore(t)
	certificates.resolveErr = errors.New("resolve failed")
	certificates.setFailures = map[int]error{2: errors.New("reference restore failed")}
	manager := newCertificateDeploymentManager(t, root, runtime, certificates)
	result, err := manager.Process(t.Context(), certificateDeploymentCommand(t, "reference-restore-failure", 1, testConfigV1, "", testCertificateV1))
	if err != nil || result.State != StateRollbackFailed || result.RunningConfigUnchanged {
		t.Fatalf("Process() = (%+v, %v), want rollback_failed", result, err)
	}
	if pointers, pointerErr := manager.Pointers(); pointerErr != nil || pointers != (Pointers{}) {
		t.Fatalf("Pointers() = (%+v, %v)", pointers, pointerErr)
	}
	if len(runtime.activationList()) != 0 {
		t.Fatalf("reload occurred after reference restore failure: %v", runtime.activationList())
	}
}

func TestCertificateReferencesRestoreAfterReloadFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deployment")
	runtime := &fakeRuntime{
		activationFailures: map[string]map[int]error{testConfigV2: {1: errors.New("reload failed")}},
		healthFailures:     map[string]error{},
	}
	certificates := newTestCertificateVersionStore(t)
	manager := newCertificateDeploymentManager(t, root, runtime, certificates)
	if result, err := manager.Process(t.Context(), certificateDeploymentCommand(t, "reload-restore-v1", 1, testConfigV1, "", testCertificateV1)); err != nil || result.State != StateHealthy {
		t.Fatalf("Process(v1) = (%+v, %v)", result, err)
	}
	result, err := manager.Process(t.Context(), certificateDeploymentCommand(t, "reload-restore-v2", 1, testConfigV2, testConfigV1, testCertificateV2))
	if err != nil || result.State != StateFailed || !result.RunningConfigUnchanged {
		t.Fatalf("Process(v2) = (%+v, %v)", result, err)
	}
	want := certstore.CertificateVersionReferences{Current: []string{testCertificateV1}}
	if !reflect.DeepEqual(certificates.references, want) {
		t.Fatalf("references = %+v, want %+v", certificates.references, want)
	}
	if pointers, pointerErr := manager.Pointers(); pointerErr != nil || pointers.Current != testConfigV1 {
		t.Fatalf("Pointers() = (%+v, %v)", pointers, pointerErr)
	}
	if got := runtime.activationList(); !reflect.DeepEqual(got, []string{testConfigV1, testConfigV2, testConfigV1}) {
		t.Fatalf("reloads = %v", got)
	}
}

func TestCertificateReferencesFollowAutomaticHealthRollback(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deployment")
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	certificates := newTestCertificateVersionStore(t)
	manager := newCertificateDeploymentManager(t, root, runtime, certificates)
	if result, err := manager.Process(t.Context(), certificateDeploymentCommand(t, "health-rollback-v1", 1, testConfigV1, "", testCertificateV1)); err != nil || result.State != StateHealthy {
		t.Fatalf("Process(v1) = (%+v, %v)", result, err)
	}
	runtime.healthFailures[testConfigV2] = errors.New("unhealthy")
	result, err := manager.Process(t.Context(), certificateDeploymentCommand(t, "health-rollback-v2", 1, testConfigV2, testConfigV1, testCertificateV2))
	if err != nil || result.State != StateReverted {
		t.Fatalf("Process(v2) = (%+v, %v)", result, err)
	}
	want := certstore.CertificateVersionReferences{Current: []string{testCertificateV1}}
	if !reflect.DeepEqual(certificates.references, want) {
		t.Fatalf("references = %+v, want %+v", certificates.references, want)
	}
	if pointers, pointerErr := manager.Pointers(); pointerErr != nil || pointers.Current != testConfigV1 || pointers.Previous != "" {
		t.Fatalf("Pointers() = (%+v, %v)", pointers, pointerErr)
	}
	certificates.references = certstore.CertificateVersionReferences{Current: []string{testCertificateV2}}
	restarted := newCertificateDeploymentManager(t, root, runtime, certificates)
	if err := restarted.RecoverCertificateVersionReferences(t.Context()); err != nil {
		t.Fatalf("RecoverCertificateVersionReferences() error = %v", err)
	}
	if !reflect.DeepEqual(certificates.references, want) {
		t.Fatalf("recovered references = %+v, want %+v", certificates.references, want)
	}
}

type rollbackFailureRuntime struct {
	mu             sync.Mutex
	reloads        []string
	healthCalls    map[string]int
	reloadFailures map[string]map[int]error
	healthFailures map[string]map[int]error
	blockHealth    map[string]map[int]bool
}

func (runtime *rollbackFailureRuntime) Reload(_ context.Context, versionID, _ string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.reloads = append(runtime.reloads, versionID)
	call := 0
	for _, value := range runtime.reloads {
		if value == versionID {
			call++
		}
	}
	return runtime.reloadFailures[versionID][call]
}

func (runtime *rollbackFailureRuntime) Healthy(ctx context.Context, versionID string) error {
	runtime.mu.Lock()
	runtime.healthCalls[versionID]++
	call := runtime.healthCalls[versionID]
	blocked := runtime.blockHealth[versionID][call]
	err := runtime.healthFailures[versionID][call]
	runtime.mu.Unlock()
	if blocked {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

func TestCertificateAutomaticRollbackFailuresRestoreCandidatePointerAndReferences(t *testing.T) {
	for _, failure := range []string{"pointer", "reload", "health", "save-state"} {
		t.Run(failure, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "deployment")
			runtime := &rollbackFailureRuntime{
				healthCalls: map[string]int{}, reloadFailures: map[string]map[int]error{},
				healthFailures: map[string]map[int]error{},
				blockHealth:    map[string]map[int]bool{testConfigV2: {1: true}},
			}
			certificates := newTestCertificateVersionStore(t)
			manager := newCertificateDeploymentManager(t, root, runtime, certificates)
			v1 := certificateDeploymentCommand(t, "rollback-failure-v1-"+failure, 1, testConfigV1, "", testCertificateV1)
			v2 := certificateDeploymentCommand(t, "rollback-failure-v2-"+failure, 1, testConfigV2, testConfigV1, testCertificateV2)
			if result, err := manager.Process(t.Context(), v1); err != nil || result.State != StateHealthy {
				t.Fatalf("Process(v1) = (%+v, %v)", result, err)
			}
			switch failure {
			case "pointer":
				failed := false
				manager.switchCurrent = func(digest string) error {
					if digest == v1.Bundle.ManifestSHA256 && !failed {
						failed = true
						return errors.New("rollback pointer failed")
					}
					return manager.store.switchCurrent(digest)
				}
			case "reload":
				runtime.reloadFailures[testConfigV1] = map[int]error{2: errors.New("rollback reload failed")}
			case "health":
				runtime.blockHealth[testConfigV1] = map[int]bool{2: true}
			case "save-state":
				failed := false
				manager.savePointers = func(pointers Pointers) error {
					if pointers.Current == testConfigV1 && !failed {
						failed = true
						return errors.New("rollback pointer state failed")
					}
					return manager.store.savePointers(pointers)
				}
			}
			result, err := manager.Process(t.Context(), v2)
			if err != nil || result.State != StateRollbackFailed {
				t.Fatalf("Process(v2) = (%+v, %v), want rollback_failed", result, err)
			}
			wantPointers := Pointers{
				Current: testConfigV2, CurrentDigest: v2.Bundle.ManifestSHA256,
				Previous: testConfigV1, PreviousDigest: v1.Bundle.ManifestSHA256,
			}
			if pointers, pointerErr := manager.Pointers(); pointerErr != nil || pointers != wantPointers {
				t.Fatalf("Pointers() = (%+v, %v), want %+v", pointers, pointerErr, wantPointers)
			}
			if active, activeErr := manager.store.currentDigest(); activeErr != nil || active != v2.Bundle.ManifestSHA256 {
				t.Fatalf("currentDigest() = (%q, %v)", active, activeErr)
			}
			wantReferences := certstore.CertificateVersionReferences{Current: []string{testCertificateV2}, Previous: []string{testCertificateV1}}
			if !reflect.DeepEqual(certificates.references, wantReferences) {
				t.Fatalf("references = %+v, want %+v", certificates.references, wantReferences)
			}
			restarted := newCertificateDeploymentManager(t, root, runtime, certificates)
			if err := restarted.RecoverCertificateVersionReferences(t.Context()); err != nil {
				t.Fatalf("RecoverCertificateVersionReferences() error = %v", err)
			}
		})
	}
}

func TestCertificateReferencesFollowExplicitRollbackAndRestartRecovery(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deployment")
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	certificates := newTestCertificateVersionStore(t)
	manager := newCertificateDeploymentManager(t, root, runtime, certificates)
	for _, command := range []Command{
		certificateDeploymentCommand(t, "rollback-cert-v1", 1, testConfigV1, "", testCertificateV1),
		certificateDeploymentCommand(t, "rollback-cert-v2", 1, testConfigV2, testConfigV1, testCertificateV2),
	} {
		if result, err := manager.Process(t.Context(), command); err != nil || result.State != StateHealthy {
			t.Fatalf("Process(%s) = (%+v, %v)", command.ConfigVersionID, result, err)
		}
	}
	rollback := testRollbackCommand("rollback-cert", testConfigV1, testConfigV2)
	if result, err := manager.Process(t.Context(), rollback); err != nil || result.State != StateReverted {
		t.Fatalf("Process(rollback) = (%+v, %v)", result, err)
	}
	want := certstore.CertificateVersionReferences{Current: []string{testCertificateV1}, Previous: []string{testCertificateV2}}
	if !reflect.DeepEqual(certificates.references, want) {
		t.Fatalf("references = %+v, want %+v", certificates.references, want)
	}

	certificates.references = certstore.CertificateVersionReferences{}
	restarted := newCertificateDeploymentManager(t, root, runtime, certificates)
	if err := restarted.RecoverCertificateVersionReferences(t.Context()); err != nil {
		t.Fatalf("RecoverCertificateVersionReferences() error = %v", err)
	}
	if !reflect.DeepEqual(certificates.references, want) {
		t.Fatalf("recovered references = %+v, want %+v", certificates.references, want)
	}
}

func TestCertificateReferencesLegacyTransitionAndRestartClearStalePins(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deployment")
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	certificates := newTestCertificateVersionStore(t)
	manager := newCertificateDeploymentManager(t, root, runtime, certificates)
	v2 := certificateDeploymentCommand(t, "legacy-clear-v2", 1, testConfigV1, "", testCertificateV1)
	if result, err := manager.Process(t.Context(), v2); err != nil || result.State != StateHealthy {
		t.Fatalf("Process(v2) = (%+v, %v)", result, err)
	}
	legacy1 := testCommand(t, "legacy-clear-1", 1, "legacy-v1", testConfigV1, map[string][]byte{"nginx/site.conf": []byte("server { listen 80; }")})
	if result, err := manager.Process(t.Context(), legacy1); err != nil || result.State != StateHealthy {
		t.Fatalf("Process(legacy1) = (%+v, %v)", result, err)
	}
	legacy2 := testCommand(t, "legacy-clear-2", 1, "legacy-v2", "legacy-v1", map[string][]byte{"nginx/site.conf": []byte("server { listen 8080; }")})
	if result, err := manager.Process(t.Context(), legacy2); err != nil || result.State != StateHealthy {
		t.Fatalf("Process(legacy2) = (%+v, %v)", result, err)
	}
	if !reflect.DeepEqual(certificates.references, certstore.CertificateVersionReferences{}) {
		t.Fatalf("legacy transition retained references: %+v", certificates.references)
	}
	certificates.references = certstore.CertificateVersionReferences{
		Current: []string{testCertificateV2}, Previous: []string{testCertificateV1},
	}
	restarted := newCertificateDeploymentManager(t, root, runtime, certificates)
	if err := restarted.RecoverCertificateVersionReferences(t.Context()); err != nil {
		t.Fatalf("RecoverCertificateVersionReferences() error = %v", err)
	}
	if !reflect.DeepEqual(certificates.references, certstore.CertificateVersionReferences{}) {
		t.Fatalf("restart retained stale references: %+v", certificates.references)
	}
}

func TestCertificateReferenceResolutionPrecedesReloadButDoesNotClaimNginxConsumption(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deployment")
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	certificates := newTestCertificateVersionStore(t)
	manager := newCertificateDeploymentManager(t, root, runtime, certificates)
	if result, err := manager.Process(t.Context(), certificateDeploymentCommand(t, "resolution-boundary", 1, testConfigV1, "", testCertificateV1)); err != nil || result.State != StateHealthy {
		t.Fatalf("Process() = (%+v, %v)", result, err)
	}
	if len(certificates.resolveRequests) != 2 || !reflect.DeepEqual(runtime.activationList(), []string{testConfigV1}) {
		t.Fatalf("unexpected resolve/reload evidence: resolves=%v reloads=%v", certificates.resolveRequests, runtime.activationList())
	}
	// The deployment Runtime contract only reports reload/health; it cannot prove that Nginx consumed either resolved path.
}

func TestCertificateReferenceRequestsAreDeterministicAcrossManagers(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deployment")
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	certificates := newTestCertificateVersionStore(t)
	first := newCertificateDeploymentManager(t, root, runtime, certificates)
	second := newCertificateDeploymentManager(t, root, runtime, certificates)
	commands := []Command{
		certificateDeploymentCommand(t, "concurrent-cert-a", 1, testConfigV1, "", testCertificateV1),
		certificateDeploymentCommand(t, "concurrent-cert-b", 1, testConfigV2, "", testCertificateV2),
	}
	var wait sync.WaitGroup
	results := make(chan Result, 2)
	for index, manager := range []*Manager{first, second} {
		wait.Add(1)
		go func(manager *Manager, command Command) {
			defer wait.Done()
			result, _ := manager.Process(context.Background(), command)
			results <- result
		}(manager, commands[index])
	}
	wait.Wait()
	close(results)
	states := make([]State, 0, 2)
	for result := range results {
		states = append(states, result.State)
	}
	sort.Slice(states, func(left, right int) bool { return states[left] < states[right] })
	if !reflect.DeepEqual(states, []State{StateFailed, StateHealthy}) {
		t.Fatalf("states = %v, want one failed and one healthy", states)
	}
	if len(certificates.references.Current) != 1 {
		t.Fatalf("references = %+v", certificates.references)
	}
}
