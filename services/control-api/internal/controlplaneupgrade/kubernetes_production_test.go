package controlplaneupgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestKubernetesProductionMigrationJobAndMixedRolloutGate(t *testing.T) {
	oldDigest := strings.Repeat("62", 32)
	newDigest := strings.Repeat("63", 32)
	var mu sync.Mutex
	observedGeneration, updatedReplicas := int64(8), 2
	var jobs []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/deployments/"):
			_, _ = fmt.Fprintf(writer, `{"metadata":{"resourceVersion":"7","generation":9},"spec":{"replicas":2,"minReadySeconds":10,"strategy":{"type":"RollingUpdate","rollingUpdate":{"maxUnavailable":0,"maxSurge":1}},"template":{"spec":{"containers":[{"name":"control-api","image":"registry.example.invalid/cdnca/control-api@sha256:%s","env":[{"name":"CONTROL_VERSION","value":"1.4.0"},{"name":"CONTROL_ARTIFACT_SHA256","value":"%s"}]}]}}},"status":{"observedGeneration":%d,"readyReplicas":2,"availableReplicas":2,"updatedReplicas":%d,"unavailableReplicas":0}}`, oldDigest, oldDigest, observedGeneration, updatedReplicas)
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/jobs"):
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			jobs = append(jobs, body)
			body["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Complete", "status": "True"}}}
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(body)
		default:
			http.Error(writer, request.Method+" "+request.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()

	executor, err := NewKubernetesExecutor(KubernetesConfig{
		APIServer: server.URL, Namespace: "cdnca", Deployment: "cdnca-control-api", Container: "control-api",
		ImageRepository: "registry.example.invalid/cdnca/control-api", ServiceAccount: "cdnca-control-upgrade-migration",
		DatabaseSecret: "cdnca-customer-datastores", DatabaseSecretKey: "database-url",
		InstallationID: "00000000-0000-4000-8000-000000000005", ProtocolVersion: 2,
		InternalURL: server.URL, InternalToken: "internal-token-32-bytes-long-value",
		HTTPClient: server.Client(), PollInterval: time.Millisecond, HealthTimeout: time.Minute,
		StepTimeout: 20 * time.Second, ImagePullSecrets: []string{"registry-primary", "registry-fallback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := adapterTestPlan(oldDigest, newDigest)
	if err := executor.Preflight(t.Context(), plan); !errors.Is(err, ErrTargetMismatch) {
		t.Fatalf("stale observed generation error = %v", err)
	}
	mu.Lock()
	observedGeneration, updatedReplicas = 9, 1
	mu.Unlock()
	if err := executor.Preflight(t.Context(), plan); !errors.Is(err, ErrTargetMismatch) {
		t.Fatalf("mixed rollout error = %v", err)
	}
	mu.Lock()
	updatedReplicas = 2
	mu.Unlock()
	if err := executor.Preflight(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if err := executor.Expand(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("migration jobs = %d", len(jobs))
	}
	jobSpec := jobs[0]["spec"].(map[string]any)
	if intValue(jobSpec["activeDeadlineSeconds"]) != 20 {
		t.Fatalf("active deadline = %v", jobSpec["activeDeadlineSeconds"])
	}
	podSpec := jobSpec["template"].(map[string]any)["spec"].(map[string]any)
	if podSpec["automountServiceAccountToken"] != false || podSpec["enableServiceLinks"] != false {
		t.Fatalf("pod isolation = %#v", podSpec)
	}
	pullSecrets := podSpec["imagePullSecrets"].([]any)
	if fmt.Sprint(pullSecrets) != "[map[name:registry-primary] map[name:registry-fallback]]" {
		t.Fatalf("image pull secrets = %#v", pullSecrets)
	}
	podSecurity := podSpec["securityContext"].(map[string]any)
	if podSecurity["seccompProfile"].(map[string]any)["type"] != "RuntimeDefault" {
		t.Fatalf("pod security context = %#v", podSecurity)
	}
	container := podSpec["containers"].([]any)[0].(map[string]any)
	security := container["securityContext"].(map[string]any)
	capabilities := security["capabilities"].(map[string]any)
	if security["runAsNonRoot"] != true || security["allowPrivilegeEscalation"] != false ||
		security["readOnlyRootFilesystem"] != true || fmt.Sprint(capabilities["drop"]) != "[ALL]" {
		t.Fatalf("container security context = %#v", security)
	}
	if fmt.Sprint(container["volumeMounts"]) != "[map[mountPath:/tmp name:tmp]]" ||
		fmt.Sprint(podSpec["volumes"]) != "[map[emptyDir:map[] name:tmp]]" {
		t.Fatalf("migration tmp volume is not isolated: container=%#v pod=%#v", container, podSpec)
	}
}

func TestKubernetesProductionMigrationHasIndependentDeadline(t *testing.T) {
	oldDigest := strings.Repeat("72", 32)
	newDigest := strings.Repeat("73", 32)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/jobs") {
			var body map[string]any
			_ = json.NewDecoder(request.Body).Decode(&body)
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(body)
			return
		}
		if request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/jobs/") {
			<-request.Context().Done()
			return
		}
		http.Error(writer, "not found", http.StatusNotFound)
	}))
	defer server.Close()
	executor, err := NewKubernetesExecutor(KubernetesConfig{
		APIServer: server.URL, Namespace: "cdnca", Deployment: "cdnca-control-api", Container: "control-api",
		ImageRepository: "registry.example.invalid/cdnca/control-api", ServiceAccount: "cdnca-control-upgrade-migration",
		DatabaseSecret: "cdnca-customer-datastores", DatabaseSecretKey: "database-url",
		InstallationID: "00000000-0000-4000-8000-000000000005", ProtocolVersion: 2,
		InternalURL: server.URL, InternalToken: "internal-token-32-bytes-long-value",
		HTTPClient: server.Client(), PollInterval: time.Millisecond, StepTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	executor.config.StepTimeout = 15 * time.Millisecond
	err = executor.Expand(context.Background(), adapterTestPlan(oldDigest, newDigest))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("migration deadline error = %v", err)
	}
}
