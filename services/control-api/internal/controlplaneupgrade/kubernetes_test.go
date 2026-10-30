package controlplaneupgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestKubernetesExecutorUsesDigestCASJobsAndAvailabilityGate(t *testing.T) {
	oldDigest := strings.Repeat("52", 32)
	newDigest := strings.Repeat("51", 32)
	var mu sync.Mutex
	currentImage := "registry.example.invalid/cdnca/control-api@sha256:" + oldDigest
	currentVersion := "1.4.0"
	currentArtifactDigest := oldDigest
	resourceVersion := "7"
	var phases []string
	var jobs []map[string]any
	var patches [][]map[string]any
	var controlCalls []string
	const internalToken = "internal-token-32-bytes-long-value"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(request.URL.Path, "/v1/internal/control-upgrade/"):
			if request.Header.Get("Authorization") != "Bearer "+internalToken {
				http.Error(writer, "unauthorized", http.StatusUnauthorized)
				return
			}
			controlCalls = append(controlCalls, request.URL.Path)
			if request.Method == http.MethodGet {
				_, _ = fmt.Fprintf(writer, `{"phase":"draining","plan_id":"00000000-0000-4000-8000-000000000002","quorum":2,"replicas":[{"replica_id":"control-0","version":%q,"digest":%q,"observed_at":1800000000},{"replica_id":"control-1","version":%q,"digest":%q,"observed_at":1800000000}]}`, currentVersion, currentArtifactDigest, currentVersion, currentArtifactDigest)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/deployments/"):
			_, _ = fmt.Fprintf(writer, `{"metadata":{"resourceVersion":%q,"generation":9},"spec":{"replicas":2,"minReadySeconds":10,"strategy":{"type":"RollingUpdate","rollingUpdate":{"maxUnavailable":0,"maxSurge":1}},"template":{"spec":{"containers":[{"name":"control-api","image":%q,"env":[{"name":"CONTROL_VERSION","value":%q},{"name":"CONTROL_ARTIFACT_SHA256","value":%q}]}]}}},"status":{"observedGeneration":9,"readyReplicas":2,"availableReplicas":2,"updatedReplicas":2,"unavailableReplicas":0}}`, resourceVersion, currentImage, currentVersion, currentArtifactDigest)
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/jobs"):
			var body map[string]any
			_ = json.NewDecoder(request.Body).Decode(&body)
			metadata := body["metadata"].(map[string]any)
			labels := metadata["labels"].(map[string]any)
			phases = append(phases, labels["cdnca.io/upgrade-phase"].(string))
			jobs = append(jobs, body)
			body["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Complete", "status": "True"}}}
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(body)
		case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/jobs/"):
			_, _ = writer.Write([]byte(`{"status":{"conditions":[{"type":"Complete","status":"True"}]}}`))
		case request.Method == http.MethodPatch && strings.Contains(request.URL.Path, "/deployments/"):
			var operations []map[string]any
			_ = json.NewDecoder(request.Body).Decode(&operations)
			patches = append(patches, operations)
			for _, operation := range operations {
				path, _ := operation["path"].(string)
				value, _ := operation["value"].(string)
				if operation["op"] == "replace" && strings.HasSuffix(path, "/image") {
					currentImage = value
				} else if operation["op"] == "replace" && strings.HasSuffix(path, "/value") {
					if value == "1.4.0" || value == "1.5.0" {
						currentVersion = value
					} else {
						currentArtifactDigest = value
					}
				}
			}
			resourceVersion = "8"
			_, _ = writer.Write([]byte(`{"metadata":{"resourceVersion":"8"}}`))
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
		InternalURL: server.URL, InternalToken: internalToken,
		HTTPClient: server.Client(), PollInterval: time.Millisecond,
		HealthTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := adapterTestPlan(oldDigest, newDigest)
	facts, err := executor.Facts(t.Context())
	if err != nil || facts.CurrentVersion != "1.4.0" || facts.CurrentDigest != oldDigest {
		t.Fatalf("Facts() = (%#v, %v)", facts, err)
	}
	for _, operation := range []func(context.Context, Plan) error{
		executor.Expand, executor.Preflight, executor.Drain, executor.Activate,
	} {
		if err := operation(t.Context(), plan); err != nil {
			t.Fatal(err)
		}
	}
	if err := executor.Health(t.Context(), plan, plan.Target); err != nil {
		t.Fatal(err)
	}
	if err := executor.Contract(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if err := executor.Resume(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if err := executor.Rollback(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if err := executor.Health(t.Context(), plan, plan.Rollback); err != nil {
		t.Fatal(err)
	}
	if strings.Join(phases, ",") != "expand,contract" {
		t.Fatalf("migration phases = %v", phases)
	}
	if len(jobs) != 2 {
		t.Fatalf("migration jobs = %d", len(jobs))
	}
	for _, mutation := range []func(map[string]any){
		func(job map[string]any) {
			spec := job["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
			spec["serviceAccountName"] = "unexpected-service-account"
		},
		func(job map[string]any) {
			container := job["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
			container["args"] = []string{"serve"}
		},
		func(job map[string]any) {
			container := job["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
			container["env"] = []any{}
		},
	} {
		encoded, _ := json.Marshal(jobs[0])
		var candidate map[string]any
		_ = json.Unmarshal(encoded, &candidate)
		mutation(candidate)
		if jobMatches(candidate, plan, "expand", "registry.example.invalid/cdnca/control-api@sha256:"+newDigest,
			"cdnca-control-upgrade-migration", "cdnca-customer-datastores", "database-url") {
			t.Fatal("mutated migration execution identity was accepted")
		}
	}
	if strings.Join(controlCalls, ",") != "/v1/internal/control-upgrade/drain,/v1/internal/control-upgrade/health,/v1/internal/control-upgrade/resume,/v1/internal/control-upgrade/health" {
		t.Fatalf("control API calls = %v", controlCalls)
	}
	encodedPatches, _ := json.Marshal(patches)
	for _, required := range []string{`"op":"test"`, `/metadata/resourceVersion`, `maxUnavailable`, "sha256:" + newDigest, "sha256:" + oldDigest} {
		if !strings.Contains(string(encodedPatches), required) {
			t.Fatalf("patches omit %q: %s", required, encodedPatches)
		}
	}
}

func adapterTestPlan(oldHex, newHex string) Plan {
	return Plan{ID: "00000000-0000-4000-8000-000000000002", BundleSHA256: digestBytes([]byte("bundle")), Sequence: 42,
		CurrentVersion: "1.4.0", TargetVersion: "1.5.0", ProtocolVersion: 2,
		Target: Artifact{Version: "1.5.0", Digest: newHex, Size: 4096,
			URL: "https://releases.example.invalid/control-api/1.5.0"},
		Rollback: Artifact{Version: "1.4.0", Digest: oldHex, Size: 4096,
			URL: "https://releases.example.invalid/control-api/1.4.0"}}
}
