package controlplaneupgrade

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type KubernetesConfig struct {
	APIServer         string
	Namespace         string
	Deployment        string
	Container         string
	ImageRepository   string
	ServiceAccount    string
	DatabaseSecret    string
	DatabaseSecretKey string
	InstallationID    string
	ProtocolVersion   int
	TokenFile         string
	CAFile            string
	InternalURL       string
	InternalToken     string
	HTTPClient        *http.Client
	PollInterval      time.Duration
	StepTimeout       time.Duration
	HealthTimeout     time.Duration
	ImagePullSecrets  []string
}

type KubernetesExecutor struct {
	config  KubernetesConfig
	client  *http.Client
	control *internalControlClient
}

type kubernetesDeployment struct {
	Metadata struct {
		ResourceVersion string            `json:"resourceVersion"`
		Generation      int64             `json:"generation"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Replicas        int `json:"replicas"`
		MinReadySeconds int `json:"minReadySeconds"`
		Strategy        struct {
			Type          string `json:"type"`
			RollingUpdate struct {
				MaxUnavailable any `json:"maxUnavailable"`
				MaxSurge       any `json:"maxSurge"`
			} `json:"rollingUpdate"`
		} `json:"strategy"`
		Template struct {
			Metadata struct {
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec struct {
				Containers []struct {
					Name  string `json:"name"`
					Image string `json:"image"`
					Env   []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"env"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration  int64 `json:"observedGeneration"`
		ReadyReplicas       int   `json:"readyReplicas"`
		AvailableReplicas   int   `json:"availableReplicas"`
		UpdatedReplicas     int   `json:"updatedReplicas"`
		UnavailableReplicas int   `json:"unavailableReplicas"`
	} `json:"status"`
}

func NewKubernetesExecutor(config KubernetesConfig) (*KubernetesExecutor, error) {
	parsed, err := url.Parse(config.APIServer)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" ||
		!secretNamePattern.MatchString(config.Namespace) || !secretNamePattern.MatchString(config.Deployment) ||
		!secretNamePattern.MatchString(config.Container) || !secretNamePattern.MatchString(config.ServiceAccount) ||
		!secretNamePattern.MatchString(config.DatabaseSecret) || !validSecretKey(config.DatabaseSecretKey) ||
		config.ImageRepository == "" || strings.ContainsAny(config.ImageRepository, "@ \t\r\n") ||
		strings.HasSuffix(config.ImageRepository, "/") || config.ProtocolVersion < 1 {
		return nil, ErrInvalidConfig
	}
	if parsedInstallationID, err := uuid.Parse(config.InstallationID); err != nil ||
		parsedInstallationID == uuid.Nil || parsedInstallationID.String() != config.InstallationID {
		return nil, ErrInvalidConfig
	}
	if config.StepTimeout <= 0 {
		config.StepTimeout = 3 * time.Minute
	}
	if config.StepTimeout < 10*time.Second || config.StepTimeout > 30*time.Minute {
		return nil, ErrInvalidConfig
	}
	pullSecrets, err := normalizeImagePullSecrets(config.ImagePullSecrets)
	if err != nil {
		return nil, err
	}
	config.ImagePullSecrets = pullSecrets
	client := config.HTTPClient
	if client == nil {
		if parsed.Scheme != "https" {
			return nil, ErrInvalidConfig
		}
		if config.CAFile == "" {
			return nil, ErrInvalidConfig
		}
		encoded, err := os.ReadFile(config.CAFile)
		roots := x509.NewCertPool()
		if err != nil || !roots.AppendCertsFromPEM(encoded) {
			return nil, ErrInvalidConfig
		}
		client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		}}
	}
	if config.PollInterval <= 0 {
		config.PollInterval = time.Second
	}
	if config.HealthTimeout <= 0 {
		config.HealthTimeout = 10 * time.Minute
	}
	if config.TokenFile != "" {
		if _, err := readKubernetesToken(config.TokenFile); err != nil {
			return nil, ErrInvalidConfig
		}
	} else if config.HTTPClient == nil {
		return nil, ErrInvalidConfig
	}
	base := strings.TrimRight(config.InternalURL, "/")
	control, err := newInternalControlClient(client, config.InternalToken,
		base+"/v1/internal/control-upgrade/drain", base+"/v1/internal/control-upgrade/resume",
		base+"/v1/internal/control-upgrade/health", config.PollInterval, config.HealthTimeout)
	if err != nil {
		return nil, err
	}
	return &KubernetesExecutor{config: config, client: client, control: control}, nil
}

func (executor *KubernetesExecutor) Target() Target { return TargetKubernetes }

func (executor *KubernetesExecutor) Facts(ctx context.Context) (Facts, error) {
	deployment, err := executor.deployment(ctx)
	if err != nil {
		return Facts{}, err
	}
	_, image, version, artifactDigest, err := executor.container(deployment)
	if err != nil {
		return Facts{}, err
	}
	digest, err := imageDigest(image)
	if err != nil {
		return Facts{}, err
	}
	if artifactDigest != digest {
		return Facts{}, ErrTargetMismatch
	}
	return Facts{InstallationID: executor.config.InstallationID, CurrentVersion: version,
		CurrentDigest: digest, ProtocolVersion: executor.config.ProtocolVersion}, nil
}

func (executor *KubernetesExecutor) Expand(ctx context.Context, plan Plan) error {
	return executor.migration(ctx, plan, "expand")
}

func (executor *KubernetesExecutor) Contract(ctx context.Context, plan Plan) error {
	return executor.migration(ctx, plan, "contract")
}

func (executor *KubernetesExecutor) Preflight(ctx context.Context, plan Plan) error {
	deployment, err := executor.deployment(ctx)
	if err != nil {
		return err
	}
	_, image, version, artifactDigest, err := executor.container(deployment)
	if err != nil {
		return err
	}
	digest, err := imageDigest(image)
	if err != nil || digest != plan.Rollback.Digest || artifactDigest != digest || version != plan.CurrentVersion ||
		deployment.Spec.Strategy.Type != "RollingUpdate" || intValue(deployment.Spec.Strategy.RollingUpdate.MaxUnavailable) != 0 ||
		intValue(deployment.Spec.Strategy.RollingUpdate.MaxSurge) < 1 || deployment.Spec.MinReadySeconds < 1 ||
		deployment.Spec.Replicas < 2 || deployment.Status.ReadyReplicas != deployment.Spec.Replicas ||
		deployment.Status.AvailableReplicas != deployment.Spec.Replicas || deployment.Status.UnavailableReplicas != 0 ||
		deployment.Status.ObservedGeneration < deployment.Metadata.Generation ||
		deployment.Status.UpdatedReplicas != deployment.Spec.Replicas {
		return ErrTargetMismatch
	}
	return nil
}

func (executor *KubernetesExecutor) Drain(ctx context.Context, plan Plan) error {
	return executor.control.drain(ctx, plan)
}

func (executor *KubernetesExecutor) Resume(ctx context.Context, plan Plan) error {
	return executor.control.resume(ctx, plan)
}

func (executor *KubernetesExecutor) Activate(ctx context.Context, plan Plan) error {
	return executor.switchArtifact(ctx, plan.Rollback, plan.Target)
}

func (executor *KubernetesExecutor) Rollback(ctx context.Context, plan Plan) error {
	return executor.switchArtifact(ctx, plan.Target, plan.Rollback)
}

func (executor *KubernetesExecutor) Health(ctx context.Context, plan Plan, artifact Artifact) error {
	ctx, cancel := context.WithTimeout(ctx, executor.config.HealthTimeout)
	defer cancel()
	ticker := time.NewTicker(executor.config.PollInterval)
	defer ticker.Stop()
	var last error
	for {
		deployment, err := executor.deployment(ctx)
		if err == nil {
			_, image, version, artifactDigest, containerErr := executor.container(deployment)
			digest, digestErr := imageDigest(image)
			if containerErr == nil && digestErr == nil && digest == artifact.Digest && artifactDigest == digest && version == artifact.Version &&
				deployment.Status.ObservedGeneration >= deployment.Metadata.Generation &&
				deployment.Status.UpdatedReplicas == deployment.Spec.Replicas &&
				deployment.Status.ReadyReplicas == deployment.Spec.Replicas &&
				deployment.Status.AvailableReplicas == deployment.Spec.Replicas && deployment.Status.UnavailableReplicas == 0 {
				return executor.control.health(ctx, plan, artifact)
			}
			last = fmt.Errorf("%w: image=%q version=%q/%q digest=%q/%q env_digest=%q generation=%d/%d replicas=%d updated=%d ready=%d available=%d unavailable=%d container=%v digest_error=%v",
				ErrTargetMismatch, image, version, artifact.Version, digest, artifact.Digest, artifactDigest, deployment.Status.ObservedGeneration, deployment.Metadata.Generation,
				deployment.Spec.Replicas, deployment.Status.UpdatedReplicas, deployment.Status.ReadyReplicas,
				deployment.Status.AvailableReplicas, deployment.Status.UnavailableReplicas, containerErr, digestErr)
		} else if ctx.Err() == nil {
			last = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("health deadline: %v: %w", last, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (executor *KubernetesExecutor) switchArtifact(ctx context.Context, from, to Artifact) error {
	deployment, err := executor.deployment(ctx)
	if err != nil {
		return err
	}
	index, image, version, artifactDigest, err := executor.container(deployment)
	if err != nil {
		return err
	}
	digest, err := imageDigest(image)
	if err != nil {
		return err
	}
	if digest == to.Digest && artifactDigest == to.Digest && version == to.Version {
		return nil
	}
	if digest != from.Digest || version != from.Version {
		return ErrPlanConflict
	}
	imagePath := fmt.Sprintf("/spec/template/spec/containers/%d/image", index)
	envIndex := -1
	digestEnvIndex := -1
	for candidate, item := range deployment.Spec.Template.Spec.Containers[index].Env {
		if item.Name == "CONTROL_VERSION" {
			envIndex = candidate
		}
		if item.Name == "CONTROL_ARTIFACT_SHA256" {
			digestEnvIndex = candidate
		}
	}
	operations := []map[string]any{
		{"op": "test", "path": "/metadata/resourceVersion", "value": deployment.Metadata.ResourceVersion},
		{"op": "test", "path": "/spec/strategy/rollingUpdate/maxUnavailable", "value": deployment.Spec.Strategy.RollingUpdate.MaxUnavailable},
		{"op": "test", "path": "/spec/strategy/rollingUpdate/maxSurge", "value": deployment.Spec.Strategy.RollingUpdate.MaxSurge},
		{"op": "test", "path": imagePath, "value": image},
		{"op": "replace", "path": imagePath, "value": executor.config.ImageRepository + "@sha256:" + to.Digest},
	}
	if envIndex >= 0 {
		path := fmt.Sprintf("/spec/template/spec/containers/%d/env/%d/value", index, envIndex)
		operations = append(operations, map[string]any{"op": "test", "path": path, "value": version},
			map[string]any{"op": "replace", "path": path, "value": to.Version})
	} else {
		operations = append(operations, map[string]any{"op": "add",
			"path":  fmt.Sprintf("/spec/template/spec/containers/%d/env/-", index),
			"value": map[string]string{"name": "CONTROL_VERSION", "value": to.Version}})
	}
	if digestEnvIndex >= 0 {
		path := fmt.Sprintf("/spec/template/spec/containers/%d/env/%d/value", index, digestEnvIndex)
		operations = append(operations, map[string]any{"op": "test", "path": path, "value": artifactDigest},
			map[string]any{"op": "replace", "path": path, "value": to.Digest})
	} else {
		operations = append(operations, map[string]any{"op": "add",
			"path":  fmt.Sprintf("/spec/template/spec/containers/%d/env/-", index),
			"value": map[string]string{"name": "CONTROL_ARTIFACT_SHA256", "value": to.Digest}})
	}
	return executor.patchDeployment(ctx, operations)
}

func (executor *KubernetesExecutor) migration(ctx context.Context, plan Plan, phase string) error {
	if parsedPlanID, err := uuid.Parse(plan.ID); err != nil || parsedPlanID == uuid.Nil || parsedPlanID.String() != plan.ID ||
		!digestPattern.MatchString(plan.BundleSHA256) ||
		!digestPattern.MatchString(plan.Target.Digest) || phase != "expand" && phase != "contract" {
		return ErrInvalidPlan
	}
	ctx, cancel := context.WithTimeout(ctx, executor.config.StepTimeout)
	defer cancel()
	name := "control-upgrade-" + strings.ReplaceAll(plan.ID, "-", "") + "-" + phase
	image := executor.config.ImageRepository + "@sha256:" + plan.Target.Digest
	deadlineSeconds := int((executor.config.StepTimeout + time.Second - 1) / time.Second)
	pullSecrets := make([]any, 0, len(executor.config.ImagePullSecrets))
	for _, secret := range executor.config.ImagePullSecrets {
		pullSecrets = append(pullSecrets, map[string]any{"name": secret})
	}
	body := map[string]any{
		"apiVersion": "batch/v1", "kind": "Job",
		"metadata": map[string]any{"name": name, "annotations": map[string]any{
			"cdnca.io/upgrade-bundle-sha256":   plan.BundleSHA256,
			"cdnca.io/upgrade-artifact-sha256": plan.Target.Digest,
		}, "labels": map[string]any{
			"app.kubernetes.io/component": "control-upgrade-runner", "cdnca.io/upgrade-plan": plan.ID,
			"cdnca.io/upgrade-phase": phase}},
		"spec": map[string]any{"backoffLimit": 0, "activeDeadlineSeconds": deadlineSeconds, "ttlSecondsAfterFinished": 86400,
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{
					"cdnca.io/upgrade-plan": plan.ID, "cdnca.io/upgrade-phase": phase}},
				"spec": map[string]any{"restartPolicy": "Never", "serviceAccountName": executor.config.ServiceAccount,
					"automountServiceAccountToken": false, "enableServiceLinks": false,
					"imagePullSecrets": pullSecrets,
					"securityContext":  map[string]any{"seccompProfile": map[string]any{"type": "RuntimeDefault"}},
					"volumes":          []any{map[string]any{"name": "tmp", "emptyDir": map[string]any{}}},
					"containers": []any{map[string]any{
						"name": "migration", "image": image,
						"command": []string{"/control-api"}, "args": []string{"migrate", "up"},
						"securityContext": map[string]any{"runAsNonRoot": true, "allowPrivilegeEscalation": false,
							"readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []any{"ALL"}}},
						"volumeMounts": []any{map[string]any{"name": "tmp", "mountPath": "/tmp"}},
						"env": []any{map[string]any{"name": "CDNCA_MIGRATION_PHASE", "value": phase},
							map[string]any{"name": "DATABASE_URL", "valueFrom": map[string]any{"secretKeyRef": map[string]any{
								"name": executor.config.DatabaseSecret, "key": executor.config.DatabaseSecretKey}}}},
					}}}}},
	}
	encoded, _ := json.Marshal(body)
	path := fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs", url.PathEscape(executor.config.Namespace))
	var response map[string]any
	status, err := executor.request(ctx, http.MethodPost, path, "application/json", encoded, &response)
	if err != nil && status != http.StatusConflict {
		return err
	}
	if err == nil {
		if !jobMatchesProduction(response, plan, phase, image, executor.config.ServiceAccount,
			executor.config.DatabaseSecret, executor.config.DatabaseSecretKey, deadlineSeconds, executor.config.ImagePullSecrets) {
			return ErrPlanConflict
		}
		if jobComplete(response) {
			return nil
		}
	}
	jobPath := path + "/" + url.PathEscape(name)
	ticker := time.NewTicker(executor.config.PollInterval)
	defer ticker.Stop()
	for {
		response = nil
		_, err := executor.request(ctx, http.MethodGet, jobPath, "", nil, &response)
		if err == nil && !jobMatchesProduction(response, plan, phase, image, executor.config.ServiceAccount,
			executor.config.DatabaseSecret, executor.config.DatabaseSecretKey, deadlineSeconds, executor.config.ImagePullSecrets) {
			return ErrPlanConflict
		}
		if err == nil && jobComplete(response) {
			return nil
		}
		if err == nil && jobFailed(response) {
			return errors.New("control-plane migration job failed")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (executor *KubernetesExecutor) deployment(ctx context.Context) (kubernetesDeployment, error) {
	var deployment kubernetesDeployment
	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", url.PathEscape(executor.config.Namespace),
		url.PathEscape(executor.config.Deployment))
	_, err := executor.request(ctx, http.MethodGet, path, "", nil, &deployment)
	return deployment, err
}

func (executor *KubernetesExecutor) patchDeployment(ctx context.Context, operations []map[string]any) error {
	encoded, _ := json.Marshal(operations)
	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", url.PathEscape(executor.config.Namespace),
		url.PathEscape(executor.config.Deployment))
	_, err := executor.request(ctx, http.MethodPatch, path, "application/json-patch+json", encoded, nil)
	return err
}

func (executor *KubernetesExecutor) request(ctx context.Context, method, path, contentType string, body []byte, output any) (int, error) {
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(executor.config.APIServer, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Accept", "application/json")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if executor.config.TokenFile != "" {
		token, err := readKubernetesToken(executor.config.TokenFile)
		if err != nil {
			return 0, err
		}
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := executor.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return response.StatusCode, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, fmt.Errorf("kubernetes API status %d", response.StatusCode)
	}
	if output != nil && len(encoded) != 0 {
		if err := json.Unmarshal(encoded, output); err != nil {
			return response.StatusCode, err
		}
	}
	return response.StatusCode, nil
}

func (executor *KubernetesExecutor) container(deployment kubernetesDeployment) (int, string, string, string, error) {
	for index, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name != executor.config.Container {
			continue
		}
		version, digest := "", ""
		for _, item := range container.Env {
			if item.Name == "CONTROL_VERSION" {
				version = item.Value
			}
			if item.Name == "CONTROL_ARTIFACT_SHA256" {
				digest = item.Value
			}
		}
		if version != "" && digestPattern.MatchString(digest) {
			return index, container.Image, version, digest, nil
		}
		return 0, "", "", "", ErrTargetMismatch
	}
	return 0, "", "", "", ErrTargetMismatch
}

func imageDigest(image string) (string, error) {
	parts := strings.Split(image, "@sha256:")
	if len(parts) != 2 || parts[0] == "" || !digestPattern.MatchString(parts[1]) {
		return "", ErrTargetMismatch
	}
	return parts[1], nil
}

func intValue(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case string:
		result, _ := strconv.Atoi(strings.TrimSuffix(typed, "%"))
		return result
	default:
		return -1
	}
}

func jobComplete(job map[string]any) bool { return jobCondition(job, "Complete") }
func jobFailed(job map[string]any) bool   { return jobCondition(job, "Failed") }

func jobMatches(job map[string]any, plan Plan, phase, image, serviceAccount, databaseSecret, databaseSecretKey string) bool {
	return jobMatchesWithDeadline(job, plan, phase, image, serviceAccount, databaseSecret, databaseSecretKey, 180)
}

func jobMatchesWithDeadline(job map[string]any, plan Plan, phase, image, serviceAccount, databaseSecret, databaseSecretKey string, deadlineSeconds int) bool {
	metadata, _ := job["metadata"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	expectedName := "control-upgrade-" + strings.ReplaceAll(plan.ID, "-", "") + "-" + phase
	if metadata["name"] != expectedName || labels["cdnca.io/upgrade-plan"] != plan.ID ||
		labels["cdnca.io/upgrade-phase"] != phase ||
		annotations["cdnca.io/upgrade-bundle-sha256"] != plan.BundleSHA256 ||
		annotations["cdnca.io/upgrade-artifact-sha256"] != plan.Target.Digest {
		return false
	}
	spec, _ := job["spec"].(map[string]any)
	if intValue(spec["backoffLimit"]) != 0 || intValue(spec["activeDeadlineSeconds"]) != deadlineSeconds ||
		intValue(spec["ttlSecondsAfterFinished"]) != 86400 {
		return false
	}
	template, _ := spec["template"].(map[string]any)
	templateMetadata, _ := template["metadata"].(map[string]any)
	templateLabels, _ := templateMetadata["labels"].(map[string]any)
	if templateLabels["cdnca.io/upgrade-plan"] != plan.ID || templateLabels["cdnca.io/upgrade-phase"] != phase {
		return false
	}
	podSpec, _ := template["spec"].(map[string]any)
	if podSpec["restartPolicy"] != "Never" || podSpec["serviceAccountName"] != serviceAccount ||
		podSpec["automountServiceAccountToken"] != false {
		return false
	}
	containers, _ := podSpec["containers"].([]any)
	if len(containers) != 1 {
		return false
	}
	container, _ := containers[0].(map[string]any)
	if container["name"] != "migration" || container["image"] != image ||
		!stringListEquals(container["command"], "/control-api") || !stringListEquals(container["args"], "migrate", "up") {
		return false
	}
	environment, _ := container["env"].([]any)
	if len(environment) != 2 {
		return false
	}
	phaseEnvironment, _ := environment[0].(map[string]any)
	databaseEnvironment, _ := environment[1].(map[string]any)
	valueFrom, _ := databaseEnvironment["valueFrom"].(map[string]any)
	secretKeyRef, _ := valueFrom["secretKeyRef"].(map[string]any)
	return phaseEnvironment["name"] == "CDNCA_MIGRATION_PHASE" && phaseEnvironment["value"] == phase &&
		databaseEnvironment["name"] == "DATABASE_URL" && secretKeyRef["name"] == databaseSecret &&
		secretKeyRef["key"] == databaseSecretKey
}

func jobMatchesProduction(job map[string]any, plan Plan, phase, image, serviceAccount, databaseSecret, databaseSecretKey string, deadlineSeconds int, pullSecrets []string) bool {
	if !jobMatchesWithDeadline(job, plan, phase, image, serviceAccount, databaseSecret, databaseSecretKey, deadlineSeconds) {
		return false
	}
	spec, _ := job["spec"].(map[string]any)
	template, _ := spec["template"].(map[string]any)
	podSpec, _ := template["spec"].(map[string]any)
	if podSpec["enableServiceLinks"] != false || !imagePullSecretsEqual(podSpec["imagePullSecrets"], pullSecrets) {
		return false
	}
	podSecurity, _ := podSpec["securityContext"].(map[string]any)
	seccomp, _ := podSecurity["seccompProfile"].(map[string]any)
	containers, _ := podSpec["containers"].([]any)
	if seccomp["type"] != "RuntimeDefault" || len(containers) != 1 {
		return false
	}
	container, _ := containers[0].(map[string]any)
	security, _ := container["securityContext"].(map[string]any)
	capabilities, _ := security["capabilities"].(map[string]any)
	return security["runAsNonRoot"] == true && security["allowPrivilegeEscalation"] == false &&
		security["readOnlyRootFilesystem"] == true && stringListEquals(capabilities["drop"], "ALL") &&
		volumeMountMatches(container["volumeMounts"], "tmp", "/tmp") && emptyDirVolumeMatches(podSpec["volumes"], "tmp")
}

func normalizeImagePullSecrets(values []string) ([]string, error) {
	if len(values) > 32 {
		return nil, ErrInvalidConfig
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !secretNamePattern.MatchString(value) {
			return nil, ErrInvalidConfig
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func imagePullSecretsEqual(value any, expected []string) bool {
	items, _ := value.([]any)
	if len(items) != len(expected) {
		return false
	}
	for index, item := range items {
		secret, _ := item.(map[string]any)
		if len(secret) != 1 || secret["name"] != expected[index] {
			return false
		}
	}
	return true
}

func volumeMountMatches(value any, name, path string) bool {
	items, _ := value.([]any)
	if len(items) != 1 {
		return false
	}
	mount, _ := items[0].(map[string]any)
	return len(mount) == 2 && mount["name"] == name && mount["mountPath"] == path
}

func emptyDirVolumeMatches(value any, name string) bool {
	items, _ := value.([]any)
	if len(items) != 1 {
		return false
	}
	volume, _ := items[0].(map[string]any)
	_, empty := volume["emptyDir"].(map[string]any)
	return len(volume) == 2 && volume["name"] == name && empty
}

func stringListEquals(value any, expected ...string) bool {
	items, ok := value.([]any)
	if !ok || len(items) != len(expected) {
		return false
	}
	for index, item := range items {
		if item != expected[index] {
			return false
		}
	}
	return true
}

func readKubernetesToken(path string) (string, error) {
	encoded, err := os.ReadFile(path)
	if err != nil || len(encoded) == 0 || len(encoded) > 16*1024 {
		return "", ErrInvalidConfig
	}
	token := strings.TrimSpace(string(encoded))
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return "", ErrInvalidConfig
	}
	return token, nil
}

func jobCondition(job map[string]any, kind string) bool {
	status, _ := job["status"].(map[string]any)
	conditions, _ := status["conditions"].([]any)
	for _, candidate := range conditions {
		condition, _ := candidate.(map[string]any)
		if condition["type"] == kind && condition["status"] == "True" {
			return true
		}
	}
	return false
}
