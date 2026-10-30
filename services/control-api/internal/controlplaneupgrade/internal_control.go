package controlplaneupgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type internalControlClient struct {
	client       *http.Client
	token        string
	drainURL     string
	resumeURL    string
	healthURL    string
	pollInterval time.Duration
	timeout      time.Duration
}

func newInternalControlClient(client *http.Client, token, drainURL, resumeURL, healthURL string,
	pollInterval, timeout time.Duration) (*internalControlClient, error) {
	if client == nil || len(token) < 32 || len(token) > 256 ||
		!validHTTPURL(drainURL, true) || !validHTTPURL(resumeURL, true) || !validHTTPURL(healthURL, true) {
		return nil, ErrInvalidConfig
	}
	if pollInterval <= 0 {
		pollInterval = time.Second
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	return &internalControlClient{client: client, token: token, drainURL: drainURL, resumeURL: resumeURL,
		healthURL: healthURL, pollInterval: pollInterval, timeout: timeout}, nil
}

func (client *internalControlClient) drain(ctx context.Context, plan Plan) error {
	return client.waitPost(ctx, client.drainURL, plan.ID)
}

func (client *internalControlClient) resume(ctx context.Context, plan Plan) error {
	return client.waitPost(ctx, client.resumeURL, plan.ID)
}

func (client *internalControlClient) health(ctx context.Context, plan Plan, artifact Artifact) error {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	for {
		var snapshot ControlSnapshot
		status, err := client.request(ctx, http.MethodGet, client.healthURL, nil, &snapshot)
		if err != nil && status != http.StatusServiceUnavailable {
			return err
		}
		if err == nil && status >= 200 && status < 300 && snapshot.PlanID == plan.ID &&
			snapshot.Phase == ControlDraining && matchingReplicas(snapshot.Replicas, artifact) >= snapshot.Quorum &&
			snapshot.Quorum > 0 {
			return nil
		}
		if err := client.wait(ctx); err != nil {
			return err
		}
	}
}

func (client *internalControlClient) waitPost(ctx context.Context, address, planID string) error {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	body, _ := json.Marshal(struct {
		PlanID string `json:"plan_id"`
	}{PlanID: planID})
	for {
		status, err := client.request(ctx, http.MethodPost, address, body, nil)
		if err == nil && status >= 200 && status < 300 {
			return nil
		}
		if err != nil && status != http.StatusServiceUnavailable {
			return err
		}
		if err := client.wait(ctx); err != nil {
			return err
		}
	}
}

func (client *internalControlClient) request(ctx context.Context, method, address string, body []byte, output any) (int, error) {
	request, err := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	encoded, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if readErr != nil {
		return response.StatusCode, readErr
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, fmt.Errorf("control upgrade API status %d", response.StatusCode)
	}
	if output != nil && (len(encoded) == 0 || json.Unmarshal(encoded, output) != nil) {
		return response.StatusCode, ErrTargetMismatch
	}
	return response.StatusCode, nil
}

func (client *internalControlClient) wait(ctx context.Context) error {
	timer := time.NewTimer(client.pollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func matchingReplicas(replicas []ReplicaObservation, artifact Artifact) int {
	count := 0
	for _, replica := range replicas {
		if replica.Version == artifact.Version && replica.Digest == artifact.Digest {
			count++
		}
	}
	return count
}

func validHTTPURL(value string, allowHTTP bool) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Host != "" && (parsed.Scheme == "https" || allowHTTP && parsed.Scheme == "http")
}
