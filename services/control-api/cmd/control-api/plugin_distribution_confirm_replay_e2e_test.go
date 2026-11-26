package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/google/uuid"
)

// mutateAsConsole sends one mutation the way the management console retries it: the same body, If-Match,
// Idempotency-Key and X-Request-ID (the key) on every attempt.
func (client controlClient) mutateAsConsole(id uuid.UUID, action string, revision uint64, body any, key string) (int, string,
	installationView) {
	client.t.Helper()
	headers := map[string]string{"If-Match": `"` + jsonNumber(revision) + `"`, "Idempotency-Key": key,
		"X-Request-ID": key}
	response := client.do(http.MethodPost, "/"+id.String()+"/"+action, headers, body)
	var wrapper struct {
		Installation installationView `json:"installation"`
	}
	if response.Code == http.StatusOK && json.Unmarshal(response.Body.Bytes(), &wrapper) != nil {
		client.t.Fatalf("%s answer=%s", action, response.Body.String())
	}
	return response.Code, errorCode(response.Body.Bytes()), wrapper.Installation
}

// lostActivationAnswer wraps the controller's license client. Armed with an idempotency
// key, it lets the license service commit one activation of that key and drops the successful answer on its way
// back, as a connection lost after the license commit would.
type lostActivationAnswer struct {
	next    http.RoundTripper
	mu      sync.Mutex
	key     string
	dropped int
}

func (fault *lostActivationAnswer) arm(key string) {
	fault.mu.Lock()
	defer fault.mu.Unlock()
	fault.key = key
}

func (fault *lostActivationAnswer) droppedCount() int {
	fault.mu.Lock()
	defer fault.mu.Unlock()
	return fault.dropped
}

func (fault *lostActivationAnswer) RoundTrip(request *http.Request) (*http.Response, error) {
	fault.mu.Lock()
	key := fault.key
	fault.mu.Unlock()
	if key == "" || request.Body == nil {
		return fault.next.RoundTrip(request)
	}
	body, err := io.ReadAll(request.Body)
	_ = request.Body.Close()
	if err != nil {
		return nil, err
	}
	forwarded := request.Clone(request.Context())
	forwarded.Body = io.NopCloser(bytes.NewReader(body))
	forwarded.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	var probe struct {
		Schema         string `json:"schema"`
		IdempotencyKey string `json:"idempotency_key"`
	}
	_ = json.Unmarshal(body, &probe)
	response, err := fault.next.RoundTrip(forwarded)
	if err != nil || probe.Schema != "cdnca.plugin-installation-activation-request/v1" || probe.IdempotencyKey != key ||
		response.StatusCode != http.StatusOK {
		return response, err
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	fault.mu.Lock()
	fault.key, fault.dropped = "", fault.dropped+1
	fault.mu.Unlock()
	return nil, errors.New("e2e: activation answer lost after the license service committed it")
}
