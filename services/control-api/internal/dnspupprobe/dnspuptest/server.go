// Package dnspuptest is a fake dnspup customer API for tests. It is an
// independent re-implementation of dnspup's behaviour (backend/internal/httpapi
// customer_api.go / customer_api_jobs.go at e8975a2e), not of the client.
package dnspuptest

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server follows dnspup's customer API (customer_api.go /
// customer_api_jobs.go at e8975a2e): key pair check, domain signature with
// nonce replay protection, the per-key rate limit (429 rate_limited,
// Retry-After 60), monthly quota charged once per created job (429
// quota_exceeded), target restrictions (403 target_restricted), async jobs
// (202 created / 200 same key and body / 409 different body), job reads
// (Retry-After 2 while running, 404 unknown id).
type Server struct {
	mu sync.Mutex
	// Errors records protocol violations by the client (e.g. no Prefer).
	Errors       []string
	APIKey       string
	Secret       string
	SourceDomain string // non-empty: requests must be signed
	Async        bool
	MonthlyLimit int64
	MonthlyUsed  int64
	RateLimit    int // per minute, 0: unlimited
	RateCount    int
	Restricted   map[string]bool
	AllowedTools []string
	nonces       map[string]bool
	jobs         map[string]*fakeJob
	byIdem       map[string]string
	nextID       int
	// PollsUntilDone: GETs a job answers running before it completes.
	PollsUntilDone int
	// Checkpoints is GET /v1/nodes.
	Checkpoints []Checkpoint
	// Answer builds a job's results from its request.
	Answer   func(ProbeRequest) []Result
	Creates  int
	Gets     int
	Requests []string
}

// ProbeRequest is the POST /v1/probes body dnspup accepts
// (customerProbeRequest; unknown fields are refused).
type ProbeRequest struct {
	Type      string   `json:"type"`
	Target    string   `json:"target"`
	Port      int      `json:"port,omitempty"`
	Count     int      `json:"count,omitempty"`
	Method    string   `json:"method,omitempty"`
	Record    string   `json:"record,omitempty"`
	Server    string   `json:"server,omitempty"`
	Mode      string   `json:"mode,omitempty"`
	IPVersion string   `json:"ipVersion,omitempty"`
	NodeIDs   []string `json:"nodeIds,omitempty"`
}

// Result is one checkpoint's answer (models.ProbeResult subset).
type Result struct {
	NodeID     string `json:"node_id"`
	Region     string `json:"region"`
	Location   string `json:"location"`
	ISP        string `json:"isp"`
	Status     string `json:"status"`
	HTTPStatus int    `json:"http_status,omitempty"`
	TotalTime  int    `json:"total_time,omitempty"`
	LatencyMS  int    `json:"latency_ms"`
	AvgLatency int    `json:"avg_latency"`
	LossRate   int    `json:"loss_rate"`
	Error      string `json:"error,omitempty"`
}

// Checkpoint is one GET /v1/nodes item.
type Checkpoint struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Region string `json:"region"`
	City   string `json:"city"`
	ISP    string `json:"isp"`
	Status string `json:"status"`
}

type fakeJob struct {
	id      string
	hash    string
	request ProbeRequest
	polls   int
}

// New starts a fake (close the returned server when done).
func New() (*Server, *httptest.Server) {
	fake := &Server{APIKey: "dp_key_12345678", Secret: "dp_secret_0123456789abcdef", Async: true,
		MonthlyLimit: 1000, Restricted: map[string]bool{}, nonces: map[string]bool{}, jobs: map[string]*fakeJob{},
		byIdem: map[string]string{}, AllowedTools: []string{"http", "tcping", "ping"}, PollsUntilDone: 1}
	return fake, httptest.NewServer(fake)
}

// Do runs change under the server lock (tests changing knobs while a
// runner is in flight).
func (fake *Server) Do(change func(*Server)) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	change(fake)
}

func writeFakeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": code}})
}

func writeFakeData(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func (fake *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.Requests = append(fake.Requests, r.Method+" "+r.URL.Path)
	if r.Header.Get("X-API-Key") != fake.APIKey || r.Header.Get("X-API-Secret") != fake.Secret {
		writeFakeError(w, 401, "unauthorized")
		return
	}
	body, _ := io.ReadAll(r.Body)
	if fake.SourceDomain != "" && !fake.verifySignature(w, r, body) {
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/account":
		if !fake.rate(w) {
			return
		}
		writeFakeData(w, 200, map[string]any{"name": "cdnca", "plan": "pro", "enabled": true, "monthlyLimit": fake.MonthlyLimit,
			"monthlyUsed": fake.MonthlyUsed, "allowedTools": fake.AllowedTools, "maxNodes": 20, "rateLimitPerMinute": fake.RateLimit,
			"capabilities": map[string]bool{"asyncProbesV1": fake.Async}})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/nodes":
		if !fake.rate(w) {
			return
		}
		writeFakeData(w, 200, append([]Checkpoint{}, fake.Checkpoints...))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/probes":
		fake.create(w, r, body)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/probes/"):
		fake.get(w, strings.TrimPrefix(r.URL.Path, "/v1/probes/"))
	default:
		writeFakeError(w, 404, "not_found")
	}
}

func (fake *Server) verifySignature(w http.ResponseWriter, r *http.Request, body []byte) bool {
	if r.Header.Get("X-API-Source-Domain") != fake.SourceDomain {
		writeFakeError(w, 403, "source_forbidden")
		return false
	}
	timestamp, nonce, signature := r.Header.Get("X-API-Timestamp"), r.Header.Get("X-API-Nonce"), r.Header.Get("X-API-Signature")
	if timestamp == "" {
		writeFakeError(w, 401, "signature_required")
		return false
	}
	if _, err := hex.DecodeString(nonce); err != nil || len(nonce) != 32 || len(signature) != 64 {
		writeFakeError(w, 401, "malformed_signature")
		return false
	}
	at, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || time.Since(time.Unix(at, 0)).Abs() > 90*time.Second {
		writeFakeError(w, 401, "stale_signature")
		return false
	}
	// Independent re-implementation of customerAPIRequestCanonical /
	// customerAPIRequestSigningKey.
	secretSum := sha256.Sum256([]byte(fake.Secret))
	derive := hmac.New(sha256.New, []byte(hex.EncodeToString(secretSum[:])))
	derive.Write([]byte("dnspup-customer-api-signing/v1\x00"))
	bodySum := sha256.Sum256(body)
	canonical := strings.Join([]string{"dnspup-customer-api-v1", r.Method, r.URL.EscapedPath(), r.URL.RawQuery, timestamp,
		nonce, fake.SourceDomain, hex.EncodeToString(bodySum[:])}, "\n")
	mac := hmac.New(sha256.New, derive.Sum(nil))
	mac.Write([]byte(canonical))
	provided, _ := hex.DecodeString(signature)
	if !hmac.Equal(provided, mac.Sum(nil)) {
		writeFakeError(w, 401, "bad_signature")
		return false
	}
	if fake.nonces[nonce] {
		writeFakeError(w, 409, "replay")
		return false
	}
	fake.nonces[nonce] = true
	return true
}

func (fake *Server) rate(w http.ResponseWriter) bool {
	fake.RateCount++
	if fake.RateLimit > 0 && fake.RateCount > fake.RateLimit {
		w.Header().Set("Retry-After", "60")
		writeFakeError(w, 429, "rate_limited")
		return false
	}
	return true
}

func (fake *Server) create(w http.ResponseWriter, r *http.Request, body []byte) {
	var request ProbeRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeFakeError(w, 400, "invalid_request")
		return
	}
	if !slices.Contains(fake.AllowedTools, request.Type) {
		writeFakeError(w, 403, "tool_not_allowed")
		return
	}
	if !fake.rate(w) {
		return
	}
	if !strings.EqualFold(r.Header.Get("Prefer"), "respond-async") {
		fake.Errors = append(fake.Errors, "probe without Prefer: respond-async")
		writeFakeError(w, 400, "sync_not_supported_by_fake")
		return
	}
	if !fake.Async {
		writeFakeError(w, 503, "async_unavailable")
		return
	}
	idem := r.Header.Get("Idempotency-Key")
	if len(idem) < 1 || len(idem) > 128 {
		writeFakeError(w, 400, "invalid_idempotency_key")
		return
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	if id, ok := fake.byIdem[idem]; ok {
		job := fake.jobs[id]
		if job.hash != hash {
			writeFakeError(w, 409, "idempotency_conflict")
			return
		}
		fake.writeJob(w, job, 200)
		return
	}
	if fake.Restricted[request.Target] {
		writeFakeError(w, 403, "target_restricted")
		return
	}
	if fake.MonthlyUsed >= fake.MonthlyLimit {
		writeFakeError(w, 429, "quota_exceeded")
		return
	}
	fake.MonthlyUsed++
	fake.Creates++
	fake.nextID++
	job := &fakeJob{id: "req_" + strconv.Itoa(fake.nextID), hash: hash, request: request}
	fake.jobs[job.id], fake.byIdem[idem] = job, job.id
	fake.writeJob(w, job, 202)
}

func (fake *Server) get(w http.ResponseWriter, id string) {
	fake.Gets++
	job, ok := fake.jobs[id]
	if !ok {
		writeFakeError(w, 404, "task_not_found")
		return
	}
	job.polls++
	fake.writeJob(w, job, 200)
}

func (fake *Server) writeJob(w http.ResponseWriter, job *fakeJob, code int) {
	status := "running"
	if job.polls > fake.PollsUntilDone {
		status = "completed"
	}
	w.Header().Set("Location", "/v1/probes/"+job.id)
	value := map[string]any{"requestId": job.id, "status": status, "totalNodes": 3}
	if status == "running" {
		w.Header().Set("Retry-After", "2")
	} else {
		results := []Result{}
		if fake.Answer != nil {
			results = fake.Answer(job.request)
		}
		value["completedNodes"] = len(results)
		value["result"] = map[string]any{"requestId": job.id, "status": status, "type": job.request.Type,
			"target": job.request.Target, "results": results}
	}
	writeFakeData(w, code, value)
}

// RetryAfterTransport rewrites Retry-After on running job answers.
type RetryAfterTransport struct {
	Base  http.RoundTripper
	Value string
}

func (transport RetryAfterTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	base := transport.Base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(request)
	if err == nil && response.Header.Get("Retry-After") != "" {
		response.Header.Set("Retry-After", transport.Value)
	}
	return response, err
}
