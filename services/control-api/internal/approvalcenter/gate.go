package approvalcenter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Gate holds the managed operations of platform administration sessions.
// Settings, Session and Submit are functions so the gate is testable without
// PostgreSQL; Store provides them in production.
type Gate struct {
	Settings func(context.Context) (Settings, error)
	// Session resolves the live Bearer session of r; ok=false for anything
	// else (no or invalid credential, API key, impersonation cookie): those
	// requests pass and the business handler answers as before.
	Session   func(*http.Request) (Session, bool)
	Submit    func(context.Context, Session, Rule, string, string, Step, string) (Request, error)
	RequestID func(context.Context) string
}

type executionKey struct{}

// withExecution marks a replay of an approved request: the gate lets it through.
func withExecution(ctx context.Context) context.Context {
	return context.WithValue(ctx, executionKey{}, true)
}

func isExecution(ctx context.Context) bool {
	marked, _ := ctx.Value(executionKey{}).(bool)
	return marked
}

// storedHeaders are copied into the stored request and replayed.
var storedHeaders = []string{"Content-Type", "Idempotency-Key", "If-Match"}

// Wrap returns next behind the gate.
func (g Gate) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isExecution(r.Context()) || !candidate(r.Method, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		// Q4: API keys pass; only Bearer sessions can go through approval.
		scheme, _, _ := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
		if !strings.EqualFold(scheme, "Bearer") {
			next.ServeHTTP(w, r)
			return
		}
		settings, err := g.Settings(r.Context())
		if err != nil {
			writeError(w, g.requestID(r), http.StatusServiceUnavailable, "approval_center_unavailable", "approval center settings are unavailable")
			return
		}
		if !settings.Enabled || len(settings.Rules) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		// Q5: only platform administration sessions are held.
		session, ok := g.Session(r)
		if !ok || session.ScopeKind != "platform" {
			next.ServeHTTP(w, r)
			return
		}
		body, ok := readBody(r)
		if !ok {
			next.ServeHTTP(w, r) // the business handler rejects an oversized body itself
			return
		}
		rule, held := matchRule(settings.Rules, r.Method, r.URL.Path, body)
		if !held {
			next.ServeHTTP(w, r)
			return
		}
		reason, present, valid := approvalReason(r)
		if !present {
			writeJSON(w, http.StatusPreconditionRequired, map[string]any{"error": map[string]any{
				"code": "approval_required", "message": "this operation needs an approval; resend it with X-Approval-Reason",
				"request_id": g.requestID(r), "details": map[string]string{"rule": rule.Name},
			}})
			return
		}
		if !valid {
			writeError(w, g.requestID(r), http.StatusBadRequest, "validation_error", "X-Approval-Reason must be 1-500 characters")
			return
		}
		group := strings.TrimSpace(r.Header.Get(headerApprovalGroup))
		if group != "" && !validGroup(group) {
			writeError(w, g.requestID(r), http.StatusBadRequest, "validation_error", "X-Approval-Group is invalid")
			return
		}
		step := Step{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Headers: map[string]string{}, Body: body}
		for _, name := range storedHeaders {
			if value := r.Header.Get(name); value != "" {
				step.Headers[name] = value
			}
		}
		stored, err := g.Submit(r.Context(), session, rule, group, reason, step, g.requestID(r))
		if err != nil {
			writeError(w, g.requestID(r), http.StatusServiceUnavailable, "approval_center_unavailable", "the approval request could not be stored")
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"code": "approval_submitted", "approval": stored})
	})
}

func (g Gate) requestID(r *http.Request) string {
	if g.RequestID == nil {
		return ""
	}
	return g.RequestID(r.Context())
}

// approvalReason reads the URL-encoded X-Approval-Reason header.
func approvalReason(r *http.Request) (reason string, present, valid bool) {
	raw := r.Header.Get(headerApprovalReason)
	if raw == "" {
		return "", false, false
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return "", true, false
	}
	decoded = strings.TrimSpace(decoded)
	return decoded, true, validNote(decoded, 1)
}

func validNote(value string, minimum int) bool {
	count := utf8.RuneCountInString(value)
	if !utf8.ValidString(value) || count < minimum || count > 500 {
		return false
	}
	for _, char := range value {
		if char < 0x20 && char != '\n' || char == 0x7f {
			return false
		}
	}
	return true
}

func validGroup(value string) bool {
	if len(value) > 128 {
		return false
	}
	for index, char := range value {
		alnum := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
		if !alnum && (index == 0 || char != '.' && char != '_' && char != '-') {
			return false
		}
	}
	return value != ""
}

// Replay runs the stored steps in order through handler with the approver's
// Authorization header, stopping at the first failure (later steps stay unrun).
func Replay(ctx context.Context, handler http.Handler, authorization string, steps []Step) []StepResult {
	results := make([]StepResult, 0, len(steps))
	for _, step := range steps {
		target := step.Path
		if step.Query != "" {
			target += "?" + step.Query
		}
		request, err := http.NewRequestWithContext(withExecution(ctx), step.Method, target, bytes.NewReader(step.Body))
		if err != nil {
			results = append(results, StepResult{Status: http.StatusInternalServerError, Body: "invalid stored request"})
			break
		}
		for name, value := range step.Headers {
			request.Header.Set(name, value)
		}
		request.Header.Set("Authorization", authorization)
		recorder := &responseRecorder{header: http.Header{}, status: http.StatusOK}
		handler.ServeHTTP(recorder, request)
		results = append(results, StepResult{Status: recorder.status, Body: recorder.body.String()})
		if recorder.status >= 400 {
			break
		}
	}
	return results
}

type responseRecorder struct {
	header      http.Header
	status      int
	wroteHeader bool
	body        bytes.Buffer
}

func (r *responseRecorder) Header() http.Header { return r.header }

func (r *responseRecorder) WriteHeader(status int) {
	if !r.wroteHeader {
		r.status, r.wroteHeader = status, true
	}
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	if room := maxResult - r.body.Len(); room > 0 {
		if len(data) > room {
			r.body.Write(data[:room])
		} else {
			r.body.Write(data)
		}
	}
	return len(data), nil
}

func writeError(w http.ResponseWriter, requestID string, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message, "request_id": requestID}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
