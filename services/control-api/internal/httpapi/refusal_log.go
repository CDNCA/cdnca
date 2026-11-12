package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"unicode/utf8"
)

// refusalBodyLimit bounds how much of a 4xx response body is kept to read the
// error code and reason back for the log line.
const refusalBodyLimit = 4096

// refusalReasonLimit bounds the reason text written to the log.
const refusalReasonLimit = 200

type refusalTrackerKey struct{}

// refusalTracker watches one response. Sub-packages write their own error
// bodies straight to the ResponseWriter and never reach writeAPIError, so the
// refusal is logged here from the status and the bounded body instead.
type refusalTracker struct {
	http.ResponseWriter
	status int
	body   []byte
	logged bool
}

func (t *refusalTracker) WriteHeader(status int) {
	if t.status == 0 {
		t.status = status
	}
	t.ResponseWriter.WriteHeader(status)
}

func (t *refusalTracker) Write(p []byte) (int, error) {
	if t.status == 0 {
		t.status = http.StatusOK
	}
	if t.status >= 400 && t.status < 500 && len(t.body) < refusalBodyLimit {
		room := refusalBodyLimit - len(t.body)
		if len(p) < room {
			room = len(p)
		}
		t.body = append(t.body, p[:room]...)
	}
	return t.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (t *refusalTracker) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// markRefusalLogged tells the tracker that a 4xx was already logged by
// logClientError, so the same response is not logged twice.
func markRefusalLogged(ctx context.Context) {
	if t, ok := ctx.Value(refusalTrackerKey{}).(*refusalTracker); ok {
		t.logged = true
	}
}

// withRefusalLog logs every 4xx that no other path has logged: the code and
// reason are read from the JSON error body, which is never changed.
func (s *Server) withRefusalLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracker := &refusalTracker{ResponseWriter: w}
		// next (the mux) sets Pattern on the request it receives, so read it
		// from this copy rather than from r.
		seen := r.WithContext(context.WithValue(r.Context(), refusalTrackerKey{}, tracker))
		next.ServeHTTP(tracker, seen)
		if tracker.logged || s.logger == nil || tracker.status < 400 || tracker.status >= 500 {
			return
		}
		code, reason := parseRefusalBody(tracker.body)
		route := seen.Pattern
		if route == "" {
			route = "(unrouted)"
		}
		s.logger.InfoContext(r.Context(), "request refused",
			"request_id", requestID(r.Context()),
			"status", tracker.status,
			"code", code,
			"reason", reason,
			"method", r.Method,
			"route", route,
		)
	})
}

// parseRefusalBody reads the error code and reason out of the shapes the
// handlers use: {"error":{"code":..,"message":..}}, {"error":"code"} and
// {"code":..,"message":..}. Unreadable bodies give "unknown" and "".
func parseRefusalBody(body []byte) (code string, reason string) {
	var envelope struct {
		Error   json.RawMessage `json:"error"`
		Code    string          `json:"code"`
		Message string          `json:"message"`
		Reason  string          `json:"reason"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return "unknown", ""
	}
	code, reason = envelope.Code, firstNonEmpty(envelope.Reason, envelope.Message)
	if len(envelope.Error) > 0 {
		var nested struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Reason  string `json:"reason"`
		}
		var text string
		switch {
		case json.Unmarshal(envelope.Error, &nested) == nil:
			code = firstNonEmpty(nested.Code, code)
			reason = firstNonEmpty(nested.Reason, nested.Message, reason)
		case json.Unmarshal(envelope.Error, &text) == nil:
			code = firstNonEmpty(code, text)
		}
	}
	if code == "" {
		code = "unknown"
	}
	return code, truncateRunes(reason, refusalReasonLimit)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func truncateRunes(value string, limit int) string {
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	runes := []rune(value)
	return string(runes[:limit])
}
