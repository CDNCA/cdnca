package tickets

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// TestTicketHTTP drives the handler end to end: surface separation by scope
// kind, idempotent JSON writes, raw attachment upload and a download served as
// a sandboxed attachment.
func TestTicketHTTP(t *testing.T) {
	f := newFixture(t)
	sessions := map[string]identity.AuthenticatedSession{
		"customer": {SessionID: f.customer.SessionID, Principal: identity.Principal{UserID: f.customer.UserID,
			ScopeID: f.customer.ScopeID, ScopeKind: "tenant"}},
		"staff": {SessionID: f.manager.SessionID, Principal: identity.Principal{UserID: f.manager.UserID,
			ScopeID: f.manager.ScopeID, ScopeKind: "platform", Permissions: []string{PermissionRead, PermissionManage}}},
		"outsider": {SessionID: f.outsider.SessionID, Principal: identity.Principal{UserID: f.outsider.UserID,
			ScopeID: f.outsider.ScopeID, ScopeKind: "platform", Permissions: []string{"sites.read"}}},
	}
	handler, err := NewHandler(f.service, func(_ context.Context, token string) (identity.AuthenticatedSession, error) {
		session, ok := sessions[token]
		if !ok {
			return identity.AuthenticatedSession{}, ErrUnauthenticated
		}
		return session, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	do := func(token, method, path string, body io.Reader, headers map[string]string) (*http.Response, []byte) {
		t.Helper()
		request, _ := http.NewRequestWithContext(t.Context(), method, server.URL+path, body)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		for name, value := range headers {
			request.Header.Set(name, value)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		return response, raw
	}
	jsonHeaders := func(key string) map[string]string {
		return map[string]string{"Content-Type": "application/json", "Idempotency-Key": key}
	}

	if response, _ := do("", "GET", "/v1/tickets", nil, nil); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d", response.StatusCode)
	}
	if response, _ := do("staff", "GET", "/v1/tickets", nil, nil); response.StatusCode != http.StatusForbidden {
		t.Fatalf("staff on customer surface = %d", response.StatusCode)
	}
	if response, _ := do("customer", "GET", "/v1/admin/tickets", nil, nil); response.StatusCode != http.StatusForbidden {
		t.Fatalf("customer on admin surface = %d", response.StatusCode)
	}
	if response, _ := do("outsider", "GET", "/v1/admin/tickets", nil, nil); response.StatusCode != http.StatusForbidden {
		t.Fatalf("outsider = %d", response.StatusCode)
	}

	response, raw := do("customer", "POST", "/v1/tickets/attachments", bytes.NewReader(pngBody),
		map[string]string{"Content-Type": "image/png", "X-File-Name": url.PathEscape("截图 1.png")})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("upload = %d %s", response.StatusCode, raw)
	}
	var attachment Attachment
	_ = json.Unmarshal(raw, &attachment)
	if attachment.FileName != "截图 1.png" || strings.Contains(string(raw), "ticket-attachments/") {
		t.Fatalf("upload body = %s", raw)
	}
	if response, raw := do("customer", "POST", "/v1/tickets/attachments", strings.NewReader("<html>"),
		map[string]string{"Content-Type": "text/html", "X-File-Name": "a.html"}); response.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("html upload = %d %s", response.StatusCode, raw)
	}

	create := `{"category":"billing","subject":"充值未到账","body":"已付款","attachment_ids":["` + attachment.ID + `"]}`
	if response, _ := do("customer", "POST", "/v1/tickets", strings.NewReader(create),
		map[string]string{"Content-Type": "application/json"}); response.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing idempotency key = %d", response.StatusCode)
	}
	if response, _ := do("customer", "POST", "/v1/tickets", strings.NewReader(`{"category":"billing","subject":"x","body":"x","extra":1}`),
		jsonHeaders("http-0")); response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field = %d", response.StatusCode)
	}
	response, raw = do("customer", "POST", "/v1/tickets", strings.NewReader(create), jsonHeaders("http-1"))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", response.StatusCode, raw)
	}
	var detail Detail
	_ = json.Unmarshal(raw, &detail)
	if response, again := do("customer", "POST", "/v1/tickets", strings.NewReader(create), jsonHeaders("http-1")); response.StatusCode != http.StatusCreated ||
		!strings.Contains(string(again), detail.Ticket.ID) {
		t.Fatalf("replay = %d %s", response.StatusCode, again)
	}

	response, raw = do("staff", "GET", "/v1/admin/tickets/attachments/"+attachment.ID, nil, nil)
	if response.StatusCode != http.StatusOK || !bytes.Equal(raw, pngBody) ||
		!strings.HasPrefix(response.Header.Get("Content-Disposition"), "attachment;") ||
		response.Header.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(response.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("download = %d %v", response.StatusCode, response.Header)
	}

	patch := `{"expected_revision":` + itoa64(detail.Ticket.Revision) + `,"status":"resolved"}`
	response, raw = do("staff", "PATCH", "/v1/admin/tickets/"+detail.Ticket.ID, strings.NewReader(patch),
		map[string]string{"Content-Type": "application/json"})
	if response.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"status":"resolved"`) {
		t.Fatalf("patch = %d %s", response.StatusCode, raw)
	}
	if response, raw := do("staff", "PATCH", "/v1/admin/tickets/"+detail.Ticket.ID, strings.NewReader(patch),
		map[string]string{"Content-Type": "application/json"}); response.StatusCode != http.StatusConflict ||
		!strings.Contains(string(raw), "ticket_revision_conflict") {
		t.Fatalf("stale patch = %d %s", response.StatusCode, raw)
	}
	if response, raw := do("customer", "POST", "/v1/tickets/"+detail.Ticket.ID+"/messages", strings.NewReader(`{"body":"x"}`),
		jsonHeaders("http-2")); response.StatusCode != http.StatusConflict || !strings.Contains(string(raw), "ticket_invalid_state") {
		t.Fatalf("reply to resolved = %d %s", response.StatusCode, raw)
	}
	if response, raw := do("customer", "GET", "/v1/tickets?assignee=me", nil, nil); response.StatusCode != http.StatusBadRequest {
		t.Fatalf("customer staff filter = %d %s", response.StatusCode, raw)
	}
	if response, raw := do("customer", "GET", "/v1/tickets/summary", nil, nil); response.StatusCode != http.StatusOK ||
		!strings.Contains(string(raw), `"unread":1`) {
		t.Fatalf("summary = %d %s", response.StatusCode, raw)
	}
	// fix-ticketops: staff soft delete; the customer surface has no delete.
	if response, _ := do("customer", "DELETE", "/v1/admin/tickets/"+detail.Ticket.ID, nil, nil); response.StatusCode != http.StatusForbidden {
		t.Fatalf("customer delete = %d", response.StatusCode)
	}
	if response, raw := do("staff", "DELETE", "/v1/admin/tickets/"+detail.Ticket.ID, nil, nil); response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d %s", response.StatusCode, raw)
	}
	if response, raw := do("staff", "DELETE", "/v1/admin/tickets/"+detail.Ticket.ID, nil, nil); response.StatusCode != http.StatusNotFound ||
		!strings.Contains(string(raw), "ticket_not_found") {
		t.Fatalf("delete again = %d %s", response.StatusCode, raw)
	}
	if response, _ := do("customer", "GET", "/v1/tickets/"+detail.Ticket.ID, nil, nil); response.StatusCode != http.StatusNotFound {
		t.Fatalf("customer get deleted = %d", response.StatusCode)
	}
}

func itoa64(value int64) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
