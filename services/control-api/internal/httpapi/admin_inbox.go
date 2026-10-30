package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/admininbox"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// Message center (admininbox). Every platform-scope session reads its own
// operations messages under /v1/admin/inbox; every tenant-scope session reads
// its own in-app notices (attack escalation, N23) under /v1/account/inbox.
// The inbox only holds events already addressed to that user in that scope.

func (s *Server) adminInboxRecipient(w http.ResponseWriter, r *http.Request) (admininbox.Recipient, bool) {
	principal, err := s.authenticatedSessionPrincipal(r)
	if err != nil {
		s.writeError(w, r, err)
		return admininbox.Recipient{}, false
	}
	// /v1/admin/inbox is the platform's, /v1/account/inbox the tenant's.
	if (principal.ScopeKind == "platform") != strings.HasPrefix(r.URL.Path, "/v1/admin/") {
		s.writeError(w, r, identity.ErrPermissionDenied)
		return admininbox.Recipient{}, false
	}
	if s.adminInbox == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "admin_inbox_unavailable", "message center is unavailable")
		return admininbox.Recipient{}, false
	}
	return admininbox.Recipient{UserID: principal.UserID, ScopeID: principal.ScopeID, RequestID: requestID(r.Context())}, true
}

func (s *Server) handleAdminInboxUnread(w http.ResponseWriter, r *http.Request) {
	recipient, ok := s.adminInboxRecipient(w, r)
	if !ok {
		return
	}
	count, err := s.adminInbox.UnreadCount(r.Context(), recipient)
	if err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "admin_inbox_unavailable", "message center is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"unread": count})
}

func (s *Server) handleAdminInboxList(w http.ResponseWriter, r *http.Request) {
	recipient, ok := s.adminInboxRecipient(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	pageSize := 20
	if raw := query.Get("page_size"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "page_size is invalid")
			return
		}
		pageSize = value
	}
	page, err := s.adminInbox.List(r.Context(), recipient, query.Get("unread") == "true", pageSize, query.Get("cursor"))
	if errors.Is(err, admininbox.ErrInvalidInput) {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "query is invalid")
		return
	}
	if err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "admin_inbox_unavailable", "message center is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleAdminInboxRead(w http.ResponseWriter, r *http.Request) {
	recipient, ok := s.adminInboxRecipient(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("message_id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "message_id is invalid")
		return
	}
	if err := s.adminInbox.MarkRead(r.Context(), recipient, id); err != nil {
		if errors.Is(err, admininbox.ErrNotFound) {
			s.writeAPIError(w, r, http.StatusNotFound, "admin_inbox_message_not_found", "message was not found")
			return
		}
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "admin_inbox_unavailable", "message center is unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminInboxReadAll(w http.ResponseWriter, r *http.Request) {
	recipient, ok := s.adminInboxRecipient(w, r)
	if !ok {
		return
	}
	marked, err := s.adminInbox.MarkAllRead(r.Context(), recipient)
	if err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "admin_inbox_unavailable", "message center is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"marked": marked})
}
