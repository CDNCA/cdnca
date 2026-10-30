package announcementhttp

import (
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type globalDraftRequest struct {
	Title                string                           `json:"title"`
	Body                 string                           `json:"body"`
	Format               string                           `json:"format"`
	LinkURL              string                           `json:"link_url"`
	SortOrder            *int64                           `json:"sort_order"`
	Visible              *bool                            `json:"visible"`
	Popup                bool                             `json:"popup"`
	Red                  bool                             `json:"red"`
	Bold                 bool                             `json:"bold"`
	AllTenants           *bool                            `json:"all_tenants"`
	TenantScopeIDs       *[]uuid.UUID                     `json:"tenant_scope_ids"`
	RoleTargets          *[]announcement.GlobalRoleTarget `json:"role_targets"`
	UserTargets          *[]announcement.GlobalUserTarget `json:"user_targets"`
	WithdrawalVisibility string                           `json:"withdrawal_visibility"`
}

type globalUpdateRequest struct {
	ExpectedRevision     int64                            `json:"expected_revision"`
	Title                string                           `json:"title"`
	Body                 string                           `json:"body"`
	Format               string                           `json:"format"`
	LinkURL              string                           `json:"link_url"`
	SortOrder            *int64                           `json:"sort_order"`
	Visible              *bool                            `json:"visible"`
	Popup                bool                             `json:"popup"`
	Red                  bool                             `json:"red"`
	Bold                 bool                             `json:"bold"`
	AllTenants           *bool                            `json:"all_tenants"`
	TenantScopeIDs       *[]uuid.UUID                     `json:"tenant_scope_ids"`
	RoleTargets          *[]announcement.GlobalRoleTarget `json:"role_targets"`
	UserTargets          *[]announcement.GlobalUserTarget `json:"user_targets"`
	WithdrawalVisibility string                           `json:"withdrawal_visibility"`
}

type globalTransitionRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
}

func (h *Handler) listGlobal(w http.ResponseWriter, r *http.Request) {
	session, ok := h.platformManager(w, r)
	if !ok {
		return
	}
	if !validQuery(r, map[string]bool{"limit": true, "cursor": true, "status": true}) {
		writeError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
		return
	}
	limit, err := queryLimit(r)
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	result, err := h.store.ListGlobalAnnouncements(r.Context(), actor(session), announcement.AnnouncementListRequest{
		Limit: limit, Cursor: r.URL.Query().Get("cursor"), Status: r.URL.Query().Get("status"),
	})
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) getGlobal(w http.ResponseWriter, r *http.Request) {
	session, ok := h.platformManager(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	result, err := h.store.GetGlobalAnnouncement(r.Context(), actor(session), id)
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) createGlobal(w http.ResponseWriter, r *http.Request) {
	session, ok := h.platformManager(w, r)
	if !ok {
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	var body globalDraftRequest
	if !h.decode(w, r, &body) {
		return
	}
	audience, ok := requiredGlobalAudience(w, r, body.AllTenants, body.TenantScopeIDs, body.RoleTargets, body.UserTargets)
	if !ok {
		return
	}
	result, err := h.store.CreateGlobalDraft(r.Context(), actor(session), announcement.CreateGlobalDraftRequest{
		Content:              announcement.Content{Title: body.Title, Body: body.Body},
		Presentation:         presentation(body.Format, body.LinkURL, body.SortOrder, body.Visible, body.Popup, body.Red, body.Bold),
		Audience:             audience,
		WithdrawalVisibility: body.WithdrawalVisibility, IdempotencyKey: key, RequestID: requestID(r),
	})
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, result)
}

func (h *Handler) updateGlobal(w http.ResponseWriter, r *http.Request) {
	session, ok := h.platformManager(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	revision, ok := ifMatch(w, r)
	if !ok {
		return
	}
	var body globalUpdateRequest
	if !h.decode(w, r, &body) {
		return
	}
	if body.ExpectedRevision != revision {
		writeError(w, r, http.StatusBadRequest, "validation_error", "expected_revision must match If-Match")
		return
	}
	audience, ok := requiredGlobalAudience(w, r, body.AllTenants, body.TenantScopeIDs, body.RoleTargets, body.UserTargets)
	if !ok {
		return
	}
	result, err := h.store.UpdateGlobalDraft(r.Context(), actor(session), announcement.UpdateGlobalDraftRequest{
		AnnouncementID: id, ExpectedRevision: body.ExpectedRevision,
		Content:              announcement.Content{Title: body.Title, Body: body.Body},
		Presentation:         presentation(body.Format, body.LinkURL, body.SortOrder, body.Visible, body.Popup, body.Red, body.Bold),
		Audience:             audience,
		WithdrawalVisibility: body.WithdrawalVisibility, IdempotencyKey: key, RequestID: requestID(r),
	})
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) publishGlobal(w http.ResponseWriter, r *http.Request) {
	h.transitionGlobal(w, r, true)
}

func (h *Handler) withdrawGlobal(w http.ResponseWriter, r *http.Request) {
	h.transitionGlobal(w, r, false)
}

func (h *Handler) archiveGlobal(w http.ResponseWriter, r *http.Request) {
	h.globalLifecycle(w, r, true)
}

func (h *Handler) restoreGlobal(w http.ResponseWriter, r *http.Request) {
	h.globalLifecycle(w, r, false)
}

func (h *Handler) globalLifecycle(w http.ResponseWriter, r *http.Request, archive bool) {
	session, ok := h.platformManager(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	revision, ok := ifMatch(w, r)
	if !ok {
		return
	}
	var body lifecycleRequest
	if !h.decode(w, r, &body) {
		return
	}
	if body.ExpectedLifecycleRevision != revision {
		writeError(w, r, http.StatusBadRequest, "validation_error", "expected_lifecycle_revision must match If-Match")
		return
	}
	request := announcement.ArchiveRequest{AnnouncementID: id, ExpectedLifecycleRevision: revision, IdempotencyKey: key, RequestID: requestID(r)}
	var result announcement.GlobalAnnouncement
	var err error
	if archive {
		result, err = h.store.ArchiveGlobal(r.Context(), actor(session), request)
	} else {
		result, err = h.store.RestoreGlobal(r.Context(), actor(session), announcement.RestoreRequest(request))
	}
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) transitionGlobal(w http.ResponseWriter, r *http.Request, publish bool) {
	session, ok := h.platformManager(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	revision, ok := ifMatch(w, r)
	if !ok {
		return
	}
	var body globalTransitionRequest
	if !h.decode(w, r, &body) {
		return
	}
	if body.ExpectedRevision != revision {
		writeError(w, r, http.StatusBadRequest, "validation_error", "expected_revision must match If-Match")
		return
	}
	request := announcement.GlobalTransitionRequest{
		AnnouncementID: id, ExpectedRevision: body.ExpectedRevision,
		IdempotencyKey: key, RequestID: requestID(r),
	}
	var result announcement.GlobalAnnouncement
	var err error
	if publish {
		result, err = h.store.PublishGlobal(r.Context(), actor(session), request)
	} else {
		result, err = h.store.WithdrawGlobal(r.Context(), actor(session), request)
	}
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) platformManager(w http.ResponseWriter, r *http.Request) (SessionEnvelope, bool) {
	session, err := h.authenticate(r)
	if err != nil || session.SessionID == uuid.Nil {
		writeError(w, r, http.StatusUnauthorized, "invalid_session", "authentication is required")
		return SessionEnvelope{}, false
	}
	principal := session.Principal
	if principal.ScopeKind != "platform" || principal.TenantID != nil || identity.Authorize(principal, "announcements.manage") != nil {
		writeError(w, r, http.StatusForbidden, "permission_denied", "platform announcement permission is required")
		return SessionEnvelope{}, false
	}
	return session, true
}

func requiredGlobalAudience(
	w http.ResponseWriter,
	r *http.Request,
	allTenants *bool,
	tenantScopeIDs *[]uuid.UUID,
	roleTargets *[]announcement.GlobalRoleTarget,
	userTargets *[]announcement.GlobalUserTarget,
) (announcement.GlobalAudience, bool) {
	if allTenants == nil || tenantScopeIDs == nil || roleTargets == nil || userTargets == nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "global audience arrays are required")
		return announcement.GlobalAudience{}, false
	}
	return announcement.GlobalAudience{
		AllTenants: *allTenants, TenantScopeIDs: *tenantScopeIDs, RoleTargets: *roleTargets, UserTargets: *userTargets,
	}, true
}
