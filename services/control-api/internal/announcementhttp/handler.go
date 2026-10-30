package announcementhttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const maxResponseBytes = 1 << 20

type SessionEnvelope struct {
	Principal identity.Principal
	SessionID uuid.UUID
}

type AuthenticateFunc func(*http.Request) (SessionEnvelope, error)

type AuthenticatorV1 interface {
	AuthenticateAnnouncementSessionV1(*http.Request) (SessionEnvelope, error)
}

func (authenticate AuthenticateFunc) AuthenticateAnnouncementSessionV1(request *http.Request) (SessionEnvelope, error) {
	return authenticate(request)
}

type Handler struct {
	store        *announcement.Store
	authenticate AuthenticateFunc
	maxBodyBytes int64
}

func New(store *announcement.Store, authenticator AuthenticatorV1) (*Handler, error) {
	if store == nil || authenticator == nil {
		return nil, errors.New("announcement HTTP dependencies are required")
	}
	if authenticate, ok := authenticator.(AuthenticateFunc); ok && authenticate == nil {
		return nil, errors.New("announcement HTTP dependencies are required")
	}
	return &Handler{store: store, authenticate: authenticator.AuthenticateAnnouncementSessionV1, maxBodyBytes: 1 << 20}, nil
}

func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/admin/announcements/global", h.listGlobal)
	mux.HandleFunc("POST /v1/admin/announcements/global", h.createGlobal)
	mux.HandleFunc("GET /v1/admin/announcements/global/{id}", h.getGlobal)
	mux.HandleFunc("PATCH /v1/admin/announcements/global/{id}", h.updateGlobal)
	mux.HandleFunc("POST /v1/admin/announcements/global/{id}/publish", h.publishGlobal)
	mux.HandleFunc("POST /v1/admin/announcements/global/{id}/withdraw", h.withdrawGlobal)
	mux.HandleFunc("POST /v1/admin/announcements/global/{id}/archive", h.archiveGlobal)
	mux.HandleFunc("POST /v1/admin/announcements/global/{id}/restore", h.restoreGlobal)
	mux.HandleFunc("GET /v1/admin/announcements/global/audience-directory", h.globalAudienceDirectory)
	mux.HandleFunc("GET /v1/admin/announcements/global/{id}/audience/count", h.globalAudienceCount)
	mux.HandleFunc("GET /v1/admin/announcements/audience-directory", h.audienceDirectory)
	mux.HandleFunc("GET /v1/admin/announcements/{id}/audience/count", h.audienceCount)
	mux.HandleFunc("GET /v1/admin/announcements", h.list)
	mux.HandleFunc("GET /v1/admin/announcements/{id}", h.get)
	mux.HandleFunc("POST /v1/admin/announcements", h.create)
	mux.HandleFunc("PATCH /v1/admin/announcements/{id}", h.update)
	mux.HandleFunc("POST /v1/admin/announcements/{id}/schedule", h.schedule)
	mux.HandleFunc("POST /v1/admin/announcements/{id}/publish", h.publish)
	mux.HandleFunc("POST /v1/admin/announcements/{id}/revise", h.revise)
	mux.HandleFunc("POST /v1/admin/announcements/{id}/withdraw", h.withdraw)
	mux.HandleFunc("POST /v1/admin/announcements/{id}/archive", h.archive)
	mux.HandleFunc("POST /v1/admin/announcements/{id}/restore", h.restore)
	mux.HandleFunc("GET /v1/account/messages", h.listInbox)
	mux.HandleFunc("POST /v1/account/messages/{event_id}/delivered", h.delivered)
	mux.HandleFunc("POST /v1/account/messages/{event_id}/read", h.read)
	return mux
}

type createRequest struct {
	Title                string       `json:"title"`
	Body                 string       `json:"body"`
	Format               string       `json:"format"`
	LinkURL              string       `json:"link_url"`
	SortOrder            *int64       `json:"sort_order"`
	Visible              *bool        `json:"visible"`
	Popup                bool         `json:"popup"`
	Red                  bool         `json:"red"`
	Bold                 bool         `json:"bold"`
	All                  bool         `json:"all"`
	UserIDs              *[]uuid.UUID `json:"user_ids"`
	GroupIDs             *[]uuid.UUID `json:"group_ids"`
	WithdrawalVisibility string       `json:"withdrawal_visibility"`
}

type updateRequest struct {
	Version              int64        `json:"version"`
	ExpectedRevision     int64        `json:"expected_revision"`
	Title                string       `json:"title"`
	Body                 string       `json:"body"`
	Format               string       `json:"format"`
	LinkURL              string       `json:"link_url"`
	SortOrder            *int64       `json:"sort_order"`
	Visible              *bool        `json:"visible"`
	Popup                bool         `json:"popup"`
	Red                  bool         `json:"red"`
	Bold                 bool         `json:"bold"`
	All                  bool         `json:"all"`
	UserIDs              *[]uuid.UUID `json:"user_ids"`
	GroupIDs             *[]uuid.UUID `json:"group_ids"`
	WithdrawalVisibility string       `json:"withdrawal_visibility"`
}

type scheduleRequest struct {
	Version          int64  `json:"version"`
	ExpectedRevision int64  `json:"expected_revision"`
	PublishAt        string `json:"publish_at"`
}

type publishRequest struct {
	Version          int64 `json:"version"`
	ExpectedRevision int64 `json:"expected_revision"`
}

type reviseRequest struct {
	ExpectedHeadVersion  int64        `json:"expected_head_version"`
	Title                string       `json:"title"`
	Body                 string       `json:"body"`
	Format               string       `json:"format"`
	LinkURL              string       `json:"link_url"`
	SortOrder            *int64       `json:"sort_order"`
	Visible              *bool        `json:"visible"`
	Popup                bool         `json:"popup"`
	Red                  bool         `json:"red"`
	Bold                 bool         `json:"bold"`
	All                  bool         `json:"all"`
	UserIDs              *[]uuid.UUID `json:"user_ids"`
	GroupIDs             *[]uuid.UUID `json:"group_ids"`
	WithdrawalVisibility string       `json:"withdrawal_visibility"`
}

func presentation(format, linkURL string, sortOrder *int64, visible *bool, popup, red, bold bool) announcement.Presentation {
	if format == "" {
		format = announcement.FormatContent
	}
	result := announcement.Presentation{Format: format, LinkURL: linkURL, SortOrder: 100, Popup: popup, Red: red, Bold: bold}
	if sortOrder != nil {
		result.SortOrder = *sortOrder
	}
	if visible == nil {
		result.Visible = true
	} else {
		result.Visible = *visible
	}
	return announcement.NormalizePresentation(result)
}

type withdrawRequest struct {
	Version          int64 `json:"version"`
	ExpectedRevision int64 `json:"expected_revision"`
}

type lifecycleRequest struct {
	ExpectedLifecycleRevision int64 `json:"expected_lifecycle_revision"`
}

type stateRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.manager(w, r)
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
	result, err := h.store.ListAnnouncements(r.Context(), actor(principal), announcement.AnnouncementListRequest{
		Limit: limit, Cursor: r.URL.Query().Get("cursor"), Status: r.URL.Query().Get("status"),
	})
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.manager(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	result, err := h.store.GetAnnouncement(r.Context(), actor(principal), id)
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.manager(w, r)
	if !ok {
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createRequest
	if !h.decode(w, r, &body) {
		return
	}
	audience, ok := requiredAudience(w, r, body.All, body.UserIDs, body.GroupIDs)
	if !ok {
		return
	}
	result, err := h.store.CreateDraft(r.Context(), actor(principal), announcement.CreateDraftRequest{
		Content:              announcement.Content{Title: body.Title, Body: body.Body},
		Presentation:         presentation(body.Format, body.LinkURL, body.SortOrder, body.Visible, body.Popup, body.Red, body.Bold),
		Audience:             audience,
		WithdrawalVisibility: body.WithdrawalVisibility,
		IdempotencyKey:       key, RequestID: requestID(r),
	})
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, result)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.manager(w, r)
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
	var body updateRequest
	if !h.decode(w, r, &body) {
		return
	}
	audience, ok := requiredAudience(w, r, body.All, body.UserIDs, body.GroupIDs)
	if !ok {
		return
	}
	if body.ExpectedRevision != revision {
		writeError(w, r, http.StatusBadRequest, "validation_error", "expected_revision must match If-Match")
		return
	}
	result, err := h.store.UpdateDraft(r.Context(), actor(principal), announcement.UpdateDraftRequest{
		AnnouncementID: id, Version: body.Version, ExpectedRevision: body.ExpectedRevision,
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

func (h *Handler) schedule(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.manager(w, r)
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
	var body scheduleRequest
	if !h.decode(w, r, &body) {
		return
	}
	if body.ExpectedRevision != revision {
		writeError(w, r, http.StatusBadRequest, "validation_error", "expected_revision must match If-Match")
		return
	}
	publishAt, err := parseTime(body.PublishAt)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "validation_error", "publish_at must be an RFC3339 timestamp")
		return
	}
	result, err := h.store.Schedule(r.Context(), actor(principal), announcement.ScheduleRequest{
		AnnouncementID: id, Version: body.Version, ExpectedRevision: body.ExpectedRevision,
		PublishAt: publishAt, IdempotencyKey: key, RequestID: requestID(r),
	})
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) publish(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.manager(w, r)
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
	var body publishRequest
	if !h.decode(w, r, &body) {
		return
	}
	if body.ExpectedRevision != revision {
		writeError(w, r, http.StatusBadRequest, "validation_error", "expected_revision must match If-Match")
		return
	}
	result, err := h.store.Publish(r.Context(), actor(principal), announcement.PublishRequest{
		AnnouncementID: id, Version: body.Version, ExpectedRevision: body.ExpectedRevision,
		IdempotencyKey: key, RequestID: requestID(r),
	})
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) revise(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.manager(w, r)
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
	var body reviseRequest
	if !h.decode(w, r, &body) {
		return
	}
	audience, ok := requiredAudience(w, r, body.All, body.UserIDs, body.GroupIDs)
	if !ok {
		return
	}
	if body.ExpectedHeadVersion != revision {
		writeError(w, r, http.StatusBadRequest, "validation_error", "expected_head_version must match If-Match")
		return
	}
	result, err := h.store.Revise(r.Context(), actor(principal), announcement.ReviseRequest{
		AnnouncementID: id, ExpectedHeadVersion: body.ExpectedHeadVersion,
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

func (h *Handler) withdraw(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.manager(w, r)
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
	var body withdrawRequest
	if !h.decode(w, r, &body) {
		return
	}
	if body.ExpectedRevision != revision {
		writeError(w, r, http.StatusBadRequest, "validation_error", "expected_revision must match If-Match")
		return
	}
	result, err := h.store.Withdraw(r.Context(), actor(principal), announcement.WithdrawRequest{
		AnnouncementID: id, Version: body.Version, ExpectedRevision: body.ExpectedRevision,
		IdempotencyKey: key, RequestID: requestID(r),
	})
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) archive(w http.ResponseWriter, r *http.Request) {
	h.lifecycle(w, r, true)
}

func (h *Handler) restore(w http.ResponseWriter, r *http.Request) {
	h.lifecycle(w, r, false)
}

func (h *Handler) lifecycle(w http.ResponseWriter, r *http.Request, archive bool) {
	principal, ok := h.manager(w, r)
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
	var result announcement.Announcement
	var err error
	if archive {
		result, err = h.store.Archive(r.Context(), actor(principal), announcement.ArchiveRequest{
			AnnouncementID: id, ExpectedLifecycleRevision: revision, IdempotencyKey: key, RequestID: requestID(r),
		})
	} else {
		result, err = h.store.Restore(r.Context(), actor(principal), announcement.RestoreRequest{
			AnnouncementID: id, ExpectedLifecycleRevision: revision, IdempotencyKey: key, RequestID: requestID(r),
		})
	}
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) listInbox(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.reader(w, r)
	if !ok {
		return
	}
	if !validQuery(r, map[string]bool{"limit": true, "cursor": true, "filter": true, "offset": true}) {
		writeError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
		return
	}
	limit, err := queryLimit(r)
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		if offset, err = strconv.Atoi(raw); err != nil || strconv.Itoa(offset) != raw {
			writeCoreError(w, r, announcement.ErrInvalidInput)
			return
		}
	}
	result, err := h.store.ListInbox(r.Context(), actor(principal), announcement.ListRequest{
		Limit: limit, Cursor: r.URL.Query().Get("cursor"), Offset: offset, ReadFilter: r.URL.Query().Get("filter"),
	})
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) delivered(w http.ResponseWriter, r *http.Request) {
	h.state(w, r, false)
}

func (h *Handler) read(w http.ResponseWriter, r *http.Request) {
	h.state(w, r, true)
}

func (h *Handler) state(w http.ResponseWriter, r *http.Request, markRead bool) {
	principal, ok := h.reader(w, r)
	if !ok {
		return
	}
	eventID, ok := pathUUID(w, r, "event_id")
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
	var body stateRequest
	if !h.decode(w, r, &body) {
		return
	}
	if body.ExpectedRevision != revision {
		writeError(w, r, http.StatusBadRequest, "validation_error", "expected_revision must match If-Match")
		return
	}
	request := announcement.StateRequest{EventID: eventID, ExpectedRevision: body.ExpectedRevision, IdempotencyKey: key, RequestID: requestID(r)}
	var result announcement.InboxState
	var err error
	if markRead {
		result, err = h.store.MarkRead(r.Context(), actor(principal), request)
	} else {
		result, err = h.store.MarkDelivered(r.Context(), actor(principal), request)
	}
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) manager(w http.ResponseWriter, r *http.Request) (SessionEnvelope, bool) {
	return h.authorized(w, r, true)
}

func (h *Handler) reader(w http.ResponseWriter, r *http.Request) (SessionEnvelope, bool) {
	return h.authorized(w, r, false)
}

func (h *Handler) authorized(w http.ResponseWriter, r *http.Request, manage bool) (SessionEnvelope, bool) {
	session, err := h.authenticate(r)
	if err != nil || session.SessionID == uuid.Nil {
		writeError(w, r, http.StatusUnauthorized, "invalid_session", "authentication is required")
		return SessionEnvelope{}, false
	}
	principal := session.Principal
	if principal.ScopeKind != "tenant" && !(principal.ScopeKind == "platform" && principal.TenantID == nil) {
		writeError(w, r, http.StatusForbidden, "permission_denied", "tenant scope is required")
		return SessionEnvelope{}, false
	}
	permission := "announcements.read"
	if manage {
		permission = "announcements.manage"
	}
	if err := identity.Authorize(principal, permission); err != nil {
		writeError(w, r, http.StatusForbidden, "permission_denied", "permission is required")
		return SessionEnvelope{}, false
	}
	return session, true
}

func actor(session SessionEnvelope) announcement.Actor {
	return announcement.Actor{
		ScopeID: session.Principal.ScopeID, UserID: session.Principal.UserID, SessionID: session.SessionID,
	}
}

func (h *Handler) decode(w http.ResponseWriter, r *http.Request, destination any) bool {
	mediaType, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if len(r.Header.Values("Content-Type")) != 1 || err != nil || mediaType != "application/json" ||
		(len(parameters) != 0 && (len(parameters) != 1 || !strings.EqualFold(parameters["charset"], "utf-8"))) {
		writeError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	payload, err := io.ReadAll(r.Body)
	if err != nil || !uniqueJSONKeys(payload) {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "request body must contain one JSON value")
		return false
	}
	return true
}

func uniqueJSONKeys(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := scanUniqueJSONValue(decoder); err != nil {
		return false
	}
	var extra any
	return decoder.Decode(&extra) == io.EOF
}

func scanUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := keys[key]; exists {
				return errors.New("duplicate JSON object key")
			}
			keys[key] = struct{}{}
			if err := scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

func requiredAudience(w http.ResponseWriter, r *http.Request, all bool, userIDs, groupIDs *[]uuid.UUID) (announcement.Audience, bool) {
	if userIDs == nil || groupIDs == nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "user_ids and group_ids are required arrays")
		return announcement.Audience{}, false
	}
	return announcement.Audience{All: all, UserIDs: *userIDs, GroupIDs: *groupIDs}, true
}

func queryLimit(r *http.Request) (int, error) {
	value := strings.TrimSpace(r.URL.Query().Get("limit"))
	if value == "" {
		return announcement.DefaultPageSize, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 1 || limit > announcement.MaxPageSize {
		return 0, announcement.ErrInvalidInput
	}
	return limit, nil
}

func validQuery(r *http.Request, allowed map[string]bool) bool {
	for key, values := range r.URL.Query() {
		if !allowed[key] || len(values) != 1 {
			return false
		}
	}
	return true
}

func pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil || id == uuid.Nil {
		writeError(w, r, http.StatusBadRequest, "validation_error", "resource ID must be a UUID")
		return uuid.Nil, false
	}
	return id, true
}

func idempotencyKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || len(key) > 128 || !metaPattern(key) {
		writeError(w, r, http.StatusBadRequest, "validation_error", "Idempotency-Key is invalid")
		return "", false
	}
	return key, true
}

func ifMatch(w http.ResponseWriter, r *http.Request) (int64, bool) {
	value := strings.TrimSpace(r.Header.Get("If-Match"))
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		writeError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive revision")
		return 0, false
	}
	revision, err := strconv.ParseInt(value[1:len(value)-1], 10, 64)
	if err != nil || revision < 1 {
		writeError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive revision")
		return 0, false
	}
	return revision, true
}

func metaPattern(value string) bool {
	for index, r := range value {
		alphaNumeric := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !(alphaNumeric || r == '.' || r == '_' || r == ':' || r == '-') || (index == 0 && !alphaNumeric) {
			return false
		}
	}
	return true
}

func parseTime(value string) (t time.Time, err error) {
	return time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id == "" || len(id) > 128 || !metaPattern(id) {
		return "http-announcement-request"
	}
	return id
}

func writeCoreError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := http.StatusInternalServerError, "internal_error", "the request could not be completed"
	switch {
	case errors.Is(err, announcement.ErrInvalidInput), errors.Is(err, announcement.ErrInvalidContent), errors.Is(err, announcement.ErrInvalidAudience):
		status, code, message = http.StatusBadRequest, "validation_error", "request fields are invalid"
	case errors.Is(err, announcement.ErrInvalidCursor):
		status, code, message = http.StatusBadRequest, "invalid_cursor", "the cursor is invalid"
	case errors.Is(err, announcement.ErrPermissionDenied):
		status, code, message = http.StatusForbidden, "permission_denied", "permission is required"
	case errors.Is(err, announcement.ErrAudienceScopeDenied):
		status, code, message = http.StatusUnprocessableEntity, "audience_scope_denied", "audience members must belong to the tenant"
	case errors.Is(err, announcement.ErrEmptyAudience):
		status, code, message = http.StatusConflict, "empty_audience", "the audience has no active members"
	case errors.Is(err, announcement.ErrNotFound):
		status, code, message = http.StatusNotFound, "announcement_not_found", "the announcement was not found"
	case errors.Is(err, announcement.ErrRevisionConflict):
		status, code, message = http.StatusConflict, "version_conflict", "the announcement revision is stale"
	case errors.Is(err, announcement.ErrInvalidTransition):
		status, code, message = http.StatusConflict, "announcement_state_conflict", "the announcement state does not allow this operation"
	case errors.Is(err, announcement.ErrIdempotencyConflict):
		status, code, message = http.StatusConflict, "idempotency_conflict", "Idempotency-Key was already used with different input"
	}
	if located, ok := fielderr.As(err); ok && code == "validation_error" {
		// fix-fielderr-be4: the refused body field, for the editor to mark.
		writeJSON(w, r, status, map[string]any{"error": map[string]any{
			"code": code, "message": message, "request_id": requestID(r),
			"details": map[string]string{"field": located.Field, "reason": located.Reason},
		}})
		return
	}
	writeError(w, r, status, code, message)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, r, status, map[string]any{"error": map[string]string{
		"code": code, "message": message, "request_id": requestID(r),
	}})
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > maxResponseBytes {
		encoded, _ = json.Marshal(map[string]any{"error": map[string]string{
			"code": "internal_error", "message": "the response could not be encoded", "request_id": requestID(r),
		}})
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(encoded, '\n'))
}
