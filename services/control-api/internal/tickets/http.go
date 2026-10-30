package tickets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const maxJSONBytes = 128 << 10

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

// Handler serves the customer surface /v1/tickets (tenant sessions, own
// tickets only), the staff surface /v1/admin/tickets (platform sessions
// with tickets.read / tickets.manage).
type Handler struct {
	service      *Service
	authenticate AuthenticateSessionFunc
	mux          *http.ServeMux
}

// Patterns are the routes the control-api server forwards here.
var Patterns = []string{
	"GET /v1/tickets", "POST /v1/tickets", "GET /v1/tickets/summary",
	"POST /v1/tickets/attachments", "GET /v1/tickets/attachments/{id}",
	"GET /v1/tickets/{id}", "POST /v1/tickets/{id}/messages",
	"POST /v1/tickets/{id}/close", "POST /v1/tickets/{id}/reopen",
	"GET /v1/admin/tickets", "POST /v1/admin/tickets", "GET /v1/admin/tickets/summary", "GET /v1/admin/tickets/assignees",
	"POST /v1/admin/tickets/attachments", "GET /v1/admin/tickets/attachments/{id}",
	"GET /v1/admin/tickets/{id}", "PATCH /v1/admin/tickets/{id}", "POST /v1/admin/tickets/{id}/messages",
	"DELETE /v1/admin/tickets/{id}",
}

// surface is who a route serves.
type surface int

const (
	surfaceCustomer surface = iota
	surfaceStaff
)

func NewHandler(service *Service, authenticate AuthenticateSessionFunc) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, ErrInvalidInput
	}
	handler := &Handler{service: service, authenticate: authenticate, mux: http.NewServeMux()}
	for _, side := range []surface{surfaceCustomer, surfaceStaff} {
		prefix := map[surface]string{surfaceCustomer: "/v1/tickets", surfaceStaff: "/v1/admin/tickets"}[side]
		handler.mux.HandleFunc("GET "+prefix, handler.withActor(side, handler.list))
		handler.mux.HandleFunc("GET "+prefix+"/summary", handler.withActor(side, handler.summary))
		handler.mux.HandleFunc("POST "+prefix+"/attachments", handler.withActor(side, handler.upload))
		handler.mux.HandleFunc("GET "+prefix+"/attachments/{id}", handler.withActor(side, handler.download))
		handler.mux.HandleFunc("GET "+prefix+"/{id}", handler.withActor(side, handler.get))
		handler.mux.HandleFunc("POST "+prefix+"/{id}/messages", handler.withActor(side, handler.reply))
	}
	handler.mux.HandleFunc("POST /v1/tickets", handler.withActor(surfaceCustomer, handler.create))
	handler.mux.HandleFunc("POST /v1/tickets/{id}/close", handler.withActor(surfaceCustomer, handler.transition(false)))
	handler.mux.HandleFunc("POST /v1/tickets/{id}/reopen", handler.withActor(surfaceCustomer, handler.transition(true)))
	handler.mux.HandleFunc("POST /v1/admin/tickets", handler.withActor(surfaceStaff, handler.staffCreate))
	handler.mux.HandleFunc("GET /v1/admin/tickets/assignees", handler.withActor(surfaceStaff, handler.assignees))
	handler.mux.HandleFunc("PATCH /v1/admin/tickets/{id}", handler.withActor(surfaceStaff, handler.update))
	handler.mux.HandleFunc("DELETE /v1/admin/tickets/{id}", handler.withActor(surfaceStaff, handler.remove))
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	handler.mux.ServeHTTP(response, request)
}

type call struct {
	actor     Actor
	staff     bool
	requestID string
}

type route func(http.ResponseWriter, *http.Request, call)

func (handler *Handler) withActor(side surface, next route) http.HandlerFunc {
	staff := side != surfaceCustomer
	return func(response http.ResponseWriter, request *http.Request) {
		values := request.Header.Values("Authorization")
		if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || values[0][7:] == "" ||
			strings.TrimSpace(values[0][7:]) != values[0][7:] {
			writeError(response, http.StatusUnauthorized, "unauthorized")
			return
		}
		session, err := handler.authenticate(request.Context(), values[0][7:])
		if err != nil || session.Principal.UserID == uuid.Nil || session.SessionID == uuid.Nil ||
			session.Principal.ScopeID == uuid.Nil {
			writeError(response, http.StatusUnauthorized, "unauthorized")
			return
		}
		kind, read, manage := "tenant", PermissionRead, PermissionManage
		if side == surfaceStaff {
			kind = "platform"
		}
		if session.Principal.ScopeKind != kind || (staff && identity.Authorize(session.Principal, read) != nil &&
			identity.Authorize(session.Principal, manage) != nil) {
			writeError(response, http.StatusForbidden, "permission_denied")
			return
		}
		requestID := request.Header.Get("X-Request-ID")
		if !keyPattern.MatchString(requestID) {
			requestID = uuid.NewString()
		}
		next(response, request, call{actor: Actor{UserID: session.Principal.UserID, ScopeID: session.Principal.ScopeID,
			SessionID: session.SessionID}, staff: staff, requestID: requestID})
	}
}

func parseFilter(values url.Values, staff bool) (Filter, bool) {
	allowed := map[string]bool{"status": true, "category": true, "q": true, "limit": true, "offset": true}
	if staff {
		for _, name := range []string{"priority", "assignee", "user_id", "sla_breached"} {
			allowed[name] = true
		}
	}
	for name, list := range values {
		if !allowed[name] || len(list) != 1 {
			return Filter{}, false
		}
	}
	filter := Filter{Status: values.Get("status"), Category: values.Get("category"), Query: values.Get("q"),
		Priority: values.Get("priority"), AssigneeUserID: values.Get("assignee"), UserID: values.Get("user_id")}
	for name, target := range map[string]*int{"limit": &filter.Limit, "offset": &filter.Offset} {
		if raw := values.Get(name); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || strconv.Itoa(parsed) != raw {
				return Filter{}, false
			}
			*target = parsed
		}
	}
	switch values.Get("sla_breached") {
	case "":
	case "true":
		filter.SLABreached = true
	default:
		return Filter{}, false
	}
	return filter, true
}

func (handler *Handler) list(response http.ResponseWriter, request *http.Request, call call) {
	filter, ok := parseFilter(request.URL.Query(), call.staff)
	if !ok {
		writeError(response, http.StatusBadRequest, "invalid_ticket_query")
		return
	}
	page, err := handler.service.List(request.Context(), call.actor, call.staff, filter)
	writeResult(response, http.StatusOK, page, err)
}

func (handler *Handler) summary(response http.ResponseWriter, request *http.Request, call call) {
	summary, err := handler.service.Summary(request.Context(), call.actor, call.staff)
	writeResult(response, http.StatusOK, summary, err)
}

func (handler *Handler) assignees(response http.ResponseWriter, request *http.Request, call call) {
	items, err := handler.service.Assignees(request.Context(), call.actor)
	writeResult(response, http.StatusOK, map[string]any{"items": items}, err)
}

func (handler *Handler) get(response http.ResponseWriter, request *http.Request, call call) {
	detail, err := handler.service.Get(request.Context(), call.actor, call.staff, request.PathValue("id"))
	writeResult(response, http.StatusOK, detail, err)
}

func idempotencyKey(response http.ResponseWriter, request *http.Request) (string, bool) {
	keys := request.Header.Values("Idempotency-Key")
	if len(keys) != 1 || !keyPattern.MatchString(keys[0]) {
		writeError(response, http.StatusBadRequest, "idempotency_key_required")
		return "", false
	}
	return keys[0], true
}

func decode(response http.ResponseWriter, request *http.Request, target any) bool {
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || !strings.HasPrefix(strings.ToLower(contentTypes[0]), "application/json") {
		writeError(response, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maxJSONBytes))
	if err != nil {
		writeError(response, http.StatusRequestEntityTooLarge, "request_too_large")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func (handler *Handler) create(response http.ResponseWriter, request *http.Request, call call) {
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	var input CreateInput
	if !decode(response, request, &input) {
		return
	}
	detail, err := handler.service.Create(request.Context(), call.actor, key, call.requestID, input)
	writeResult(response, http.StatusCreated, detail, err)
}

// staffCreate (fix-ticket2): staff open a ticket for a chosen user.
func (handler *Handler) staffCreate(response http.ResponseWriter, request *http.Request, call call) {
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	var input StaffCreateInput
	if !decode(response, request, &input) {
		return
	}
	detail, err := handler.service.StaffCreate(request.Context(), call.actor, key, call.requestID, input)
	writeResult(response, http.StatusCreated, detail, err)
}

func (handler *Handler) reply(response http.ResponseWriter, request *http.Request, call call) {
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	var input ReplyInput
	if !decode(response, request, &input) {
		return
	}
	detail, err := handler.service.Reply(request.Context(), call.actor, call.staff, key, call.requestID,
		request.PathValue("id"), input)
	writeResult(response, http.StatusCreated, detail, err)
}

func (handler *Handler) transition(reopen bool) route {
	return func(response http.ResponseWriter, request *http.Request, call call) {
		var detail Detail
		var err error
		if reopen {
			detail, err = handler.service.Reopen(request.Context(), call.actor, call.requestID, request.PathValue("id"))
		} else {
			detail, err = handler.service.Close(request.Context(), call.actor, call.requestID, request.PathValue("id"))
		}
		writeResult(response, http.StatusOK, detail, err)
	}
}

func (handler *Handler) update(response http.ResponseWriter, request *http.Request, call call) {
	var input UpdateInput
	if !decode(response, request, &input) {
		return
	}
	detail, err := handler.service.Update(request.Context(), call.actor, call.requestID, request.PathValue("id"), input)
	writeResult(response, http.StatusOK, detail, err)
}

func (handler *Handler) remove(response http.ResponseWriter, request *http.Request, call call) {
	if err := handler.service.Delete(request.Context(), call.actor, call.requestID, request.PathValue("id")); err != nil {
		writeServiceError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

// upload takes the raw file body; the type is Content-Type and the name the
// URL-encoded X-File-Name header.
func (handler *Handler) upload(response http.ResponseWriter, request *http.Request, call call) {
	mimeType := strings.ToLower(strings.TrimSpace(strings.SplitN(request.Header.Get("Content-Type"), ";", 2)[0]))
	names := request.Header.Values("X-File-Name")
	if len(names) != 1 {
		writeError(response, http.StatusBadRequest, "invalid_attachment")
		return
	}
	name, err := url.PathUnescape(names[0])
	if err != nil {
		writeError(response, http.StatusBadRequest, "invalid_attachment")
		return
	}
	if request.ContentLength > MaxAttachmentSize {
		writeServiceError(response, ErrAttachmentTooLarge)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, MaxAttachmentSize+1))
	if err != nil {
		writeServiceError(response, ErrAttachmentTooLarge)
		return
	}
	attachment, err := handler.service.Upload(request.Context(), call.actor, call.staff, call.requestID,
		UploadInput{FileName: name, MIMEType: mimeType, Body: body})
	writeResult(response, http.StatusCreated, attachment, err)
}

func (handler *Handler) download(response http.ResponseWriter, request *http.Request, call call) {
	download, err := handler.service.Open(request.Context(), call.actor, call.staff, request.PathValue("id"))
	if err != nil {
		writeServiceError(response, err)
		return
	}
	defer download.Body.Close()
	header := response.Header()
	header.Set("Content-Type", download.MIMEType)
	header.Set("Content-Length", strconv.FormatInt(download.SizeBytes, 10))
	header.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	header.Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(download.FileName))
	response.WriteHeader(http.StatusOK)
	_, _ = io.Copy(response, io.LimitReader(download.Body, download.SizeBytes))
}

func writeResult(response http.ResponseWriter, status int, value any, err error) {
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, status, value)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, map[string]string{"code": code})
}

func writeServiceError(response http.ResponseWriter, err error) {
	status, code := http.StatusServiceUnavailable, "ticket_unavailable"
	switch {
	case errors.Is(err, ErrNotFound):
		status, code = http.StatusNotFound, "ticket_not_found"
	case errors.Is(err, ErrInvalidInput):
		status, code = http.StatusBadRequest, "invalid_ticket"
	case errors.Is(err, ErrUnauthenticated):
		status, code = http.StatusUnauthorized, "unauthorized"
	case errors.Is(err, ErrPermissionDenied):
		status, code = http.StatusForbidden, "permission_denied"
	case errors.Is(err, ErrRevisionConflict):
		status, code = http.StatusConflict, "ticket_revision_conflict"
	case errors.Is(err, ErrIdempotency):
		status, code = http.StatusConflict, "idempotency_conflict"
	case errors.Is(err, ErrInvalidState):
		status, code = http.StatusConflict, "ticket_invalid_state"
	case errors.Is(err, ErrReopenExpired):
		status, code = http.StatusConflict, "ticket_reopen_expired"
	case errors.Is(err, ErrAttachmentsDisabled):
		status, code = http.StatusServiceUnavailable, "ticket_attachments_disabled"
	case errors.Is(err, ErrAttachmentTooLarge):
		status, code = http.StatusRequestEntityTooLarge, "ticket_attachment_too_large"
	case errors.Is(err, ErrAttachmentType):
		status, code = http.StatusUnsupportedMediaType, "ticket_attachment_type"
	case errors.Is(err, ErrAttachmentRejected):
		status, code = http.StatusUnprocessableEntity, "ticket_attachment_rejected"
	case errors.Is(err, ErrUploadLimit):
		status, code = http.StatusTooManyRequests, "ticket_attachment_limit"
	}
	writeError(response, status, code)
}
