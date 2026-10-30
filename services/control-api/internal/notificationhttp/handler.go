package notificationhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

const maxRequestBytes = 256 << 10

type Service interface {
	GetChannels(context.Context, notificationcontrol.Actor) (notificationcontrol.ChannelSettings, error)
	UpdateChannels(context.Context, notificationcontrol.Actor, notificationcontrol.UpdateChannelsRequest) (notificationcontrol.ChannelSettings, error)
	GetDeliveryPolicy(context.Context, notificationcontrol.Actor) (notificationcontrol.DeliveryPolicySettings, error)
	UpdateDeliveryPolicy(context.Context, notificationcontrol.Actor, notificationcontrol.UpdateDeliveryPolicyRequest) (notificationcontrol.DeliveryPolicySettings, error)
	ListTemplates(context.Context, notificationcontrol.Actor) ([]notificationcontrol.Template, error)
	PutTemplate(context.Context, notificationcontrol.Actor, string, int64, string, notificationcontrol.TemplateInput, string) (notificationcontrol.Template, error)
	GetSubscription(context.Context, notificationcontrol.Actor, string) (notificationcontrol.Subscription, error)
	UpdateSubscription(context.Context, notificationcontrol.Actor, string, notificationcontrol.UpdateSubscriptionRequest) (notificationcontrol.Subscription, error)
	ListDeliveryLogs(context.Context, notificationcontrol.Actor, notificationcontrol.DeliveryLogQuery) (notificationcontrol.DeliveryLogPage, error)
	ListDeliveryAttempts(context.Context, notificationcontrol.Actor, string) (notificationcontrol.DeliveryAttemptPage, error)
}

// MessageService is kept separate from the historical notification service
// contract so existing embedders can roll out the compatibility projection
// independently. The production control store implements both interfaces.
type MessageService interface {
	ListMessages(context.Context, notificationcontrol.Actor, notificationcontrol.MessageQuery) (notificationcontrol.MessagePage, error)
}

// OwnMessageService lists the caller's own event messages (SEC-ACCOUNT-07);
// scope and recipient come from the session only.
type OwnMessageService interface {
	ListOwnMessages(context.Context, notificationcontrol.Actor, notificationcontrol.OwnMessageQuery) (notificationcontrol.OwnMessagePage, error)
}

type AuthenticateFunc func(*http.Request) (identity.AuthenticatedSession, error)

type Handler struct {
	service      Service
	authenticate AuthenticateFunc
}

func New(service Service, authenticate AuthenticateFunc) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, errors.New("notification HTTP dependencies are required")
	}
	return &Handler{service: service, authenticate: authenticate}, nil
}

func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/admin/notifications/channels", h.getChannels)
	mux.HandleFunc("PUT /v1/admin/notifications/channels", h.updateChannels)
	mux.HandleFunc("GET /v1/admin/notifications/policy", h.getDeliveryPolicy)
	mux.HandleFunc("PUT /v1/admin/notifications/policy", h.updateDeliveryPolicy)
	mux.HandleFunc("GET /v1/admin/notifications/templates", h.listTemplates)
	mux.HandleFunc("PUT /v1/admin/notifications/templates/{template_id}/versions/{version}/{channel}", h.putTemplate)
	mux.HandleFunc("GET /v1/account/notification-subscriptions/{event_type}", h.getSubscription)
	mux.HandleFunc("PUT /v1/account/notification-subscriptions/{event_type}", h.updateSubscription)
	mux.HandleFunc("GET /v1/admin/notifications/deliveries", h.listDeliveryLogs)
	mux.HandleFunc("GET /v1/admin/notifications/delivery-history", h.listDeliveryHistory)
	mux.HandleFunc("GET /v1/admin/notifications/deliveries/{outbox_id}/attempts", h.listDeliveryAttempts)
	mux.HandleFunc("GET /v1/admin/notifications/messages", h.listMessages)
	mux.HandleFunc("GET /v1/account/notification-messages", h.listOwnMessages)
	mux.HandleFunc("/v1/admin/notifications/channels", methodNotAllowed("GET, PUT"))
	mux.HandleFunc("/v1/admin/notifications/policy", methodNotAllowed("GET, PUT"))
	mux.HandleFunc("/v1/admin/notifications/templates", methodNotAllowed("GET"))
	mux.HandleFunc("/v1/admin/notifications/templates/{template_id}/versions/{version}/{channel}", methodNotAllowed("PUT"))
	mux.HandleFunc("/v1/account/notification-subscriptions/{event_type}", methodNotAllowed("GET, PUT"))
	mux.HandleFunc("/v1/admin/notifications/deliveries", methodNotAllowed("GET"))
	mux.HandleFunc("/v1/admin/notifications/delivery-history", methodNotAllowed("GET"))
	mux.HandleFunc("/v1/admin/notifications/deliveries/{outbox_id}/attempts", methodNotAllowed("GET"))
	mux.HandleFunc("/v1/admin/notifications/messages", methodNotAllowed("GET"))
	mux.HandleFunc("/v1/account/notification-messages", methodNotAllowed("GET"))
	return mux
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Handler().ServeHTTP(w, r)
}

func (h *Handler) getChannels(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok || !emptyQuery(w, r) {
		return
	}
	value, err := h.service.GetChannels(r.Context(), actor)
	h.writeValue(w, r, value, err, value.Revision)
}

func (h *Handler) updateChannels(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok || !emptyQuery(w, r) {
		return
	}
	revision, ok := parseIfMatch(w, r, false)
	if !ok {
		return
	}
	input, ok := decodeSwitches(w, r)
	if !ok {
		return
	}
	value, err := h.service.UpdateChannels(r.Context(), actor, notificationcontrol.UpdateChannelsRequest{
		ExpectedRevision: revision, SMSEnabled: input.sms, EmailEnabled: input.email, RequestID: requestID(r),
	})
	h.writeValue(w, r, value, err, value.Revision)
}

func (h *Handler) getDeliveryPolicy(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok || !emptyQuery(w, r) {
		return
	}
	value, err := h.service.GetDeliveryPolicy(r.Context(), actor)
	h.writeValue(w, r, value, err, value.Revision)
}

func (h *Handler) updateDeliveryPolicy(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok || !emptyQuery(w, r) {
		return
	}
	revision, ok := parseIfMatch(w, r, false)
	if !ok {
		return
	}
	var body struct {
		WindowMode  string                                    `json:"window_mode"`
		WindowStart string                                    `json:"window_start"`
		WindowEnd   string                                    `json:"window_end"`
		Timezone    string                                    `json:"timezone"`
		Events      []notificationcontrol.DeliveryPolicyEvent `json:"events"`
	}
	if !decodeObject(w, r, &body) {
		return
	}
	if field := firstMissing(
		requiredField{"window_mode", body.WindowMode == ""}, requiredField{"window_start", body.WindowStart == ""},
		requiredField{"window_end", body.WindowEnd == ""}, requiredField{"timezone", body.Timezone == ""},
		requiredField{"events", body.Events == nil},
	); field != "" {
		writeFieldError(w, r, field, fielderr.Required)
		return
	}
	value, err := h.service.UpdateDeliveryPolicy(r.Context(), actor, notificationcontrol.UpdateDeliveryPolicyRequest{
		ExpectedRevision: revision, WindowMode: body.WindowMode, WindowStart: body.WindowStart,
		WindowEnd: body.WindowEnd, Timezone: body.Timezone, Events: body.Events, RequestID: requestID(r),
	})
	h.writeValue(w, r, value, err, value.Revision)
}

func (h *Handler) listTemplates(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok || !emptyQuery(w, r) {
		return
	}
	items, err := h.service.ListTemplates(r.Context(), actor)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) putTemplate(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok || !emptyQuery(w, r) {
		return
	}
	version, err := strconv.ParseInt(r.PathValue("version"), 10, 64)
	if err != nil || version < 1 || strconv.FormatInt(version, 10) != r.PathValue("version") {
		writeError(w, r, http.StatusBadRequest, "validation_error")
		return
	}
	var body struct {
		Subject   *string   `json:"subject"`
		Body      *string   `json:"body"`
		Variables *[]string `json:"variables"`
	}
	if !decodeObject(w, r, &body) {
		return
	}
	if field := firstMissing(requiredField{"subject", body.Subject == nil}, requiredField{"body", body.Body == nil}, requiredField{"variables", body.Variables == nil}); field != "" {
		writeFieldError(w, r, field, fielderr.Required)
		return
	}
	value, err := h.service.PutTemplate(r.Context(), actor, r.PathValue("template_id"), version,
		r.PathValue("channel"), notificationcontrol.TemplateInput{
			Subject: *body.Subject, Body: *body.Body, Variables: *body.Variables,
		}, requestID(r))
	h.writeValue(w, r, value, err, -1)
}

func (h *Handler) getSubscription(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok || !emptyQuery(w, r) {
		return
	}
	value, err := h.service.GetSubscription(r.Context(), actor, r.PathValue("event_type"))
	h.writeValue(w, r, value, err, value.Revision)
}

func (h *Handler) updateSubscription(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok || !emptyQuery(w, r) {
		return
	}
	revision, ok := parseIfMatch(w, r, true)
	if !ok {
		return
	}
	// 546 (fix-ticket2): inbox_enabled is optional; absent keeps the stored
	// in-app choice, null is refused.
	var body struct {
		SMSEnabled   *bool           `json:"sms_enabled"`
		EmailEnabled *bool           `json:"email_enabled"`
		InboxEnabled json.RawMessage `json:"inbox_enabled"`
	}
	if !decodeObject(w, r, &body) {
		return
	}
	var inbox *bool
	if body.InboxEnabled != nil {
		var value bool
		if string(body.InboxEnabled) == "null" || json.Unmarshal(body.InboxEnabled, &value) != nil {
			writeFieldError(w, r, "inbox_enabled", fielderr.Invalid)
			return
		}
		inbox = &value
	}
	if field := firstMissing(requiredField{"sms_enabled", body.SMSEnabled == nil}, requiredField{"email_enabled", body.EmailEnabled == nil}); field != "" {
		writeFieldError(w, r, field, fielderr.Required)
		return
	}
	value, err := h.service.UpdateSubscription(r.Context(), actor, r.PathValue("event_type"), notificationcontrol.UpdateSubscriptionRequest{
		ExpectedRevision: revision, SMSEnabled: *body.SMSEnabled, EmailEnabled: *body.EmailEnabled, InboxEnabled: inbox,
		RequestID: requestID(r),
	})
	h.writeValue(w, r, value, err, value.Revision)
}

func (h *Handler) listDeliveryLogs(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	query := deliveryLogQuery(r)
	value, err := h.service.ListDeliveryLogs(r.Context(), actor, query)
	h.writeValue(w, r, value, err, -1)
}

func (h *Handler) listDeliveryAttempts(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok || !emptyQuery(w, r) {
		return
	}
	value, err := h.service.ListDeliveryAttempts(r.Context(), actor, r.PathValue("outbox_id"))
	h.writeValue(w, r, value, err, -1)
}

func (h *Handler) listMessages(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	service, ok := h.service.(MessageService)
	if !ok {
		writeError(w, r, http.StatusInternalServerError, "internal_error")
		return
	}
	value, err := service.ListMessages(r.Context(), actor, messageQuery(r))
	h.writeValue(w, r, value, err, -1)
}

func (h *Handler) listOwnMessages(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	service, ok := h.service.(OwnMessageService)
	if !ok {
		writeError(w, r, http.StatusInternalServerError, "internal_error")
		return
	}
	value, err := service.ListOwnMessages(r.Context(), actor, ownMessageQuery(r))
	h.writeValue(w, r, value, err, -1)
}

func ownMessageQuery(r *http.Request) notificationcontrol.OwnMessageQuery {
	values := r.URL.Query()
	allowed := map[string]bool{"type": true, "site_id": true, "package_id": true, "site": true, "package": true, "limit": true, "offset": true}
	for key, items := range values {
		if !allowed[key] || len(items) != 1 || items[0] == "" {
			return notificationcontrol.OwnMessageQuery{Invalid: true}
		}
	}
	return notificationcontrol.OwnMessageQuery{
		Type: values.Get("type"), SiteID: values.Get("site_id"), PackageID: values.Get("package_id"),
		Site: values.Get("site"), Package: values.Get("package"),
		Limit: values.Get("limit"), Offset: values.Get("offset"),
	}
}

func deliveryLogQuery(r *http.Request) notificationcontrol.DeliveryLogQuery {
	values := r.URL.Query()
	allowed := map[string]bool{"scope_id": true, "channel": true, "state": true, "limit": true, "cursor": true}
	for key, items := range values {
		if !allowed[key] || len(items) != 1 || items[0] == "" {
			return notificationcontrol.DeliveryLogQuery{Invalid: true}
		}
	}
	return notificationcontrol.DeliveryLogQuery{
		ScopeID: values.Get("scope_id"), Channel: values.Get("channel"), State: values.Get("state"),
		Limit: values.Get("limit"), Cursor: values.Get("cursor"),
	}
}

func messageQuery(r *http.Request) notificationcontrol.MessageQuery {
	values := r.URL.Query()
	allowed := map[string]bool{
		"scope_id": true, "type": true, "user_id": true, "package_id": true,
		"site_id": true, "user": true, "package": true, "site": true, "limit": true, "cursor": true,
	}
	for key, items := range values {
		if !allowed[key] || len(items) != 1 || items[0] == "" {
			return notificationcontrol.MessageQuery{Invalid: true}
		}
	}
	return notificationcontrol.MessageQuery{
		ScopeID: values.Get("scope_id"), Type: values.Get("type"), UserID: values.Get("user_id"),
		PackageID: values.Get("package_id"), SiteID: values.Get("site_id"),
		User: values.Get("user"), Package: values.Get("package"), Site: values.Get("site"),
		Limit: values.Get("limit"), Cursor: values.Get("cursor"),
	}
}

func (h *Handler) actor(w http.ResponseWriter, r *http.Request) (notificationcontrol.Actor, bool) {
	session, err := h.authenticate(r)
	if err != nil || session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil || session.Principal.ScopeID == uuid.Nil {
		writeError(w, r, http.StatusUnauthorized, "authentication_required")
		return notificationcontrol.Actor{}, false
	}
	return notificationcontrol.Actor{
		UserID: session.Principal.UserID, ScopeID: session.Principal.ScopeID,
		SessionID: session.SessionID, ScopeKind: session.Principal.ScopeKind,
	}, true
}

func (h *Handler) writeValue(w http.ResponseWriter, r *http.Request, value any, err error, revision int64) {
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if revision >= 0 {
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, revision))
	}
	writeJSON(w, http.StatusOK, value)
}

type switchInput struct{ sms, email bool }

func decodeSwitches(w http.ResponseWriter, r *http.Request) (switchInput, bool) {
	var body struct {
		SMSEnabled   *bool `json:"sms_enabled"`
		EmailEnabled *bool `json:"email_enabled"`
	}
	if !decodeObject(w, r, &body) {
		return switchInput{}, false
	}
	if field := firstMissing(requiredField{"sms_enabled", body.SMSEnabled == nil}, requiredField{"email_enabled", body.EmailEnabled == nil}); field != "" {
		writeFieldError(w, r, field, fielderr.Required)
		return switchInput{}, false
	}
	return switchInput{sms: *body.SMSEnabled, email: *body.EmailEnabled}, true
}

// requiredField is a body field and whether the request left it out.
type requiredField struct {
	name    string
	missing bool
}

// firstMissing returns the first field the request left out, or "".
func firstMissing(fields ...requiredField) string {
	for _, field := range fields {
		if field.missing {
			return field.name
		}
	}
	return ""
}

func decodeObject(w http.ResponseWriter, r *http.Request, destination any) bool {
	if !validJSONContentType(r.Header.Values("Content-Type")) {
		writeError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	}
	reader := http.MaxBytesReader(w, r.Body, maxRequestBytes)
	payload, err := io.ReadAll(reader)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "validation_error")
		return false
	}
	if !utf8.Valid(payload) {
		writeError(w, r, http.StatusBadRequest, "validation_error")
		return false
	}
	validator := json.NewDecoder(bytes.NewReader(payload))
	if err := consumeUniqueJSONValue(validator); err != nil {
		writeError(w, r, http.StatusBadRequest, "validation_error")
		return false
	}
	if _, err := validator.Token(); !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "validation_error")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(w, r, http.StatusBadRequest, "validation_error")
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "validation_error")
		return false
	}
	return true
}

func validJSONContentType(values []string) bool {
	if len(values) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || !strings.EqualFold(mediaType, "application/json") || len(parameters) > 1 {
		return false
	}
	charset, present := parameters["charset"]
	return !present || strings.EqualFold(charset, "utf-8")
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
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
			if _, duplicate := keys[key]; duplicate {
				return errors.New("duplicate JSON object key")
			}
			keys[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

func methodNotAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allow)
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func parseIfMatch(w http.ResponseWriter, r *http.Request, allowZero bool) (int64, bool) {
	values := r.Header.Values("If-Match")
	if len(values) != 1 || len(values[0]) < 3 || values[0][0] != '"' || values[0][len(values[0])-1] != '"' {
		writeError(w, r, http.StatusBadRequest, "validation_error")
		return 0, false
	}
	raw := values[0][1 : len(values[0])-1]
	revision, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || revision < 0 || (!allowZero && revision == 0) || strconv.FormatInt(revision, 10) != raw {
		writeError(w, r, http.StatusBadRequest, "validation_error")
		return 0, false
	}
	return revision, true
}

func emptyQuery(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.RawQuery != "" {
		writeError(w, r, http.StatusBadRequest, "validation_error")
		return false
	}
	return true
}

func writeDomainError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, notificationcontrol.ErrInvalidInput):
		if located, ok := fielderr.As(err); ok {
			// fix-fielderr-be5: the refused body field, for the settings page to mark.
			writeFieldError(w, r, located.Field, located.Reason)
			return
		}
		writeError(w, r, http.StatusBadRequest, "validation_error")
	case errors.Is(err, notificationcontrol.ErrUnauthenticated):
		writeError(w, r, http.StatusUnauthorized, "authentication_required")
	case errors.Is(err, notificationcontrol.ErrPermissionDenied):
		writeError(w, r, http.StatusForbidden, "notification_permission_denied")
	case errors.Is(err, notificationcontrol.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "notification_not_found")
	case errors.Is(err, notificationcontrol.ErrVersionConflict):
		writeError(w, r, http.StatusConflict, "version_conflict")
	case errors.Is(err, notificationcontrol.ErrTemplateVersionConflict):
		writeError(w, r, http.StatusConflict, "template_version_conflict")
	case errors.Is(err, notificationcontrol.ErrChannelUnsupported):
		writeError(w, r, http.StatusConflict, "notification_channel_unsupported")
	default:
		logInternalError(r, err)
		writeError(w, r, http.StatusInternalServerError, "internal_error")
	}
}

// logInternalError records an unclassified failure (notif-sub A8) without SQL
// text, parameters or tokens: the Go error chain types, the PostgreSQL
// SQLSTATE and the constraint name are enough to tell a deadlock, a lock
// timeout, an IAM lock-order rejection or a pool wait apart.
func logInternalError(r *http.Request, err error) {
	attrs := []any{
		"request_id", requestID(r), "method", r.Method, "route", r.Pattern,
		"error_types", errorChainTypes(err),
		"iam_lock_order", errors.Is(err, protocol.ErrLockOrder),
		"iam_unavailable", errors.Is(err, protocol.ErrUnavailable),
		"context_canceled", errors.Is(err, context.Canceled),
		"context_deadline", errors.Is(err, context.DeadlineExceeded),
	}
	var pgErr *pgconn.PgError
	var state interface{ SQLState() string }
	switch {
	case errors.As(err, &pgErr):
		attrs = append(attrs, "sqlstate", pgErr.Code, "constraint", pgErr.ConstraintName)
	case errors.As(err, &state) && state.SQLState() != "":
		attrs = append(attrs, "sqlstate", state.SQLState())
	}
	slog.ErrorContext(r.Context(), "notification request failed", attrs...)
}

func errorChainTypes(err error) []string {
	var types []string
	for pending := []error{err}; len(pending) > 0 && len(types) < 16; {
		current := pending[0]
		pending = pending[1:]
		if current == nil {
			continue
		}
		types = append(types, fmt.Sprintf("%T", current))
		switch wrapped := current.(type) {
		case interface{ Unwrap() []error }:
			pending = append(pending, wrapped.Unwrap()...)
		case interface{ Unwrap() error }:
			pending = append(pending, wrapped.Unwrap())
		}
	}
	return types
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{
		"code": code, "message": code, "request_id": requestID(r),
	}})
}

// writeFieldError: 400 validation_error with details {field, reason}.
func writeFieldError(w http.ResponseWriter, r *http.Request, field, reason string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
		"code": "validation_error", "message": "validation_error", "request_id": requestID(r),
		"details": map[string]string{"field": field, "reason": reason},
	}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func requestID(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if value == "" || len(value) > 128 {
		return uuid.NewString()
	}
	return value
}
