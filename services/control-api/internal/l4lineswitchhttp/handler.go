package l4lineswitchhttp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/l4lineswitch"
	"github.com/google/uuid"
)

const maxRequestBytes = 64 << 10

var (
	errInvalidRequest   = errors.New("invalid L4 line switch HTTP request")
	errMethodNotAllowed = errors.New("L4 line switch method not allowed")
	metadataPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type Service interface {
	Start(context.Context, l4lineswitch.StartRequest) (l4lineswitch.Switch, error)
	Get(context.Context, l4lineswitch.Actor, uuid.UUID, uuid.UUID) (l4lineswitch.Switch, error)
	Latest(context.Context, l4lineswitch.Actor, uuid.UUID) (l4lineswitch.Switch, error)
	Reconcile(context.Context, l4lineswitch.Actor, uuid.UUID, uuid.UUID) (l4lineswitch.Switch, error)
}

type Authenticator interface {
	Authenticate(*http.Request) (l4lineswitch.Actor, error)
}

type AuthenticatorFunc func(*http.Request) (l4lineswitch.Actor, error)

func (function AuthenticatorFunc) Authenticate(request *http.Request) (l4lineswitch.Actor, error) {
	return function(request)
}

type Handler struct {
	service       Service
	authenticator Authenticator
	mux           *http.ServeMux
}

type startBody struct {
	ExpectedSourceRevision int64        `json:"expected_source_revision"`
	From                   snapshotBody `json:"from"`
	To                     snapshotBody `json:"to"`
	Health                 healthBody   `json:"health"`
	Drain                  drainBody    `json:"drain"`
	MaxAttempts            uint32       `json:"max_attempts"`
	Deadline               string       `json:"deadline"`
}

type snapshotBody struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	SHA256   string `json:"sha256"`
}

type healthBody struct {
	ActivationTimeoutMS          int64  `json:"activation_timeout_ms"`
	ObservationWindowMS          int64  `json:"observation_window_ms"`
	RequiredConsecutiveSuccesses uint32 `json:"required_consecutive_successes"`
}

type drainBody struct {
	HealthTimeoutMS int64 `json:"health_timeout_ms"`
	MaxDrainMS      int64 `json:"max_drain_ms"`
}

type switchView struct {
	ID                      string          `json:"id"`
	ConfigurationScopeID    string          `json:"configuration_scope_id"`
	ExpectedSourceRevision  int64           `json:"expected_source_revision"`
	From                    snapshotView    `json:"from"`
	To                      snapshotView    `json:"to"`
	PrepareNodeCount        int             `json:"prepare_node_count"`
	RetiringNodeCount       int             `json:"retiring_node_count"`
	State                   string          `json:"state"`
	StateRevision           int64           `json:"state_revision"`
	PreparePublication      publicationView `json:"prepare_publication,omitempty"`
	CompensationPublication publicationView `json:"compensation_publication,omitempty"`
	DrainCommandCount       int             `json:"drain_command_count"`
	ErrorCode               string          `json:"error_code,omitempty"`
	DNSGate                 *dnsGateView    `json:"dns_gate,omitempty"`
	Deadline                string          `json:"deadline"`
	CreatedAt               string          `json:"created_at"`
	UpdatedAt               string          `json:"updated_at"`
	Replayed                bool            `json:"replayed,omitempty"`
}

type dnsGateView struct {
	State         string `json:"state"`
	Owners        int    `json:"owners"`
	PendingOwners int    `json:"pending_owners"`
	ReadyAt       string `json:"ready_at,omitempty"`
}

type snapshotView struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	SHA256   string `json:"sha256"`
}

type publicationView struct {
	ID              string `json:"id,omitempty"`
	RolloutID       string `json:"rollout_id,omitempty"`
	ConfigVersionID string `json:"config_version_id,omitempty"`
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func NewHandler(service Service, authenticator Authenticator) (*Handler, error) {
	if service == nil || authenticator == nil {
		return nil, l4lineswitch.ErrInvalidInput
	}
	handler := &Handler{service: service, authenticator: authenticator, mux: http.NewServeMux()}
	handler.mux.HandleFunc("/v1/tenant-scopes/{scope_id}/l4-line-switches", handler.collection)
	handler.mux.HandleFunc("/v1/tenant-scopes/{scope_id}/l4-line-switches/current", handler.current)
	handler.mux.HandleFunc("/v1/tenant-scopes/{scope_id}/l4-line-switches/{switch_id}", handler.item)
	handler.mux.HandleFunc("/v1/tenant-scopes/{scope_id}/l4-line-switches/{switch_id}/reconcile", handler.reconcile)
	return handler, nil
}

func (handler *Handler) current(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", "GET")
		handler.writeError(response, request, errMethodNotAllowed)
		return
	}
	actor, scopeID, ok := handler.authenticate(response, request)
	if !ok {
		return
	}
	result, err := handler.service.Latest(request.Context(), actor, scopeID)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", quoteRevision(result.StateRevision))
	handler.writeJSON(response, http.StatusOK, responseView(result))
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	requestID := request.Header.Get("X-Request-ID")
	if _, err := strictUUID(requestID); err != nil || len(request.Header.Values("X-Request-ID")) != 1 {
		handler.writeError(response, request, errInvalidRequest)
		return
	}
	response.Header().Set("X-Request-ID", requestID)
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	handler.mux.ServeHTTP(response, request.WithContext(ctx))
}

func (handler *Handler) collection(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", "POST")
		handler.writeError(response, request, errMethodNotAllowed)
		return
	}
	actor, scopeID, ok := handler.authenticate(response, request)
	if !ok {
		return
	}
	key := request.Header.Get("Idempotency-Key")
	requestID, err := strictUUID(request.Header.Get("X-Request-ID"))
	if err != nil || !metadataPattern.MatchString(key) || len(request.Header.Values("Idempotency-Key")) != 1 {
		handler.writeError(response, request, errInvalidRequest)
		return
	}
	correlationID := requestID
	if value := request.Header.Get("X-Correlation-ID"); value != "" {
		correlationID, err = strictUUID(value)
		if err != nil || len(request.Header.Values("X-Correlation-ID")) != 1 {
			handler.writeError(response, request, errInvalidRequest)
			return
		}
	}
	traceparent := request.Header.Get("Traceparent")
	if traceparent == "" || len(request.Header.Values("Traceparent")) != 1 {
		handler.writeError(response, request, errInvalidRequest)
		return
	}
	var body startBody
	if err := decodeBody(request, &body); err != nil {
		handler.writeError(response, request, err)
		return
	}
	from, err := parseSnapshot(body.From)
	if err != nil {
		handler.writeError(response, request, errInvalidRequest)
		return
	}
	to, err := parseSnapshot(body.To)
	if err != nil {
		handler.writeError(response, request, errInvalidRequest)
		return
	}
	deadline, err := time.Parse(time.RFC3339Nano, body.Deadline)
	if err != nil {
		handler.writeError(response, request, errInvalidRequest)
		return
	}
	result, err := handler.service.Start(request.Context(), l4lineswitch.StartRequest{
		Actor: actor, ConfigurationScopeID: scopeID, ExpectedSourceRevision: body.ExpectedSourceRevision,
		From: from, To: to, Health: l4lineswitch.HealthPolicy{
			ActivationTimeout:            time.Duration(body.Health.ActivationTimeoutMS) * time.Millisecond,
			ObservationWindow:            time.Duration(body.Health.ObservationWindowMS) * time.Millisecond,
			RequiredConsecutiveSuccesses: body.Health.RequiredConsecutiveSuccesses,
		}, Drain: l4lineswitch.DrainPolicy{
			HealthTimeout: time.Duration(body.Drain.HealthTimeoutMS) * time.Millisecond,
			MaxDrain:      time.Duration(body.Drain.MaxDrainMS) * time.Millisecond,
		}, MaxAttempts: body.MaxAttempts, Deadline: deadline, IdempotencyKey: key,
		RequestID: requestID, CorrelationID: correlationID, Traceparent: traceparent,
	})
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	if result.Replayed {
		response.Header().Set("X-Idempotent-Replay", "true")
	}
	response.Header().Set("ETag", quoteRevision(result.StateRevision))
	response.Header().Set("Location", request.URL.Path+"/"+result.ID.String())
	handler.writeJSON(response, http.StatusCreated, responseView(result))
}

func (handler *Handler) item(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", "GET")
		handler.writeError(response, request, errMethodNotAllowed)
		return
	}
	actor, scopeID, switchID, ok := handler.authenticateItem(response, request)
	if !ok {
		return
	}
	result, err := handler.service.Get(request.Context(), actor, scopeID, switchID)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", quoteRevision(result.StateRevision))
	handler.writeJSON(response, http.StatusOK, responseView(result))
}

func (handler *Handler) reconcile(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", "POST")
		handler.writeError(response, request, errMethodNotAllowed)
		return
	}
	actor, scopeID, switchID, ok := handler.authenticateItem(response, request)
	if !ok || !emptyBody(request) {
		if ok {
			handler.writeError(response, request, errInvalidRequest)
		}
		return
	}
	result, err := handler.service.Reconcile(request.Context(), actor, scopeID, switchID)
	if err != nil && !errors.Is(err, l4lineswitch.ErrUnsafeRollback) {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", quoteRevision(result.StateRevision))
	handler.writeJSON(response, http.StatusOK, responseView(result))
}

func (handler *Handler) authenticate(response http.ResponseWriter, request *http.Request) (l4lineswitch.Actor, uuid.UUID, bool) {
	actor, err := handler.authenticator.Authenticate(request)
	if err != nil {
		handler.writeError(response, request, l4lineswitch.ErrUnauthenticated)
		return l4lineswitch.Actor{}, uuid.Nil, false
	}
	scopeID, err := strictUUID(request.PathValue("scope_id"))
	if err != nil || actor.ScopeKind == "tenant" && actor.ScopeID != scopeID {
		handler.writeError(response, request, l4lineswitch.ErrPermissionDenied)
		return l4lineswitch.Actor{}, uuid.Nil, false
	}
	return actor, scopeID, true
}

func (handler *Handler) authenticateItem(response http.ResponseWriter, request *http.Request) (l4lineswitch.Actor, uuid.UUID, uuid.UUID, bool) {
	actor, scopeID, ok := handler.authenticate(response, request)
	if !ok {
		return l4lineswitch.Actor{}, uuid.Nil, uuid.Nil, false
	}
	switchID, err := strictUUID(request.PathValue("switch_id"))
	if err != nil {
		handler.writeError(response, request, errInvalidRequest)
		return l4lineswitch.Actor{}, uuid.Nil, uuid.Nil, false
	}
	return actor, scopeID, switchID, true
}

func parseSnapshot(body snapshotBody) (l4lineswitch.SnapshotReference, error) {
	id, err := strictUUID(body.ID)
	digest, digestErr := hex.DecodeString(body.SHA256)
	if err != nil || digestErr != nil || len(digest) != 32 || body.Revision < 1 {
		return l4lineswitch.SnapshotReference{}, errInvalidRequest
	}
	var sha [32]byte
	copy(sha[:], digest)
	if sha == ([32]byte{}) {
		return l4lineswitch.SnapshotReference{}, errInvalidRequest
	}
	return l4lineswitch.SnapshotReference{ID: id, Revision: body.Revision, SHA256: sha}, nil
}

func responseView(value l4lineswitch.Switch) switchView {
	var gate *dnsGateView
	if value.DNSGate != nil {
		gate = &dnsGateView{State: value.DNSGate.State, Owners: value.DNSGate.Owners, PendingOwners: value.DNSGate.PendingOwners}
		if value.DNSGate.ReadyAt != nil {
			gate.ReadyAt = value.DNSGate.ReadyAt.UTC().Format(time.RFC3339Nano)
		}
	}
	return switchView{
		ID: value.ID.String(), ConfigurationScopeID: value.ConfigurationScopeID.String(),
		ExpectedSourceRevision: value.ExpectedSourceRevision, From: responseSnapshot(value.From.Reference), To: responseSnapshot(value.To.Reference),
		PrepareNodeCount: len(value.PrepareNodes), RetiringNodeCount: len(value.RetiringNodes), State: value.State,
		StateRevision: value.StateRevision, PreparePublication: responsePublication(value.PreparePublication),
		CompensationPublication: responsePublication(value.CompensationPublication), DrainCommandCount: len(value.DrainCommands),
		ErrorCode: value.ErrorCode, DNSGate: gate, Deadline: value.Deadline.UTC().Format(time.RFC3339Nano),
		CreatedAt: value.CreatedAt.UTC().Format(time.RFC3339Nano), UpdatedAt: value.UpdatedAt.UTC().Format(time.RFC3339Nano), Replayed: value.Replayed,
	}
}

func responseSnapshot(value l4lineswitch.SnapshotReference) snapshotView {
	return snapshotView{ID: value.ID.String(), Revision: value.Revision, SHA256: hex.EncodeToString(value.SHA256[:])}
}

func responsePublication(value l4lineswitch.Publication) publicationView {
	result := publicationView{}
	if value.ID != uuid.Nil {
		result.ID = value.ID.String()
	}
	if value.RolloutID != uuid.Nil {
		result.RolloutID = value.RolloutID.String()
	}
	if value.ConfigVersionID != uuid.Nil {
		result.ConfigVersionID = value.ConfigVersionID.String()
	}
	return result
}

func decodeBody(request *http.Request, target any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errInvalidRequest
	}
	content, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBytes+1))
	if err != nil || len(content) == 0 || len(content) > maxRequestBytes {
		return errInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errInvalidRequest
	}
	return nil
}

func emptyBody(request *http.Request) bool {
	content, err := io.ReadAll(io.LimitReader(request.Body, 2))
	return err == nil && len(bytes.TrimSpace(content)) == 0
}

func strictUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, errInvalidRequest
	}
	return parsed, nil
}

func quoteRevision(value int64) string { return `"` + strconv.FormatInt(value, 10) + `"` }

func (handler *Handler) writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func (handler *Handler) writeError(response http.ResponseWriter, request *http.Request, err error) {
	status, code := errorStatus(err)
	envelope := errorEnvelope{}
	envelope.Error.Code, envelope.Error.RequestID = code, request.Header.Get("X-Request-ID")
	handler.writeJSON(response, status, envelope)
}

func errorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, errMethodNotAllowed):
		return http.StatusMethodNotAllowed, "method_not_allowed"
	case errors.Is(err, errInvalidRequest), errors.Is(err, l4lineswitch.ErrInvalidInput):
		return http.StatusBadRequest, "l4_line_switch_invalid_request"
	case errors.Is(err, l4lineswitch.ErrUnauthenticated):
		return http.StatusUnauthorized, "authentication_required"
	case errors.Is(err, l4lineswitch.ErrPermissionDenied):
		return http.StatusForbidden, "permission_denied"
	case errors.Is(err, l4lineswitch.ErrNotFound):
		return http.StatusNotFound, "l4_line_switch_not_found"
	case errors.Is(err, l4lineswitch.ErrIdempotencyConflict), errors.Is(err, l4lineswitch.ErrConflict):
		return http.StatusConflict, "l4_line_switch_conflict"
	case errors.Is(err, l4lineswitch.ErrUnsafeRollback):
		return http.StatusServiceUnavailable, "l4_line_switch_needs_attention"
	default:
		return http.StatusServiceUnavailable, "l4_line_switch_unavailable"
	}
}
