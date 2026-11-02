package nodesshinstall

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// PermissionManage: installing nodes is node management.
const PermissionManage = "nodes.manage"

// Patterns are the routes the control-api server forwards here.
var Patterns = []string{
	"GET /v1/admin/nodes/ssh-installs",
	"POST /v1/admin/nodes/ssh-installs",
	"GET /v1/admin/nodes/ssh-installs/{id}",
	"POST /v1/admin/nodes/ssh-installs/{id}/confirm-host-key",
	"POST /v1/admin/nodes/ssh-installs/{id}/cancel",
	"GET /v1/admin/nodes/ssh-access/controller-egress",
	"GET /v1/nodes/{id}/ssh-access",
	"PUT /v1/nodes/{id}/ssh-access",
}

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

type Handler struct {
	service      *Service
	authenticate AuthenticateSessionFunc
	mux          *http.ServeMux
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func NewHandler(service *Service, authenticate AuthenticateSessionFunc) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, ErrInvalidInput
	}
	handler := &Handler{service: service, authenticate: authenticate, mux: http.NewServeMux()}
	routes := map[string]func(http.ResponseWriter, *http.Request, Actor){
		Patterns[0]: handler.list, Patterns[1]: handler.create, Patterns[2]: handler.get,
		Patterns[3]: handler.confirm, Patterns[4]: handler.cancel,
		Patterns[5]: handler.controllerEgress, Patterns[6]: handler.getAccess, Patterns[7]: handler.putAccess,
	}
	for pattern, route := range routes {
		route := route
		handler.mux.HandleFunc(pattern, func(response http.ResponseWriter, request *http.Request) {
			if actor, ok := handler.actor(response, request); ok {
				route(response, request, actor)
			}
		})
	}
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	handler.mux.ServeHTTP(response, request)
}

func (handler *Handler) actor(response http.ResponseWriter, request *http.Request) (Actor, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || values[0][7:] == "" {
		writeError(response, http.StatusUnauthorized, "unauthorized")
		return Actor{}, false
	}
	session, err := handler.authenticate(request.Context(), values[0][7:])
	if err != nil {
		writeError(response, http.StatusUnauthorized, "unauthorized")
		return Actor{}, false
	}
	if session.Principal.UserID == uuid.Nil || session.Principal.ScopeKind != "platform" || session.Principal.TenantID != nil ||
		identity.Authorize(session.Principal, PermissionManage) != nil {
		writeError(response, http.StatusForbidden, "permission_denied")
		return Actor{}, false
	}
	requestID := response.Header().Get("X-Request-ID")
	if !requestIDPattern.MatchString(requestID) {
		requestID = uuid.NewString()
	}
	ip := request.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	return Actor{UserID: session.Principal.UserID, ScopeID: session.Principal.ScopeID, RequestID: requestID, IP: ip}, true
}

// createBody is either hosts (one shared login: username + password or
// private_key) or targets (batch install: each host with its own login).
type createBody struct {
	Hosts       []string     `json:"hosts"`
	Port        int          `json:"port"`
	Names       []string     `json:"names"`
	Username    string       `json:"username"`
	Password    string       `json:"password"`
	PrivateKey  string       `json:"private_key"`
	Targets     []targetBody `json:"targets"`
	BatchID     string       `json:"batch_id"`
	RestrictSSH bool         `json:"restrict_ssh"`
	// AllowCIDRs: "also allow" addresses of the restriction.
	AllowCIDRs []string `json:"allow_cidrs"`
	// Language is the console UI language (i18n code such as "zh-CN" or
	// "en"); the install command then carries --lang zh / --lang en.
	Language string `json:"language"`
}

type targetBody struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Name       string `json:"name"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
}

// createRequest maps the body; ok is false for a malformed one.
func (body createBody) createRequest() (CreateRequest, bool) {
	request := CreateRequest{RestrictSSH: body.RestrictSSH, AllowCIDRs: body.AllowCIDRs}
	switch code := strings.ToLower(body.Language); {
	case code == "":
	case code == "zh" || strings.HasPrefix(code, "zh-") || strings.HasPrefix(code, "zh_"):
		request.Language = "zh"
	case code == "en" || strings.HasPrefix(code, "en-") || strings.HasPrefix(code, "en_"):
		request.Language = "en"
	default:
		return CreateRequest{}, false
	}
	if body.BatchID != "" {
		parsed, err := uuid.Parse(body.BatchID)
		if err != nil || parsed == uuid.Nil {
			return CreateRequest{}, false
		}
		request.BatchID = parsed
	}
	if len(body.Targets) > 0 {
		// Per-host logins only: mixing in the shared form is ambiguous.
		if len(body.Hosts) > 0 || len(body.Names) > 0 || body.Port != 0 || body.Username != "" || body.Password != "" ||
			body.PrivateKey != "" || len(body.Targets) > MaxBatch {
			return CreateRequest{}, false
		}
		for _, target := range body.Targets {
			request.Targets = append(request.Targets, Target{Host: target.Host, Port: target.Port, Name: target.Name,
				Credential: &Credential{Username: target.Username, Password: target.Password, PrivateKey: target.PrivateKey}})
		}
		return request, true
	}
	if len(body.Names) > 0 && len(body.Names) != len(body.Hosts) {
		return CreateRequest{}, false
	}
	request.Credential = Credential{Username: body.Username, Password: body.Password, PrivateKey: body.PrivateKey}
	for index, host := range body.Hosts {
		target := Target{Host: host, Port: body.Port}
		if len(body.Names) > 0 {
			target.Name = body.Names[index]
		}
		request.Targets = append(request.Targets, target)
	}
	return request, true
}

func (handler *Handler) create(response http.ResponseWriter, request *http.Request, actor Actor) {
	var body createBody
	decoder := json.NewDecoder(io.LimitReader(request.Body, 512<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	create, ok := body.createRequest()
	if !ok {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	controlPlane, ok := consoleOrigin(request)
	if !ok {
		writeError(response, http.StatusBadRequest, "control_plane_origin_required")
		return
	}
	create.ControlPlane = controlPlane
	jobs, err := handler.service.Create(request.Context(), actor, create)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, map[string]any{"items": jobs})
}

// consoleOrigin is where the node downloads install-node.sh: the https
// origin the operator's browser used (Origin header), as the copied install
// command does.
func consoleOrigin(request *http.Request) (string, bool) {
	origin := request.Header.Get("Origin")
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", false
	}
	value := parsed.Scheme + "://" + parsed.Host
	return value, ValidControlPlane(value)
}

func (handler *Handler) list(response http.ResponseWriter, request *http.Request, actor Actor) {
	var batchID uuid.UUID
	if raw := request.URL.Query().Get("batch_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			writeError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		batchID = parsed
	}
	limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
	jobs, err := handler.service.List(request.Context(), actor, batchID, limit)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"items": jobs})
}

func (handler *Handler) jobID(response http.ResponseWriter, request *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(request.PathValue("id"))
	if err != nil {
		writeError(response, http.StatusNotFound, "not_found")
		return uuid.Nil, false
	}
	return id, true
}

func (handler *Handler) get(response http.ResponseWriter, request *http.Request, actor Actor) {
	id, ok := handler.jobID(response, request)
	if !ok {
		return
	}
	job, err := handler.service.Get(request.Context(), actor, id)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, job)
}

func (handler *Handler) confirm(response http.ResponseWriter, request *http.Request, actor Actor) {
	id, ok := handler.jobID(response, request)
	if !ok {
		return
	}
	var body struct {
		HostKeySHA256 string `json:"host_key_sha256"`
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, 4<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	job, err := handler.service.ConfirmHostKey(request.Context(), actor, id, body.HostKeySHA256)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, job)
}

func (handler *Handler) cancel(response http.ResponseWriter, request *http.Request, actor Actor) {
	id, ok := handler.jobID(response, request)
	if !ok {
		return
	}
	job, err := handler.service.Cancel(request.Context(), actor, id)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, job)
}

func (handler *Handler) controllerEgress(response http.ResponseWriter, request *http.Request, _ Actor) {
	cidrs, source := handler.service.ControllerEgress(request.Context())
	writeJSON(response, http.StatusOK, map[string]any{"controller_cidrs": cidrs, "configured": len(cidrs) > 0,
		"source": source, "rollback_seconds": int(AccessRollbackWindow / time.Second)})
}

func (handler *Handler) nodeID(response http.ResponseWriter, request *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(request.PathValue("id"))
	if err != nil {
		writeError(response, http.StatusNotFound, "not_found")
		return uuid.Nil, false
	}
	return id, true
}

func (handler *Handler) getAccess(response http.ResponseWriter, request *http.Request, actor Actor) {
	nodeID, ok := handler.nodeID(response, request)
	if !ok {
		return
	}
	access, err := handler.service.GetAccess(request.Context(), actor, nodeID)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, access)
}

func (handler *Handler) putAccess(response http.ResponseWriter, request *http.Request, actor Actor) {
	nodeID, ok := handler.nodeID(response, request)
	if !ok {
		return
	}
	var body struct {
		Enabled    bool     `json:"enabled"`
		SSHPort    int      `json:"ssh_port"`
		AllowCIDRs []string `json:"allow_cidrs"`
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	access, err := handler.service.SetAccess(request.Context(), actor, nodeID,
		AccessChange{Enabled: body.Enabled, SSHPort: body.SSHPort, AllowCIDRs: body.AllowCIDRs})
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, access)
}

func writeServiceError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidInput):
		writeError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, ErrNotFound):
		writeError(response, http.StatusNotFound, "not_found")
	case errors.Is(err, ErrConflict):
		writeError(response, http.StatusConflict, "state_conflict")
	case errors.Is(err, ErrDuplicate):
		writeError(response, http.StatusConflict, "ssh_install_in_progress")
	case errors.Is(err, ErrPermission):
		writeError(response, http.StatusForbidden, "permission_denied")
	case errors.Is(err, ErrControllerEgressUnknown):
		writeError(response, http.StatusConflict, "controller_egress_unknown")
	default:
		writeError(response, http.StatusServiceUnavailable, "unavailable")
	}
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, map[string]any{"error": map[string]string{"code": code}})
}
