package nodesshinstall

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// TerminalPatterns are the console SSH terminal routes.
var TerminalPatterns = []string{
	"GET /v1/nodes/{id}/ssh-endpoint",
	"POST /v1/nodes/{id}/ssh-host-key",
	"GET /v1/nodes/{id}/ssh-terminal",
	"DELETE /v1/nodes/{id}/ssh-credential",
}

// Terminal WebSocket protocol. A browser cannot set Authorization on a
// WebSocket, and a token in the URL ends up in access logs, so the first
// frame (text) carries the access token with the login:
//
//	{"type":"open","access_token":"…","port":22,"username":"root","password":"…",
//	 "use_saved":false,"remember":false,"cols":120,"rows":32}
//
// host_key_sha256 is optional: without it the controller uses the key known
// for the node, or trusts the presented one on first use (and pins it when
// remember is set). The server answers {"type":"opened","session_id":"…",
// "host_key_sha256":"SHA256:…","remembered":true|false} or
// {"type":"error","code":"…"} and closes. Then binary frames are terminal
// bytes both ways, and the client sends {"type":"resize","cols":…,"rows":…}.
// The server ends with {"type":"closed","reason":"…"}.
type terminalFrame struct {
	Type          string `json:"type"`
	AccessToken   string `json:"access_token,omitempty"`
	Port          int    `json:"port,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	PrivateKey    string `json:"private_key,omitempty"`
	HostKeySHA256 string `json:"host_key_sha256,omitempty"`
	UseSaved      bool   `json:"use_saved,omitempty"`
	Remember      bool   `json:"remember,omitempty"`
	Cols          int    `json:"cols,omitempty"`
	Rows          int    `json:"rows,omitempty"`
}

const (
	terminalOpenTimeout    = 10 * time.Second
	terminalReadLimit      = 64 << 10
	terminalSessionRecheck = time.Minute
)

// TerminalHandler serves the terminal routes.
type TerminalHandler struct {
	service      *Service
	authenticate AuthenticateSessionFunc
	mux          *http.ServeMux
	idle, max    time.Duration
}

func NewTerminalHandler(service *Service, authenticate AuthenticateSessionFunc) (*TerminalHandler, error) {
	if service == nil || authenticate == nil {
		return nil, ErrInvalidInput
	}
	handler := &TerminalHandler{service: service, authenticate: authenticate, mux: http.NewServeMux(),
		idle: TerminalIdleTimeout, max: TerminalMaxDuration}
	handler.mux.HandleFunc(TerminalPatterns[0], handler.withActor(handler.endpoint))
	handler.mux.HandleFunc(TerminalPatterns[1], handler.withActor(handler.hostKey))
	handler.mux.HandleFunc(TerminalPatterns[2], handler.terminal)
	handler.mux.HandleFunc(TerminalPatterns[3], handler.withActor(handler.forget))
	return handler, nil
}

func (handler *TerminalHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	handler.mux.ServeHTTP(response, request)
}

// sshActor authorizes a platform session holding nodes.ssh.
func sshActor(ctx context.Context, authenticate AuthenticateSessionFunc, token, requestID, remoteAddr string) (Actor, int, string) {
	if token == "" {
		return Actor{}, http.StatusUnauthorized, "unauthorized"
	}
	session, err := authenticate(ctx, token)
	if err != nil {
		return Actor{}, http.StatusUnauthorized, "unauthorized"
	}
	if session.Principal.UserID == uuid.Nil || session.Principal.ScopeKind != "platform" || session.Principal.TenantID != nil ||
		identity.Authorize(session.Principal, PermissionSSH) != nil {
		return Actor{}, http.StatusForbidden, "permission_denied"
	}
	if !requestIDPattern.MatchString(requestID) {
		requestID = uuid.NewString()
	}
	ip := remoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	return Actor{UserID: session.Principal.UserID, ScopeID: session.Principal.ScopeID, RequestID: requestID, IP: ip}, 0, ""
}

func (handler *TerminalHandler) withActor(route func(http.ResponseWriter, *http.Request, Actor, uuid.UUID)) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		values := request.Header.Values("Authorization")
		token := ""
		if len(values) == 1 && strings.HasPrefix(values[0], "Bearer ") {
			token = values[0][7:]
		}
		actor, status, code := sshActor(request.Context(), handler.authenticate, token, response.Header().Get("X-Request-ID"),
			request.RemoteAddr)
		if status != 0 {
			writeError(response, status, code)
			return
		}
		nodeID, err := uuid.Parse(request.PathValue("id"))
		if err != nil {
			writeError(response, http.StatusNotFound, "not_found")
			return
		}
		route(response, request, actor, nodeID)
	}
}

func writeTerminalError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNoAddress):
		writeError(response, http.StatusConflict, "node_address_missing")
	case errors.Is(err, ErrUnreachable):
		writeError(response, http.StatusBadGateway, FailUnreachable)
	default:
		writeServiceError(response, err)
	}
}

func (handler *TerminalHandler) endpoint(response http.ResponseWriter, request *http.Request, actor Actor, nodeID uuid.UUID) {
	endpoint, err := handler.service.Endpoint(request.Context(), actor, nodeID)
	if err != nil {
		writeTerminalError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, endpoint)
}

func (handler *TerminalHandler) hostKey(response http.ResponseWriter, request *http.Request, actor Actor, nodeID uuid.UUID) {
	var body struct {
		Port int `json:"port"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 4<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	endpoint, key, err := handler.service.NodeHostKey(request.Context(), actor, nodeID, body.Port)
	if err != nil {
		writeTerminalError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"node_id": nodeID, "host": endpoint.Host, "port": body.Port,
		"host_key_sha256": key, "saved_host_key_matches": endpoint.Saved != nil && endpoint.Saved.Port == body.Port &&
			endpoint.Saved.HostKeySHA256 == key})
}

func (handler *TerminalHandler) forget(response http.ResponseWriter, request *http.Request, actor Actor, nodeID uuid.UUID) {
	if err := handler.service.ForgetCredential(request.Context(), actor, nodeID); err != nil {
		writeTerminalError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

// sameOrigin refuses cross-site WebSocket hijacking: the page's Origin must
// name the host the request reached (directly or through management-web).
func sameOrigin(request *http.Request) bool {
	origin, err := url.Parse(request.Header.Get("Origin"))
	if err != nil || origin.Host == "" || (origin.Scheme != "https" && origin.Scheme != "http") {
		return false
	}
	host := request.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = request.Host
	}
	return strings.EqualFold(origin.Host, host)
}

func terminalErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrNoAddress):
		return "node_address_missing"
	case errors.Is(err, ErrHostKeyChanged):
		return FailHostKeyMismatch
	case errors.Is(err, ErrAuthFailed):
		return FailAuth
	case errors.Is(err, ErrUnreachable):
		return FailUnreachable
	case errors.Is(err, ErrTerminalsBusy):
		return "terminals_busy"
	case errors.Is(err, ErrInvalidInput):
		return "invalid_request"
	case errors.Is(err, ErrPermission):
		return "permission_denied"
	}
	return "unavailable"
}

func (handler *TerminalHandler) terminal(response http.ResponseWriter, request *http.Request) {
	nodeID, err := uuid.Parse(request.PathValue("id"))
	if err != nil {
		writeError(response, http.StatusNotFound, "not_found")
		return
	}
	if !sameOrigin(request) {
		writeError(response, http.StatusForbidden, "origin_not_allowed")
		return
	}
	upgrader := websocket.Upgrader{HandshakeTimeout: 10 * time.Second, ReadBufferSize: 8 << 10, WriteBufferSize: 32 << 10,
		CheckOrigin: sameOrigin}
	requestID := response.Header().Get("X-Request-ID")
	conn, err := upgrader.Upgrade(response, request, http.Header{"Cache-Control": {"no-store"}})
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadLimit(terminalReadLimit)
	var writeMu sync.Mutex
	send := func(kind int, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		return conn.WriteMessage(kind, payload)
	}
	control := func(value any) {
		encoded, _ := json.Marshal(value)
		_ = send(websocket.TextMessage, encoded)
	}
	fail := func(code string) {
		control(map[string]string{"type": "error", "code": code})
		writeMu.Lock()
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, code),
			time.Now().Add(time.Second))
		writeMu.Unlock()
	}

	_ = conn.SetReadDeadline(time.Now().Add(terminalOpenTimeout))
	kind, payload, err := conn.ReadMessage()
	if err != nil || kind != websocket.TextMessage {
		fail("open_required")
		return
	}
	var open terminalFrame
	decodeErr := json.Unmarshal(payload, &open)
	clear(payload)
	if decodeErr != nil || open.Type != "open" {
		fail("open_required")
		return
	}
	defer clear([]byte(open.Password))
	token := open.AccessToken
	open.AccessToken = ""
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	actor, status, code := sshActor(ctx, handler.authenticate, token, requestID, request.RemoteAddr)
	if status != 0 {
		fail(code)
		return
	}

	var bytesIn, bytesOut atomic.Int64
	var lastInput atomic.Int64
	lastInput.Store(time.Now().UnixNano())
	terminal, err := handler.service.OpenTerminal(ctx, actor, TerminalRequest{NodeID: nodeID, Port: open.Port,
		Credential:    Credential{Username: open.Username, Password: open.Password, PrivateKey: open.PrivateKey},
		HostKeySHA256: open.HostKeySHA256, UseSaved: open.UseSaved, Remember: open.Remember, Cols: open.Cols, Rows: open.Rows},
		func(chunk []byte) {
			bytesOut.Add(int64(len(chunk)))
			if send(websocket.BinaryMessage, chunk) != nil {
				cancel()
			}
		})
	open.Password, open.PrivateKey = "", ""
	if err != nil {
		fail(terminalErrorCode(err))
		return
	}
	reason := "client_closed"
	var reasonMu sync.Mutex
	setReason := func(value string) {
		reasonMu.Lock()
		if reason == "client_closed" {
			reason = value
		}
		reasonMu.Unlock()
	}
	defer func() {
		reasonMu.Lock()
		final := reason
		reasonMu.Unlock()
		control(map[string]string{"type": "closed", "reason": final})
		terminal.End(final, bytesIn.Load(), bytesOut.Load())
	}()
	control(map[string]any{"type": "opened", "session_id": terminal.id.String(), "host_key_sha256": terminal.HostKeySHA256,
		"remembered": terminal.Remembered})
	_ = conn.SetReadDeadline(time.Time{})

	go func() {
		_ = terminal.Wait()
		setReason("remote_exit")
		cancel()
		// Unblocks ReadMessage below.
		_ = conn.SetReadDeadline(time.Now())
	}()
	go func() {
		started := time.Now()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		lastCheck := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				switch {
				case now.Sub(started) >= handler.max:
					setReason("max_duration")
				case now.Sub(time.Unix(0, lastInput.Load())) >= handler.idle:
					setReason("idle_timeout")
				case now.Sub(lastCheck) >= terminalSessionRecheck:
					lastCheck = now
					// The console session may have been signed out or lost the permission.
					if _, status, _ := sshActor(ctx, handler.authenticate, token, requestID, request.RemoteAddr); status != 0 {
						setReason("session_revoked")
					} else {
						continue
					}
				default:
					continue
				}
				cancel()
				_ = conn.Close()
				return
			}
		}
	}()
	for {
		kind, payload, err := conn.ReadMessage()
		if err != nil {
			break
		}
		lastInput.Store(time.Now().UnixNano())
		if kind == websocket.BinaryMessage {
			bytesIn.Add(int64(len(payload)))
			if _, err := terminal.Stdin.Write(payload); err != nil {
				break
			}
			clear(payload)
			continue
		}
		var frame terminalFrame
		if json.Unmarshal(payload, &frame) == nil && frame.Type == "resize" &&
			frame.Cols >= 1 && frame.Cols <= 1000 && frame.Rows >= 1 && frame.Rows <= 500 {
			_ = terminal.Resize(frame.Cols, frame.Rows)
		}
	}
}
