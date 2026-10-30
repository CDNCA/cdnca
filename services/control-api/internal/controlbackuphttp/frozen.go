package controlbackuphttp

// The frozen console (fix-migrollback) replaces control-api on its port while
// a migration hold is in force, so the operator can still watch the migration,
// stop it and roll back from the browser. It serves only:
//
//	POST /v1/admin/control-backup/frozen-session  sign in (username + password)
//	GET  /v1/admin/control-backup                 status, runs and logs
//	GET  /v1/admin/control-backup/runs/{id}       one run with its log
//	POST /v1/admin/control-backup/runs/{id}/stop  stop the running migration
//	GET  /v1/admin/control-backup/new-master      is the new host serving?
//	POST /v1/admin/control-backup/rollback        roll back to this host
//
// Everything else under /v1/ answers 503 control_migration_hold. Sessions
// live in memory only; the password check reads the database and never
// writes a session, throttle or login row.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const (
	FrozenSessionPath = Prefix + "/frozen-session"
	HoldErrorCode     = "control_migration_hold"
	frozenSessionTTL  = 30 * time.Minute
)

type frozenSession struct {
	principal identity.Principal
	expires   time.Time
}

// FrozenConsole wraps a Handler whose Authenticate accepts frozen sessions
// (and, while they last, access tokens minted before the hold).
type FrozenConsole struct {
	handler  *Handler
	now      func() time.Time
	limiter  passwordLimiter
	mu       sync.Mutex
	sessions map[[32]byte]frozenSession
}

// NewFrozenConsole builds the console. existing authenticates access tokens
// issued before the hold (nil: frozen sessions only).
func NewFrozenConsole(dependencies Dependencies, existing AuthenticateSessionFunc) (*FrozenConsole, error) {
	console := &FrozenConsole{sessions: map[[32]byte]frozenSession{}}
	dependencies.Authenticate = func(ctx context.Context, token string) (identity.AuthenticatedSession, error) {
		if session, ok := console.lookup(token); ok {
			return session, nil
		}
		if existing != nil {
			return existing(ctx, token)
		}
		return identity.AuthenticatedSession{}, identity.ErrInvalidSession
	}
	handler, err := NewHandler(dependencies)
	if err != nil {
		return nil, err
	}
	if dependencies.VerifyPassword == nil {
		return nil, errNotConfigured
	}
	console.handler, console.now = handler, handler.dependencies.Now
	return console, nil
}

var errNotConfigured = errors.New("frozen console is not configured")

// withSourceIP records the client address for audit and the admin allow-list:
// nginx on the same host passes it in X-Real-IP; direct peers use RemoteAddr.
func withSourceIP(request *http.Request) *http.Request {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return request
	}
	if address.Unmap().IsLoopback() {
		if forwarded, err := netip.ParseAddr(strings.TrimSpace(request.Header.Get("X-Real-IP"))); err == nil {
			address = forwarded
		}
	}
	return request.WithContext(audit.WithSourceIP(request.Context(), address.Unmap()))
}

func digest(token string) [32]byte { return sha256.Sum256([]byte(token)) }

func (console *FrozenConsole) lookup(token string) (identity.AuthenticatedSession, bool) {
	console.mu.Lock()
	defer console.mu.Unlock()
	key := digest(token)
	session, ok := console.sessions[key]
	if !ok {
		return identity.AuthenticatedSession{}, false
	}
	if !console.now().Before(session.expires) {
		delete(console.sessions, key)
		return identity.AuthenticatedSession{}, false
	}
	// A stable per-token session ID keeps the handler's checks unchanged.
	return identity.AuthenticatedSession{SessionID: uuid.NewSHA1(uuid.NameSpaceOID, key[:]), Principal: session.principal}, true
}

// frozenRoute: the handler routes the frozen console serves.
func frozenRoute(method, path string) bool {
	switch {
	case path == Prefix && method == http.MethodGet,
		path == Prefix+"/new-master" && method == http.MethodGet,
		path == Prefix+"/rollback" && method == http.MethodPost:
		return true
	}
	if match := runPath.FindStringSubmatch(path); match != nil {
		return (match[2] == "" && method == http.MethodGet) || (match[2] != "" && method == http.MethodPost)
	}
	return false
}

func (console *FrozenConsole) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	request = withSourceIP(request)
	path := request.URL.Path
	switch {
	case path == "/health/live" && request.Method == http.MethodGet:
		writeJSON(response, http.StatusOK, map[string]string{"status": "live"})
	case path == FrozenSessionPath && request.Method == http.MethodPost:
		console.signIn(response, request)
	case frozenRoute(request.Method, path):
		console.handler.ServeHTTP(response, request)
	case strings.HasPrefix(path, Prefix):
		writeJSON(response, http.StatusConflict, map[string]any{"error": map[string]string{"code": "control_backup_host_held"}})
	default:
		// /health/ready included: the held host must not look ready.
		writeJSON(response, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": HoldErrorCode}})
	}
}

func (console *FrozenConsole) signIn(response http.ResponseWriter, request *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(request, &body); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "control_backup_invalid_request"}})
		return
	}
	defer func() { body.Password = "" }()
	username := strings.ToLower(strings.TrimSpace(body.Username))
	if !console.limiter.allow(username, console.now()) {
		writeJSON(response, http.StatusTooManyRequests, map[string]any{"error": map[string]string{"code": "control_backup_rollback_rate_limited"}})
		return
	}
	principal, err := console.handler.dependencies.VerifyPassword(request.Context(), username, body.Password, audit.SourceIPFrom(request.Context()))
	if err != nil || principal.ScopeKind != "platform" || identity.Authorize(principal, readPermission) != nil {
		writeJSON(response, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "invalid_credentials"}})
		return
	}
	console.limiter.reset(username)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "control_backup_unavailable"}})
		return
	}
	token := "frozen." + base64.RawURLEncoding.EncodeToString(raw)
	expires := console.now().Add(frozenSessionTTL)
	console.mu.Lock()
	for key, session := range console.sessions {
		if !console.now().Before(session.expires) {
			delete(console.sessions, key)
		}
	}
	console.sessions[digest(token)] = frozenSession{principal: principal, expires: expires}
	console.mu.Unlock()
	writeJSON(response, http.StatusOK, map[string]any{"data": map[string]any{"access_token": token, "expires_at": expires.UTC(),
		"username": principal.Username, "can_manage": identity.Authorize(principal, managePermission) == nil}})
}
