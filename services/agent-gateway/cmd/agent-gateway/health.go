package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

var errRuntimeNotReady = errors.New("Gateway runtime is not ready")

type livenessState struct {
	live atomic.Bool
}

func (s *livenessState) set(live bool) {
	if s != nil {
		s.live.Store(live)
	}
}

func (s *livenessState) isLive() bool {
	return s != nil && s.live.Load()
}

type readyListener struct {
	net.Listener
	ready        atomic.Bool
	plannedClose atomic.Bool
}

func (l *readyListener) MarkPlannedClose() {
	if l != nil {
		l.plannedClose.Store(true)
	}
}

func (l *readyListener) wasPlannedClose() bool {
	return l != nil && l.plannedClose.Load()
}

func newReadyListener(listener net.Listener) *readyListener {
	return &readyListener{Listener: listener}
}

func (l *readyListener) Accept() (net.Conn, error) {
	if l == nil || l.Listener == nil {
		return nil, net.ErrClosed
	}
	l.ready.Store(true)
	connection, err := l.Listener.Accept()
	if err != nil {
		l.ready.Store(false)
	}
	return connection, err
}

func (l *readyListener) Close() error {
	if l == nil || l.Listener == nil {
		return nil
	}
	l.ready.Store(false)
	return l.Listener.Close()
}

func (l *readyListener) isReady() bool {
	return l != nil && l.ready.Load()
}

func (l *readyListener) markNotReady() {
	if l != nil {
		l.ready.Store(false)
	}
}

type readinessCheck func(context.Context) error

type runtimeReadiness struct {
	checks []readinessCheck
	gate   chan struct{}
}

func newRuntimeReadiness(checks ...readinessCheck) *runtimeReadiness {
	return &runtimeReadiness{checks: checks, gate: make(chan struct{}, 1)}
}

func (r *runtimeReadiness) ready(ctx context.Context) error {
	if r == nil || ctx == nil || len(r.checks) == 0 {
		return errRuntimeNotReady
	}
	select {
	case r.gate <- struct{}{}:
		defer func() { <-r.gate }()
	case <-ctx.Done():
		return errRuntimeNotReady
	}

	ready := true
	for _, check := range r.checks {
		if check == nil || check(ctx) != nil {
			ready = false
		}
	}
	if !ready || ctx.Err() != nil {
		return errRuntimeNotReady
	}
	return nil
}

type healthHandler struct {
	liveness  *livenessState
	readiness *runtimeReadiness
	timeout   time.Duration
}

func newHealthHandler(liveness *livenessState, readiness *runtimeReadiness, timeout time.Duration) http.Handler {
	return &healthHandler{liveness: liveness, readiness: readiness, timeout: timeout}
}

func (h *healthHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeHealthResponse(response, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	switch request.URL.Path {
	case "/health/live":
		if h.liveness.isLive() {
			writeHealthResponse(response, http.StatusOK, "live")
			return
		}
		writeHealthResponse(response, http.StatusServiceUnavailable, "not_live")
	case "/health/ready":
		if !h.liveness.isLive() || h.readiness == nil || h.timeout <= 0 {
			writeHealthResponse(response, http.StatusServiceUnavailable, "not_ready")
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), h.timeout)
		defer cancel()
		if h.readiness.ready(ctx) != nil {
			writeHealthResponse(response, http.StatusServiceUnavailable, "not_ready")
			return
		}
		writeHealthResponse(response, http.StatusOK, "ready")
	default:
		writeHealthResponse(response, http.StatusNotFound, "not_found")
	}
}

func writeHealthResponse(response http.ResponseWriter, status int, state string) {
	response.WriteHeader(status)
	_, _ = io.WriteString(response, `{"status":"`+state+`"}`+"\n")
}

func newHealthHTTPServer(handler http.Handler, checkTimeout time.Duration) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       checkTimeout + time.Second,
		WriteTimeout:      checkTimeout + time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}
