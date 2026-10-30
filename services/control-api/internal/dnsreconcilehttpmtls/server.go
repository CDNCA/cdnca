package dnsreconcilehttpmtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/http/httpguts"
)

var (
	ErrNotReady       = errors.New("DNS reconcile workload mTLS listener is not ready")
	ErrAlreadyStarted = errors.New("DNS reconcile workload mTLS listener was already started")
	ErrServerClosed   = errors.New("DNS reconcile workload mTLS listener is closed")
	ErrServeFailed    = errors.New("DNS reconcile workload mTLS listener stopped unexpectedly")
)

const maximumBufferedResponseBytes = 1 << 20

type Server struct {
	httpServer *http.Server
	listener   net.Listener
	ready      atomic.Bool
	mu         sync.Mutex
	state      uint8
	err        error
	done       chan struct{}
	once       sync.Once
}

func New(ctx context.Context, config *Config, authenticator *Authenticator, handler http.Handler) (*Server, error) {
	if ctx == nil || authenticator == nil || handler == nil {
		return nil, ErrInvalidConfig
	}
	tlsConfig, err := loadTLS(config, time.Now)
	if err != nil {
		return nil, err
	}
	startup, cancel := context.WithTimeout(ctx, config.StartupTimeout)
	defer cancel()
	listener, err := (&net.ListenConfig{}).Listen(startup, "tcp", config.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("bind DNS reconcile workload mTLS listener: %w", err)
	}
	guard := &routeGuard{next: handler, authenticator: authenticator}
	return &Server{
		httpServer: &http.Server{Handler: guard, ReadHeaderTimeout: config.ReadHeaderTimeout,
			ReadTimeout: config.ReadTimeout, WriteTimeout: config.WriteTimeout, IdleTimeout: config.IdleTimeout,
			MaxHeaderBytes: config.MaxHeaderBytes},
		listener: tls.NewListener(listener, tlsConfig), done: make(chan struct{}),
	}, nil
}

func (server *Server) Start() error {
	if err := server.begin(); err != nil {
		return err
	}
	go server.run()
	return nil
}

func (server *Server) Serve() error {
	if err := server.begin(); err != nil {
		return err
	}
	return server.run()
}

func (server *Server) begin() error {
	if server == nil {
		return ErrInvalidConfig
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.state == 1 {
		return ErrAlreadyStarted
	}
	if server.state != 0 {
		return ErrServerClosed
	}
	server.state = 1
	server.ready.Store(true)
	return nil
}

func (server *Server) run() error {
	err := server.httpServer.Serve(server.listener)
	server.mu.Lock()
	closing := server.state == 2
	if closing && (errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)) {
		err = nil
	} else if err == nil {
		err = ErrServeFailed
	} else {
		err = fmt.Errorf("%w: %v", ErrServeFailed, err)
	}
	server.err = err
	server.state = 3
	server.ready.Store(false)
	server.mu.Unlock()
	server.once.Do(func() { close(server.done) })
	return err
}

func (server *Server) Ready() error {
	if server == nil || !server.ready.Load() {
		return ErrNotReady
	}
	return nil
}

func (server *Server) Address() string {
	if server == nil || server.listener == nil {
		return ""
	}
	return server.listener.Addr().String()
}

func (server *Server) Wait() error {
	if server == nil {
		return ErrInvalidConfig
	}
	<-server.done
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.err
}

func (server *Server) Shutdown(ctx context.Context) error {
	if server == nil || ctx == nil {
		return ErrInvalidConfig
	}
	server.mu.Lock()
	state := server.state
	if state < 3 {
		server.state = 2
	}
	server.mu.Unlock()
	server.ready.Store(false)
	if state == 0 {
		return server.finishWithoutServe(server.listener.Close())
	}
	err := server.httpServer.Shutdown(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (server *Server) Close() error {
	if server == nil {
		return nil
	}
	server.mu.Lock()
	state := server.state
	if state < 3 {
		server.state = 2
	}
	server.mu.Unlock()
	server.ready.Store(false)
	if state == 0 {
		return server.finishWithoutServe(server.listener.Close())
	}
	err := server.httpServer.Close()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (server *Server) finishWithoutServe(err error) error {
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	server.mu.Lock()
	server.state, server.err = 3, err
	server.mu.Unlock()
	server.once.Do(func() { close(server.done) })
	return err
}

type routeGuard struct {
	next          http.Handler
	authenticator *Authenticator
}

func newRouteGuard(next http.Handler) http.Handler { return &routeGuard{next: next} }

func (guard *routeGuard) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if !providerReportPath(request) {
		writeStatus(writer, http.StatusNotFound)
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeStatus(writer, http.StatusMethodNotAllowed)
		return
	}
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 {
		writeStatus(writer, http.StatusUnauthorized)
		return
	}
	if guard == nil || guard.next == nil {
		writeFailure(writer)
		return
	}
	if guard.authenticator != nil {
		if _, err := guard.authenticator.Authenticate(request); err != nil {
			writeStatus(writer, http.StatusUnauthorized)
			return
		}
	}

	buffered := newBufferedResponseWriter()
	panicked := func() (panicked bool) {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		guard.next.ServeHTTP(buffered, request)
		return false
	}()
	if panicked || buffered.validate() != nil {
		writeFailure(writer)
		return
	}
	if buffered.commit(writer) != nil {
		writeFailure(writer)
	}
}

// bufferedResponseWriter keeps the internal workload response uncommitted
// until its status, headers, and body have passed the protocol boundary.
type bufferedResponseWriter struct {
	header           http.Header
	committedHeader  http.Header
	body             bytes.Buffer
	status           int
	contentLength    int64
	hasContentLength bool
	invalidLength    bool
	invalidStatus    bool
	overflow         bool
	validated        bool
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{header: make(http.Header)}
}

func (writer *bufferedResponseWriter) Header() http.Header { return writer.header }

func (writer *bufferedResponseWriter) WriteHeader(status int) {
	if writer.status != 0 || writer.overflow || writer.invalidStatus {
		return
	}
	if !validDownstreamStatus(status) {
		writer.invalidStatus = true
		return
	}
	writer.status = status
	writer.committedHeader = writer.header.Clone()
	writer.contentLength, writer.hasContentLength, writer.invalidLength = parseContentLength(writer.committedHeader)
}

func (writer *bufferedResponseWriter) Write(contents []byte) (int, error) {
	if writer.invalidStatus || writer.overflow {
		return 0, errInvalidDownstreamResponse
	}
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	if writer.invalidStatus {
		return 0, errInvalidDownstreamResponse
	}
	if len(contents) == 0 {
		return 0, nil
	}
	if !bodyAllowedForStatus(writer.status) {
		return 0, errInvalidDownstreamResponse
	}
	if writer.hasContentLength && int64(len(contents)) > writer.contentLength-int64(writer.body.Len()) {
		return 0, errInvalidDownstreamResponse
	}
	if len(contents) > maximumBufferedResponseBytes-writer.body.Len() {
		writer.overflow = true
		writer.body.Reset()
		writer.committedHeader = nil
		return 0, errResponseTooLarge
	}
	return writer.body.Write(contents)
}

func (writer *bufferedResponseWriter) validate() error {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	if writer.invalidStatus || writer.invalidLength || writer.overflow || writer.committedHeader == nil {
		return errInvalidDownstreamResponse
	}
	for name, values := range writer.committedHeader {
		if !validDownstreamHeader(name, values) {
			return errInvalidDownstreamResponse
		}
	}
	if writer.headerSize() > maximumBufferedResponseBytes {
		return errResponseTooLarge
	}
	if writer.hasContentLength && int64(writer.body.Len()) != writer.contentLength {
		return errInvalidDownstreamResponse
	}
	writer.validated = true
	return nil
}

func validDownstreamHeader(name string, values []string) bool {
	if !httpguts.ValidHeaderFieldName(name) {
		return false
	}
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
		"te", "trailer", "transfer-encoding", "upgrade":
		return false
	}
	for _, value := range values {
		if !httpguts.ValidHeaderFieldValue(value) {
			return false
		}
	}
	return true
}

func (writer *bufferedResponseWriter) headerSize() int {
	size := 0
	for name, values := range writer.committedHeader {
		size += len(name)
		for _, value := range values {
			size += len(value)
		}
	}
	return size
}

func (writer *bufferedResponseWriter) commit(destination http.ResponseWriter) error {
	if !writer.validated {
		return errInvalidDownstreamResponse
	}
	clearHeader(destination.Header())
	for name, values := range writer.committedHeader {
		destination.Header()[name] = append([]string(nil), values...)
	}
	destination.Header().Set("Cache-Control", "no-store")
	destination.Header().Set("X-Content-Type-Options", "nosniff")
	destination.WriteHeader(writer.status)
	if writer.body.Len() == 0 {
		return nil
	}
	written, err := destination.Write(writer.body.Bytes())
	if err != nil {
		return err
	}
	if written != writer.body.Len() {
		return io.ErrShortWrite
	}
	return nil
}

var errInvalidDownstreamResponse = errors.New("invalid DNS reconcile workload response")
var errResponseTooLarge = errors.New("DNS reconcile workload response is too large")

func validDownstreamStatus(status int) bool {
	return status == http.StatusOK || status == http.StatusAccepted || status == http.StatusNoContent ||
		status >= http.StatusBadRequest && status <= 599
}

func bodyAllowedForStatus(status int) bool {
	return status != http.StatusNoContent && status != http.StatusNotModified
}

func parseContentLength(header http.Header) (int64, bool, bool) {
	var values []string
	for name, entries := range header {
		if strings.EqualFold(name, "Content-Length") {
			values = append(values, entries...)
		}
	}
	if len(values) == 0 {
		return 0, false, false
	}
	if len(values) != 1 || values[0] == "" {
		return 0, false, true
	}
	for index := range values[0] {
		if values[0][index] < '0' || values[0][index] > '9' {
			return 0, false, true
		}
	}
	length, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || length > maximumBufferedResponseBytes {
		return 0, false, true
	}
	return length, true, false
}

func clearHeader(header http.Header) {
	for name := range header {
		delete(header, name)
	}
}

func writeStatus(writer http.ResponseWriter, status int) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
}

func writeFailure(writer http.ResponseWriter) {
	clearHeader(writer.Header())
	writeStatus(writer, http.StatusInternalServerError)
}

func providerReportPath(request *http.Request) bool {
	if request == nil || request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery {
		return false
	}
	suffix, ok := strings.CutPrefix(request.URL.Path, "/internal/v1/dns/reconcile/tasks/")
	if !ok {
		return false
	}
	id, ok := strings.CutSuffix(suffix, "/provider-reports")
	if !ok || id == "" || strings.Contains(id, "/") {
		return false
	}
	parsed, err := uuid.Parse(id)
	return err == nil && parsed.String() == id
}
