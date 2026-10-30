package challenge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const (
	ExternalVerifierAddress  = "127.0.0.1:19178"
	ExternalVerifierPath     = "/v1/challenge/external/verify"
	maxExternalEnvelopeBytes = 8 << 10
)

type ExternalVerifyEnvelope struct {
	PolicyID      string           `json:"policy_id"`
	PolicyVersion uint64           `json:"policy_version"`
	TenantID      string           `json:"tenant_id"`
	SiteID        string           `json:"site_id"`
	Provider      ExternalProvider `json:"provider"`
	AppID         string           `json:"app_id"`
	Proof         string           `json:"proof"`
	ClientIP      string           `json:"client_ip"`
}

type ExternalVerifierHandler struct {
	stateRoot string
	client    *http.Client
	service   *ExternalVerificationService
}

func NewExternalVerifierHandler(stateRoot string, client *http.Client, replays ExternalReplayStore,
	limit int, window time.Duration, now func() time.Time) (*ExternalVerifierHandler, error) {
	if !cleanAbsoluteNonRoot(stateRoot) || client == nil || replays == nil || limit < 1 ||
		window < time.Second || now == nil {
		return nil, ErrExternalVerification
	}
	service := &ExternalVerificationService{replays: replays, limit: limit, window: window, now: now,
		usage: make(map[string]externalUsage)}
	return &ExternalVerifierHandler{stateRoot: stateRoot, client: client, service: service}, nil
}

func (handler *ExternalVerifierHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if handler == nil || request == nil || request.Method != http.MethodPost || request.URL.Path != ExternalVerifierPath ||
		request.URL.RawQuery != "" || request.Header.Get("Content-Type") != "application/json" ||
		!canonicalLoopbackRemote(request.RemoteAddr) {
		writer.WriteHeader(http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxExternalEnvelopeBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxExternalEnvelopeBytes || rejectDuplicateJSONKeys(body) != nil {
		writer.WriteHeader(http.StatusForbidden)
		return
	}
	var envelope ExternalVerifyEnvelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || requireJSONEOF(decoder) != nil {
		writer.WriteHeader(http.StatusForbidden)
		return
	}
	credential, err := LoadExternalCredentials(handler.stateRoot, ExternalCredentialBinding{
		PolicyID: envelope.PolicyID, PolicyVersion: envelope.PolicyVersion, TenantID: envelope.TenantID,
		SiteID: envelope.SiteID, Provider: envelope.Provider, AppID: envelope.AppID,
	})
	if err != nil {
		writer.WriteHeader(http.StatusForbidden)
		return
	}
	defer clear(credential.Secret)
	verifier, err := NewHTTPExternalVerifier(handler.client, credential)
	if err != nil {
		writer.WriteHeader(http.StatusForbidden)
		return
	}
	defer clear(verifier.credential.Secret)
	ctx, cancel := context.WithTimeout(request.Context(), 4*time.Second)
	defer cancel()
	_, err = handler.service.verifyWith(ctx, ExternalRequest{Provider: envelope.Provider, AppID: envelope.AppID,
		Proof: envelope.Proof, ClientIP: envelope.ClientIP, SiteID: envelope.SiteID}, verifier)
	if err != nil {
		writer.WriteHeader(http.StatusForbidden)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func canonicalLoopbackRemote(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil || port == "" {
		return false
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address == netip.MustParseAddr("127.0.0.1")
}

type ExternalVerifierServer struct {
	address string
	server  *http.Server
}

func NewExternalVerifierServer(stateRoot, address string, client *http.Client) (*ExternalVerifierServer, error) {
	host, port, err := net.SplitHostPort(address)
	parsed, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || parsed != netip.MustParseAddr("127.0.0.1") || port == "" ||
		strings.TrimSpace(port) != port {
		return nil, ErrExternalVerification
	}
	handler, err := NewExternalVerifierHandler(stateRoot, client, NewMemoryExternalReplayStore(100_000),
		120, time.Minute, time.Now)
	if err != nil {
		return nil, err
	}
	return &ExternalVerifierServer{address: address, server: &http.Server{Handler: handler,
		ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 2 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}}, nil
}

func (server *ExternalVerifierServer) Run(ctx context.Context) error {
	if server == nil || server.server == nil || ctx == nil {
		return ErrExternalVerification
	}
	listener, err := net.Listen("tcp4", server.address)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- server.server.Serve(listener) }()
	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		shutdownErr := server.server.Shutdown(shutdownContext)
		serveErr := <-done
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
		if shutdownErr != nil {
			return shutdownErr
		}
		return ctx.Err()
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
