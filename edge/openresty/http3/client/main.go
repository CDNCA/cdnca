package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/logging"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type responseEvidence struct {
	Protocol      string `json:"protocol"`
	Status        int    `json:"status"`
	Body          string `json:"body"`
	AltSvc        string `json:"alt_svc"`
	VersionHeader string `json:"version_header"`
	TLSVersion    string `json:"tls_version"`
	QUICVersion   string `json:"quic_version"`
	RetryReceived bool   `json:"retry_received"`
	Used0RTT      bool   `json:"used_0rtt"`
	DidResume     bool   `json:"did_resume"`
}

type h3Client struct {
	client         *http.Client
	http3          *http3.Transport
	transport      *quic.Transport
	mu             sync.Mutex
	conn           *quic.Conn
	dialCount      int
	retryCount     int
	streamSent     chan struct{}
	streamExpected int
	streamIDs      map[int64]struct{}
}

const (
	reloadFreshConnectionAttempts = 3
	reloadWorkerShutdownDelay     = 8500 * time.Millisecond
)

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("command is required"))
	}
	var err error
	switch os.Args[1] {
	case "version":
		err = runVersion(os.Args[2:])
	case "request":
		err = runRequest(os.Args[2:])
	case "concurrency":
		err = runConcurrency(os.Args[2:])
	case "connections":
		err = runConnections(os.Args[2:])
	case "reload-survival":
		err = runReloadSurvival(os.Args[2:])
	case "h2-hold":
		err = runH2Hold(os.Args[2:])
	case "migration":
		err = runMigration(os.Args[2:])
	case "fallback":
		err = runFallback(os.Args[2:])
	case "h2-attack":
		err = runH2Attack(os.Args[2:])
	case "tcp-proxy":
		err = runTCPProxy(os.Args[2:])
	case "wait":
		for {
			time.Sleep(time.Hour)
		}
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
}

func runRequest(arguments []string) error {
	flags := flag.NewFlagSet("request", flag.ContinueOnError)
	url, serverName, bind, timeout := commonFlags(flags)
	headerBytes := flags.Int("header-bytes", 0, "request header value size")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client, err := newH3Client(*bind, *serverName, *timeout)
	if err != nil {
		return err
	}
	defer client.close()
	evidence, err := client.request(ctx, *url, *headerBytes)
	if err != nil {
		return err
	}
	if evidence.Protocol != "HTTP/3.0" || evidence.Status != http.StatusOK || evidence.TLSVersion != "TLSv1.3" {
		return fmt.Errorf("unexpected HTTP/3 response: %+v", evidence)
	}
	return printJSON(evidence)
}

func runConcurrency(arguments []string) error {
	flags := flag.NewFlagSet("concurrency", flag.ContinueOnError)
	url, serverName, bind, timeout := commonFlags(flags)
	count := flags.Int("count", 4, "concurrent requests")
	headerBytes := flags.Int("header-bytes", 0, "request header value size")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *count < 1 || *count > 64 {
		return errors.New("count must be between 1 and 64")
	}
	client, err := newH3Client(*bind, *serverName, *timeout)
	if err != nil {
		return err
	}
	defer client.close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	start := make(chan struct{})
	type result struct {
		evidence responseEvidence
		err      error
	}
	results := make(chan result, *count)
	startedAt := time.Now()
	for index := 0; index < *count; index++ {
		go func() {
			<-start
			evidence, requestErr := client.request(ctx, *url, *headerBytes)
			results <- result{evidence: evidence, err: requestErr}
		}()
	}
	close(start)
	statusCounts := make(map[string]int)
	protocolCounts := make(map[string]int)
	for index := 0; index < *count; index++ {
		result := <-results
		if result.err != nil {
			return result.err
		}
		statusCounts[strconv.Itoa(result.evidence.Status)]++
		protocolCounts[result.evidence.Protocol]++
	}
	evidence := struct {
		Count          int            `json:"count"`
		StatusCounts   map[string]int `json:"status_counts"`
		ProtocolCounts map[string]int `json:"protocol_counts"`
		ElapsedMS      int64          `json:"elapsed_ms"`
	}{*count, statusCounts, protocolCounts, time.Since(startedAt).Milliseconds()}
	return printJSON(evidence)
}

func runConnections(arguments []string) error {
	flags := flag.NewFlagSet("connections", flag.ContinueOnError)
	url, serverName, bind, timeout := commonFlags(flags)
	count := flags.Int("count", 16, "independent HTTP/3 connections")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *count < 1 || *count > 64 {
		return errors.New("count must be between 1 and 64")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	type result struct {
		evidence responseEvidence
		err      error
	}
	results := make(chan result, *count)
	start := make(chan struct{})
	for index := 0; index < *count; index++ {
		go func() {
			<-start
			client, err := newH3Client(*bind, *serverName, *timeout)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer client.close()
			evidence, requestErr := client.request(ctx, *url, 0)
			results <- result{evidence: evidence, err: requestErr}
		}()
	}
	close(start)
	statusCounts := make(map[string]int)
	versionCounts := make(map[string]int)
	for index := 0; index < *count; index++ {
		result := <-results
		if result.err != nil {
			return result.err
		}
		statusCounts[strconv.Itoa(result.evidence.Status)]++
		versionCounts[result.evidence.VersionHeader]++
	}
	return printJSON(struct {
		Count         int            `json:"count"`
		StatusCounts  map[string]int `json:"status_counts"`
		VersionCounts map[string]int `json:"version_counts"`
	}{*count, statusCounts, versionCounts})
}

func runReloadSurvival(arguments []string) error {
	flags := flag.NewFlagSet("reload-survival", flag.ContinueOnError)
	baselineURL := flags.String("baseline-url", "", "HTTP/3 URL used to establish the connection")
	holdURL := flags.String("hold-url", "", "HTTP/3 URL held across the reload")
	serverName := flags.String("server-name", "", "TLS server name")
	bind := flags.String("bind", "0.0.0.0:0", "local UDP address")
	readyFile := flags.String("ready-file", "", "absolute marker path written after a hold stream is sent")
	count := flags.Int("count", 4, "concurrent held requests")
	timeout := flags.Duration("timeout", 15*time.Second, "operation timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *baselineURL == "" || *holdURL == "" || *serverName == "" || !filepath.IsAbs(*readyFile) ||
		*count < 1 || *count > 64 || *timeout <= 0 {
		return errors.New("baseline-url, hold-url, server-name, absolute ready-file, count, and timeout are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client, baseline, baselineAttempts, err := freshH3Request(ctx, *bind, *serverName, *timeout, *baselineURL, "http3-v1")
	if err != nil {
		return fmt.Errorf("establish reload baseline: %w", err)
	}
	defer client.close()
	client.mu.Lock()
	connection := client.conn
	baselineDials := client.dialCount
	client.mu.Unlock()
	if connection == nil || baselineDials != 1 || baseline.VersionHeader != "http3-v1" {
		return fmt.Errorf("reload baseline did not establish v1 on one connection: evidence=%+v dials=%d", baseline, baselineDials)
	}

	streamSent := client.armRequestStream(*count)
	type result struct {
		evidence responseEvidence
		err      error
	}
	results := make(chan result, *count)
	start := make(chan struct{})
	for index := 0; index < *count; index++ {
		go func() {
			<-start
			evidence, requestErr := client.request(ctx, *holdURL, 0)
			results <- result{evidence: evidence, err: requestErr}
		}()
	}
	close(start)
	select {
	case <-streamSent:
	case <-ctx.Done():
		return fmt.Errorf("hold request stream was not sent before timeout: %w", ctx.Err())
	}
	if err := writeReadyMarker(*readyFile); err != nil {
		return fmt.Errorf("write reload marker: %w", err)
	}

	statusCounts := make(map[string]int)
	versionCounts := make(map[string]int)
	statelessResets := 0
	for index := 0; index < *count; index++ {
		result := <-results
		if result.err != nil {
			var reset *quic.StatelessResetError
			if !errors.As(result.err, &reset) {
				return result.err
			}
			statelessResets++
			continue
		}
		statusCounts[strconv.Itoa(result.evidence.Status)]++
		versionCounts[result.evidence.VersionHeader]++
	}
	client.mu.Lock()
	sameConnection := client.conn == connection && client.dialCount == 1
	dialCount := client.dialCount
	client.mu.Unlock()
	if statusCounts["200"]+statelessResets != *count || versionCounts["http3-v1"] != statusCounts["200"] || !sameConnection {
		return fmt.Errorf("held requests had an invalid reload outcome: statuses=%v versions=%v resets=%d dials=%d", statusCounts, versionCounts, statelessResets, dialCount)
	}
	client.close()
	drainTimer := time.NewTimer(reloadWorkerShutdownDelay)
	select {
	case <-ctx.Done():
		drainTimer.Stop()
		return ctx.Err()
	case <-drainTimer.C:
	}
	recoveryClient, recovery, recoveryAttempts, err := freshH3Request(ctx, *bind, *serverName, *timeout, *baselineURL, "http3-v2")
	if err != nil {
		return fmt.Errorf("recover on a fresh HTTP/3 connection: %w", err)
	}
	recoveryClient.close()
	return printJSON(struct {
		Count                    int            `json:"count"`
		CompletedOnOldConnection int            `json:"completed_on_old_connection"`
		StatelessResets          int            `json:"stateless_resets"`
		StatusCounts             map[string]int `json:"status_counts"`
		VersionCounts            map[string]int `json:"version_counts"`
		OldConnectionDials       int            `json:"old_connection_dials"`
		OldConnectionUnredialed  bool           `json:"old_connection_unredialed"`
		BaselineAttempts         int            `json:"baseline_attempts"`
		FreshAttemptLimit        int            `json:"fresh_attempt_limit"`
		FreshAttempts            int            `json:"fresh_attempts"`
		FreshVersion             string         `json:"fresh_version"`
	}{*count, statusCounts["200"], statelessResets, statusCounts, versionCounts, dialCount, sameConnection,
		baselineAttempts, reloadFreshConnectionAttempts, recoveryAttempts, recovery.VersionHeader})
}

func runH2Hold(arguments []string) error {
	flags := flag.NewFlagSet("h2-hold", flag.ContinueOnError)
	requestURL := flags.String("url", "", "HTTPS URL held across the reload")
	serverName := flags.String("server-name", "", "TLS server name")
	readyFile := flags.String("ready-file", "", "absolute marker path written after the request is sent")
	expectedVersion := flags.String("expected-version", "", "expected response version header")
	timeout := flags.Duration("timeout", 15*time.Second, "operation timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *requestURL == "" || *serverName == "" || !filepath.IsAbs(*readyFile) || *expectedVersion == "" || *timeout <= 0 {
		return errors.New("url, server-name, absolute ready-file, expected-version, and timeout are required")
	}
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Isolated smoke uses an ephemeral self-signed certificate.
			ServerName:         *serverName,
			MinVersion:         tls.VersionTLS13,
		},
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, *requestURL, nil)
	if err != nil {
		return err
	}
	var markerErr error
	var markerOnce sync.Once
	trace := &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
		markerOnce.Do(func() {
			if info.Err != nil {
				markerErr = info.Err
				return
			}
			markerErr = writeReadyMarker(*readyFile)
		})
	}}
	response, err := transport.RoundTrip(request.WithContext(httptrace.WithClientTrace(request.Context(), trace)))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if markerErr != nil {
		return fmt.Errorf("write HTTP/2 reload marker: %w", markerErr)
	}
	tlsVersionName := ""
	if response.TLS != nil {
		tlsVersionName = tlsVersion(response.TLS.Version)
	}
	evidence := responseEvidence{
		Protocol: response.Proto, Status: response.StatusCode, Body: strings.TrimSpace(string(body)),
		VersionHeader: response.Header.Get("X-CDNCA-HTTP3-Version"), TLSVersion: tlsVersionName,
	}
	if evidence.Protocol != "HTTP/2.0" || evidence.Status != http.StatusOK ||
		evidence.VersionHeader != *expectedVersion || evidence.TLSVersion != "TLSv1.3" {
		return fmt.Errorf("HTTP/2 hold did not drain on the old generation: %+v", evidence)
	}
	return printJSON(evidence)
}

func freshH3Request(
	ctx context.Context,
	bind, serverName string,
	timeout time.Duration,
	requestURL, expectedVersion string,
) (*h3Client, responseEvidence, int, error) {
	var last error
	for attempt := 1; attempt <= reloadFreshConnectionAttempts; attempt++ {
		client, err := newH3Client(bind, serverName, timeout)
		if err != nil {
			return nil, responseEvidence{}, attempt, err
		}
		evidence, requestErr := client.request(ctx, requestURL, 0)
		if requestErr == nil && evidence.VersionHeader == expectedVersion {
			return client, evidence, attempt, nil
		}
		client.close()
		if requestErr != nil {
			var reset *quic.StatelessResetError
			if !errors.As(requestErr, &reset) {
				return nil, responseEvidence{}, attempt, requestErr
			}
			last = requestErr
		} else {
			last = fmt.Errorf("fresh connection reached version %q, want %q", evidence.VersionHeader, expectedVersion)
		}
		if attempt < reloadFreshConnectionAttempts {
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, responseEvidence{}, attempt, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return nil, responseEvidence{}, reloadFreshConnectionAttempts, last
}

func writeReadyMarker(path string) error {
	marker, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return marker.Close()
}

func runMigration(arguments []string) error {
	flags := flag.NewFlagSet("migration", flag.ContinueOnError)
	url := flags.String("url", "", "HTTPS URL")
	serverName := flags.String("server-name", "", "TLS server name")
	initialBind := flags.String("initial-bind", "", "initial local UDP address")
	migrationBind := flags.String("migration-bind", "", "migration local UDP address")
	timeout := flags.Duration("timeout", 15*time.Second, "operation timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *url == "" || *serverName == "" || *initialBind == "" || *migrationBind == "" {
		return errors.New("url, server-name, initial-bind and migration-bind are required")
	}
	client, err := newH3Client(*initialBind, *serverName, *timeout)
	if err != nil {
		return err
	}
	defer client.close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	first, err := client.request(ctx, *url, 0)
	if err != nil {
		return err
	}
	client.mu.Lock()
	connection := client.conn
	initialDialCount := client.dialCount
	client.mu.Unlock()
	if connection == nil || initialDialCount != 1 {
		return errors.New("HTTP/3 connection was not captured")
	}
	secondUDP, err := net.ListenPacket("udp", *migrationBind)
	if err != nil {
		return err
	}
	secondTransport := &quic.Transport{Conn: secondUDP}
	defer secondTransport.Close()
	path, err := connection.AddPath(secondTransport)
	if err != nil {
		return err
	}
	if err := path.Probe(ctx); err != nil {
		return fmt.Errorf("probe migration path: %w", err)
	}
	if err := path.Switch(); err != nil {
		return fmt.Errorf("switch migration path: %w", err)
	}
	second, err := client.request(ctx, *url, 0)
	if err != nil {
		return err
	}
	initialAddress := client.transport.Conn.LocalAddr().String()
	migratedAddress := connection.LocalAddr().String()
	client.mu.Lock()
	sameConnection := client.conn == connection && client.dialCount == 1
	dialCount := client.dialCount
	client.mu.Unlock()
	if hostOnly(initialAddress) == hostOnly(migratedAddress) || first.Protocol != "HTTP/3.0" || second.Protocol != "HTTP/3.0" ||
		!sameConnection {
		return fmt.Errorf("migration did not preserve the HTTP/3 connection: first=%+v second=%+v initial=%s migrated=%s", first, second, initialAddress, migratedAddress)
	}
	evidence := struct {
		InitialLocal     string `json:"initial_local"`
		MigratedLocal    string `json:"migrated_local"`
		InitialProtocol  string `json:"initial_protocol"`
		MigratedProtocol string `json:"migrated_protocol"`
		DialCount        int    `json:"dial_count"`
		SameConnection   bool   `json:"same_connection"`
	}{initialAddress, migratedAddress, first.Protocol, second.Protocol, dialCount, sameConnection}
	return printJSON(evidence)
}

func runFallback(arguments []string) error {
	flags := flag.NewFlagSet("fallback", flag.ContinueOnError)
	url := flags.String("url", "", "HTTPS URL whose UDP endpoint is unavailable")
	serverName := flags.String("server-name", "", "TLS server name")
	h3Timeout := flags.Duration("h3-timeout", 800*time.Millisecond, "HTTP/3 attempt timeout")
	timeout := flags.Duration("timeout", 10*time.Second, "total timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *url == "" || *serverName == "" || *h3Timeout <= 0 {
		return errors.New("url, server-name and a positive h3-timeout are required")
	}
	h3, err := newH3Client("0.0.0.0:0", *serverName, *h3Timeout)
	if err != nil {
		return err
	}
	h3Ctx, h3Cancel := context.WithTimeout(context.Background(), *h3Timeout)
	_, h3Err := h3.request(h3Ctx, *url, 0)
	h3Cancel()
	h3.close()
	if h3Err == nil {
		return errors.New("HTTP/3 unexpectedly succeeded on TCP-only endpoint")
	}
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Isolated smoke uses an ephemeral self-signed certificate.
			ServerName:         *serverName,
			MinVersion:         tls.VersionTLS13,
		},
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		return err
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		return fmt.Errorf("TCP fallback failed after HTTP/3 error %v: %w", h3Err, err)
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20)); err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || response.Proto != "HTTP/2.0" {
		return fmt.Errorf("unexpected fallback response: protocol=%s status=%d", response.Proto, response.StatusCode)
	}
	evidence := struct {
		H3Attempted      bool   `json:"h3_attempted"`
		H3Failed         bool   `json:"h3_failed"`
		FallbackProtocol string `json:"fallback_protocol"`
		FallbackStatus   int    `json:"fallback_status"`
	}{true, true, response.Proto, response.StatusCode}
	return printJSON(evidence)
}

func runTCPProxy(arguments []string) error {
	flags := flag.NewFlagSet("tcp-proxy", flag.ContinueOnError)
	listenAddress := flags.String("listen", "0.0.0.0:18443", "TCP listen address")
	target := flags.String("target", "", "TCP target")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *target == "" {
		return errors.New("target is required")
	}
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		client, err := listener.Accept()
		if err != nil {
			return err
		}
		go proxyConnection(client, *target)
	}
}

func runH2Attack(arguments []string) error {
	flags := flag.NewFlagSet("h2-attack", flag.ContinueOnError)
	target := flags.String("url", "", "HTTPS URL")
	serverName := flags.String("server-name", "", "TLS server name")
	mode := flags.String("mode", "", "injection or bomb")
	timeout := flags.Duration("timeout", 10*time.Second, "operation timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	parsed, err := url.Parse(*target)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || *serverName == "" ||
		(*mode != "injection" && *mode != "bomb") || *timeout <= 0 {
		return errors.New("url, server-name, mode, and a positive timeout are required")
	}
	dialer := &net.Dialer{Timeout: *timeout}
	connection, err := tls.DialWithDialer(dialer, "tcp", parsed.Host, &tls.Config{
		InsecureSkipVerify: true, // Isolated smoke uses an ephemeral self-signed certificate.
		ServerName:         *serverName, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
	})
	if err != nil {
		return err
	}
	defer connection.Close()
	if connection.ConnectionState().NegotiatedProtocol != "h2" {
		return errors.New("HTTP/2 was not negotiated")
	}
	if err := connection.SetDeadline(time.Now().Add(*timeout)); err != nil {
		return err
	}
	framer := http2.NewFramer(connection, connection)
	if _, err := io.WriteString(connection, http2.ClientPreface); err != nil {
		return err
	}
	if err := framer.WriteSettings(); err != nil {
		return err
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: *serverName}, {Name: ":path", Value: parsed.RequestURI()},
	} {
		if err := encoder.WriteField(field); err != nil {
			return err
		}
	}
	if *mode == "injection" {
		if err := encoder.WriteField(hpack.HeaderField{Name: "x-cdnca-boundary", Value: "safe\r\nx-injected: true"}); err != nil {
			return err
		}
	} else {
		for index := 0; index < 64; index++ {
			if err := encoder.WriteField(hpack.HeaderField{Name: fmt.Sprintf("x-bomb-%02d", index), Value: strings.Repeat("x", 1024)}); err != nil {
				return err
			}
		}
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
		return err
	}
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return printJSON(map[string]any{"mode": *mode, "rejected": true, "evidence": "connection_closed"})
			}
			return err
		}
		switch typed := frame.(type) {
		case *http2.SettingsFrame:
			if !typed.IsAck() {
				if err := framer.WriteSettingsAck(); err != nil {
					return err
				}
			}
		case *http2.RSTStreamFrame:
			return printJSON(map[string]any{"mode": *mode, "rejected": true, "evidence": "rst_stream", "code": typed.ErrCode.String()})
		case *http2.GoAwayFrame:
			return printJSON(map[string]any{"mode": *mode, "rejected": true, "evidence": "goaway", "code": typed.ErrCode.String()})
		case *http2.HeadersFrame:
			status := ""
			decoder := hpack.NewDecoder(1<<20, func(field hpack.HeaderField) {
				if field.Name == ":status" {
					status = field.Value
				}
			})
			if _, err := decoder.Write(typed.HeaderBlockFragment()); err != nil {
				return err
			}
			if status == "400" || status == "413" || status == "414" || status == "431" {
				return printJSON(map[string]any{"mode": *mode, "rejected": true, "evidence": "http_status", "status": status})
			}
			return fmt.Errorf("HTTP/2 %s attack reached application response status %q", *mode, status)
		}
	}
}

func proxyConnection(client net.Conn, target string) {
	defer client.Close()
	server, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return
	}
	defer server.Close()
	closed := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(server, client)
		if tcp, ok := server.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		closed <- struct{}{}
	}()
	_, _ = io.Copy(client, server)
	<-closed
}

func commonFlags(flags *flag.FlagSet) (*string, *string, *string, *time.Duration) {
	return flags.String("url", "", "HTTPS URL"), flags.String("server-name", "", "TLS server name"),
		flags.String("bind", "0.0.0.0:0", "local UDP address"), flags.Duration("timeout", 15*time.Second, "operation timeout")
}

func newH3Client(bind, serverName string, timeout time.Duration) (*h3Client, error) {
	if serverName == "" || timeout <= 0 {
		return nil, errors.New("server-name and a positive timeout are required")
	}
	packetConn, err := net.ListenPacket("udp", bind)
	if err != nil {
		return nil, err
	}
	client := &h3Client{transport: &quic.Transport{Conn: packetConn}}
	client.http3 = &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Isolated smoke uses an ephemeral self-signed certificate.
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS13,
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: timeout, MaxIdleTimeout: timeout,
			Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
				return &logging.ConnectionTracer{
					ReceivedRetry: func(*logging.Header) {
						client.mu.Lock()
						client.retryCount++
						client.mu.Unlock()
					},
					SentShortHeaderPacket: func(_ *logging.ShortHeader, _ logging.ByteCount, _ logging.ECN, _ *logging.AckFrame, frames []logging.Frame) {
						for _, frame := range frames {
							stream, ok := frame.(*logging.StreamFrame)
							if !ok || stream.StreamID < 4 || stream.StreamID%4 != 0 || stream.Length == 0 {
								continue
							}
							client.signalRequestStream(int64(stream.StreamID))
							return
						}
					},
				}
			},
		},
	}
	client.http3.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
		remote, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return nil, err
		}
		connection, err := client.transport.DialEarly(ctx, remote, tlsConfig, config)
		if err == nil {
			client.mu.Lock()
			client.conn = connection
			client.dialCount++
			client.mu.Unlock()
		}
		return connection, err
	}
	client.client = &http.Client{Transport: client.http3, Timeout: timeout}
	return client, nil
}

func (c *h3Client) armRequestStream(expected int) <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streamSent = make(chan struct{})
	c.streamExpected = expected
	c.streamIDs = make(map[int64]struct{}, expected)
	return c.streamSent
}

func (c *h3Client) signalRequestStream(streamID int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.streamSent != nil {
		c.streamIDs[streamID] = struct{}{}
	}
	if c.streamSent != nil && len(c.streamIDs) >= c.streamExpected {
		close(c.streamSent)
		c.streamSent = nil
		c.streamExpected = 0
		c.streamIDs = nil
	}
}

func (c *h3Client) request(ctx context.Context, url string, headerBytes int) (responseEvidence, error) {
	if url == "" || headerBytes < 0 || headerBytes > 1<<20 {
		return responseEvidence{}, errors.New("invalid request parameters")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return responseEvidence{}, err
	}
	if headerBytes > 0 {
		request.Header.Set("X-CDNCA-Boundary", strings.Repeat("x", headerBytes))
	}
	response, err := c.client.Do(request)
	if err != nil {
		return responseEvidence{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return responseEvidence{}, err
	}
	c.mu.Lock()
	connection := c.conn
	c.mu.Unlock()
	if connection == nil {
		return responseEvidence{}, errors.New("HTTP/3 connection is unavailable")
	}
	state := connection.ConnectionState()
	c.mu.Lock()
	retryReceived := c.retryCount > 0
	c.mu.Unlock()
	return responseEvidence{
		Protocol: response.Proto, Status: response.StatusCode, Body: strings.TrimSpace(string(body)),
		AltSvc: response.Header.Get("Alt-Svc"), VersionHeader: response.Header.Get("X-CDNCA-HTTP3-Version"),
		TLSVersion: tlsVersion(state.TLS.Version), QUICVersion: state.Version.String(),
		RetryReceived: retryReceived, Used0RTT: state.Used0RTT, DidResume: state.TLS.DidResume,
	}, nil
}

func (c *h3Client) close() {
	_ = c.http3.Close()
	_ = c.transport.Close()
}

func tlsVersion(version uint16) string {
	if version == tls.VersionTLS13 {
		return "TLSv1.3"
	}
	return fmt.Sprintf("0x%x", version)
}

func hostOnly(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// runVersion is the self-test the edge agent runs before declaring HTTP_3:
// it proves the packaged binary executes and names its build.
func runVersion(args []string) error {
	info, ok := debug.ReadBuildInfo()
	if len(args) != 0 || !ok {
		return errors.New("version takes no arguments and needs build information")
	}
	quicGo := ""
	for _, dependency := range info.Deps {
		if dependency.Path == "github.com/quic-go/quic-go" {
			quicGo = dependency.Version
		}
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Schema string `json:"schema"`
		Go     string `json:"go"`
		QUICGo string `json:"quic_go"`
	}{"cdnca.h3probe/v1", info.GoVersion, quicGo})
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
