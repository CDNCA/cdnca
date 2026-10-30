package edgegolden

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// UserAgent is what every client request sends (Go's default differs by
// version and protocol).
const UserAgent = "cdnca-edge-golden/1"

const requestTimeout = 15 * time.Second

func stepAddress(step Step) string {
	address := step.Address
	if address == "" {
		address = "127.0.0.1"
	}
	return net.JoinHostPort(address, strconv.Itoa(step.Port))
}

func stepSNI(step Step) string {
	if step.SNI != nil {
		return *step.SNI
	}
	return step.Host
}

func tlsVersion(value string) uint16 {
	switch value {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		return 0
	}
}

func versionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func clientTLSConfig(step Step, alpn []string) *tls.Config {
	if alpn == nil {
		alpn = step.ALPN
	}
	if alpn == nil {
		alpn = []string{"h2", "http/1.1"}
	}
	config := &tls.Config{ServerName: stepSNI(step), NextProtos: alpn, InsecureSkipVerify: true, //nolint:gosec // the result records and verifies the chain itself
		MinVersion: tlsVersion(step.TLSMin), MaxVersion: tlsVersion(step.TLSMax)}
	for _, name := range step.Ciphers {
		for _, suite := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
			if suite.Name == name {
				config.CipherSuites = append(config.CipherSuites, suite.ID)
			}
		}
	}
	if step.clientCertificate != nil {
		config.Certificates = []tls.Certificate{*step.clientCertificate}
	}
	return config
}

func dialer(step Step) (*net.Dialer, error) {
	value := &net.Dialer{Timeout: 5 * time.Second}
	if step.Source != "" {
		address := net.ParseIP(step.Source)
		if address == nil {
			return nil, fmt.Errorf("step %s: source %q is not an address", step.ID, step.Source)
		}
		value.LocalAddr = &net.TCPAddr{IP: address}
	}
	return value, nil
}

func describeTLS(state tls.ConnectionState, roots *x509.CertPool, sni string) *TLSResult {
	result := &TLSResult{Version: versionName(state.Version), ALPN: state.NegotiatedProtocol}
	if len(state.PeerCertificates) == 0 {
		return result
	}
	leaf := state.PeerCertificates[0]
	result.Subject, result.Names, result.Serial, result.Issuer = leaf.Subject.CommonName, leaf.DNSNames, leaf.SerialNumber.Int64(), leaf.Issuer.CommonName
	if sni != "" && roots != nil {
		intermediates := x509.NewCertPool()
		for _, certificate := range state.PeerCertificates[1:] {
			intermediates.AddCert(certificate)
		}
		_, err := leaf.Verify(x509.VerifyOptions{DNSName: sni, Roots: roots, Intermediates: intermediates})
		result.Verified = err == nil
	}
	return result
}

type bodyReader struct{ io.Reader }

func requestBody(step Step) (io.Reader, int64) {
	payload := step.Body
	if step.BodyBytes > 0 {
		payload = strings.Repeat("x", step.BodyBytes)
	}
	if payload == "" {
		return nil, 0
	}
	if step.Chunked {
		// A reader whose length net/http cannot see: sent chunked.
		return bodyReader{strings.NewReader(payload)}, -1
	}
	return strings.NewReader(payload), int64(len(payload))
}

// sendHTTP sends one request of step on a fresh connection.
func sendHTTP(ctx context.Context, step Step, roots *x509.CertPool, mask Mask) Response {
	method := step.Method
	if method == "" {
		method = http.MethodGet
	}
	scheme := step.Scheme
	if scheme == "" {
		scheme = "http"
	}
	path := step.Path
	if path == "" {
		path = "/"
	}
	netDialer, err := dialer(step)
	if err != nil {
		return Response{Error: err.Error()}
	}
	address := stepAddress(step)
	var tlsState *tls.ConnectionState
	transport := &http.Transport{DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: scheme == "https",
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return netDialer.DialContext(ctx, network, address)
		}}
	if scheme == "https" {
		transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			raw, err := netDialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			connection := tls.Client(raw, clientTLSConfig(step, nil))
			if err := connection.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			state := connection.ConnectionState()
			tlsState = &state
			return connection, nil
		}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authority := step.Host
	if authority == "" {
		authority = address
	}
	body, length := requestBody(step)
	request, err := http.NewRequestWithContext(ctx, method, scheme+"://"+authority+path, body)
	if err != nil {
		return Response{Error: "invalid_request"}
	}
	request.ContentLength = length
	request.Host = authority
	request.Header.Set("User-Agent", UserAgent)
	for _, name := range sortedKeys(step.Headers) {
		if strings.EqualFold(name, "host") {
			request.Host = step.Headers[name]
			continue
		}
		request.Header.Set(name, step.Headers[name])
	}
	response, err := client.Do(request)
	if err != nil {
		result := Response{Error: classifyError(err)}
		return result
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	result := Response{Status: response.StatusCode, Proto: response.Proto,
		Headers: headerMap(mask, mask.ResponseHeaders, response.Header), Body: newBody(mask, payload),
		location: response.Header.Get("Location")}
	if readErr != nil {
		result.Error = "body_" + classifyError(readErr)
	}
	if tlsState != nil {
		result.TLS = describeTLS(*tlsState, roots, stepSNI(step))
	}
	return result
}

// handshake runs a TLS handshake only.
func handshake(ctx context.Context, step Step, roots *x509.CertPool) *TLSResult {
	netDialer, err := dialer(step)
	if err != nil {
		return &TLSResult{Error: err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	raw, err := netDialer.DialContext(ctx, "tcp", stepAddress(step))
	if err != nil {
		return &TLSResult{Error: classifyError(err)}
	}
	defer raw.Close()
	connection := tls.Client(raw, clientTLSConfig(step, nil))
	if err := connection.HandshakeContext(ctx); err != nil {
		return &TLSResult{Error: classifyError(err)}
	}
	return describeTLS(connection.ConnectionState(), roots, stepSNI(step))
}

// websocketExchange upgrades, sends step.Message and reads one frame back.
func websocketExchange(ctx context.Context, step Step) *WebSocketResult {
	netDialer, err := dialer(step)
	if err != nil {
		return &WebSocketResult{Error: err.Error()}
	}
	address := stepAddress(step)
	scheme := "ws"
	webSocketDialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second,
		NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return netDialer.DialContext(ctx, network, address)
		}}
	if step.Scheme == "https" {
		scheme = "wss"
		webSocketDialer.TLSClientConfig = clientTLSConfig(step, []string{"http/1.1"})
	}
	path := step.Path
	if path == "" {
		path = "/"
	}
	header := http.Header{"User-Agent": {UserAgent}}
	for name, value := range step.Headers {
		// e.g. Origin, for a WebSocket Origin allowlist.
		header.Set(name, value)
	}
	if step.Host != "" {
		header.Set("Host", step.Host)
	}
	target := url.URL{Scheme: scheme, Host: address, Path: path}
	connection, response, err := webSocketDialer.DialContext(ctx, target.String(), header)
	result := &WebSocketResult{}
	if response != nil {
		result.Status = response.StatusCode
	}
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	_ = connection.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := connection.WriteMessage(websocket.TextMessage, []byte(step.Message)); err != nil {
		result.Error = classifyError(err)
		return result
	}
	_, echo, err := connection.ReadMessage()
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	result.Echo = string(echo)
	return result
}

var (
	alertPattern   = regexp.MustCompile(`tls: (?:[a-z ]*)?alert\(?\d*\)?:? ?([a-z ]+)$|remote error: tls: ([a-z ]+)`)
	addressPattern = regexp.MustCompile(`(\[[0-9a-fA-F:]+\]|[0-9]{1,3}(\.[0-9]{1,3}){3}):[0-9]+`)
)

// classifyError turns a client error into a stable class (no addresses,
// ports or Go wording that changes between versions).
func classifyError(err error) string {
	var netErr net.Error
	text := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case strings.Contains(text, "connection refused"):
		return "connect_refused"
	case strings.Contains(text, "connection reset"):
		return "connection_reset"
	case strings.Contains(text, "broken pipe"):
		return "broken_pipe"
	case errors.Is(err, websocket.ErrBadHandshake):
		return "websocket_bad_handshake"
	}
	if match := alertPattern.FindStringSubmatch(text); match != nil {
		alert := match[1]
		if alert == "" {
			alert = match[2]
		}
		return "tls_alert_" + strings.ReplaceAll(strings.TrimSpace(alert), " ", "_")
	}
	switch {
	case strings.Contains(text, "tls: "):
		return "tls_error"
	case strings.Contains(text, "unexpected EOF"):
		return "unexpected_eof"
	case strings.HasSuffix(text, "EOF"):
		return "eof"
	case strings.Contains(text, "stream error"):
		return "http2_stream_error"
	case strings.Contains(text, "malformed HTTP"):
		return "malformed_http"
	}
	return "error: " + addressPattern.ReplaceAllString(text, "<address>")
}

// followLocation requests a 3xx's Location (http:// to a loopback address)
// once from the step's source. The Location's host:port is dialed; Host is
// the Location's authority.
func followLocation(ctx context.Context, step Step, location string, roots *x509.CertPool, mask Mask) *Response {
	target, err := url.Parse(location)
	if err != nil || target.Scheme != "http" || target.Host == "" {
		return &Response{Error: "invalid_location"}
	}
	host, port, err := net.SplitHostPort(target.Host)
	if err != nil {
		host, port = target.Host, "80"
	}
	if address, err := netip.ParseAddr(host); err != nil || !address.IsLoopback() {
		return &Response{Error: "location_not_loopback"}
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		return &Response{Error: "invalid_location"}
	}
	next := step
	next.FollowLocation, next.Scheme, next.Method, next.Body, next.BodyBytes = false, "http", http.MethodGet, "", 0
	next.Address, next.Port, next.Host, next.Path = host, number, target.Host, target.RequestURI()
	next.Headers = nil
	response := sendHTTP(ctx, next, roots, mask)
	return &response
}
