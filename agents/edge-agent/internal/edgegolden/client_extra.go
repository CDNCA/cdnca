package edgegolden

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os/exec"
	"strings"
	"time"
)

// sendHTTP3 sends one request of step over HTTP/3 with the run's client
// (Env.HTTP3, tests/dynroute-filters/probe -full): a fresh QUIC connection.
func sendHTTP3(ctx context.Context, env Env, step Step, mask Mask) Response {
	method := step.Method
	if method == "" {
		method = http.MethodGet
	}
	path := step.Path
	if path == "" {
		path = "/"
	}
	args := []string{"-proto", "h3", "-full", "-method", method, "-host", step.Host,
		"-url", "https://" + stepAddress(step) + path}
	if step.BodyBytes > 0 {
		args = append(args, "-body-bytes", fmt.Sprint(step.BodyBytes))
	}
	args = append(args, "-header", "User-Agent:"+UserAgent)
	for _, name := range sortedKeys(step.Headers) {
		args = append(args, "-header", name+":"+step.Headers[name])
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout+5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, env.HTTP3, args...).Output()
	if err != nil {
		return Response{Error: "http3_client: " + err.Error()}
	}
	var result struct {
		Status       int                 `json:"status"`
		Proto        string              `json:"proto"`
		Reset        bool                `json:"reset"`
		Err          string              `json:"err"`
		HeaderValues map[string][]string `json:"header_values"`
		BodyBase64   string              `json:"body_base64"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return Response{Error: "http3_client_output"}
	}
	if result.Err != "" {
		return Response{Error: classifyHTTP3Error(result.Err)}
	}
	payload, err := base64.StdEncoding.DecodeString(result.BodyBase64)
	if err != nil {
		return Response{Error: "http3_client_output"}
	}
	response := Response{Status: result.Status, Proto: result.Proto,
		Headers: headerMap(mask, mask.ResponseHeaders, result.HeaderValues), Body: newBody(mask, payload)}
	if result.Reset {
		response.Error = "body_reset"
	}
	return response
}

// classifyHTTP3Error: QUIC errors have no stable Go wording either.
func classifyHTTP3Error(text string) string {
	switch {
	case strings.Contains(text, "timeout"):
		return "timeout"
	case strings.Contains(text, "CRYPTO_ERROR"):
		return "quic_crypto_error"
	}
	return "error: " + addressPattern.ReplaceAllString(text, "<address>")
}

// connections are the named client connections of a run (Step.Connection):
// each a transport with one kept-alive connection to the step's address.
type connections struct {
	byName map[string]*namedConnection
}

type namedConnection struct {
	transport *http.Transport
	tlsState  *tls.ConnectionState
}

func (pool *connections) close() {
	for _, connection := range pool.byName {
		connection.transport.CloseIdleConnections()
	}
}

// send sends step over its named connection, opening it the first time (or
// again when the edge closed it). Response.Reused reports the reuse.
func (pool *connections) send(ctx context.Context, step Step, roots *x509.CertPool, mask Mask) Response {
	if pool.byName == nil {
		pool.byName = map[string]*namedConnection{}
	}
	connection := pool.byName[step.Connection]
	if connection == nil {
		netDialer, err := dialer(step)
		if err != nil {
			return Response{Error: err.Error()}
		}
		address := stepAddress(step)
		connection = &namedConnection{}
		// One connection at a time, HTTP/1.1 keep-alive (ALPN http/1.1).
		connection.transport = &http.Transport{DisableCompression: true, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1,
			IdleConnTimeout: time.Minute,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return netDialer.DialContext(ctx, network, address)
			}}
		if step.Scheme == "https" {
			connection.transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				raw, err := netDialer.DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				client := tls.Client(raw, clientTLSConfig(step, []string{"http/1.1"}))
				if err := client.HandshakeContext(ctx); err != nil {
					_ = raw.Close()
					return nil, err
				}
				state := client.ConnectionState()
				connection.tlsState = &state
				return client, nil
			}
		}
		pool.byName[step.Connection] = connection
	}
	scheme := step.Scheme
	if scheme == "" {
		scheme = "http"
	}
	method := step.Method
	if method == "" {
		method = http.MethodGet
	}
	path := step.Path
	if path == "" {
		path = "/"
	}
	reused := false
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}
	body, length := requestBody(step)
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, scheme+"://"+step.Host+path, body)
	if err != nil {
		return Response{Error: "invalid_request"}
	}
	request.ContentLength = length
	request.Header.Set("User-Agent", UserAgent)
	for _, name := range sortedKeys(step.Headers) {
		request.Header.Set(name, step.Headers[name])
	}
	client := &http.Client{Transport: connection.transport, Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return Response{Error: classifyError(err), Reused: reused}
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	result := Response{Status: response.StatusCode, Proto: response.Proto, Reused: reused,
		Headers: headerMap(mask, mask.ResponseHeaders, response.Header), Body: newBody(mask, payload)}
	if readErr != nil {
		result.Error = "body_" + classifyError(readErr)
	}
	if connection.tlsState != nil {
		result.TLS = describeTLS(*connection.tlsState, roots, stepSNI(step))
	}
	return result
}

// streamExchange is a tcp / udp step: one line (tcp, TLS when Scheme is
// "https": TLS passthrough to an origin that terminates it) or one datagram
// (udp), and the reply.
func streamExchange(ctx context.Context, step Step, roots *x509.CertPool) *StreamResult {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	netDialer, err := dialer(step)
	if err != nil {
		return &StreamResult{Error: err.Error()}
	}
	network := step.Kind
	if step.Source != "" && step.Kind == "udp" {
		netDialer.LocalAddr = &net.UDPAddr{IP: netDialer.LocalAddr.(*net.TCPAddr).IP}
	}
	connection, err := netDialer.DialContext(ctx, network, stepAddress(step))
	if err != nil {
		return &StreamResult{Error: classifyError(err)}
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	result := &StreamResult{}
	if step.Kind == "udp" {
		if _, err := connection.Write([]byte(step.Message)); err != nil {
			return &StreamResult{Error: classifyError(err)}
		}
		buffer := make([]byte, 2048)
		n, err := connection.Read(buffer)
		if err != nil {
			return &StreamResult{Error: classifyError(err)}
		}
		result.Reply = string(buffer[:n])
		return result
	}
	if step.Scheme == "https" {
		client := tls.Client(connection, clientTLSConfig(step, []string{}))
		if err := client.HandshakeContext(ctx); err != nil {
			return &StreamResult{Error: classifyError(err)}
		}
		result.TLS = describeTLS(client.ConnectionState(), roots, stepSNI(step))
		connection = client
	}
	if _, err := fmt.Fprintf(connection, "%s\n", step.Message); err != nil {
		result.Error = classifyError(err)
		return result
	}
	line, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	result.Reply = strings.TrimSpace(line)
	return result
}
