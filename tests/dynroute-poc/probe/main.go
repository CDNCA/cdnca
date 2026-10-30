// Command probe is the test helper of the ADR 0009 §8.5 PoC (tests/dynroute-poc).
// It runs inside the real OpenResty container and plays every role the
// scenarios need besides OpenResty itself:
//
//	probe certs -out DIR                     edge certificates + two tenants' origin PKI
//	probe tlsorigin -listen ADDR|CRT|KEY|LABEL ...   HTTPS identity origins
//	probe errorigin -listen ADDR             plain HTTP origin with error-page fixtures
//	probe get -url URL [-proto h1|h2|h3] ... client; one JSON line per request
//
// Test-only: every certificate and key is generated per run and thrown away.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: probe certs|tlsorigin|errorigin|get ..."))
	}
	var err error
	switch os.Args[1] {
	case "certs":
		err = runCerts(os.Args[2:])
	case "tlsorigin":
		err = runTLSOrigin(os.Args[2:])
	case "errorigin":
		err = runErrorOrigin(os.Args[2:])
	case "get":
		err = runGet(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "probe:", err)
	os.Exit(1)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// ---------------------------------------------------------------- origins

// runTLSOrigin serves one HTTPS listener per -listen ADDR|CRT|KEY|LABEL. The
// certificate file is served as is (leaf first, then whatever chain it holds).
// The body names the listener, the SNI it saw and the client address of the
// TCP connection, so the edge's upstream connection reuse is visible.
func runTLSOrigin(args []string) error {
	flags := flag.NewFlagSet("tlsorigin", flag.ContinueOnError)
	var listens multiFlag
	flags.Var(&listens, "listen", "ADDR|CRT|KEY|LABEL (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	errs := make(chan error, len(listens))
	for _, spec := range listens {
		parts := strings.Split(spec, "|")
		if len(parts) != 4 {
			return fmt.Errorf("bad -listen %q", spec)
		}
		cert, err := tls.LoadX509KeyPair(parts[1], parts[2])
		if err != nil {
			return err
		}
		label := parts[3]
		var handshakes atomic.Int64
		config := &tls.Config{
			Certificates: []tls.Certificate{cert},
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				handshakes.Add(1)
				return nil, nil
			},
		}
		listener, err := tls.Listen("tcp", parts[0], config)
		if err != nil {
			return err
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Origin-Handshakes", fmt.Sprint(handshakes.Load()))
			fmt.Fprintf(w, "label=%s sni=%s conn=%s\n", label, r.TLS.ServerName, r.RemoteAddr)
		})
		go func() { errs <- http.Serve(listener, mux) }()
	}
	return <-errs
}

// runErrorOrigin is the origin of the error-page scenario. Paths:
//
//	/ok /404 /404chunked /404gzip /404empty /500 /410 (net/http, HEAD handled by net/http)
//	/404partial /200partial    headers announce 1000 bytes, 10 are sent, connection closed
//	/404chunkcut               chunked 404, one chunk, then the connection is closed
func runErrorOrigin(args []string) error {
	flags := flag.NewFlagSet("errorigin", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:9000", "address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	originHeaders := func(w http.ResponseWriter) {
		w.Header().Set("X-Origin-Header", "yes")
		w.Header().Set("ETag", `"origin-etag"`)
		w.Header().Set("Set-Cookie", "origin=1; Path=/")
		w.Header().Set("Content-Type", "text/plain")
	}
	mux := http.NewServeMux()
	plain := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			originHeaders(w)
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	mux.HandleFunc("/ok", plain(200, "origin-ok-body\n"))
	mux.HandleFunc("/404", plain(404, "origin-404-body\n"))
	mux.HandleFunc("/404empty", plain(404, ""))
	mux.HandleFunc("/500", plain(500, "origin-500-body\n"))
	mux.HandleFunc("/410", plain(410, "origin-410-body-passthrough\n"))
	mux.HandleFunc("/404chunked", func(w http.ResponseWriter, r *http.Request) {
		originHeaders(w)
		w.WriteHeader(404)
		_, _ = io.WriteString(w, "origin-404-chunk-1\n")
		w.(http.Flusher).Flush()
		time.Sleep(50 * time.Millisecond)
		_, _ = io.WriteString(w, "origin-404-chunk-2\n")
	})
	mux.HandleFunc("/404gzip", func(w http.ResponseWriter, r *http.Request) {
		var compressed bytes.Buffer
		zw := gzip.NewWriter(&compressed)
		_, _ = zw.Write([]byte(strings.Repeat("origin-404-gzip-body\n", 20)))
		_ = zw.Close()
		originHeaders(w)
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		w.Header().Set("Content-Length", fmt.Sprint(compressed.Len()))
		w.WriteHeader(404)
		_, _ = w.Write(compressed.Bytes())
	})
	raw := func(head string, first string, pause time.Duration) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			conn, buffered, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = buffered.WriteString(head)
			if r.Method != http.MethodHead {
				_, _ = buffered.WriteString(first)
			}
			_ = buffered.Flush()
			time.Sleep(pause)
		}
	}
	mux.HandleFunc("/404partial", raw("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nX-Origin-Header: yes\r\nContent-Length: 1000\r\n\r\n", "0123456789", 100*time.Millisecond))
	mux.HandleFunc("/200partial", raw("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1000\r\n\r\n", "0123456789", 100*time.Millisecond))
	mux.HandleFunc("/404chunkcut", raw("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n", "a\r\n0123456789\r\n", 100*time.Millisecond))
	return http.ListenAndServe(*listen, mux)
}

// ---------------------------------------------------------------- client

type result struct {
	Seq        int               `json:"seq"`
	OK         bool              `json:"ok"`
	Err        string            `json:"err,omitempty"`
	Proto      string            `json:"proto,omitempty"`
	Status     int               `json:"status,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	BodyLen    int               `json:"body_len"`
	BodySHA    string            `json:"body_sha,omitempty"`
	Body       string            `json:"body,omitempty"`
	BodyErr    string            `json:"body_err,omitempty"`
	TLSVersion string            `json:"tls,omitempty"`
	ALPN       string            `json:"alpn,omitempty"`
	PeerCN     string            `json:"peer_cn,omitempty"`
	Resumed    bool              `json:"resumed,omitempty"`
	ElapsedMS  float64           `json:"ms"`
	Raw        string            `json:"raw,omitempty"`
	Framing    string            `json:"framing,omitempty"`
}

func runGet(args []string) error {
	flags := flag.NewFlagSet("get", flag.ContinueOnError)
	target := flags.String("url", "", "URL")
	proto := flags.String("proto", "h1", "h1 | h2 | h3")
	sni := flags.String("sni", "", "TLS server name (empty: none for IP URLs)")
	host := flags.String("host", "", "Host header (default: -sni, else URL host)")
	caFile := flags.String("ca", "", "verify the server against this CA (default: no verification)")
	method := flags.String("method", "GET", "method")
	body := flags.String("body", "", "request body (form-encoded)")
	tlsMin := flags.String("tlsmin", "", "1.2 | 1.3")
	tlsMax := flags.String("tlsmax", "", "1.2 | 1.3")
	count := flags.Int("n", 1, "requests on the same client (connection reuse)")
	sleep := flags.Duration("sleep", 0, "pause between requests")
	newConn := flags.Bool("newconn", false, "new client (new connection) per request; keeps the TLS session cache")
	rawMode := flags.Bool("raw", false, "h1 only: raw socket, report the exact framing")
	summary := flags.Bool("summary", false, "print one aggregate line instead of one line per request")
	bodyMax := flags.Int("bodymax", 160, "body bytes to print")
	var headers multiFlag
	flags.Var(&headers, "H", "request header k:v (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	parsed, err := url.Parse(*target)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{ServerName: *sni, ClientSessionCache: tls.NewLRUClientSessionCache(16)}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tlsConfig.RootCAs = pool
	} else {
		tlsConfig.InsecureSkipVerify = true // test edge certificates; peer CN is reported instead
	}
	versions := map[string]uint16{"1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13}
	tlsConfig.MinVersion = versions[*tlsMin]
	tlsConfig.MaxVersion = versions[*tlsMax]
	hostHeader := *host
	if hostHeader == "" {
		hostHeader = *sni
	}
	var client *http.Client
	var closeClient func()
	newClient := func() {
		var transport http.RoundTripper
		closeClient = func() {}
		switch *proto {
		case "h1":
			t := &http.Transport{TLSClientConfig: tlsConfig, DisableCompression: true,
				TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
			transport, closeClient = t, t.CloseIdleConnections
		case "h2":
			t := &http2.Transport{TLSClientConfig: tlsConfig, DisableCompression: true}
			transport, closeClient = t, t.CloseIdleConnections
		case "h3":
			t := &http3.Transport{TLSClientConfig: tlsConfig, DisableCompression: true}
			transport, closeClient = t, func() { _ = t.Close() }
		default:
			fail(fmt.Errorf("unknown -proto %q", *proto))
		}
		client = &http.Client{Transport: transport, Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	newClient()
	var results []result
	for seq := 1; seq <= *count; seq++ {
		if seq > 1 && *newConn {
			closeClient()
			newClient()
		}
		var res result
		if *rawMode {
			res = rawRequest(parsed, *method, hostHeader, *sni, headers, *body)
		} else {
			res = doRequest(client, parsed, *method, hostHeader, headers, *bodyMax, *body)
		}
		res.Seq = seq
		if *summary {
			res.Headers, res.Body, res.Raw = nil, "", ""
			results = append(results, res)
		} else {
			line, _ := json.Marshal(res)
			fmt.Println(string(line))
		}
		if *sleep > 0 {
			time.Sleep(*sleep)
		}
	}
	closeClient()
	if *summary {
		printSummary(results)
	}
	return nil
}

func doRequest(client *http.Client, target *url.URL, method, host string, headers []string, bodyMax int, payload string) result {
	var reader io.Reader
	if payload != "" {
		reader = strings.NewReader(payload)
	}
	request, err := http.NewRequest(method, target.String(), reader)
	if err != nil {
		return result{Err: err.Error()}
	}
	if payload != "" {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if host != "" {
		request.Host = host
	}
	for _, header := range headers {
		name, value, _ := strings.Cut(header, ":")
		request.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	started := time.Now()
	response, err := client.Do(request)
	res := result{}
	if err != nil {
		res.Err = err.Error()
		res.ElapsedMS = msSince(started)
		return res
	}
	defer response.Body.Close()
	body, bodyErr := io.ReadAll(response.Body)
	res.ElapsedMS = msSince(started)
	res.OK = bodyErr == nil
	res.Proto = response.Proto
	res.Status = response.StatusCode
	res.Headers = flatHeaders(response.Header)
	if response.ContentLength >= 0 && method != http.MethodHead {
		res.Headers["(content-length)"] = fmt.Sprint(response.ContentLength)
	}
	if len(response.TransferEncoding) > 0 {
		res.Headers["(transfer-encoding)"] = strings.Join(response.TransferEncoding, ",")
	}
	if bodyErr != nil {
		res.BodyErr = bodyErr.Error()
	}
	res.BodyLen = len(body)
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		res.BodySHA = hex.EncodeToString(sum[:6])
	}
	res.Body = printable(body, bodyMax)
	if state := response.TLS; state != nil {
		res.TLSVersion = tls.VersionName(state.Version)
		res.ALPN = state.NegotiatedProtocol
		res.Resumed = state.DidResume
		if len(state.PeerCertificates) > 0 {
			res.PeerCN = state.PeerCertificates[0].Subject.CommonName
		}
	}
	return res
}

// rawRequest sends one HTTP/1.1 request on a fresh socket and reports what
// came back byte for byte, so chunked framing and premature closes are visible.
func rawRequest(target *url.URL, method, host, sni string, headers []string, payload string) result {
	started := time.Now()
	address := target.Host
	var conn net.Conn
	var err error
	if target.Scheme == "https" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address,
			&tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) // test edge certificate
	} else {
		conn, err = net.DialTimeout("tcp", address, 5*time.Second)
	}
	if err != nil {
		return result{Err: err.Error(), ElapsedMS: msSince(started)}
	}
	defer conn.Close()
	if host == "" {
		host = target.Host
	}
	var request strings.Builder
	fmt.Fprintf(&request, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, target.RequestURI(), host)
	for _, header := range headers {
		name, value, _ := strings.Cut(header, ":")
		fmt.Fprintf(&request, "%s: %s\r\n", strings.TrimSpace(name), strings.TrimSpace(value))
	}
	if payload != "" {
		fmt.Fprintf(&request, "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n", len(payload))
	}
	request.WriteString("Connection: close\r\n\r\n")
	request.WriteString(payload)
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.WriteString(conn, request.String()); err != nil {
		return result{Err: err.Error()}
	}
	all, readErr := io.ReadAll(conn)
	res := result{ElapsedMS: msSince(started), Raw: printable(all, 600)}
	if readErr != nil {
		res.Err = readErr.Error()
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(all)), &http.Request{Method: method})
	if err != nil {
		res.Framing = "unparsable: " + err.Error()
		return res
	}
	body, bodyErr := io.ReadAll(response.Body)
	res.Status = response.StatusCode
	res.Proto = response.Proto
	res.Headers = flatHeaders(response.Header)
	res.BodyLen = len(body)
	res.Body = printable(body, 160)
	switch {
	case bodyErr != nil:
		res.Framing = "truncated: " + bodyErr.Error()
	case len(response.TransferEncoding) > 0:
		res.Framing = "complete chunked"
	case response.ContentLength >= 0:
		res.Framing = fmt.Sprintf("complete length=%d", response.ContentLength)
	default:
		res.Framing = "complete close-delimited"
	}
	res.OK = bodyErr == nil
	return res
}

func flatHeaders(header http.Header) map[string]string {
	out := map[string]string{}
	for name, values := range header {
		if name == "Date" {
			continue
		}
		out[name] = strings.Join(values, ", ")
	}
	return out
}

func printable(data []byte, max int) string {
	if len(data) > max {
		data = data[:max]
	}
	return strings.ToValidUTF8(string(data), "?")
}

func msSince(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000
}

func printSummary(results []result) {
	latencies := make([]float64, 0, len(results))
	failed := 0
	firstErr := ""
	for _, res := range results {
		if !res.OK || res.Status != 200 {
			failed++
			if firstErr == "" {
				firstErr = fmt.Sprintf("status=%d err=%s", res.Status, res.Err)
			}
		}
		latencies = append(latencies, res.ElapsedMS)
	}
	sort.Float64s(latencies)
	pick := func(q float64) float64 {
		if len(latencies) == 0 {
			return 0
		}
		return latencies[min(len(latencies)-1, int(q*float64(len(latencies))))]
	}
	line, _ := json.Marshal(map[string]any{"count": len(results), "failed": failed, "first_error": firstErr,
		"p50_ms": pick(0.5), "p99_ms": pick(0.99), "max_ms": pick(1)})
	fmt.Println(string(line))
}
