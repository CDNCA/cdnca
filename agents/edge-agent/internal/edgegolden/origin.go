package edgegolden

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// recorder keeps every request the mock origins received, in arrival order.
type recorder struct {
	mu       sync.Mutex
	requests []OriginRequest
}

func (recorder *recorder) add(request OriginRequest) {
	recorder.mu.Lock()
	recorder.requests = append(recorder.requests, request)
	recorder.mu.Unlock()
}

// drain returns and forgets what was received so far.
func (recorder *recorder) drain() []OriginRequest {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	requests := recorder.requests
	recorder.requests = nil
	if requests == nil {
		requests = []OriginRequest{}
	}
	return requests
}

type originServers struct {
	servers []*http.Server
	streams []io.Closer
}

func (servers *originServers) close() {
	for _, server := range servers.servers {
		_ = server.Close()
	}
	for _, stream := range servers.streams {
		_ = stream.Close()
	}
}

// streamOrigin is an L4 echo origin: "<name>:<first line>\n" on TCP,
// "<name>:<datagram>" on UDP. What it received is not recorded (the reply
// names it).
func streamOrigin(origin Origin, pki *PKI) (io.Closer, error) {
	if origin.Stream == "udp" {
		connection, err := net.ListenPacket("udp", origin.Address)
		if err != nil {
			return nil, err
		}
		go func() {
			buffer := make([]byte, 2048)
			for {
				n, peer, err := connection.ReadFrom(buffer)
				if err != nil {
					return
				}
				_, _ = connection.WriteTo([]byte(origin.Name+":"+string(buffer[:n])), peer)
			}
		}()
		return connection, nil
	}
	listener, err := net.Listen("tcp", origin.Address)
	if err != nil {
		return nil, err
	}
	if origin.TLS != nil {
		ca, err := pki.CA(origin.TLS.CA)
		if err == nil {
			var certificate tls.Certificate
			if certificate, err = ca.TLSCertificate(1000, origin.TLS.Names...); err == nil {
				listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}})
			}
		}
		if err != nil {
			_ = listener.Close()
			return nil, err
		}
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
				line, _ := bufio.NewReader(connection).ReadString('\n')
				fmt.Fprintf(connection, "%s:%s\n", origin.Name, strings.TrimSpace(line))
			}()
		}
	}()
	return listener, nil
}

func startOrigins(scenario *Scenario, pki *PKI, record *recorder) (*originServers, error) {
	servers := &originServers{}
	for _, origin := range scenario.Origins {
		if origin.Stream != "" {
			stream, err := streamOrigin(origin, pki)
			if err != nil {
				servers.close()
				return nil, fmt.Errorf("origin %s: %w", origin.Name, err)
			}
			servers.streams = append(servers.streams, stream)
			continue
		}
		listener, err := net.Listen("tcp", origin.Address)
		if err != nil {
			servers.close()
			return nil, fmt.Errorf("origin %s: %w", origin.Name, err)
		}
		if origin.TLS != nil {
			ca, err := pki.CA(origin.TLS.CA)
			if err != nil {
				servers.close()
				return nil, err
			}
			certificate, err := ca.TLSCertificate(1000, origin.TLS.Names...)
			if err != nil {
				servers.close()
				return nil, err
			}
			listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}})
		}
		server := &http.Server{Handler: originHandler(origin, scenario.Mask, record), ReadHeaderTimeout: 10 * time.Second}
		servers.servers = append(servers.servers, server)
		go func() { _ = server.Serve(listener) }()
	}
	return servers, nil
}

var upgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

func originHandler(origin Origin, mask Mask, record *recorder) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(request.Body, 16<<20))
		peer, _, _ := net.SplitHostPort(request.RemoteAddr)
		received := OriginRequest{Origin: origin.Name, Method: request.Method, URI: request.RequestURI, Host: request.Host,
			Proto: request.Proto, Headers: headerMap(mask, mask.OriginHeaders, request.Header), Body: newBody(mask, body), Peer: peer}
		if request.TLS != nil {
			received.SNI = request.TLS.ServerName
		}
		// net/http moves these out of Header.
		if len(request.TransferEncoding) != 0 {
			received.Headers["transfer-encoding"] = strings.Join(request.TransferEncoding, ",")
		}
		record.add(received)
		if origin.WebSocket && strings.EqualFold(request.Header.Get("Upgrade"), "websocket") {
			connection, err := upgrader.Upgrade(writer, request, nil)
			if err != nil {
				return
			}
			defer connection.Close()
			_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
			kind, message, err := connection.ReadMessage()
			if err == nil {
				_ = connection.WriteMessage(kind, append([]byte("echo:"), message...))
			}
			return
		}
		echo := fmt.Sprintf("%s %s %s", origin.Name, request.Host, request.RequestURI)
		route := OriginRoute{Status: http.StatusOK, Body: echo}
		for _, candidate := range origin.Routes {
			if candidate.Path != "" && candidate.Path == request.URL.Path ||
				candidate.Prefix != "" && strings.HasPrefix(request.URL.Path, candidate.Prefix) {
				route = candidate
				if route.Status == 0 {
					route.Status = http.StatusOK
				}
				route.Body = strings.ReplaceAll(route.Body, "${request}", echo)
				break
			}
		}
		if route.DelayMS > 0 {
			select {
			case <-time.After(time.Duration(route.DelayMS) * time.Millisecond):
			case <-request.Context().Done():
				return
			}
		}
		payload := []byte(route.Body)
		for _, name := range sortedKeys(route.Headers) {
			writer.Header().Set(name, route.Headers[name])
		}
		if route.Gzip {
			var compressed bytes.Buffer
			gz, _ := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
			_, _ = gz.Write(payload)
			_ = gz.Close()
			payload = compressed.Bytes()
			writer.Header().Set("Content-Encoding", "gzip")
		}
		if route.Ranges {
			http.ServeContent(writer, request, "", time.Time{}, bytes.NewReader(payload))
			return
		}
		if route.Truncate > 0 {
			truncate(writer, route, payload)
			return
		}
		writer.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		writer.WriteHeader(route.Status)
		if request.Method != http.MethodHead {
			_, _ = writer.Write(payload)
		}
	})
}

// truncate announces more bytes than it sends, then closes the connection.
func truncate(writer http.ResponseWriter, route OriginRoute, payload []byte) {
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		return
	}
	connection, buffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer connection.Close()
	fmt.Fprintf(buffer, "HTTP/1.1 %d %s\r\n", route.Status, http.StatusText(route.Status))
	header := http.Header{}
	for name, value := range route.Headers {
		header.Set(name, value)
	}
	header.Set("Content-Length", strconv.Itoa(len(payload)+route.Truncate))
	_ = header.Write(buffer)
	buffer.WriteString("\r\n")
	_, _ = buffer.Write(payload)
	_ = buffer.Flush()
}
