package http3runtime

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func validPolicy(versionID string) Policy {
	return Policy{
		SchemaVersion: SchemaVersionV1,
		VersionID:     versionID,
		Protocols:     []string{"http1", "http2", "http3"},
		Runtime:       RuntimeRef{Family: RuntimeFamilyOpenResty, Version: RuntimeVersionOpenResty},
		Listener: Listener{
			Address: "0.0.0.0", Port: 18443, ServerName: "h3.test", AltSvcMaxAgeSeconds: 300,
		},
		TLS: TLSConfig{
			MinimumVersion: "TLSv1.3", CertificateFile: "/var/lib/cdnca-edge-http3/certs/server.crt",
			CertificateSHA256: strings.Repeat("a", 64), PrivateKeyFile: "/var/lib/cdnca-edge-http3/certs/server.key",
			PrivateKeySHA256: strings.Repeat("b", 64),
		},
		Limits: Limits{
			IdleTimeoutMS: 30_000, WorkerConnections: 128, ConnectionsPerClient: 8,
			ConcurrentStreams: 2, RequestHeaderBytes: 4_096, ActiveConnectionIDs: 4,
		},
	}
}

func TestCompileIsDeterministicAndBindsBothTransports(t *testing.T) {
	first, err := Compile(validPolicy("http3-v1"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(validPolicy("http3-v1"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || !reflect.DeepEqual(first, second) {
		t.Fatal("equivalent policy produced different output")
	}
	if first.Policy.TLS.CertificateFile != "/var/lib/cdnca-edge-http3/certs/server.crt" ||
		first.Policy.TLS.PrivateKeyFile != "/var/lib/cdnca-edge-http3/certs/server.key" ||
		!strings.Contains(string(first.CanonicalJSON), `"certificate_file":"/var/lib/cdnca-edge-http3/certs/server.crt"`) ||
		!strings.Contains(string(first.CanonicalJSON), `"private_key_file":"/var/lib/cdnca-edge-http3/certs/server.key"`) {
		t.Fatalf("source policy identity changed: digest=%s policy=%+v canonical=%s", first.Digest, first.Policy.TLS, first.CanonicalJSON)
	}
	text := string(first.NginxConfig)
	for _, expected := range []string{
		"schema=cdnca.edge.http3/v1 version=http3-v1 digest=" + first.Digest,
		"worker_shutdown_timeout 8s",
		"quic_bpf on",
		"listen 0.0.0.0:18443 ssl; # TCP HTTP/2 and HTTP/1.1 fallback",
		"listen 0.0.0.0:18443 quic reuseport; # UDP HTTP/3",
		"ssl_protocols TLSv1.3", "http2 on", "http3 on",
		"quic_retry on",
		"quic_host_key quic-host.key",
		"Alt-Svc 'h3=\":18443\"; ma=300'", "keepalive_timeout 30000ms",
		"worker_connections 128", "limit_conn http3_client 8",
		"http3_max_concurrent_streams 2", "client_header_buffer_size 4096",
		"large_client_header_buffers 1 4096", "quic_active_connection_id_limit 4",
		"ssl_certificate tls/server.crt",
		"ssl_certificate_key tls/server.key",
		"client_body_temp_path /var/lib/cdnca-edge-http3/run/nginx-temp/client-body",
		"proxy_temp_path /var/lib/cdnca-edge-http3/run/nginx-temp/proxy",
		"fastcgi_temp_path /var/lib/cdnca-edge-http3/run/nginx-temp/fastcgi",
		"uwsgi_temp_path /var/lib/cdnca-edge-http3/run/nginx-temp/uwsgi",
		"scgi_temp_path /var/lib/cdnca-edge-http3/run/nginx-temp/scgi",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("generated configuration missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, first.Policy.TLS.CertificateFile) || strings.Contains(text, first.Policy.TLS.PrivateKeyFile) {
		t.Fatalf("generated configuration references mutable TLS source paths:\n%s", text)
	}
}

// http3_stream_buffer_size 决定 nginx 每连接帧配额 (3+2)*size/2000；
// 跟随小请求头上限（如 4096 只有 10 帧）会触发 "quic flood detected"。
func TestCompileKeepsHTTP3StreamBufferIndependentOfHeaderLimit(t *testing.T) {
	for _, headerBytes := range []int{minHeaderBytes, 4_096, maxHeaderBytes} {
		policy := validPolicy("http3-v1")
		policy.Limits.RequestHeaderBytes = headerBytes
		compiled, err := Compile(policy)
		if err != nil {
			t.Fatal(err)
		}
		text := string(compiled.NginxConfig)
		if !strings.Contains(text, "    http3_stream_buffer_size 65536;\n") {
			t.Errorf("header=%d: http3_stream_buffer_size must stay 65536:\n%s", headerBytes, text)
		}
		if !strings.Contains(text, fmt.Sprintf("client_header_buffer_size %d;", headerBytes)) ||
			!strings.Contains(text, fmt.Sprintf("large_client_header_buffers 1 %d;", headerBytes)) {
			t.Errorf("header=%d: header limits must still follow request_header_bytes:\n%s", headerBytes, text)
		}
	}
}

func TestCompileRejectsUnsafeOrUnboundedPolicy(t *testing.T) {
	tests := map[string]func(*Policy){
		"unknown schema":             func(p *Policy) { p.SchemaVersion = "cdnca.edge.http3/v2" },
		"version injection":          func(p *Policy) { p.VersionID = "v1\nworker_processes 9" },
		"unsupported family":         func(p *Policy) { p.Runtime.Family = "nginx" },
		"unsupported runtime":        func(p *Policy) { p.Runtime.Version = "1.29.0" },
		"invalid address":            func(p *Policy) { p.Listener.Address = "0.0.0.0; deny all" },
		"mapped address":             func(p *Policy) { p.Listener.Address = "::ffff:127.0.0.1" },
		"multicast address":          func(p *Policy) { p.Listener.Address = "224.0.0.1" },
		"zero port":                  func(p *Policy) { p.Listener.Port = 0 },
		"server name injection":      func(p *Policy) { p.Listener.ServerName = "h3.test\rinclude" },
		"alt svc age high":           func(p *Policy) { p.Listener.AltSvcMaxAgeSeconds = maxAltSvcAgeSeconds + 1 },
		"weak tls":                   func(p *Policy) { p.TLS.MinimumVersion = "TLSv1.2" },
		"missing certificate":        func(p *Policy) { p.TLS.CertificateFile = "" },
		"relative certificate":       func(p *Policy) { p.TLS.CertificateFile = "server.crt" },
		"certificate injection":      func(p *Policy) { p.TLS.CertificateFile += ";include" },
		"missing certificate digest": func(p *Policy) { p.TLS.CertificateSHA256 = "" },
		"same certificate and key":   func(p *Policy) { p.TLS.PrivateKeyFile = p.TLS.CertificateFile },
		"idle unlimited":             func(p *Policy) { p.Limits.IdleTimeoutMS = 0 },
		"workers unlimited":          func(p *Policy) { p.Limits.WorkerConnections = 0 },
		"connections unlimited":      func(p *Policy) { p.Limits.ConnectionsPerClient = 0 },
		"streams unlimited":          func(p *Policy) { p.Limits.ConcurrentStreams = 0 },
		"headers unlimited":          func(p *Policy) { p.Limits.RequestHeaderBytes = 0 },
		"headers non power of two":   func(p *Policy) { p.Limits.RequestHeaderBytes = 3_000 },
		"migration ids low":          func(p *Policy) { p.Limits.ActiveConnectionIDs = 1 },
		"missing protocols":          func(p *Policy) { p.Protocols = nil },
		"missing HTTP1":              func(p *Policy) { p.Protocols = []string{"http2", "http3"} },
		"missing HTTP2":              func(p *Policy) { p.Protocols = []string{"http1", "http3"} },
		"protocol order":             func(p *Policy) { p.Protocols = []string{"http2", "http1", "http3"} },
		"unknown protocol":           func(p *Policy) { p.Protocols = []string{"http1", "http2", "spdy"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			policy := validPolicy("http3-v1")
			mutate(&policy)
			_, err := Compile(policy)
			if name == "unsupported family" || name == "unsupported runtime" {
				if !errors.Is(err, ErrUnsupported) {
					t.Fatalf("Compile() error = %v, want ErrUnsupported", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("Compile() error = %v, want ErrInvalidPolicy", err)
			}
		})
	}
}

func TestCompileHTTP3DisabledKeepsHTTP1AndHTTP2Only(t *testing.T) {
	policy := validPolicy("http3-off")
	policy.Protocols = []string{"http1", "http2"}
	compiled, err := Compile(policy)
	if err != nil {
		t.Fatal(err)
	}
	text := string(compiled.NginxConfig)
	for _, expected := range []string{
		"listen 0.0.0.0:18443 ssl; # TCP HTTP/2 and HTTP/1.1 fallback",
		"http2 on",
		"http3 off",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("disabled configuration missing %q:\n%s", expected, text)
		}
	}
	for _, forbidden := range []string{"quic_bpf on", "quic reuseport", "quic_retry on", "quic_host_key", "Alt-Svc", "http3_max_concurrent_streams"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("disabled configuration retained %q:\n%s", forbidden, text)
		}
	}
}

func TestCompileCanonicalizesAddressAndServerName(t *testing.T) {
	policy := validPolicy("http3-v1")
	policy.Listener.Address = "2001:0db8::1"
	policy.Listener.ServerName = "H3.TEST."
	compiled, err := Compile(policy)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Policy.Listener.Address != "2001:db8::1" || compiled.Policy.Listener.ServerName != "h3.test" ||
		!strings.Contains(string(compiled.NginxConfig), "listen [2001:db8::1]:18443 quic reuseport") {
		t.Fatalf("normalization failed: %+v\n%s", compiled.Policy.Listener, compiled.NginxConfig)
	}
}
