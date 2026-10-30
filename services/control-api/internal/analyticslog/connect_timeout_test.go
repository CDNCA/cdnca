package analyticslog

import (
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRuntimeHTTPClientUsesConfiguredConnectTimeout(t *testing.T) {
	const (
		connectTimeout = 100 * time.Millisecond
		queryTimeout   = 5 * time.Second
	)
	client := newRuntimeHTTPClient(connectTimeout, queryTimeout, nil)
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil || transport.TLSHandshakeTimeout != connectTimeout ||
		transport.ResponseHeaderTimeout != queryTimeout {
		t.Fatalf("analytics logs transport = %#v", client.Transport)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	accepted := make(chan struct{})
	t.Cleanup(func() {
		close(release)
		_ = listener.Close()
	})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		close(accepted)
		defer connection.Close()
		<-release
	}()

	started := time.Now()
	_, err = client.Get("https://" + listener.Addr().String())
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("stalled TLS handshake unexpectedly succeeded")
	}
	select {
	case <-accepted:
	default:
		t.Fatal("transport did not establish the TCP connection")
	}
	if elapsed < connectTimeout/2 || elapsed >= time.Second {
		t.Fatalf("stalled transport elapsed = %s, want configured %s deadline", elapsed, connectTimeout)
	}
}
