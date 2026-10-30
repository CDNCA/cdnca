package controlgrpc

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSourceFilterAllowsOnlyBoundGatewaysAndLoopback(t *testing.T) {
	filter := &sourceFilter{}
	if filter.allows(&net.TCPAddr{IP: net.ParseIP("198.51.100.1")}) {
		t.Fatal("empty filter allowed a remote address")
	}
	if !filter.allows(&net.TCPAddr{IP: net.ParseIP("127.0.0.1")}) || !filter.allows(&net.TCPAddr{IP: net.IPv6loopback}) {
		t.Fatal("loopback refused")
	}
	filter.set([]net.IP{net.ParseIP("198.51.100.1"), net.ParseIP("2001:db8::7")})
	for addr, want := range map[string]bool{"198.51.100.1": true, "::ffff:198.51.100.1": true, "2001:db8::7": true, "198.51.100.2": false} {
		if got := filter.allows(&net.TCPAddr{IP: net.ParseIP(addr)}); got != want {
			t.Errorf("%s = %v", addr, got)
		}
	}
	if filter.allows(&net.UnixAddr{Name: "x"}) {
		t.Fatal("non-TCP address allowed")
	}
}

func TestFilteredListenerClosesRefusedConnections(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	filter := &sourceFilter{}
	listener := &filteredListener{Listener: &rewriteListener{Listener: inner, remote: net.ParseIP("203.0.113.9")}, filter: filter}
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	refused, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = refused.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := refused.Read(make([]byte, 1)); err == nil {
		t.Fatal("refused connection stayed open")
	}
	select {
	case <-accepted:
		t.Fatal("refused connection was accepted")
	default:
	}
	_ = listener.Close()
}

// rewriteListener reports every connection as coming from remote.
type rewriteListener struct {
	net.Listener
	remote net.IP
}

type rewrittenConn struct {
	net.Conn
	remote net.Addr
}

func (c rewrittenConn) RemoteAddr() net.Addr { return c.remote }

func (l *rewriteListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return rewrittenConn{Conn: conn, remote: &net.TCPAddr{IP: l.remote, Port: 1}}, nil
}

func TestAttachRemoteValidatesAndLoadsTheAllowList(t *testing.T) {
	server := &Server{}
	for _, address := range []string{"", "gateway.example.com:9446", "0.0.0.0:0"} {
		if err := server.AttachRemote(context.Background(), RemoteConfig{ListenAddress: address,
			AllowedSources: func(context.Context) ([]net.IP, error) { return nil, nil }}); err == nil {
			t.Errorf("%q accepted", address)
		}
	}
	if err := server.AttachRemote(context.Background(), RemoteConfig{ListenAddress: "127.0.0.1:9446"}); err == nil {
		t.Error("missing allow list accepted")
	}
}
