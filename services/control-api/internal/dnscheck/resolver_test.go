package dnscheck

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetworkResolverUsesRealDNSPackets(t *testing.T) {
	server := startUDPTestServer(t, func(query []byte) []byte {
		return wireResponse(query, 0x0400, wireAnswer(RecordA, 60, []byte{192, 0, 2, 10}))
	})
	endpoint := udpEndpoint(t, server.LocalAddr())
	policy, err := NewEndpointPolicy(endpoint)
	if err != nil {
		t.Fatalf("NewEndpointPolicy() error = %v", err)
	}
	resolver, err := NewNetworkResolver(policy, NetworkResolverOptions{MaximumResponseBytes: 512})
	if err != nil {
		t.Fatalf("NewNetworkResolver() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := resolver.Resolve(ctx, endpoint, DNSQuery{Name: "www.example.test", Type: RecordA})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if !response.Authoritative || len(response.Answers) != 1 || response.Answers[0].Value != "192.0.2.10" {
		t.Fatalf("Resolve() = %#v", response)
	}
}

func TestNetworkResolverFallsBackToTCPOnTruncation(t *testing.T) {
	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	t.Cleanup(func() { _ = tcpListener.Close() })
	tcpAddress := tcpListener.Addr().(*net.TCPAddr)
	udpConnection, err := net.ListenUDP("udp", &net.UDPAddr{IP: tcpAddress.IP, Port: tcpAddress.Port})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	t.Cleanup(func() { _ = udpConnection.Close() })
	go func() {
		buffer := make([]byte, 2048)
		read, peer, readErr := udpConnection.ReadFromUDP(buffer)
		if readErr == nil {
			_, _ = udpConnection.WriteToUDP(wireResponse(buffer[:read], 0x0200), peer)
		}
	}()
	go func() {
		connection, acceptErr := tcpListener.AcceptTCP()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		lengthPrefix := make([]byte, 2)
		if _, readErr := io.ReadFull(connection, lengthPrefix); readErr != nil {
			return
		}
		query := make([]byte, int(binary.BigEndian.Uint16(lengthPrefix)))
		if _, readErr := io.ReadFull(connection, query); readErr != nil {
			return
		}
		response := wireResponse(query, 0x0400, wireAnswer(RecordA, 60, []byte{192, 0, 2, 10}))
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(response)))
		_, _ = connection.Write(append(framed, response...))
	}()

	endpoint, err := NewResolverEndpoint("udp", tcpAddress.IP.String(), uint16(tcpAddress.Port))
	if err != nil {
		t.Fatalf("NewResolverEndpoint() error = %v", err)
	}
	policy, _ := NewEndpointPolicy(endpoint)
	resolver, _ := NewNetworkResolver(policy, NetworkResolverOptions{MaximumResponseBytes: 512})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := resolver.Resolve(ctx, endpoint, DNSQuery{Name: "www.example.test", Type: RecordA})
	if err != nil || response.Truncated || len(response.Answers) != 1 || response.Answers[0].Value != "192.0.2.10" {
		t.Fatalf("Resolve() = (%#v, %v)", response, err)
	}
}

func TestNetworkResolverRejectsTruncatedFinalResponse(t *testing.T) {
	startTCP := func(t *testing.T) (*net.TCPListener, *atomic.Int32, <-chan error) {
		t.Helper()
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("ListenTCP() error = %v", err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		requests := &atomic.Int32{}
		done := make(chan error, 1)
		go func() {
			for {
				connection, acceptErr := listener.AcceptTCP()
				if acceptErr != nil {
					if errors.Is(acceptErr, net.ErrClosed) {
						done <- nil
					} else {
						done <- acceptErr
					}
					return
				}
				requests.Add(1)
				serveErr := func() error {
					defer connection.Close()
					lengthPrefix := make([]byte, 2)
					if _, err := io.ReadFull(connection, lengthPrefix); err != nil {
						return err
					}
					query := make([]byte, int(binary.BigEndian.Uint16(lengthPrefix)))
					if _, err := io.ReadFull(connection, query); err != nil {
						return err
					}
					response := wireResponse(query, 0x0600, wireAnswer(RecordA, 60, []byte{192, 0, 2, 10}))
					framed := binary.BigEndian.AppendUint16(nil, uint16(len(response)))
					return writeAll(connection, append(framed, response...))
				}()
				if serveErr != nil {
					done <- serveErr
					return
				}
			}
		}()
		return listener, requests, done
	}
	waitTCP := func(t *testing.T, listener *net.TCPListener, done <-chan error) {
		t.Helper()
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("TCP server error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("TCP server did not stop")
		}
	}

	t.Run("direct TCP", func(t *testing.T) {
		listener, tcpRequests, tcpDone := startTCP(t)
		address := listener.Addr().(*net.TCPAddr)
		endpoint, err := NewResolverEndpoint("tcp", address.IP.String(), uint16(address.Port))
		if err != nil {
			t.Fatal(err)
		}
		policy, _ := NewEndpointPolicy(endpoint)
		resolver, _ := NewNetworkResolver(policy, NetworkResolverOptions{MaximumResponseBytes: 512})
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		response, err := resolver.Resolve(ctx, endpoint, DNSQuery{Name: "www.example.test", Type: RecordA})
		waitTCP(t, listener, tcpDone)
		if !errors.Is(err, ErrMalformedResponse) || !reflect.DeepEqual(response, DNSResponse{}) || tcpRequests.Load() != 1 {
			t.Fatalf("Resolve()=(%#v,%v); TCP requests=%d", response, err, tcpRequests.Load())
		}
	})

	t.Run("UDP then TCP", func(t *testing.T) {
		listener, tcpRequests, tcpDone := startTCP(t)
		address := listener.Addr().(*net.TCPAddr)
		udpConnection, err := net.ListenUDP("udp", &net.UDPAddr{IP: address.IP, Port: address.Port})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = udpConnection.Close() })
		udpRequests := &atomic.Int32{}
		udpDone := make(chan error, 1)
		go func() {
			buffer := make([]byte, 2048)
			read, peer, readErr := udpConnection.ReadFromUDP(buffer)
			if readErr != nil {
				udpDone <- readErr
				return
			}
			udpRequests.Add(1)
			response := wireResponse(buffer[:read], 0x0600, wireAnswer(RecordA, 60, []byte{192, 0, 2, 9}))
			_, writeErr := udpConnection.WriteToUDP(response, peer)
			udpDone <- writeErr
		}()

		endpoint, err := NewResolverEndpoint("udp", address.IP.String(), uint16(address.Port))
		if err != nil {
			t.Fatal(err)
		}
		policy, _ := NewEndpointPolicy(endpoint)
		resolver, _ := NewNetworkResolver(policy, NetworkResolverOptions{MaximumResponseBytes: 512})
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		response, err := resolver.Resolve(ctx, endpoint, DNSQuery{Name: "www.example.test", Type: RecordA})
		waitTCP(t, listener, tcpDone)
		select {
		case serverErr := <-udpDone:
			if serverErr != nil {
				t.Fatalf("UDP server error = %v", serverErr)
			}
		case <-time.After(time.Second):
			t.Fatal("UDP server did not stop")
		}
		if !errors.Is(err, ErrMalformedResponse) || !reflect.DeepEqual(response, DNSResponse{}) ||
			udpRequests.Load() != 1 || tcpRequests.Load() != 1 {
			t.Fatalf("Resolve()=(%#v,%v); UDP/TCP requests=%d/%d",
				response, err, udpRequests.Load(), tcpRequests.Load())
		}
	})
}

func TestNetworkResolverRejectsEndpointBeforeDial(t *testing.T) {
	allowed := testEndpoint(t, "192.0.2.50", 53)
	policy, _ := NewEndpointPolicy(allowed)
	resolver, _ := NewNetworkResolver(policy, NetworkResolverOptions{})
	deniedPort := testEndpoint(t, "192.0.2.50", 54)
	deniedTransport, err := NewResolverEndpoint("tcp", "192.0.2.50", 53)
	if err != nil {
		t.Fatalf("NewResolverEndpoint() error = %v", err)
	}
	for _, endpoint := range []ResolverEndpoint{deniedPort, deniedTransport} {
		_, err := resolver.Resolve(context.Background(), endpoint, DNSQuery{Name: "www.example.test", Type: RecordA})
		if !errors.Is(err, ErrEndpointDenied) {
			t.Fatalf("Resolve(%s) error = %v", endpointKey(endpoint), err)
		}
	}
}

func TestNetworkResolverBoundsResponseAndTimeout(t *testing.T) {
	t.Run("oversized", func(t *testing.T) {
		server := startUDPTestServer(t, func(query []byte) []byte {
			response := wireResponse(query, 0x0400)
			return append(response, make([]byte, 512)...)
		})
		endpoint := udpEndpoint(t, server.LocalAddr())
		policy, _ := NewEndpointPolicy(endpoint)
		resolver, _ := NewNetworkResolver(policy, NetworkResolverOptions{MaximumResponseBytes: 512})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := resolver.Resolve(ctx, endpoint, DNSQuery{Name: "www.example.test", Type: RecordA})
		if !errors.Is(err, ErrResponseTooLarge) {
			t.Fatalf("Resolve() error = %v", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		server := startUDPTestServer(t, func([]byte) []byte { return nil })
		endpoint := udpEndpoint(t, server.LocalAddr())
		policy, _ := NewEndpointPolicy(endpoint)
		resolver, _ := NewNetworkResolver(policy, NetworkResolverOptions{})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := resolver.Resolve(ctx, endpoint, DNSQuery{Name: "www.example.test", Type: RecordA})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Resolve() error = %v", err)
		}
	})
}

func startUDPTestServer(t *testing.T, respond func([]byte) []byte) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			read, peer, err := connection.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			response := respond(append([]byte(nil), buffer[:read]...))
			if response != nil {
				_, _ = connection.WriteToUDP(response, peer)
			}
		}
	}()
	return connection
}

func udpEndpoint(t *testing.T, address net.Addr) ResolverEndpoint {
	t.Helper()
	udpAddress, ok := address.(*net.UDPAddr)
	if !ok {
		t.Fatalf("address = %T", address)
	}
	endpoint, err := NewResolverEndpoint("udp", udpAddress.IP.String(), uint16(udpAddress.Port))
	if err != nil {
		t.Fatalf("NewResolverEndpoint() error = %v", err)
	}
	return endpoint
}
