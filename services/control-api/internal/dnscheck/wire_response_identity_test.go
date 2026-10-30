package dnscheck

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetworkResolverFallsBackFromStructurallyTruncatedUDPResponse(t *testing.T) {
	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpListener.Close() })
	address := tcpListener.Addr().(*net.TCPAddr)
	udpConnection, err := net.ListenUDP("udp", &net.UDPAddr{IP: address.IP, Port: address.Port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpConnection.Close() })

	var udpRequests atomic.Int32
	var tcpRequests atomic.Int32
	go func() {
		buffer := make([]byte, 2048)
		read, peer, readErr := udpConnection.ReadFromUDP(buffer)
		if readErr != nil {
			return
		}
		udpRequests.Add(1)
		response := wireResponse(buffer[:read], 0x0200, wireAnswer(RecordA, 60, []byte{192, 0, 2, 9}))
		_, _ = udpConnection.WriteToUDP(response[:len(response)-1], peer)
	}()
	go func() {
		connection, acceptErr := tcpListener.AcceptTCP()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		tcpRequests.Add(1)
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
		_ = writeAll(connection, append(framed, response...))
	}()

	endpoint, err := NewResolverEndpoint("udp", address.IP.String(), uint16(address.Port))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewEndpointPolicy(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewNetworkResolver(policy, NetworkResolverOptions{MaximumResponseBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	response, err := resolver.Resolve(ctx, endpoint, DNSQuery{Name: "www.example.test", Type: RecordA})
	if err != nil || response.Truncated || len(response.Answers) != 1 || response.Answers[0].Value != "192.0.2.10" ||
		udpRequests.Load() != 1 || tcpRequests.Load() != 1 {
		t.Fatalf("Resolve()=(%#v,%v); UDP/TCP requests=%d/%d", response, err, udpRequests.Load(), tcpRequests.Load())
	}
}
