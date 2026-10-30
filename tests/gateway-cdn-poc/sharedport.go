package main

// One gateway port (ADR 0013 §4.2, e.g. 19444 or a CDN-proxiable 8443) that
// serves both node paths after a single TLS handshake:
//
//   ALPN h2 + verified node client certificate -> direct gRPC mTLS (the
//       unchanged agent.v1 server; identity = verified leaf certificate)
//   anything else (http/1.1 or no ALPN)         -> HTTP: /agent/v1/tunnel
//       WebSocket, signed upgrade token, inner unchanged mTLS gRPC
//
// The client certificate is optional at the outer handshake
// (VerifyClientCertIfGiven), so a CDN re-encrypting to this port without a
// certificate reaches the tunnel, and a node dialling directly with its
// certificate reaches gRPC. h2 without a certificate is closed: gRPC needs
// the certificate, and the tunnel upgrade is HTTP/1.1.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// preTLS hands an already-terminated *tls.Conn to grpc.Server and reports
// its verified state, so authenticatedNode reads VerifiedChains as usual.
type preTLS struct{}

func (preTLS) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("preTLS is server side only")
}

func (preTLS) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, nil, errors.New("shared port connection is not TLS")
	}
	return conn, credentials.TLSInfo{State: tlsConn.ConnectionState(),
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}}, nil
}

func (preTLS) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls", SecurityVersion: "1.3"}
}
func (preTLS) Clone() credentials.TransportCredentials { return preTLS{} }
func (preTLS) OverrideServerName(string) error         { return nil }

func serveSharedPort(name, addr string, certificate tls.Certificate, nodeCAs *x509.CertPool,
	direct *grpc.Server, handler http.Handler, errs chan<- error) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	grpcConns, httpConns := newChanListener(listener.Addr()), newChanListener(listener.Addr())
	go func() { errs <- direct.Serve(grpcConns) }()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { errs <- server.Serve(httpConns) }()
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate},
		ClientCAs: nodeCAs, ClientAuth: tls.VerifyClientCertIfGiven, NextProtos: []string{"h2", "http/1.1"}}
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				errs <- err
				return
			}
			go func() {
				conn := tls.Server(raw, config)
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if err := conn.Handshake(); err != nil {
					_ = conn.Close()
					return
				}
				_ = conn.SetDeadline(time.Time{})
				state := conn.ConnectionState()
				target := httpConns
				switch {
				case state.NegotiatedProtocol == "h2" && len(state.VerifiedChains) > 0:
					target = grpcConns
				case state.NegotiatedProtocol == "h2":
					log.Printf("[%s] reject shared port: h2 without node certificate from %s", name, raw.RemoteAddr())
					_ = conn.Close()
					return
				}
				select {
				case target.conns <- conn:
				case <-target.done:
					_ = conn.Close()
				}
			}()
		}
	}()
	return nil
}
