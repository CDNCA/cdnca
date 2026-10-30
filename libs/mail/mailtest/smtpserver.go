// Package mailtest is a minimal TLS SMTP server for tests of mail senders:
// implicit TLS or STARTTLS (STARTTLS can be withheld), PLAIN auth, captured
// messages and commands. It never relays anything.
package mailtest

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Options of a test server.
type Options struct {
	// Implicit serves TLS from the first byte; otherwise plaintext + STARTTLS.
	Implicit bool
	// NoSTARTTLS hides STARTTLS from EHLO (a server a client must refuse).
	NoSTARTTLS bool
	// Username/Password are the accepted PLAIN credentials ("" = no auth).
	Username, Password string
	// RejectRcpt answers RCPT TO with this reply (e.g. "550 no such user").
	RejectRcpt string
}

// Message is one received DATA payload.
type Message struct {
	From, To string
	Data     string
	TLS      bool
}

// Server is a running test server.
type Server struct {
	Host string
	Port int
	// RootCAs trusts the server certificate (ServerName "localhost"... use Host).
	RootCAs *x509.CertPool

	options  Options
	listener net.Listener
	tls      *tls.Config
	mu       sync.Mutex
	messages []Message
	commands []string
	wg       sync.WaitGroup
}

// Start runs a server on 127.0.0.1 until the test ends.
func Start(t testing.TB, options Options) *Server {
	t.Helper()
	certificate, pool := certificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().(*net.TCPAddr)
	server := &Server{Host: "127.0.0.1", Port: address.Port, RootCAs: pool, options: options, listener: listener,
		tls: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}}
	server.wg.Add(1)
	go server.serve()
	t.Cleanup(func() {
		_ = listener.Close()
		server.wg.Wait()
	})
	return server
}

// Messages returns the received messages.
func (server *Server) Messages() []Message {
	server.mu.Lock()
	defer server.mu.Unlock()
	return append([]Message(nil), server.messages...)
}

// Commands returns every command line received (AUTH arguments redacted).
func (server *Server) Commands() []string {
	server.mu.Lock()
	defer server.mu.Unlock()
	return append([]string(nil), server.commands...)
}

func (server *Server) serve() {
	defer server.wg.Done()
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			return
		}
		server.wg.Add(1)
		go func() {
			defer server.wg.Done()
			server.session(connection)
		}()
	}
}

func (server *Server) session(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	secure := false
	if server.options.Implicit {
		tlsConnection := tls.Server(connection, server.tls)
		if tlsConnection.Handshake() != nil {
			return
		}
		connection, secure = tlsConnection, true
	}
	reader, writer := bufio.NewReader(connection), bufio.NewWriter(connection)
	reply := func(line string) {
		_, _ = writer.WriteString(line + "\r\n")
		_ = writer.Flush()
	}
	reply("220 mailtest ESMTP")
	var from, to string
	authenticated := server.options.Username == ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		recorded := line
		if verb == "AUTH" {
			recorded = "AUTH <redacted>"
		}
		server.mu.Lock()
		server.commands = append(server.commands, recorded)
		server.mu.Unlock()
		switch verb {
		case "EHLO", "HELO":
			extensions := []string{"mailtest"}
			if !secure && !server.options.NoSTARTTLS {
				extensions = append(extensions, "STARTTLS")
			}
			extensions = append(extensions, "AUTH PLAIN")
			for index, extension := range extensions {
				separator := "-"
				if index == len(extensions)-1 {
					separator = " "
				}
				_, _ = writer.WriteString("250" + separator + extension + "\r\n")
			}
			_ = writer.Flush()
		case "STARTTLS":
			if secure || server.options.NoSTARTTLS {
				reply("502 not supported")
				continue
			}
			reply("220 go ahead")
			tlsConnection := tls.Server(connection, server.tls)
			if tlsConnection.Handshake() != nil {
				return
			}
			connection, secure = tlsConnection, true
			reader, writer = bufio.NewReader(connection), bufio.NewWriter(connection)
		case "AUTH":
			fields := strings.Fields(line)
			raw, _ := base64.StdEncoding.DecodeString(fields[len(fields)-1])
			parts := strings.Split(string(raw), "\x00")
			if !secure || len(parts) != 3 || parts[1] != server.options.Username || parts[2] != server.options.Password {
				reply("535 authentication failed")
				continue
			}
			authenticated = true
			reply("235 ok")
		case "MAIL":
			if !authenticated {
				reply("530 authentication required")
				continue
			}
			from = strings.Trim(strings.TrimPrefix(strings.SplitN(line, ":", 2)[1], " "), "<>")
			reply("250 ok")
		case "RCPT":
			if server.options.RejectRcpt != "" {
				reply(server.options.RejectRcpt)
				continue
			}
			to = strings.Trim(strings.TrimPrefix(strings.SplitN(line, ":", 2)[1], " "), "<>")
			reply("250 ok")
		case "DATA":
			reply("354 send")
			var data strings.Builder
			for {
				part, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if part == ".\r\n" {
					break
				}
				data.WriteString(strings.TrimPrefix(part, "."))
			}
			server.mu.Lock()
			server.messages = append(server.messages, Message{From: from, To: to, Data: data.String(), TLS: secure})
			server.mu.Unlock()
			reply("250 queued")
		case "NOOP", "RSET":
			reply("250 ok")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("500 unknown " + strconv.Quote(verb))
		}
	}
}

func certificate(t testing.TB) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mailtest"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}
