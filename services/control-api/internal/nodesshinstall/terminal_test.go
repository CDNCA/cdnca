package nodesshinstall

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// testSSHD is an in-process sshd: password "test-password" for root, a pty
// request is recorded and the "shell" echoes its input back upper-cased.
type testSSHD struct {
	address     string
	fingerprint string
	mu          sync.Mutex
	ptyTerm     string
	ptyCols     uint32
	resized     []uint32
}

func startTestSSHD(t *testing.T) *testSSHD {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if meta.User() == "root" && string(password) == "test-password" {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server := &testSSHD{address: listener.Addr().String(), fingerprint: HostKeySHA256(signer.PublicKey())}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go server.serve(connection, config)
		}
	}()
	return server
}

func (server *testSSHD) serve(connection net.Conn, config *ssh.ServerConfig) {
	_, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)
	for incoming := range channels {
		channel, channelRequests, err := incoming.Accept()
		if err != nil {
			continue
		}
		go func() {
			for request := range channelRequests {
				switch request.Type {
				case "pty-req":
					length := binary.BigEndian.Uint32(request.Payload)
					server.mu.Lock()
					server.ptyTerm = string(request.Payload[4 : 4+length])
					server.ptyCols = binary.BigEndian.Uint32(request.Payload[4+length:])
					server.mu.Unlock()
					_ = request.Reply(true, nil)
				case "window-change":
					server.mu.Lock()
					server.resized = append(server.resized, binary.BigEndian.Uint32(request.Payload))
					server.mu.Unlock()
				case "shell":
					_ = request.Reply(true, nil)
					go func() {
						buffer := make([]byte, 1024)
						for {
							count, err := channel.Read(buffer)
							if err != nil {
								return
							}
							text := strings.ToUpper(string(buffer[:count]))
							if strings.Contains(text, "EXIT") {
								_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
								_ = channel.Close()
								return
							}
							_, _ = channel.Write([]byte(text))
						}
					}()
				default:
					_ = request.Reply(false, nil)
				}
			}
		}()
	}
}

func splitHostPort(t *testing.T, address string) (string, int) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	var number int
	for _, digit := range port {
		number = number*10 + int(digit-'0')
	}
	return host, number
}

func allowLoopback(netip.Addr) bool { return false }

type syncBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func TestOpenShellUsesPinnedHostKeyAndPty(t *testing.T) {
	server := startTestSSHD(t)
	host, port := splitHostPort(t, server.address)
	dialer := NewDialer(allowLoopback)
	ctx := context.Background()
	login := Credential{Username: "root", Password: "test-password"}

	if _, err := dialer.OpenShell(ctx, host, port, login, "SHA256:"+strings.Repeat("A", 43), 80, 24, io.Discard); !errors.Is(err, errHostKeyMismatch) {
		t.Fatalf("wrong pinned key: %v", err)
	}
	if _, err := dialer.OpenShell(ctx, host, port, Credential{Username: "root", Password: "wrong"}, server.fingerprint, 80, 24,
		io.Discard); !isAuthFailure(err) {
		t.Fatalf("wrong password: %v", err)
	}
	var output syncBuffer
	shell, err := dialer.OpenShell(ctx, host, port, login, server.fingerprint, 120, 32, &output)
	if err != nil {
		t.Fatal(err)
	}
	defer shell.Close()
	if _, err := shell.Stdin.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := shell.Resize(100, 40); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(output.String(), "HELLO") {
		if time.Now().After(deadline) {
			t.Fatalf("output = %q", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	server.mu.Lock()
	term, cols := server.ptyTerm, server.ptyCols
	server.mu.Unlock()
	if term != "xterm-256color" || cols != 120 {
		t.Fatalf("pty = %q %d", term, cols)
	}
	_, _ = shell.Stdin.Write([]byte("exit"))
	done := make(chan error, 1)
	go func() { done <- shell.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shell did not end")
	}
}

func terminalTestHandler(t *testing.T) *TerminalHandler {
	t.Helper()
	sessions := map[string]identity.AuthenticatedSession{
		"admin":   {SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{"platform.admin"}}},
		"manager": {SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{PermissionManage, "nodes.read"}}},
		"tenant":  {SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", Permissions: []string{"platform.admin"}}},
	}
	handler, err := NewTerminalHandler(&Service{}, func(_ context.Context, raw string) (identity.AuthenticatedSession, error) {
		session, ok := sessions[raw]
		if !ok {
			return identity.AuthenticatedSession{}, errors.New("unknown")
		}
		return session, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

// nodes.ssh is platform administrators only: nodes.manage is not enough.
func TestTerminalRoutesRequirePlatformAdmin(t *testing.T) {
	handler := terminalTestHandler(t)
	node := uuid.NewString()
	for token, want := range map[string]int{"": http.StatusUnauthorized, "bogus": http.StatusUnauthorized,
		"manager": http.StatusForbidden, "tenant": http.StatusForbidden} {
		for _, route := range []struct{ method, path, body string }{
			{http.MethodGet, "/v1/nodes/" + node + "/ssh-endpoint", ""},
			{http.MethodPost, "/v1/nodes/" + node + "/ssh-host-key", `{"port":22}`},
			{http.MethodDelete, "/v1/nodes/" + node + "/ssh-credential", ""},
		} {
			request := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body))
			if token != "" {
				request.Header.Set("Authorization", "Bearer "+token)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != want || response.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("%s %s token %q: %d, want %d", route.method, route.path, token, response.Code, want)
			}
		}
	}
}

func dialTerminal(t *testing.T, server *httptest.Server, origin string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/nodes/" + uuid.NewString() + "/ssh-terminal"
	header := http.Header{}
	if origin != "" {
		header.Set("Origin", origin)
	}
	return websocket.DefaultDialer.Dial(url, header)
}

func readControl(t *testing.T, conn *websocket.Conn) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	kind, payload, err := conn.ReadMessage()
	if err != nil || kind != websocket.TextMessage {
		t.Fatalf("read: %d %v", kind, err)
	}
	return string(payload)
}

func TestTerminalWebSocketHandshake(t *testing.T) {
	handler := terminalTestHandler(t)
	server := httptest.NewServer(handler)
	defer server.Close()

	// Cross-site pages cannot open a terminal.
	if _, response, err := dialTerminal(t, server, "https://evil.example"); err == nil || response == nil ||
		response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site origin: %v %v", response, err)
	}
	if _, response, err := dialTerminal(t, server, ""); err == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("no origin: %v", err)
	}
	origin := "http://" + strings.TrimPrefix(server.URL, "http://")

	// The first frame must be "open" with a token of a platform administrator.
	for frame, want := range map[string]string{
		`{"type":"resize","cols":1,"rows":1}`:      "open_required",
		`not json`:                                 "open_required",
		`{"type":"open","access_token":"manager"}`: "permission_denied",
		`{"type":"open","access_token":"tenant"}`:  "permission_denied",
		`{"type":"open","access_token":"bogus"}`:   "unauthorized",
		`{"type":"open"}`:                          "unauthorized",
	} {
		conn, _, err := dialTerminal(t, server, origin)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(frame)); err != nil {
			t.Fatal(err)
		}
		if got := readControl(t, conn); got != `{"code":"`+want+`","type":"error"}` {
			t.Errorf("frame %s: %s, want %s", frame, got, want)
		}
		_ = conn.Close()
	}

	// A binary first frame is refused too.
	conn, _, err := dialTerminal(t, server, origin)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.WriteMessage(websocket.BinaryMessage, []byte("ls\n"))
	if got := readControl(t, conn); !strings.Contains(got, "open_required") {
		t.Fatalf("binary first frame: %s", got)
	}
	_ = conn.Close()
}

func TestTerminalLoginValidation(t *testing.T) {
	service := &Service{}
	for name, request := range map[string]TerminalRequest{
		"no size":      {Port: 22, Credential: Credential{Username: "root", Password: "x"}, HostKeySHA256: "SHA256:" + strings.Repeat("A", 43)},
		"huge size":    {Port: 22, Cols: 5000, Rows: 10, Credential: Credential{Username: "root", Password: "x"}, HostKeySHA256: "SHA256:" + strings.Repeat("A", 43)},
		"bad port":     {Port: 70000, Cols: 80, Rows: 24, Credential: Credential{Username: "root", Password: "x"}, HostKeySHA256: "SHA256:" + strings.Repeat("A", 43)},
		"bad username": {Port: 22, Cols: 80, Rows: 24, Credential: Credential{Username: "root;id", Password: "x"}, HostKeySHA256: "SHA256:" + strings.Repeat("A", 43)},
		"no secret":    {Port: 22, Cols: 80, Rows: 24, Credential: Credential{Username: "root"}, HostKeySHA256: "SHA256:" + strings.Repeat("A", 43)},
	} {
		if _, _, _, err := service.terminalLogin(context.Background(), Actor{}, request); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a fingerprint is optional, but a malformed one is refused.
	if _, _, _, err := service.terminalLogin(context.Background(), Actor{}, TerminalRequest{Port: 22, Cols: 80, Rows: 24,
		Credential: Credential{Username: "root", Password: "x"}, HostKeySHA256: "SHA256:short"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad fingerprint: %v", err)
	}
	given := "SHA256:" + strings.Repeat("B", 43)
	if _, pinned, _, err := service.terminalLogin(context.Background(), Actor{}, TerminalRequest{Port: 22, Cols: 80, Rows: 24,
		Credential: Credential{Username: "root", Password: "x"}, HostKeySHA256: given}); err != nil || pinned != given {
		t.Fatalf("given fingerprint: %q %v", pinned, err)
	}
}

// Trust on first use: with no pinned key the shell is opened
// with the key presented, which is reported for pinning; a pinned key still
// refuses any other.
func TestOpenShellTrustsFirstUseAndReportsTheKey(t *testing.T) {
	server := startTestSSHD(t)
	host, port := splitHostPort(t, server.address)
	dialer := NewDialer(allowLoopback)
	login := Credential{Username: "root", Password: "test-password"}
	shell, err := dialer.OpenShell(context.Background(), host, port, login, "", 80, 24, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if shell.HostKeySHA256 != server.fingerprint {
		t.Fatalf("first use key = %q, want %q", shell.HostKeySHA256, server.fingerprint)
	}
	_ = shell.Close()
	shell, err = dialer.OpenShell(context.Background(), host, port, login, server.fingerprint, 80, 24, io.Discard)
	if err != nil || shell.HostKeySHA256 != server.fingerprint {
		t.Fatalf("pinned: %v", err)
	}
	_ = shell.Close()
	if _, err := dialer.OpenShell(context.Background(), host, port, login, "SHA256:"+strings.Repeat("C", 43), 80, 24,
		io.Discard); !errors.Is(err, errHostKeyMismatch) {
		t.Fatalf("changed key accepted: %v", err)
	}
	// Installs (Run) never trust on first use.
	if err := dialer.Run(context.Background(), host, port, login, "", "true", nil, func(string) {}); !errors.Is(err, errHostKeyMismatch) {
		t.Fatalf("install without a pinned key: %v", err)
	}
}
