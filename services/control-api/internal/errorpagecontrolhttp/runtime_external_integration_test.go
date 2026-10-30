package errorpagecontrolhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpageobjectstore"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagescanner"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestProductionRuntimeExternalCompositionSmoke(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("ERROR_PAGE_RUNTIME_TEST_DATABASE_URL"))
	endpoint := strings.TrimSpace(os.Getenv("ERROR_PAGE_RUNTIME_TEST_OBJECT_ENDPOINT"))
	if databaseURL == "" || endpoint == "" {
		t.Skip("production runtime external smoke dependencies are not configured")
	}
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(t.Context()); err != nil {
		t.Fatal(err)
	}

	tokens, err := identity.NewTokenManager(strings.Repeat("error-page-runtime-smoke-", 2), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x5a}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "error-page-runtime-smoke", PublicKey: publicKey,
	}})
	if err != nil {
		t.Fatal(err)
	}

	socketPath, closeClamd := startRuntimeFakeClamd(t)
	defer closeClamd()
	runtime, err := NewRuntime(t.Context(), Config{
		Enabled: true,
		ObjectStore: errorpageobjectstore.Config{
			Endpoint: endpoint, Region: "us-east-1", Bucket: "error-page-runtime", Prefix: "error-pages",
			Credentials: runtimeTestCredentials{
				accessKeyID: "error-page-access", secretAccessKey: "error-page-secret",
			},
			ConnectTimeout: time.Second, TLSHandshakeTimeout: time.Second,
			ResponseHeaderTimeout: time.Second, RequestTimeout: 5 * time.Second,
			MaxObjectSize: errorpagecontrol.MaxEdgeResourceBytes, MaxAttempts: 1,
		},
		Scanner: errorpagescanner.Config{
			SocketPath: socketPath, ConnectTimeout: time.Second, ScanTimeout: 5 * time.Second,
		},
	}, Dependencies{
		Pool: pool, Identity: identityService,
		APIKeys: apikey.NewService(pool, bytes.Repeat([]byte{0x5a}, 32), time.Now),
		IAM:     iam, EntitlementTrust: trust, Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(t.Context()) }()
	deadline := time.NewTimer(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for runtime.Ready() != nil {
		select {
		case <-deadline.C:
			t.Fatal("runtime did not become ready")
		case <-ticker.C:
		}
	}

	for _, headers := range []http.Header{
		{},
		{"CdncaKey": []string{"legacy-key"}},
		{"X-Actor-ID": []string{uuid.NewString()}, "X-Actor-Scope": []string{uuid.NewString()}},
	} {
		request := httptest.NewRequest(http.MethodGet, "/v1/error-pages/assets", nil)
		request.Header = headers
		response := httptest.NewRecorder()
		runtime.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"code":"authentication_required"`) {
			t.Fatalf("unauthenticated headers=%v status=%d body=%s", headers, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/error-pages/assets", nil)
	request.Header.Add("X-Request-ID", "request-one")
	request.Header.Add("X-Request-ID", "request-two")
	response := httptest.NewRecorder()
	runtime.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("duplicate metadata status=%d body=%s", response.Code, response.Body.String())
	}

	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run() error after Close = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not stop after Close")
	}
	if !errors.Is(runtime.Ready(), errorpagecontrol.ErrRuntimeNotReady) {
		t.Fatalf("Ready() after Close = %v", runtime.Ready())
	}
}

type runtimeTestCredentials struct {
	accessKeyID     string
	secretAccessKey string
}

func (credentials runtimeTestCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID: credentials.accessKeyID, SecretAccessKey: credentials.secretAccessKey,
		Source: "error-page-runtime-test",
	}, nil
}

func startRuntimeFakeClamd(t *testing.T) (string, func()) {
	t.Helper()
	socketPath := "/tmp/cdnca-ep-runtime-" + uuid.NewString() + ".sock"
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			if !serveRuntimeFakeClamd(connection) {
				_ = connection.Close()
				return
			}
			_ = connection.Close()
		}
	}()
	var once sync.Once
	return socketPath, func() {
		once.Do(func() {
			_ = listener.Close()
			workers.Wait()
			_ = os.Remove(socketPath)
		})
	}
}

func serveRuntimeFakeClamd(connection net.Conn) bool {
	command := make([]byte, len("zINSTREAM\x00"))
	if _, err := io.ReadFull(connection, command); err != nil || string(command) != "zINSTREAM\x00" {
		return false
	}
	for {
		var header [4]byte
		if _, err := io.ReadFull(connection, header[:]); err != nil {
			return false
		}
		length := binary.BigEndian.Uint32(header[:])
		if length == 0 {
			_, err := io.WriteString(connection, "stream: OK\x00")
			return err == nil
		}
		if length > uint32(errorpagecontrol.MaxEdgeResourceBytes) {
			return false
		}
		if _, err := io.CopyN(io.Discard, connection, int64(length)); err != nil {
			return false
		}
	}
}
