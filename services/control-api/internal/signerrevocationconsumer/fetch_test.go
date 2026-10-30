package signerrevocationconsumer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFetchCheckpointProofAndStrongETag(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	installationID := uuid.New()
	operationID := uuid.New()
	now := time.Unix(1_800_000_123, 0).UTC()
	body := []byte(`{"checkpoint":"signed"}`)
	etag := checkpointETag(body)
	knownDigest := strings.Repeat("A", 43)

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.EscapedPath() != CheckpointPath || request.URL.RawQuery != "" {
			t.Errorf("request target = %s %s", request.Method, request.URL.String())
		}
		if request.Header.Get("Accept") != CheckpointMediaType ||
			request.Header.Get("X-Request-ID") != operationID.String() ||
			request.Header.Get("X-CDNCA-Installation-ID") != installationID.String() ||
			request.Header.Get("X-CDNCA-Requested-At") != "1800000123" ||
			request.Header.Get("X-CDNCA-Known-Checkpoint-Revision") != "7" ||
			request.Header.Get("X-CDNCA-Known-Checkpoint-SHA256") != knownDigest ||
			request.Header.Get("If-None-Match") != `"`+knownDigest+`"` {
			t.Errorf("request headers = %#v", request.Header)
		}
		proof, decodeErr := base64.RawURLEncoding.DecodeString(request.Header.Get("X-CDNCA-Proof"))
		expectedProof := proofFields(fetchProofDomain, http.MethodGet, CheckpointPath, operationID.String(),
			installationID.String(), strconv.FormatInt(now.Unix(), 10), "7", knownDigest, `"`+knownDigest+`"`)
		if decodeErr != nil || !ed25519.Verify(publicKey, expectedProof, proof) {
			t.Errorf("proof verification = %v, %v", decodeErr, proof)
		}
		writer.Header().Set("Content-Type", CheckpointMediaType)
		writer.Header().Set("ETag", etag)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		BaseURL: server.URL, TLSConfig: checkpointTestTLS(server), InstallationID: installationID,
		PrivateKey: privateKey, Timeout: time.Second, Now: func() time.Time { return now },
		NewOperationID: func() uuid.UUID { return operationID },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Fetch(t.Context(), KnownCheckpoint{Revision: 7, SHA256: knownDigest, ETag: `"` + knownDigest + `"`})
	if err != nil || result.NotModified || result.ETag != etag || string(result.Body) != string(body) ||
		result.OperationID != operationID || !result.ObservedAt.Equal(now) {
		t.Fatalf("fetch = (%#v, %v)", result, err)
	}
}

func TestFetchCheckpointStrictTransportAndResponseBoundaries(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	installationID := uuid.New()
	base := ClientConfig{InstallationID: installationID, PrivateKey: privateKey, Timeout: time.Second,
		Now: func() time.Time { return time.Unix(1_800_000_123, 0).UTC() }, NewOperationID: uuid.New}
	for name, rawURL := range map[string]string{
		"http": "http://license.example.test", "path": "https://license.example.test/base",
		"query": "https://license.example.test?x=1", "bare query": "https://license.example.test?",
		"userinfo": "https://user@license.example.test",
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			config.BaseURL = rawURL
			if _, err := NewClient(config); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("configuration error = %v", err)
			}
		})
	}
	insecure := base
	insecure.BaseURL = "https://license.example.test"
	insecure.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	if _, err := NewClient(insecure); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("insecure TLS configuration error = %v", err)
	}

	tests := []struct {
		name    string
		handler http.HandlerFunc
		known   KnownCheckpoint
		reason  string
	}{
		{name: "wrong content type", reason: ReasonInvalidResponse, handler: func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("ETag", checkpointETag([]byte("{}")))
			_, _ = writer.Write([]byte("{}"))
		}},
		{name: "wrong ETag", reason: ReasonInvalidResponse, handler: func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", CheckpointMediaType)
			writer.Header().Set("ETag", `"`+strings.Repeat("A", 43)+`"`)
			_, _ = writer.Write([]byte("{}"))
		}},
		{name: "oversized", reason: ReasonInvalidResponse, handler: func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", CheckpointMediaType)
			writer.Header().Set("Content-Length", "8388609")
			writer.WriteHeader(http.StatusOK)
		}},
		{name: "chunked", reason: ReasonInvalidResponse, handler: func(writer http.ResponseWriter, _ *http.Request) {
			body := []byte(`{"checkpoint":"chunked"}`)
			writer.Header().Set("Content-Type", CheckpointMediaType)
			writer.Header().Set("ETag", checkpointETag(body))
			writer.WriteHeader(http.StatusOK)
			writer.(http.Flusher).Flush()
			_, _ = writer.Write(body)
		}},
		{name: "server outage", reason: ReasonServerOutage, handler: func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusServiceUnavailable)
		}},
		{name: "rate limited", reason: ReasonRateLimited, handler: func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusTooManyRequests)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(test.handler)
			defer server.Close()
			config := base
			config.BaseURL, config.TLSConfig = server.URL, checkpointTestTLS(server)
			client, err := NewClient(config)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Fetch(t.Context(), test.known)
			var fetchErr *FetchError
			if !errors.As(err, &fetchErr) || fetchErr.Reason != test.reason {
				t.Fatalf("fetch error = %v", err)
			}
		})
	}
}

func TestEmptyResponseBodyRejects304Payload(t *testing.T) {
	if emptyResponseBody(strings.NewReader("x")) || !emptyResponseBody(strings.NewReader("")) {
		t.Fatal("304 empty-body validation is incorrect")
	}
}

func TestFetchCheckpointNotModifiedAndRedirectRejected(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	digest := strings.Repeat("A", 43)
	known := KnownCheckpoint{Revision: 1, SHA256: digest, ETag: `"` + digest + `"`}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("ETag", request.Header.Get("If-None-Match"))
		writer.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{BaseURL: server.URL, TLSConfig: checkpointTestTLS(server),
		InstallationID: uuid.New(), PrivateKey: privateKey, Timeout: time.Second, Now: time.Now, NewOperationID: uuid.New})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Fetch(t.Context(), known)
	if err != nil || !result.NotModified || result.ETag != known.ETag || len(result.Body) != 0 {
		t.Fatalf("304 result = (%#v, %v)", result, err)
	}
	client.http.Transport = checkpointRoundTripper(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNotModified, Header: http.Header{"Etag": []string{known.ETag}},
			Body: io.NopCloser(strings.NewReader("")), ContentLength: 0,
			TransferEncoding: []string{"chunked"}, Request: request,
		}, nil
	})
	if _, err := client.Fetch(t.Context(), known); err == nil {
		t.Fatal("304 with transfer encoding was accepted")
	}

	redirect := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Redirect(writer, &http.Request{}, server.URL+CheckpointPath, http.StatusFound)
	}))
	defer redirect.Close()
	redirectClient, err := NewClient(ClientConfig{BaseURL: redirect.URL, TLSConfig: checkpointTestTLS(redirect),
		InstallationID: uuid.New(), PrivateKey: privateKey, Timeout: time.Second, Now: time.Now, NewOperationID: uuid.New})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := redirectClient.Fetch(t.Context(), KnownCheckpoint{}); err == nil {
		t.Fatal("redirect was followed")
	} else {
		var fetchErr *FetchError
		if !errors.As(err, &fetchErr) || fetchErr.Reason != ReasonInvalidResponse {
			t.Fatalf("redirect error = %v", err)
		}
	}
}

type checkpointRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip checkpointRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestKnownCheckpointValidation(t *testing.T) {
	digest := strings.Repeat("A", 43)
	for name, known := range map[string]KnownCheckpoint{
		"zero digest":    {SHA256: digest},
		"missing digest": {Revision: 1},
		"bad digest":     {Revision: 1, SHA256: "bad"},
		"weak etag":      {Revision: 1, SHA256: digest, ETag: `W/"` + digest + `"`},
	} {
		if validKnownCheckpoint(known) {
			t.Errorf("%s known state was accepted", name)
		}
	}
	if !validKnownCheckpoint(KnownCheckpoint{}) ||
		!validKnownCheckpoint(KnownCheckpoint{Revision: 1, SHA256: digest, ETag: `"` + digest + `"`}) {
		t.Fatal("valid known state was rejected")
	}
}

func checkpointETag(body []byte) string {
	digest := sha256.Sum256(body)
	return `"` + base64.RawURLEncoding.EncodeToString(digest[:]) + `"`
}

func checkpointTestTLS(server *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func proofFields(fields ...string) []byte {
	hash := sha256.New()
	var length [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = io.WriteString(hash, field)
	}
	return hash.Sum(nil)
}
