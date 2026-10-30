package challenge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExternalVerifierHandlerBindsLoopbackScopeAndConsumesProofOnce(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	installExternalCredentialForTest(t, root)
	transport := &countedRoundTripper{roundTrip: externalRoundTripper(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: ioNopCloser(`{"response":1,"evil_level":0,"err_msg":""}`)}, nil
	})}
	handler, err := NewExternalVerifierHandler(root, &http.Client{Transport: transport},
		NewMemoryExternalReplayStore(128), 4, time.Minute, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	requestBody := ExternalVerifyEnvelope{PolicyID: testChallengeArtifactBinding().PolicyID, PolicyVersion: 7,
		TenantID: testChallengeArtifactBinding().TenantID, SiteID: "01990000-0000-7000-8000-000000000008",
		Provider: ProviderTencent, AppID: "2060000000", ClientIP: "203.0.113.8",
		Proof: `{"ticket":"ticket-once","randstr":"rand-once"}`}
	raw, _ := json.Marshal(requestBody)
	for index, want := range []int{http.StatusNoContent, http.StatusForbidden} {
		request := httptest.NewRequest(http.MethodPost, ExternalVerifierPath, bytes.NewReader(raw))
		request.RemoteAddr = "127.0.0.1:49152"
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("attempt %d status=%d body=%q", index+1, response.Code, response.Body.String())
		}
	}
	callsBeforeCrossScope := transport.calls
	requestBody.SiteID = "01990000-0000-7000-8000-000000000099"
	raw, _ = json.Marshal(requestBody)
	request := httptest.NewRequest(http.MethodPost, ExternalVerifierPath, bytes.NewReader(raw))
	request.RemoteAddr = "192.0.2.10:49152"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || transport.calls != callsBeforeCrossScope {
		t.Fatalf("cross-scope request status=%d provider calls=%d", response.Code, transport.calls)
	}
}

func TestExternalVerifierServerListensOnlyOnCanonicalIPv4Loopback(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	for _, address := range []string{"0.0.0.0:19178", "[::1]:19178", "localhost:19178"} {
		if _, err := NewExternalVerifierServer(root, address, http.DefaultClient); err == nil {
			t.Fatalf("unsafe listen address %q accepted", address)
		}
	}
	server, err := NewExternalVerifierServer(root, "127.0.0.1:19178", http.DefaultClient)
	if err != nil || server == nil {
		t.Fatalf("loopback server=(%v,%v)", server, err)
	}
}

func installExternalCredentialForTest(t *testing.T, root string) {
	t.Helper()
	installer, err := NewArtifactInstaller(root)
	if err != nil {
		t.Fatal(err)
	}
	binding := testChallengeArtifactBinding()
	var document ArtifactDocument
	_ = json.Unmarshal(testChallengeArtifactJSON(t, binding,
		"current-challenge-secret-material-01", "previous-challenge-secret-material-1"), &document)
	document.Policy.Rules[0].Mode = ModeExternal
	document.Policy.Rules[0].RuleID = binding.PolicyID
	document.Policy.Rules[0].ExternalProvider = &ExternalProviderConfig{Provider: ProviderTencent, AppID: "2060000000"}
	document.ExternalCredentials = []ArtifactExternalCredential{{TenantID: binding.TenantID,
		SiteID: document.Policy.Rules[0].SiteID, Provider: ProviderTencent, AppID: "2060000000",
		Secret: []byte("tencent-controlled-secret-0001"), Environment: ExternalProduction}}
	raw, _ := json.Marshal(document)
	if _, err := installer.InstallJSON(raw, binding); err != nil {
		t.Fatal(err)
	}
}

type countedRoundTripper struct {
	calls     int
	roundTrip externalRoundTripper
}

func (transport *countedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls++
	return transport.roundTrip(request)
}

func ioNopCloser(value string) *readCloser { return &readCloser{Reader: strings.NewReader(value)} }

type readCloser struct{ *strings.Reader }

func (reader *readCloser) Close() error { return nil }
