package challenge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type ExternalEnvironment string

const (
	ExternalSandbox    ExternalEnvironment = "sandbox"
	ExternalProduction ExternalEnvironment = "production"
	maxProviderBody                        = 16 << 10
)

type ExternalCredential struct {
	Provider    ExternalProvider
	AppID       string
	Secret      []byte
	Environment ExternalEnvironment
}

type HTTPExternalVerifier struct {
	client     http.Client
	credential ExternalCredential
}

type RotatingExternalVerifier struct {
	mu       sync.RWMutex
	client   *http.Client
	revision uint64
	active   map[string]*HTTPExternalVerifier
}

func NewRotatingExternalVerifier(client *http.Client, revision uint64, credentials []ExternalCredential) (*RotatingExternalVerifier, error) {
	verifier := &RotatingExternalVerifier{client: client}
	if err := verifier.Activate(revision, credentials); err != nil {
		return nil, err
	}
	return verifier, nil
}

func (verifier *RotatingExternalVerifier) Activate(revision uint64, credentials []ExternalCredential) error {
	if verifier == nil || verifier.client == nil || revision == 0 || len(credentials) == 0 || len(credentials) > 64 {
		return ErrExternalVerification
	}
	candidate := make(map[string]*HTTPExternalVerifier, len(credentials))
	for _, credential := range credentials {
		adapter, err := NewHTTPExternalVerifier(verifier.client, credential)
		key := string(credential.Provider) + "\x00" + credential.AppID
		if err != nil || candidate[key] != nil {
			clearExternalAdapters(candidate)
			return ErrExternalVerification
		}
		candidate[key] = adapter
	}
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	if revision <= verifier.revision {
		clearExternalAdapters(candidate)
		return ErrExternalVerification
	}
	previous := verifier.active
	verifier.active, verifier.revision = candidate, revision
	clearExternalAdapters(previous)
	return nil
}

func (verifier *RotatingExternalVerifier) Verify(ctx context.Context, request ExternalRequest) (ExternalResult, error) {
	if verifier == nil {
		return ExternalResult{}, ErrExternalVerification
	}
	verifier.mu.RLock()
	defer verifier.mu.RUnlock()
	adapter := verifier.active[string(request.Provider)+"\x00"+request.AppID]
	if adapter == nil {
		return ExternalResult{}, ErrExternalVerification
	}
	return adapter.Verify(ctx, request)
}

func clearExternalAdapters(adapters map[string]*HTTPExternalVerifier) {
	for key, adapter := range adapters {
		if adapter != nil {
			clear(adapter.credential.Secret)
		}
		delete(adapters, key)
	}
}

func NewHTTPExternalVerifier(client *http.Client, credential ExternalCredential) (*HTTPExternalVerifier, error) {
	if client == nil || (credential.Provider != ProviderTencent && credential.Provider != ProviderGeetestV4) ||
		validateIdentifier(credential.AppID, MaxIdentifierBytes) != nil || len(credential.Secret) < 16 || len(credential.Secret) > 256 ||
		(credential.Environment != ExternalSandbox && credential.Environment != ExternalProduction) {
		return nil, ErrExternalVerification
	}
	owned := *client
	owned.Timeout = 3 * time.Second
	owned.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrExternalVerification }
	return &HTTPExternalVerifier{client: owned, credential: ExternalCredential{
		Provider: credential.Provider, AppID: credential.AppID, Secret: bytes.Clone(credential.Secret), Environment: credential.Environment,
	}}, nil
}

func (verifier *HTTPExternalVerifier) Verify(ctx context.Context, request ExternalRequest) (ExternalResult, error) {
	if verifier == nil || ctx == nil || request.Provider != verifier.credential.Provider || request.AppID != verifier.credential.AppID {
		return ExternalResult{}, ErrExternalVerification
	}
	switch request.Provider {
	case ProviderTencent:
		return verifier.verifyTencent(ctx, request)
	case ProviderGeetestV4:
		return verifier.verifyGeetest(ctx, request)
	default:
		return ExternalResult{}, ErrExternalVerification
	}
}

func (verifier *HTTPExternalVerifier) verifyTencent(ctx context.Context, request ExternalRequest) (ExternalResult, error) {
	var proof struct {
		Ticket  string `json:"ticket"`
		Randstr string `json:"randstr"`
	}
	if !decodeProviderProof(request.Proof, &proof) || !boundedExternalValue(proof.Ticket, 2048) || !boundedExternalValue(proof.Randstr, 512) {
		return ExternalResult{}, ErrExternalVerification
	}
	values := url.Values{"aid": {request.AppID}, "AppSecretKey": {string(verifier.credential.Secret)},
		"Ticket": {proof.Ticket}, "Randstr": {proof.Randstr}, "UserIP": {request.ClientIP}}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://ssl.captcha.qq.com/ticket/verify", strings.NewReader(values.Encode()))
	if err != nil {
		return ExternalResult{}, ErrExternalVerification
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response struct {
		Response  int `json:"response"`
		EvilLevel int `json:"evil_level"`
	}
	if !verifier.doJSON(httpRequest, &response) || response.Response != 1 || response.EvilLevel < 0 || response.EvilLevel > 100 {
		return ExternalResult{}, ErrExternalVerification
	}
	return acceptedExternal(request, proof.Ticket), nil
}

func (verifier *HTTPExternalVerifier) verifyGeetest(ctx context.Context, request ExternalRequest) (ExternalResult, error) {
	var proof struct {
		LotNumber     string `json:"lot_number"`
		CaptchaOutput string `json:"captcha_output"`
		PassToken     string `json:"pass_token"`
		GenTime       string `json:"gen_time"`
	}
	if !decodeProviderProof(request.Proof, &proof) || !boundedExternalValue(proof.LotNumber, 256) ||
		!boundedExternalValue(proof.CaptchaOutput, 2048) || !boundedExternalValue(proof.PassToken, 512) ||
		!boundedExternalValue(proof.GenTime, 32) {
		return ExternalResult{}, ErrExternalVerification
	}
	signature := hmac.New(sha256.New, verifier.credential.Secret)
	_, _ = signature.Write([]byte(proof.LotNumber))
	values := url.Values{"lot_number": {proof.LotNumber}, "captcha_output": {proof.CaptchaOutput},
		"pass_token": {proof.PassToken}, "gen_time": {proof.GenTime}, "sign_token": {hex.EncodeToString(signature.Sum(nil))}}
	endpoint := "https://gcaptcha4.geetest.com/validate?captcha_id=" + url.QueryEscape(request.AppID)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return ExternalResult{}, ErrExternalVerification
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response struct {
		Result string `json:"result"`
	}
	if !verifier.doJSON(httpRequest, &response) || response.Result != "success" {
		return ExternalResult{}, ErrExternalVerification
	}
	return acceptedExternal(request, proof.LotNumber), nil
}

func (verifier *HTTPExternalVerifier) doJSON(request *http.Request, target any) bool {
	response, err := verifier.client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProviderBody+1))
	if err != nil || len(body) == 0 || len(body) > maxProviderBody {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return false
	}
	var trailing any
	return decoder.Decode(&trailing) == io.EOF
}

func decodeProviderProof(raw string, target any) bool {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	var trailing any
	return decoder.Decode(&trailing) == io.EOF
}

func acceptedExternal(request ExternalRequest, providerKey string) ExternalResult {
	digest := sha256.Sum256([]byte(string(request.Provider) + "\x00" + request.AppID + "\x00" + providerKey))
	return ExternalResult{Valid: true, AppID: request.AppID, ReplayKey: hex.EncodeToString(digest[:])}
}
