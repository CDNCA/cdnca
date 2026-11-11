package challenge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"math"
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
	if client == nil || !validProvider(credential.Provider) ||
		validateAppID(credential.AppID) != nil || len(credential.Secret) < 16 || len(credential.Secret) > 256 ||
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
	case ProviderTurnstile:
		return verifier.verifyTurnstile(ctx, request)
	case ProviderRecaptchaV3:
		return verifier.verifyRecaptchaV3(ctx, request)
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
		return ExternalResult{}, ErrExternalUnavailable
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response struct {
		Response  int `json:"response"`
		EvilLevel int `json:"evil_level"`
	}
	if !verifier.doJSON(httpRequest, &response) {
		return ExternalResult{}, ErrExternalUnavailable
	}
	if response.Response != 1 || response.EvilLevel < 0 || response.EvilLevel > 100 {
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
		return ExternalResult{}, ErrExternalUnavailable
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response struct {
		Result string `json:"result"`
	}
	if !verifier.doJSON(httpRequest, &response) {
		return ExternalResult{}, ErrExternalUnavailable
	}
	if response.Result != "success" {
		return ExternalResult{}, ErrExternalVerification
	}
	return acceptedExternal(request, proof.LotNumber), nil
}

// Turnstile and reCAPTCHA v3. Endpoints are fixed here,
// never configured, so there is no SSRF surface. Both are form POSTs that
// answer JSON {success, hostname, action, error-codes, ...}.
const (
	turnstileVerifyURL      = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	recaptchaVerifyURL      = "https://www.recaptcha.net/recaptcha/api/siteverify"
	externalChallengeAction = "cdnca_challenge"
	recaptchaMaxTokenAge    = 120 * time.Second
	defaultScoreThreshold   = 0.5
)

type siteVerifyResponse struct {
	Success     bool     `json:"success"`
	Hostname    string   `json:"hostname"`
	Action      string   `json:"action"`
	ErrorCodes  []string `json:"error-codes"`
	ChallengeTS string   `json:"challenge_ts"`
	// recaptcha-v3 only. Field names per the reCAPTCHA v3 docs; 合并后实测
	// (developers.google.com was unreachable when this was written).
	Score *float64 `json:"score"`
}

func (verifier *HTTPExternalVerifier) verifyTurnstile(ctx context.Context, request ExternalRequest) (ExternalResult, error) {
	// Turnstile tokens are at most 2048 characters (Cloudflare docs).
	if !boundedExternalValue(request.Proof, 2048) || !validHost(request.Host) {
		return ExternalResult{}, ErrExternalVerification
	}
	values := url.Values{"secret": {string(verifier.credential.Secret)}, "response": {request.Proof},
		"remoteip": {request.ClientIP}, "idempotency_key": {newIdempotencyKey()}}
	response, err := verifier.siteVerify(ctx, turnstileVerifyURL, values)
	if err != nil {
		return ExternalResult{}, err
	}
	if !response.Success || response.Action != externalChallengeAction || !hostMatches(request.Host, response.Hostname) {
		return ExternalResult{}, ErrExternalVerification
	}
	return acceptedExternal(request, request.Proof), nil
}

func (verifier *HTTPExternalVerifier) verifyRecaptchaV3(ctx context.Context, request ExternalRequest) (ExternalResult, error) {
	if !boundedExternalValue(request.Proof, MaxExternalProofBytes) || !validHost(request.Host) {
		return ExternalResult{}, ErrExternalVerification
	}
	threshold := request.ScoreThreshold
	if threshold == 0 {
		threshold = defaultScoreThreshold
	}
	if !validScoreThreshold(threshold) {
		return ExternalResult{}, ErrExternalVerification
	}
	values := url.Values{"secret": {string(verifier.credential.Secret)}, "response": {request.Proof},
		"remoteip": {request.ClientIP}}
	response, err := verifier.siteVerify(ctx, recaptchaVerifyURL, values)
	if err != nil {
		return ExternalResult{}, err
	}
	// challenge_ts is ISO 8601 (yyyy-MM-dd'T'HH:mm:ssZZ per the docs; 合并后实测).
	issued, tsErr := time.Parse(time.RFC3339, response.ChallengeTS)
	if !response.Success || response.Action != externalChallengeAction || !hostMatches(request.Host, response.Hostname) ||
		response.Score == nil || *response.Score < threshold || tsErr != nil ||
		time.Since(issued) > recaptchaMaxTokenAge || time.Until(issued) > 30*time.Second {
		return ExternalResult{}, ErrExternalVerification
	}
	return acceptedExternal(request, request.Proof), nil
}

// siteVerify posts the form and classifies the answer: a transport, status,
// JSON or provider-side failure (internal-error, wrong / missing secret) is
// ErrExternalUnavailable; a readable answer is returned for the caller to judge.
func (verifier *HTTPExternalVerifier) siteVerify(ctx context.Context, endpoint string, values url.Values) (siteVerifyResponse, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return siteVerifyResponse{}, ErrExternalUnavailable
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response siteVerifyResponse
	if !verifier.doJSON(httpRequest, &response) {
		return siteVerifyResponse{}, ErrExternalUnavailable
	}
	for _, code := range response.ErrorCodes {
		switch code {
		case "internal-error", "missing-input-secret", "invalid-input-secret", "bad-request":
			if code != "internal-error" {
				log.Printf("challenge external verifier: provider rejected the configured secret (%s); check the policy credential", code)
			}
			return siteVerifyResponse{}, ErrExternalUnavailable
		}
	}
	return response, nil
}

func validScoreThreshold(value float64) bool {
	tenths := math.Round(value * 10)
	return tenths >= 1 && tenths <= 9 && math.Abs(value*10-tenths) < 1e-9
}

func validHost(host string) bool {
	return len(host) > 0 && len(host) <= 253 && host == strings.ToLower(host) && !strings.ContainsAny(host, ":/\\% ")
}

// hostMatches: the token's hostname must be the policy host; a wildcard
// host *.x accepts any name strictly below x.
func hostMatches(policyHost, tokenHost string) bool {
	tokenHost = strings.ToLower(tokenHost)
	if suffix, wildcard := strings.CutPrefix(policyHost, "*."); wildcard {
		return strings.HasSuffix(tokenHost, "."+suffix) && len(tokenHost) > len(suffix)+1
	}
	return tokenHost == policyHost
}

func newIdempotencyKey() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return ""
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
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
