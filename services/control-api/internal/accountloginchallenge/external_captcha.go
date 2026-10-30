package accountloginchallenge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
)

const (
	defaultTencentCaptchaEndpoint = "https://captcha.tencentcloudapi.com/"
	defaultGeetestCaptchaEndpoint = "https://gcaptcha4.geetest.com/validate"
	tencentCaptchaAction          = "DescribeCaptchaResult"
	tencentCaptchaVersion         = "2019-07-22"
	tencentCaptchaService         = "captcha"
	maxCaptchaResponseBytes       = 16 << 10
	captchaRequestTimeout         = 5 * time.Second
)

// CaptchaSettingsReader returns the platform CAPTCHA provider and secret references.
type CaptchaSettingsReader interface {
	CaptchaRuntime(context.Context) (systemusersettings.CaptchaRuntime, error)
}

// SecretResolver maps a vault:// or kms-envelope:// reference to secret material.
type SecretResolver interface {
	ResolveSecret(reference string) (string, bool)
}

// StaticSecretResolver is a reference→secret map loaded once at startup.
type StaticSecretResolver map[string]string

func (resolver StaticSecretResolver) ResolveSecret(reference string) (string, bool) {
	value, ok := resolver[reference]
	return value, ok && value != ""
}

// ParseCaptchaSecretsJSON decodes {"<reference>":"<secret>",...}. References
// must use the same vault:// or kms-envelope:// form the settings page stores.
func ParseCaptchaSecretsJSON(raw string) (StaticSecretResolver, error) {
	if rejectDuplicateCaptchaKeys([]byte(raw)) != nil {
		return nil, ErrInvalidConfig
	}
	var values map[string]string
	if err := json.Unmarshal([]byte(raw), &values); err != nil || len(values) > 16 {
		return nil, ErrInvalidConfig
	}
	result := make(StaticSecretResolver, len(values))
	for reference, secret := range values {
		if !captchaSecretReference(reference) || secret == "" || len(secret) > 256 || strings.TrimSpace(secret) != secret ||
			strings.IndexFunc(secret, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
			return nil, ErrInvalidConfig
		}
		result[reference] = secret
	}
	return result, nil
}

type ExternalCaptchaConfig struct {
	Settings        CaptchaSettingsReader
	Secrets         SecretResolver
	Client          *http.Client
	TencentEndpoint string
	GeetestEndpoint string
	Clock           func() time.Time
}

// ExternalCaptchaVerifier performs the server-side second check for the
// Tencent CAPTCHA (DescribeCaptchaResult, bound to CaptchaAppId) and GeeTest
// v4 tickets submitted with OTP login challenges. Every failure collapses to
// ErrHumanInvalid; secrets never appear in errors.
type ExternalCaptchaVerifier struct {
	settings CaptchaSettingsReader
	secrets  SecretResolver
	client   *http.Client
	tencent  url.URL
	geetest  url.URL
	now      func() time.Time
}

func NewExternalCaptchaVerifier(config ExternalCaptchaConfig) (*ExternalCaptchaVerifier, error) {
	if config.Settings == nil || config.Secrets == nil || config.Client == nil {
		return nil, ErrInvalidConfig
	}
	if config.TencentEndpoint == "" {
		config.TencentEndpoint = defaultTencentCaptchaEndpoint
	}
	if config.GeetestEndpoint == "" {
		config.GeetestEndpoint = defaultGeetestCaptchaEndpoint
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	tencent, tencentErr := url.Parse(config.TencentEndpoint)
	geetest, geetestErr := url.Parse(config.GeetestEndpoint)
	if tencentErr != nil || geetestErr != nil || !validCaptchaEndpoint(tencent) || !validCaptchaEndpoint(geetest) {
		return nil, ErrInvalidConfig
	}
	client := *config.Client
	client.Timeout = captchaRequestTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &ExternalCaptchaVerifier{settings: config.Settings, secrets: config.Secrets, client: &client,
		tencent: *tencent, geetest: *geetest, now: config.Clock}, nil
}

func (verifier *ExternalCaptchaVerifier) Verify(ctx context.Context, mode, token, source string) error {
	if verifier == nil || ctx == nil || token == "" || source == "" {
		return ErrHumanInvalid
	}
	runtime, err := verifier.settings.CaptchaRuntime(ctx)
	if err != nil || runtime.Provider != mode {
		return ErrHumanInvalid
	}
	switch mode {
	case "tencent":
		return verifier.verifyTencent(ctx, runtime, token, source)
	case "geetest_v4":
		return verifier.verifyGeetest(ctx, runtime, token)
	default:
		return ErrHumanInvalid
	}
}

func (verifier *ExternalCaptchaVerifier) verifyTencent(ctx context.Context, runtime systemusersettings.CaptchaRuntime, token, source string) error {
	var proof struct {
		Ticket  string `json:"ticket"`
		Randstr string `json:"randstr"`
	}
	appID, appIDErr := strconv.ParseUint(runtime.AppID, 10, 63)
	if appIDErr != nil || appID == 0 || !decodeCaptchaProof(token, &proof) ||
		!boundedCaptchaValue(proof.Ticket, 2048) || !boundedCaptchaValue(proof.Randstr, 512) {
		return ErrHumanInvalid
	}
	secretID, idOK := verifier.secrets.ResolveSecret(runtime.SecretIDReference)
	secretKey, keyOK := verifier.secrets.ResolveSecret(runtime.SecretKeyReference)
	appSecret, appOK := verifier.secrets.ResolveSecret(runtime.AppSecretReference)
	if !idOK || !keyOK || !appOK {
		return ErrHumanInvalid
	}
	payload, err := json.Marshal(map[string]any{
		"CaptchaType": 9, "Ticket": proof.Ticket, "UserIp": source, "Randstr": proof.Randstr,
		"CaptchaAppId": appID, "AppSecretKey": appSecret,
	})
	if err != nil {
		return ErrHumanInvalid
	}
	timestamp := verifier.now().Unix()
	host := verifier.tencent.Host
	stringToSign := tc3StringToSign(timestamp, tencentCaptchaService, tc3CanonicalRequest(host, tencentCaptchaAction, payload))
	authorization := "TC3-HMAC-SHA256 Credential=" + secretID + "/" + tc3Date(timestamp) + "/" + tencentCaptchaService +
		"/tc3_request, SignedHeaders=content-type;host;x-tc-action, Signature=" +
		tc3Signature([]byte(secretKey), timestamp, tencentCaptchaService, stringToSign)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, verifier.tencent.String(), bytes.NewReader(payload))
	if err != nil {
		return ErrHumanInvalid
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("Authorization", authorization)
	request.Header.Set("X-TC-Action", tencentCaptchaAction)
	request.Header.Set("X-TC-Version", tencentCaptchaVersion)
	request.Header.Set("X-TC-Timestamp", strconv.FormatInt(timestamp, 10))
	var response struct {
		Response struct {
			Error       *json.RawMessage `json:"Error"`
			CaptchaCode *int64           `json:"CaptchaCode"`
		} `json:"Response"`
	}
	// CaptchaCode 1 is the only success value (DescribeCaptchaResult reference).
	if !verifier.doJSON(request, &response) || response.Response.Error != nil ||
		response.Response.CaptchaCode == nil || *response.Response.CaptchaCode != 1 {
		return ErrHumanInvalid
	}
	return nil
}

func (verifier *ExternalCaptchaVerifier) verifyGeetest(ctx context.Context, runtime systemusersettings.CaptchaRuntime, token string) error {
	var proof struct {
		LotNumber     string `json:"lot_number"`
		CaptchaOutput string `json:"captcha_output"`
		PassToken     string `json:"pass_token"`
		GenTime       string `json:"gen_time"`
	}
	if !boundedCaptchaValue(runtime.AppID, 128) || !decodeCaptchaProof(token, &proof) ||
		!boundedCaptchaValue(proof.LotNumber, 256) || !boundedCaptchaValue(proof.CaptchaOutput, 2048) ||
		!boundedCaptchaValue(proof.PassToken, 512) || !boundedCaptchaValue(proof.GenTime, 32) {
		return ErrHumanInvalid
	}
	captchaKey, ok := verifier.secrets.ResolveSecret(runtime.AppSecretReference)
	if !ok {
		return ErrHumanInvalid
	}
	mac := hmac.New(sha256.New, []byte(captchaKey))
	_, _ = mac.Write([]byte(proof.LotNumber))
	form := url.Values{"lot_number": {proof.LotNumber}, "captcha_output": {proof.CaptchaOutput},
		"pass_token": {proof.PassToken}, "gen_time": {proof.GenTime}, "sign_token": {hex.EncodeToString(mac.Sum(nil))}}
	endpoint := verifier.geetest
	endpoint.RawQuery = url.Values{"captcha_id": {runtime.AppID}}.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return ErrHumanInvalid
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response struct {
		Result string `json:"result"`
	}
	if !verifier.doJSON(request, &response) || response.Result != "success" {
		return ErrHumanInvalid
	}
	return nil
}

func (verifier *ExternalCaptchaVerifier) doJSON(request *http.Request, target any) bool {
	request.Header.Set("Accept", "application/json")
	response, err := verifier.client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || response.StatusCode != http.StatusOK {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxCaptchaResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxCaptchaResponseBytes || rejectDuplicateCaptchaKeys(raw) != nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(target) != nil {
		return false
	}
	var trailing any
	return decoder.Decode(&trailing) == io.EOF
}

func tc3CanonicalRequest(host, action string, payload []byte) string {
	return "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:" + host + "\nx-tc-action:" +
		strings.ToLower(action) + "\n\ncontent-type;host;x-tc-action\n" + sha256Hex(payload)
}

func tc3StringToSign(timestamp int64, service, canonicalRequest string) string {
	return "TC3-HMAC-SHA256\n" + strconv.FormatInt(timestamp, 10) + "\n" + tc3Date(timestamp) + "/" + service +
		"/tc3_request\n" + sha256Hex([]byte(canonicalRequest))
}

func tc3Signature(secretKey []byte, timestamp int64, service, stringToSign string) string {
	date := hmacSHA256(append([]byte("TC3"), secretKey...), tc3Date(timestamp))
	signing := hmacSHA256(hmacSHA256(hmacSHA256(date, service), "tc3_request"), stringToSign)
	return hex.EncodeToString(signing)
}

func tc3Date(timestamp int64) string { return time.Unix(timestamp, 0).UTC().Format("2006-01-02") }

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func decodeCaptchaProof(raw string, target any) bool {
	if rejectDuplicateCaptchaKeys([]byte(raw)) != nil {
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return false
	}
	var trailing any
	return decoder.Decode(&trailing) == io.EOF
}

func boundedCaptchaValue(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) }) < 0
}

func captchaSecretReference(value string) bool {
	return len(value) <= 1024 && (strings.HasPrefix(value, "vault://") && len(value) > len("vault://") ||
		strings.HasPrefix(value, "kms-envelope://") && len(value) > len("kms-envelope://"))
}

func validCaptchaEndpoint(endpoint *url.URL) bool {
	return endpoint.Scheme == "https" && endpoint.Host != "" && endpoint.User == nil && endpoint.RawQuery == "" && endpoint.Fragment == ""
}

// rejectDuplicateCaptchaKeys refuses JSON objects with repeated keys at any
// depth, so a proof or provider response cannot smuggle a second value.
func rejectDuplicateCaptchaKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, _ := keyToken.(string)
				if _, exists := seen[key]; exists {
					return ErrInvalidInput
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidInput
	}
	return nil
}
