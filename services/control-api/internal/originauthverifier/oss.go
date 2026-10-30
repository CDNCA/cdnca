package originauthverifier

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
)

var ossBucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

type ossVerifier struct {
	maxAttempts int
}

func newOSSVerifier(maxAttempts int) providerVerifier {
	return &ossVerifier{maxAttempts: maxAttempts}
}

func (verifier *ossVerifier) verify(
	ctx context.Context,
	probe Probe,
	credential originauthcontrol.CredentialSecret,
	httpClient *http.Client,
) error {
	if verifier == nil || verifier.maxAttempts < 1 || verifier.maxAttempts > 3 ||
		!validOSSInput(probe, credential, httpClient) {
		return ErrInvalidConfiguration
	}

	client, err := oss.New(
		probe.Endpoint,
		credential.AccessKeyID,
		credential.SecretAccessKey,
		oss.AuthVersion(oss.AuthV4),
		oss.Region(probe.Region),
		oss.SecurityToken(credential.SessionToken),
		oss.ForcePathStyle(true),
		oss.RedirectEnabled(false),
		oss.HTTPClient(httpClient),
	)
	if err != nil {
		return ErrInvalidConfiguration
	}
	bucket, err := client.Bucket(probe.Bucket)
	if err != nil {
		return ErrInvalidConfiguration
	}

	for attempt := 0; attempt < verifier.maxAttempts; attempt++ {
		response, requestErr := bucket.Client.Conn.DoWithContext(
			ctx, http.MethodHead, probe.Bucket, probe.Object, nil, nil, nil, 0, nil,
		)
		classified := classifyOSSResponse(response, requestErr)
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if !errors.Is(classified, ErrProviderUnavailable) || attempt == verifier.maxAttempts-1 || ctx.Err() != nil {
			return classified
		}
	}
	return ErrProviderUnavailable
}

func validOSSInput(probe Probe, credential originauthcontrol.CredentialSecret, client *http.Client) bool {
	return client != nil && client.Transport != nil && client.CheckRedirect != nil && redirectsDisabled(client) &&
		validOSSProbeInput(probe) && validProviderCredential(credential)
}

func validOSSProbeInput(probe Probe) bool {
	if !probe.Enabled || !validProviderEndpoint(probe.Endpoint) || !validProviderToken(probe.Region) ||
		!ossBucketPattern.MatchString(probe.Bucket) || !validProviderObject(probe.Object) {
		return false
	}
	endpoint, err := url.Parse(probe.Endpoint)
	if err != nil || !strings.EqualFold(endpoint.Hostname(), "oss-"+probe.Region+".aliyuncs.com") {
		return false
	}
	return true
}

func classifyOSSResponse(response *oss.Response, err error) error {
	if err == nil {
		return nil
	}
	var serviceError oss.ServiceError
	if errors.As(err, &serviceError) {
		return classifyProviderResponse(serviceError.StatusCode, serviceError.Code)
	}
	var serviceErrorPointer *oss.ServiceError
	if errors.As(err, &serviceErrorPointer) && serviceErrorPointer != nil {
		return classifyProviderResponse(serviceErrorPointer.StatusCode, serviceErrorPointer.Code)
	}
	if response != nil {
		return classifyProviderResponse(response.StatusCode, "")
	}
	var statusError oss.UnexpectedStatusCodeError
	if errors.As(err, &statusError) {
		return classifyProviderResponse(statusError.Got(), "")
	}
	return ErrProviderUnavailable
}

func classifyProviderResponse(status int, code string) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return ErrCredentialRejected
	case isCredentialCode(code):
		return ErrCredentialRejected
	case status >= 300 && status < 400:
		return ErrInvalidConfiguration
	case status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500:
		return ErrProviderUnavailable
	case status >= 400 && status < 500:
		return ErrInvalidConfiguration
	default:
		return ErrProviderUnavailable
	}
}

func isCredentialCode(code string) bool {
	switch strings.ToLower(code) {
	case "accessdenied", "expiredtoken", "invalidaccesskeyid", "invalidsecuritytoken",
		"securitytokenexpired", "signaturedoesnotmatch":
		return true
	default:
		return false
	}
}

func validProviderEndpoint(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") ||
		(parsed.Port() != "" && parsed.Port() != "443") || net.ParseIP(parsed.Hostname()) != nil {
		return false
	}
	return true
}

func validProviderCredential(credential originauthcontrol.CredentialSecret) bool {
	return validCredentialPart(credential.AccessKeyID, false) &&
		validCredentialPart(credential.SecretAccessKey, false) &&
		validCredentialPart(credential.SessionToken, true)
}

func validCredentialPart(value string, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > 4096 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validProviderToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validProviderObject(value string) bool {
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) || strings.HasPrefix(value, "/") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, character := range segment {
			if unicode.IsControl(character) {
				return false
			}
		}
	}
	return true
}

func redirectsDisabled(client *http.Client) bool {
	return errors.Is(client.CheckRedirect(&http.Request{}, nil), http.ErrUseLastResponse)
}
