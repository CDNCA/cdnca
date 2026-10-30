package originauthverifier

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	cos "github.com/tencentyun/cos-go-sdk-v5"
)

var cosBucketPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,48}[a-z0-9])?-[1-9][0-9]{4,19}$`)

type cosVerifier struct {
	maxAttempts int
}

func newCOSVerifier(maxAttempts int) providerVerifier {
	return &cosVerifier{maxAttempts: maxAttempts}
}

func (verifier *cosVerifier) verify(
	ctx context.Context,
	probe Probe,
	credential originauthcontrol.CredentialSecret,
	httpClient *http.Client,
) error {
	if verifier == nil || verifier.maxAttempts < 1 || verifier.maxAttempts > 3 ||
		!validCOSInput(probe, credential, httpClient) {
		return ErrInvalidConfiguration
	}

	endpoint, err := url.Parse(probe.Endpoint)
	if err != nil {
		return ErrInvalidConfiguration
	}
	controlledClient := *httpClient
	controlledClient.Transport = &cos.AuthorizationTransport{
		SecretID:     credential.AccessKeyID,
		SecretKey:    credential.SecretAccessKey,
		SessionToken: credential.SessionToken,
		Transport:    httpClient.Transport,
	}
	client := cos.NewClient(&cos.BaseURL{BucketURL: endpoint}, &controlledClient)
	client.Conf.RetryOpt.Count = 1
	client.Conf.RetryOpt.Interval = 0
	client.Conf.RetryOpt.AutoSwitchHost = false

	for attempt := 0; attempt < verifier.maxAttempts; attempt++ {
		_, err = client.Object.Head(ctx, probe.Object, nil)
		classified := classifyCOSError(err)
		if !errors.Is(classified, ErrProviderUnavailable) || attempt == verifier.maxAttempts-1 || ctx.Err() != nil {
			return classified
		}
	}
	return ErrProviderUnavailable
}

func validCOSInput(probe Probe, credential originauthcontrol.CredentialSecret, client *http.Client) bool {
	return client != nil && client.Transport != nil && client.CheckRedirect != nil && redirectsDisabled(client) &&
		validCOSProbeInput(probe) && validProviderCredential(credential)
}

func validCOSProbeInput(probe Probe) bool {
	if !probe.Enabled || !validProviderEndpoint(probe.Endpoint) || !validProviderToken(probe.Region) ||
		!cosBucketPattern.MatchString(probe.Bucket) || !validProviderObject(probe.Object) {
		return false
	}
	endpoint, err := url.Parse(probe.Endpoint)
	if err != nil {
		return false
	}
	expectedHost := probe.Bucket + ".cos." + probe.Region + ".myqcloud.com"
	return strings.EqualFold(endpoint.Hostname(), expectedHost)
}

func classifyCOSError(err error) error {
	if err == nil {
		return nil
	}
	var responseError *cos.ErrorResponse
	if errors.As(err, &responseError) && responseError != nil && responseError.Response != nil {
		return classifyProviderResponse(responseError.Response.StatusCode, responseError.Code)
	}
	return ErrProviderUnavailable
}
