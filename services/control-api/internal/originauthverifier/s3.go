package originauthverifier

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsretry "github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
)

var (
	s3RegionPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	s3BucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

func s3Verifier(maxAttempts int) providerVerifierFunc {
	return func(
		ctx context.Context,
		probe Probe,
		credential originauthcontrol.CredentialSecret,
		client *http.Client,
	) error {
		if !validS3Request(probe, credential, client, maxAttempts) {
			return ErrInvalidConfiguration
		}

		configuration := aws.Config{
			Region: probe.Region,
			Credentials: aws.NewCredentialsCache(aws.CredentialsProviderFunc(
				func(context.Context) (aws.Credentials, error) {
					return aws.Credentials{
						AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey,
						SessionToken: credential.SessionToken, Source: "cdnca-origin-probe",
					}, nil
				},
			)),
			HTTPClient: client,
			Retryer: func() aws.Retryer {
				return awsretry.NewStandard(func(options *awsretry.StandardOptions) {
					options.MaxAttempts = maxAttempts
					options.MaxBackoff = 100 * time.Millisecond
				})
			},
		}
		service := s3.NewFromConfig(configuration, func(options *s3.Options) {
			options.BaseEndpoint = aws.String(probe.Endpoint)
			options.UsePathStyle = true
		})
		_, err := service.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(probe.Bucket),
			Key:    aws.String(probe.Object),
		})
		return classifyS3Error(err)
	}
}

func validS3Request(
	probe Probe,
	credential originauthcontrol.CredentialSecret,
	client *http.Client,
	maxAttempts int,
) bool {
	if client == nil || maxAttempts < 1 || maxAttempts > 3 || !validS3ProbeInput(probe) {
		return false
	}
	return validS3Secret(credential.AccessKeyID, 256) &&
		validS3Secret(credential.SecretAccessKey, 512) &&
		(credential.SessionToken == "" || validS3Secret(credential.SessionToken, 8192))
}

func validS3ProbeInput(probe Probe) bool {
	return probe.Enabled && validS3Endpoint(probe.Endpoint) && s3RegionPattern.MatchString(probe.Region) &&
		validS3Bucket(probe.Bucket) && validS3Object(probe.Object)
}

func validS3Endpoint(raw string) bool {
	if raw == "" || strings.ContainsAny(raw, "\r\n\t") {
		return false
	}
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "https" || endpoint.Opaque != "" || endpoint.User != nil ||
		endpoint.Host == "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" ||
		endpoint.RawFragment != "" || endpoint.RawPath != "" || endpoint.Path != "" && endpoint.Path != "/" {
		return false
	}
	host := endpoint.Hostname()
	if !validS3Host(host) || endpoint.Host != host && endpoint.Host != host+":443" {
		return false
	}
	return true
}

func validS3Host(host string) bool {
	if host == "" || len(host) > 253 || host != strings.ToLower(host) || strings.HasSuffix(host, ".") ||
		net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character > unicode.MaxASCII || !(character == '-' ||
				character >= 'a' && character <= 'z' || character >= '0' && character <= '9') {
				return false
			}
		}
	}
	return true
}

func validS3Bucket(bucket string) bool {
	return s3BucketPattern.MatchString(bucket) && !strings.Contains(bucket, "..") &&
		!strings.Contains(bucket, ".-") && !strings.Contains(bucket, "-.") && net.ParseIP(bucket) == nil
}

func validS3Object(object string) bool {
	if len(object) < 1 || len(object) > 1024 || !utf8.ValidString(object) || strings.HasPrefix(object, "/") ||
		strings.Contains(object, "\\") {
		return false
	}
	for _, segment := range strings.Split(object, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	for _, character := range object {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validS3Secret(value string, maxBytes int) bool {
	if len(value) < 1 || len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character <= unicode.MaxASCII && character > ' ' && character != unicode.MaxASCII {
			continue
		}
		return false
	}
	return true
}

func classifyS3Error(err error) error {
	if err == nil {
		return nil
	}

	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		switch strings.ToLower(apiError.ErrorCode()) {
		case "accessdenied", "accessdeniedexception", "authfailure", "expiredtoken", "expiredtokenexception",
			"invalidaccesskeyid", "invalidclienttokenid", "invalidsecurity", "invalidsecuritytoken",
			"invalidsignatureexception", "invalidtoken", "signaturedoesnotmatch", "tokenrefreshrequired",
			"unrecognizedclientexception":
			return ErrCredentialRejected
		case "authorizationheadermalformed", "illegallocationconstraintexception", "incorrectendpoint",
			"invalidargument", "invalidbucketname", "invalidrequest", "nosuchbucket", "nosuchkey",
			"notfound", "permanentredirect":
			return ErrInvalidConfiguration
		case "internalerror", "requestexpired", "requesttimeout", "requesttimeoutexception",
			"requesttimetooskewed", "serviceunavailable", "slowdown", "throttling",
			"throttlingexception":
			return ErrProviderUnavailable
		}
	}

	var responseError *smithyhttp.ResponseError
	if errors.As(err, &responseError) {
		status := responseError.HTTPStatusCode()
		switch {
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			return ErrCredentialRejected
		case status == http.StatusRequestTimeout || status == http.StatusTooEarly ||
			status == http.StatusTooManyRequests || status >= http.StatusInternalServerError:
			return ErrProviderUnavailable
		case status >= http.StatusMultipleChoices && status < http.StatusInternalServerError:
			return ErrInvalidConfiguration
		}
	}
	return ErrProviderUnavailable
}
