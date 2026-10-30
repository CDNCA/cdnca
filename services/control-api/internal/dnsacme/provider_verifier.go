package dnsacme

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscustomhttp"
)

var (
	huaweiAccessKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	huaweiProjectIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
	dnspodIDPattern        = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
)

type CredentialProviderVerifier interface {
	VerifyCredentials(context.Context, string, map[string]string) error
}

type ProviderVerifierDispatcher struct {
	cloudflare *CloudflareProviderVerifier
	aliyun     *AliyunProviderVerifier
	huawei     *HuaweiProviderVerifier
	dnspod     *DNSPodProviderVerifier
	dnscom     *DNSComProviderVerifier
	dnsla      *DNSLAProviderVerifier
	namecom    *NameComProviderVerifier
	// customHTTP overrides the custom HTTP client options (tests only).
	customHTTP *dnscustomhttp.Options
}

func NewProviderVerifierDispatcher() *ProviderVerifierDispatcher {
	dispatcher := newProviderVerifierDispatcher(
		NewCloudflareProviderVerifier(),
		NewAliyunProviderVerifier(),
		NewHuaweiProviderVerifier(),
		NewDNSPodProviderVerifier(),
		NewDNSComProviderVerifier(),
	)
	dispatcher.dnsla = NewDNSLAProviderVerifier()
	dispatcher.namecom = NewNameComProviderVerifier()
	return dispatcher
}

func newProviderVerifierDispatcher(
	cloudflare *CloudflareProviderVerifier,
	aliyun *AliyunProviderVerifier,
	huawei *HuaweiProviderVerifier,
	dnspod *DNSPodProviderVerifier,
	dnscom *DNSComProviderVerifier,
) *ProviderVerifierDispatcher {
	return &ProviderVerifierDispatcher{
		cloudflare: cloudflare,
		aliyun:     aliyun,
		huawei:     huawei,
		dnspod:     dnspod,
		dnscom:     dnscom,
	}
}

// Verify preserves the Cloudflare token verifier contract for existing callers.
func (v *ProviderVerifierDispatcher) Verify(ctx context.Context, providerType, apiToken string) error {
	if providerType != "cloudflare" {
		return ErrProviderVerificationUnsupported
	}
	return v.VerifyCredentials(ctx, providerType, map[string]string{"api_token": apiToken})
}

func (v *ProviderVerifierDispatcher) VerifyCredentials(
	ctx context.Context,
	providerType string,
	credentials map[string]string,
) error {
	switch providerType {
	case "cloudflare":
		apiToken, err := exactCredential(credentials, "api_token")
		if err != nil {
			return err
		}
		if ctx == nil {
			return ErrProviderVerificationUnavailable
		}
		if v.cloudflare == nil {
			return ErrProviderVerificationUnavailable
		}
		return v.cloudflare.Verify(ctx, providerType, apiToken)
	case "aliyun":
		accessKeyID, accessKeySecret, err := exactAliyunCredentials(credentials)
		if err != nil {
			return err
		}
		if ctx == nil {
			return ErrProviderVerificationUnavailable
		}
		if v.aliyun == nil {
			return ErrProviderVerificationUnavailable
		}
		return v.aliyun.Verify(ctx, accessKeyID, accessKeySecret)
	case "huawei":
		credentials, err := exactHuaweiCredentials(credentials)
		if err != nil {
			return err
		}
		if ctx == nil {
			return ErrProviderVerificationUnavailable
		}
		if v.huawei == nil {
			return ErrProviderVerificationUnavailable
		}
		return v.huawei.Verify(
			ctx,
			credentials.region,
			credentials.projectID,
			credentials.accessKey,
			credentials.secretKey,
		)
	case "dnspod_cn":
		dpID, dpKey, err := exactDNSPodCredentials(credentials)
		if err != nil {
			return err
		}
		if ctx == nil {
			return ErrProviderVerificationUnavailable
		}
		if v.dnspod == nil {
			return ErrProviderVerificationUnavailable
		}
		return v.dnspod.Verify(ctx, dpID, dpKey)
	case "dns_com":
		apiKey, apiSecret, err := exactDNSComCredentials(credentials)
		if err != nil {
			return err
		}
		if ctx == nil {
			return ErrProviderVerificationUnavailable
		}
		if v.dnscom == nil {
			return ErrProviderVerificationUnavailable
		}
		return v.dnscom.Verify(ctx, apiKey, apiSecret)
	case "dns_la":
		apiID, apiSecret, err := exactDNSLACredentials(credentials)
		if err != nil {
			return err
		}
		if ctx == nil {
			return ErrProviderVerificationUnavailable
		}
		if v.dnsla == nil {
			return ErrProviderVerificationUnavailable
		}
		return v.dnsla.Verify(ctx, apiID, apiSecret)
	case "namecom":
		username, apiToken, err := exactNameComCredentials(credentials)
		if err != nil {
			return err
		}
		if ctx == nil || v.namecom == nil {
			return ErrProviderVerificationUnavailable
		}
		return v.namecom.Verify(ctx, username, apiToken)
	case dnscustomhttp.ProviderType:
		if _, _, err := dnscustomhttp.Credentials(credentials); err != nil {
			return ErrProviderCredentialsInvalid
		}
		if ctx == nil {
			return ErrProviderVerificationUnavailable
		}
		return verifyCustomHTTP(ctx, credentials, v.customHTTP)
	case ProviderTypePlugin:
		if len(credentials) != 1 || !validPluginProviderID(credentials[PluginCredentialField]) || ctx == nil {
			return ErrProviderCredentialsInvalid
		}
		return verifyDNSPlugin(ctx, credentials[PluginCredentialField])
	default:
		return ErrProviderVerificationUnsupported
	}
}

func parseProviderCredentials(raw []byte) (map[string]string, error) {
	var credentials map[string]string
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	if err := decoder.Decode(&credentials); err != nil || credentials == nil {
		return nil, ErrProviderCredentialsInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrProviderCredentialsInvalid
	}
	return credentials, nil
}

func exactCredential(credentials map[string]string, field string) (string, error) {
	if len(credentials) != 1 {
		return "", ErrProviderCredentialsInvalid
	}
	value, exists := credentials[field]
	if !exists || value == "" || value != strings.TrimSpace(value) {
		return "", ErrProviderCredentialsInvalid
	}
	return value, nil
}

func exactAliyunCredentials(credentials map[string]string) (string, string, error) {
	if len(credentials) != 2 {
		return "", "", ErrProviderCredentialsInvalid
	}
	accessKeyID, idExists := credentials["access_key_id"]
	accessKeySecret, secretExists := credentials["access_key_secret"]
	if !idExists || !secretExists || accessKeyID == "" || accessKeySecret == "" ||
		accessKeyID != strings.TrimSpace(accessKeyID) || accessKeySecret != strings.TrimSpace(accessKeySecret) {
		return "", "", ErrProviderCredentialsInvalid
	}
	return accessKeyID, accessKeySecret, nil
}

type huaweiCredentials struct {
	accessKey string
	secretKey string
	region    string
	projectID string
}

func exactHuaweiCredentials(credentials map[string]string) (huaweiCredentials, error) {
	if len(credentials) != 4 {
		return huaweiCredentials{}, ErrProviderCredentialsInvalid
	}
	result := huaweiCredentials{
		accessKey: credentials["access_key"],
		secretKey: credentials["secret_key"],
		region:    credentials["region"],
		projectID: credentials["project_id"],
	}
	if _, exists := credentials["access_key"]; !exists || !huaweiAccessKeyPattern.MatchString(result.accessKey) {
		return huaweiCredentials{}, ErrProviderCredentialsInvalid
	}
	if _, exists := credentials["secret_key"]; !exists || !validHuaweiSecret(result.secretKey, 256) {
		return huaweiCredentials{}, ErrProviderCredentialsInvalid
	}
	if _, exists := credentials["region"]; !exists {
		return huaweiCredentials{}, ErrProviderCredentialsInvalid
	}
	if _, exists := huaweiDNSHost(result.region); !exists {
		return huaweiCredentials{}, ErrProviderCredentialsInvalid
	}
	if _, exists := credentials["project_id"]; !exists || !huaweiProjectIDPattern.MatchString(result.projectID) {
		return huaweiCredentials{}, ErrProviderCredentialsInvalid
	}
	return result, nil
}

func validHuaweiSecret(value string, maximumLength int) bool {
	if len(value) < 1 || len(value) > maximumLength || value != strings.TrimSpace(value) {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func exactDNSPodCredentials(credentials map[string]string) (string, string, error) {
	if len(credentials) != 2 {
		return "", "", ErrProviderCredentialsInvalid
	}
	dpID, idExists := credentials["dp_id"]
	dpKey, keyExists := credentials["dp_key"]
	if !idExists || !dnspodIDPattern.MatchString(dpID) || !keyExists || !validDNSPodKey(dpKey) {
		return "", "", ErrProviderCredentialsInvalid
	}
	return dpID, dpKey, nil
}

func validDNSPodKey(value string) bool {
	if len(value) < 1 || len(value) > 256 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e || value[index] == ',' {
			return false
		}
	}
	return true
}

// DNS.COM credentials carry an optional plan tier (free/enterprise/flagship,
// absent = free) that opens DNS lines (dnsproviderremote.DNSComPlanLines).
func exactDNSComCredentials(credentials map[string]string) (string, string, error) {
	fields := 2
	if plan, ok := credentials["plan"]; ok {
		if plan != "free" && plan != "enterprise" && plan != "flagship" {
			return "", "", ErrProviderCredentialsInvalid
		}
		fields = 3
	}
	if len(credentials) != fields {
		return "", "", ErrProviderCredentialsInvalid
	}
	apiKey, keyExists := credentials["api_key"]
	apiSecret, secretExists := credentials["api_secret"]
	if !keyExists || !validDNSComCredential(apiKey, 128, true) ||
		!secretExists || !validDNSComCredential(apiSecret, 256, false) {
		return "", "", ErrProviderCredentialsInvalid
	}
	return apiKey, apiSecret, nil
}

func exactDNSLACredentials(credentials map[string]string) (string, string, error) {
	if len(credentials) != 2 {
		return "", "", ErrProviderCredentialsInvalid
	}
	apiID, idExists := credentials["api_id"]
	apiSecret, secretExists := credentials["api_secret"]
	if !idExists || !validDNSLAUser(apiID) || !secretExists || !validDNSLAPassword(apiSecret) {
		return "", "", ErrProviderCredentialsInvalid
	}
	return apiID, apiSecret, nil
}

func validDNSComCredential(value string, maximumLength int, rejectPairDelimiters bool) bool {
	if len(value) < 1 || len(value) > maximumLength {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e ||
			(rejectPairDelimiters && (value[index] == '&' || value[index] == '=')) {
			return false
		}
	}
	return true
}

// verifyCustomHTTP calls the endpoint's verify action with the credentials.
func verifyCustomHTTP(ctx context.Context, credentials map[string]string, options *dnscustomhttp.Options) error {
	var effective dnscustomhttp.Options
	if options != nil {
		effective = *options
	}
	client, err := dnscustomhttp.New(credentials, effective)
	if err != nil {
		return ErrProviderCredentialsInvalid
	}
	defer client.Close()
	err = client.Verify(ctx)
	switch {
	case err == nil:
		return nil
	case ctx.Err() != nil:
		return ctx.Err()
	case errors.Is(err, dnscustomhttp.ErrUnauthorized), errors.Is(err, dnscustomhttp.ErrRejected):
		return ErrProviderCredentialsRejected
	case errors.Is(err, dnscustomhttp.ErrRateLimited):
		return ErrProviderVerificationRateLimited
	case errors.Is(err, dnscustomhttp.ErrTimeout):
		return ErrProviderVerificationTimeout
	case errors.Is(err, dnscustomhttp.ErrMalformed):
		return ErrProviderVerificationInvalidResponse
	default:
		return ErrProviderVerificationUnavailable
	}
}
