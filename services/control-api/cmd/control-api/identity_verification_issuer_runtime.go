package main

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsretry "github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverificationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverificationissuerhttp"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	identityVerificationIssuerEnabledEnv       = "IDENTITY_VERIFICATION_ISSUER_ENABLED"
	identityVerificationIssuerListenAddressEnv = "IDENTITY_VERIFICATION_ISSUER_MTLS_LISTEN_ADDR"
	identityVerificationIssuerServerCertEnv    = "IDENTITY_VERIFICATION_ISSUER_MTLS_SERVER_CERT_FILE"
	identityVerificationIssuerServerKeyEnv     = "IDENTITY_VERIFICATION_ISSUER_MTLS_SERVER_PRIVATE_KEY_FILE"
	identityVerificationIssuerClientCAEnv      = "IDENTITY_VERIFICATION_ISSUER_MTLS_CLIENT_CA_FILE"
	identityVerificationIssuerIdentitiesEnv    = "IDENTITY_VERIFICATION_ISSUER_WORKLOAD_IDENTITIES"
	identityVerificationIssuerKMSEndpointEnv   = "IDENTITY_VERIFICATION_ISSUER_KMS_ENDPOINT"
)

var identityVerificationIssuerEnvironmentNames = []string{
	identityVerificationIssuerEnabledEnv, identityVerificationIssuerListenAddressEnv,
	identityVerificationIssuerServerCertEnv, identityVerificationIssuerServerKeyEnv,
	identityVerificationIssuerClientCAEnv, identityVerificationIssuerIdentitiesEnv,
	identityVerificationIssuerKMSEndpointEnv,
}

type identityVerificationIssuerEnvironment struct {
	Enabled            bool
	ListenAddress      string
	ServerCertificate  string
	ServerPrivateKey   string
	ClientCA           string
	WorkloadIdentities []identityverificationissuerhttp.WorkloadIdentity
	KMSEndpoint        string
}

func loadIdentityVerificationIssuerEnvironment(environment []string) (identityVerificationIssuerEnvironment, error) {
	values := make(map[string]string, len(identityVerificationIssuerEnvironmentNames))
	known := make(map[string]struct{}, len(identityVerificationIssuerEnvironmentNames))
	for _, name := range identityVerificationIssuerEnvironmentNames {
		known[name] = struct{}{}
	}
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found || !strings.HasPrefix(name, "IDENTITY_VERIFICATION_ISSUER_") {
			continue
		}
		if _, ok := known[name]; !ok {
			return identityVerificationIssuerEnvironment{}, errors.New("unsupported identity verification issuer environment variable")
		}
		if _, duplicate := values[name]; duplicate {
			return identityVerificationIssuerEnvironment{}, errors.New("identity verification issuer environment variable is duplicated")
		}
		values[name] = value
	}
	enabled, err := identityVerificationBool(identityVerificationIssuerEnabledEnv, values[identityVerificationIssuerEnabledEnv])
	if err != nil || !enabled {
		return identityVerificationIssuerEnvironment{}, err
	}
	for _, name := range []string{identityVerificationIssuerListenAddressEnv, identityVerificationIssuerServerCertEnv,
		identityVerificationIssuerServerKeyEnv, identityVerificationIssuerClientCAEnv, identityVerificationIssuerIdentitiesEnv} {
		if values[name] == "" || strings.TrimSpace(values[name]) != values[name] {
			return identityVerificationIssuerEnvironment{}, errors.New(name + " is required for the issuer")
		}
	}
	identities, err := parseIdentityVerificationIssuerIdentities(values[identityVerificationIssuerIdentitiesEnv])
	if err != nil {
		return identityVerificationIssuerEnvironment{}, err
	}
	if _, err := identityverificationissuerhttp.NewMTLSAuthenticator(identities, time.Now); err != nil {
		return identityVerificationIssuerEnvironment{}, errors.New(identityVerificationIssuerIdentitiesEnv + " is invalid")
	}
	if endpoint := values[identityVerificationIssuerKMSEndpointEnv]; endpoint != "" {
		parsed, parseErr := url.Parse(endpoint)
		if parseErr != nil || parsed == nil {
			return identityVerificationIssuerEnvironment{}, errors.New(identityVerificationIssuerKMSEndpointEnv + " is invalid")
		}
		secureEndpoint := parsed.Scheme == "https" || parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())
		if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
			parsed.Path != "" || !secureEndpoint {
			return identityVerificationIssuerEnvironment{}, errors.New(identityVerificationIssuerKMSEndpointEnv + " is invalid")
		}
	}
	return identityVerificationIssuerEnvironment{
		Enabled: enabled, ListenAddress: values[identityVerificationIssuerListenAddressEnv],
		ServerCertificate: values[identityVerificationIssuerServerCertEnv], ServerPrivateKey: values[identityVerificationIssuerServerKeyEnv],
		ClientCA: values[identityVerificationIssuerClientCAEnv], WorkloadIdentities: identities,
		KMSEndpoint: values[identityVerificationIssuerKMSEndpointEnv],
	}, nil
}

func parseIdentityVerificationIssuerIdentities(raw string) ([]identityverificationissuerhttp.WorkloadIdentity, error) {
	parts := strings.Split(raw, ",")
	if len(parts) == 0 || len(parts) > 1024 {
		return nil, errors.New(identityVerificationIssuerIdentitiesEnv + " is invalid")
	}
	result := make([]identityverificationissuerhttp.WorkloadIdentity, 0, len(parts))
	seenURIs, seenWorkloads := make(map[string]struct{}, len(parts)), make(map[string]struct{}, len(parts))
	for _, part := range parts {
		uri, workloadID, ok := strings.Cut(part, "|")
		if !ok || uri == "" || workloadID == "" || strings.Contains(workloadID, "|") ||
			strings.TrimSpace(uri) != uri || strings.TrimSpace(workloadID) != workloadID {
			return nil, errors.New(identityVerificationIssuerIdentitiesEnv + " is invalid")
		}
		if _, duplicate := seenURIs[uri]; duplicate {
			return nil, errors.New(identityVerificationIssuerIdentitiesEnv + " is invalid")
		}
		if _, duplicate := seenWorkloads[workloadID]; duplicate {
			return nil, errors.New(identityVerificationIssuerIdentitiesEnv + " is invalid")
		}
		seenURIs[uri], seenWorkloads[workloadID] = struct{}{}, struct{}{}
		result = append(result, identityverificationissuerhttp.WorkloadIdentity{URI: uri, WorkloadID: workloadID})
	}
	return result, nil
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

type identityVerificationIssuerRuntime struct {
	listener *identityverificationissuerhttp.Listener
}

func openIdentityVerificationIssuerRuntime(ctx context.Context, pool *pgxpool.Pool,
	providerEnvironment identityVerificationProviderEnvironment,
	clock identityverification.Clock, source identityVerificationEvidenceSource,
) (*identityVerificationIssuerRuntime, error) {
	issuerEnvironment, err := loadIdentityVerificationIssuerEnvironment(os.Environ())
	if err != nil {
		return nil, err
	}
	if !issuerEnvironment.Enabled {
		if providerEnvironment.Enabled {
			return nil, errors.New(identityVerificationIssuerEnabledEnv + " must be true for the provider workflow")
		}
		return nil, nil
	}
	if !providerEnvironment.Enabled || pool == nil || clock == nil || source == nil {
		return nil, errors.New("identity verification issuer dependencies are incomplete")
	}
	issuer, ok := source.(interface {
		IssuePrincipal(context.Context, identityverificationhttp.RuntimeEvidencePrincipal,
			identityverificationhttp.RuntimeEvidenceIssueRequest) (identityverificationhttp.RuntimeEvidenceIssueResult, error)
	})
	if !ok {
		return nil, errors.New("identity verification durable source cannot issue workload evidence")
	}
	credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: string(providerEnvironment.ObjectAccessKey),
			SecretAccessKey: string(providerEnvironment.ObjectSecretKey),
			SessionToken:    string(providerEnvironment.ObjectSessionToken),
			Source:          "identity-verification-issuer"}, nil
	})
	awsConfig := aws.Config{Region: providerEnvironment.ObjectRegion,
		Credentials: aws.NewCredentialsCache(credentials), HTTPClient: http.DefaultClient,
		Retryer: func() aws.Retryer {
			return awsretry.NewStandard(func(options *awsretry.StandardOptions) { options.MaxAttempts = 3 })
		}}
	kmsClient := kms.NewFromConfig(awsConfig, func(options *kms.Options) {
		if issuerEnvironment.KMSEndpoint != "" {
			options.BaseEndpoint = aws.String(issuerEnvironment.KMSEndpoint)
		}
	})
	sealer, err := identityverificationissuerhttp.NewKMSMaterialEnvelopeSealer(kmsClient)
	if err != nil {
		return nil, errors.New("initialize identity verification KMS sealer")
	}
	resolver, err := identityverificationissuerhttp.NewPostgresEvidenceResolver(pool, sealer, audit.New(pool))
	if err != nil {
		return nil, errors.New("initialize identity verification evidence resolver")
	}
	issuerClock := identityverificationissuerhttp.Clock(clock)
	authenticator, err := identityverificationissuerhttp.NewMTLSAuthenticator(issuerEnvironment.WorkloadIdentities, issuerClock)
	if err != nil {
		return nil, errors.New("initialize identity verification issuer workload identity")
	}
	handler, err := identityverificationissuerhttp.NewHandler(identityverificationissuerhttp.Dependencies{
		Authenticator: authenticator, Resolver: resolver, Issuer: issuer, Clock: issuerClock,
	})
	if err != nil {
		return nil, errors.New("initialize identity verification issuer handler")
	}
	listener, err := identityverificationissuerhttp.NewListener(ctx, identityverificationissuerhttp.ListenerConfig{
		ListenAddress: issuerEnvironment.ListenAddress, ServerCertificateFile: issuerEnvironment.ServerCertificate,
		ServerPrivateKeyFile: issuerEnvironment.ServerPrivateKey, ClientCAFile: issuerEnvironment.ClientCA, Clock: issuerClock,
	}, handler)
	if err != nil {
		return nil, errors.New("initialize identity verification issuer mTLS listener")
	}
	return &identityVerificationIssuerRuntime{listener: listener}, nil
}

func (runtime *identityVerificationIssuerRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.listener == nil {
		return errors.New("identity verification issuer runtime is unavailable")
	}
	return runtime.listener.Run(ctx)
}

func (runtime *identityVerificationIssuerRuntime) Ready() error {
	if runtime == nil || runtime.listener == nil {
		return errors.New("identity verification issuer runtime is unavailable")
	}
	return runtime.listener.Ready()
}

func (runtime *identityVerificationIssuerRuntime) Close() error {
	if runtime == nil || runtime.listener == nil {
		return nil
	}
	return runtime.listener.Close()
}
