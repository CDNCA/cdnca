package originauthverifier

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
)

type Verifier struct {
	config    Config
	resolver  Resolver
	dial      dialContextFunc
	providers map[string]providerVerifier
	semaphore chan struct{}
}

func New(config Config) (*Verifier, error) {
	return newVerifier(config, net.DefaultResolver, defaultDialer(config), map[string]providerVerifier{
		originauthcontrol.ProviderS3:  s3Verifier(config.MaxAttempts),
		originauthcontrol.ProviderOSS: newOSSVerifier(config.MaxAttempts),
		originauthcontrol.ProviderCOS: newCOSVerifier(config.MaxAttempts),
	})
}

func newVerifier(
	config Config,
	resolver Resolver,
	dial dialContextFunc,
	providers map[string]providerVerifier,
) (*Verifier, error) {
	if err := validateConfig(config); err != nil {
		return nil, ErrInvalidConfiguration
	}
	if resolver == nil || dial == nil || providers == nil {
		return nil, ErrInvalidConfiguration
	}
	config.RootCAs = cloneRoots(config.RootCAs)
	for _, provider := range []string{originauthcontrol.ProviderS3, originauthcontrol.ProviderOSS, originauthcontrol.ProviderCOS} {
		if providers[provider] == nil {
			return nil, ErrInvalidConfiguration
		}
	}
	return &Verifier{
		config: config, resolver: resolver, dial: dial, providers: providers,
		semaphore: make(chan struct{}, config.MaxConcurrent),
	}, nil
}

func (verifier *Verifier) Verify(ctx context.Context, request originauthcontrol.VerificationRequest) error {
	if verifier == nil || ctx == nil {
		return publicError(ErrInvalidConfiguration)
	}
	requestCtx, cancel := context.WithTimeout(ctx, verifier.config.RequestTimeout)
	defer cancel()
	if err := requestCtx.Err(); err != nil {
		return err
	}
	probe, found := verifier.probe(request.Provider)
	provider := verifier.providers[request.Provider]
	if !found || !probe.Enabled || provider == nil {
		return publicError(ErrInvalidConfiguration)
	}
	if !validProviderProbe(request.Provider, probe) {
		return publicError(ErrInvalidConfiguration)
	}
	if !validCredential(verifier.config, request.Credential) {
		return publicError(ErrCredentialRejected)
	}
	select {
	case verifier.semaphore <- struct{}{}:
		defer func() { <-verifier.semaphore }()
	case <-requestCtx.Done():
		return requestCtx.Err()
	}
	target, err := resolveProbe(requestCtx, probe, verifier.resolver)
	if err != nil {
		if requestCtx.Err() != nil {
			return requestCtx.Err()
		}
		return publicError(err)
	}
	client := newPinnedClient(verifier.config, target, verifier.dial)
	defer client.CloseIdleConnections()
	err = provider.verify(requestCtx, Probe{
		Endpoint: target.endpoint.String(), Region: probe.Region, Bucket: probe.Bucket, Object: probe.Object, Enabled: true,
	}, request.Credential, client)
	if transport, ok := client.Transport.(*boundedTransport); ok && transport.Failure() != nil {
		err = transport.Failure()
	}
	if requestCtx.Err() != nil {
		return requestCtx.Err()
	}
	return publicError(err)
}

func validProviderProbe(provider string, probe Probe) bool {
	switch provider {
	case originauthcontrol.ProviderS3:
		return validS3ProbeInput(probe)
	case originauthcontrol.ProviderOSS:
		return validOSSProbeInput(probe)
	case originauthcontrol.ProviderCOS:
		return validCOSProbeInput(probe)
	default:
		return false
	}
}

func (verifier *Verifier) probe(provider string) (Probe, bool) {
	switch provider {
	case originauthcontrol.ProviderS3:
		return verifier.config.S3, true
	case originauthcontrol.ProviderOSS:
		return verifier.config.OSS, true
	case originauthcontrol.ProviderCOS:
		return verifier.config.COS, true
	default:
		return Probe{}, false
	}
}

func validCredential(config Config, credential originauthcontrol.CredentialSecret) bool {
	if !validSecretField(credential.AccessKeyID, 256, false) ||
		!validSecretField(credential.SecretAccessKey, 1024, false) ||
		!validSecretField(credential.SessionToken, 4096, true) || credential.NotBefore.IsZero() ||
		credential.ExpiresAt.IsZero() || !credential.ExpiresAt.After(credential.NotBefore) {
		return false
	}
	now := config.Now().UTC()
	return !now.Before(credential.NotBefore.UTC()) && now.Before(credential.ExpiresAt.UTC())
}

func validSecretField(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func Classify(err error) Result {
	switch {
	case err == nil:
		return Result{Code: ResultAccepted}
	case errors.Is(err, ErrCredentialRejected), errors.Is(err, originauthcontrol.ErrVerificationRejected):
		return Result{Code: ResultCredentialRejected}
	case errors.Is(err, ErrInvalidConfiguration):
		return Result{Code: ResultInvalidConfiguration}
	default:
		return Result{Code: ResultProviderUnavailable, Retryable: true}
	}
}

type classifiedError struct {
	message string
	causes  []error
}

func (err classifiedError) Error() string   { return err.message }
func (err classifiedError) Unwrap() []error { return err.causes }

func publicError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	switch Classify(err).Code {
	case ResultCredentialRejected:
		return classifiedError{
			message: "origin credential rejected",
			causes:  []error{ErrCredentialRejected, originauthcontrol.ErrVerificationRejected},
		}
	case ResultInvalidConfiguration:
		return classifiedError{
			message: "invalid origin verifier configuration",
			causes:  []error{ErrInvalidConfiguration, originauthcontrol.ErrVerifierUnavailable},
		}
	default:
		return classifiedError{
			message: "origin provider unavailable",
			causes:  []error{ErrProviderUnavailable, originauthcontrol.ErrVerifierUnavailable},
		}
	}
}

func defaultDialer(config Config) dialContextFunc {
	dialer := &net.Dialer{Timeout: config.ConnectTimeout, KeepAlive: -1}
	return dialer.DialContext
}

var _ originauthcontrol.CredentialVerifier = (*Verifier)(nil)
var _ http.RoundTripper = (*boundedTransport)(nil)
