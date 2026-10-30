package errorpageobjectstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type credentialsProviderFunc func(context.Context) (aws.Credentials, error)

type pointerCredentialsProvider struct{}

func (*pointerCredentialsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "access", SecretAccessKey: "secret"}, nil
}

func (provider credentialsProviderFunc) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return provider(ctx)
}

func validConfig(endpoint string) Config {
	return Config{
		Endpoint: endpoint,
		Region:   "test-region-1",
		Bucket:   "error-pages",
		Prefix:   "control-api/error-pages",
		Credentials: credentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "explicit-access", SecretAccessKey: "explicit-secret"}, nil
		}),
		ConnectTimeout:        time.Second,
		TLSHandshakeTimeout:   time.Second,
		ResponseHeaderTimeout: time.Second,
		RequestTimeout:        5 * time.Second,
		MaxObjectSize:         1 << 20,
		MaxAttempts:           3,
	}
}

func TestValidateConfigRejectsUnsafeValues(t *testing.T) {
	t.Parallel()
	valid := validConfig("https://s3.example.test")
	tests := map[string]func(*Config){
		"remote http":      func(config *Config) { config.Endpoint = "http://s3.example.test" },
		"userinfo":         func(config *Config) { config.Endpoint = "https://user:pass@s3.example.test" },
		"query":            func(config *Config) { config.Endpoint = "https://s3.example.test?secret=value" },
		"fragment":         func(config *Config) { config.Endpoint = "https://s3.example.test/#secret" },
		"non-root path":    func(config *Config) { config.Endpoint = "https://s3.example.test/api" },
		"encoded path":     func(config *Config) { config.Endpoint = "https://s3.example.test/%2e" },
		"missing region":   func(config *Config) { config.Region = "" },
		"invalid bucket":   func(config *Config) { config.Bucket = "Bad_Bucket" },
		"ip bucket":        func(config *Config) { config.Bucket = "127.0.0.1" },
		"empty prefix":     func(config *Config) { config.Prefix = "" },
		"prefix traversal": func(config *Config) { config.Prefix = "control-api/../other" },
		"encoded prefix":   func(config *Config) { config.Prefix = "control-api/%2e%2e" },
		"no credentials":   func(config *Config) { config.Credentials = nil },
		"typed nil credentials": func(config *Config) {
			var provider *pointerCredentialsProvider
			config.Credentials = provider
		},
		"bad ca":          func(config *Config) { config.CACertificatePEM = []byte("not a certificate") },
		"connect timeout": func(config *Config) { config.ConnectTimeout = 0 },
		"tls timeout":     func(config *Config) { config.TLSHandshakeTimeout = 0 },
		"header timeout":  func(config *Config) { config.ResponseHeaderTimeout = 0 },
		"request timeout": func(config *Config) { config.RequestTimeout = 0 },
		"size cap":        func(config *Config) { config.MaxObjectSize = 0 },
		"attempt cap":     func(config *Config) { config.MaxAttempts = 0 },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			config := valid
			mutate(&config)
			if _, err := validateConfig(config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("validateConfig() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestCredentialsValidationFailsClosedAndRedactsProviderFailures(t *testing.T) {
	t.Parallel()
	const secret = "credential-provider-secret"
	tests := []credentialsProviderFunc{
		func(context.Context) (aws.Credentials, error) { return aws.Credentials{}, errors.New(secret) },
		func(context.Context) (aws.Credentials, error) { panic(secret) },
		func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: " access", SecretAccessKey: "secret"}, nil
		},
		func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "access", SecretAccessKey: "line\nbreak"}, nil
		},
	}
	for index, candidate := range tests {
		_, err := (validatingCredentials{provider: candidate}).Retrieve(t.Context())
		if !errors.Is(err, errCredentials) || strings.Contains(err.Error(), secret) {
			t.Fatalf("candidate %d error = %v, want redacted credential error", index, err)
		}
	}
}

func TestInvalidEndpointFormattingRedactsUserinfoQueryAndPath(t *testing.T) {
	t.Parallel()
	const secret = "endpoint-secret"
	config := validConfig("https://user:" + secret + "@s3.example.test/" + secret + "?token=" + secret)
	for _, output := range []string{fmt.Sprint(config), fmt.Sprintf("%#v", config)} {
		if strings.Contains(output, secret) || strings.Contains(output, "user:") {
			t.Fatalf("unsafe config representation: %q", output)
		}
	}
}

func TestValidateConfigAllowsOnlyNumericLoopbackHTTP(t *testing.T) {
	t.Parallel()
	for _, endpoint := range []string{"http://127.0.0.1:9000", "http://[::1]:9000", "https://s3.example.test/"} {
		config := validConfig(endpoint)
		if _, err := validateConfig(config); err != nil {
			t.Fatalf("validateConfig(%q) error = %v", endpoint, err)
		}
	}
	config := validConfig("http://localhost:9000")
	if _, err := validateConfig(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("validateConfig(localhost) error = %v, want ErrInvalidConfig", err)
	}
}

func TestConfigFormattingAndJSONRedactSecrets(t *testing.T) {
	t.Parallel()
	const secret = "do-not-render-this-secret"
	config := validConfig("https://s3.example.test")
	config.CACertificatePEM = []byte(secret)
	config.Credentials = credentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "access-" + secret, SecretAccessKey: secret, SessionToken: secret}, nil
	})
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	outputs := []string{fmt.Sprint(config), fmt.Sprintf("%#v", config), string(encoded)}
	for _, output := range outputs {
		if strings.Contains(output, secret) || strings.Contains(output, "credentialsProviderFunc") {
			t.Fatalf("config representation leaked a credential or provider type: %q", output)
		}
	}
}

func TestValidateObjectKeyRejectsAmbiguity(t *testing.T) {
	t.Parallel()
	for _, key := range []string{
		"", "/absolute", "../escape", "a/../b", "a/./b", "a//b", `a\\b`,
		"a/%2e%2e/b", "a/%252e/b", "a?query", "a#fragment", "a\x00b",
	} {
		if err := validateObjectKey(key); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("validateObjectKey(%q) error = %v, want ErrInvalidKey", key, err)
		}
	}
	for _, key := range []string{
		"error-pages/staging/019f9d75-486f-7df1-a972-112233445566",
		"error-pages/objects/019f9d75-486f-7df1-a972-112233445566/" + strings.Repeat("a", 64),
	} {
		if err := validateObjectKey(key); err != nil {
			t.Fatalf("validateObjectKey(%q) error = %v", key, err)
		}
	}
}
