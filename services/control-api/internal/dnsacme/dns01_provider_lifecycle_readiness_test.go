package dnsacme

import (
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

type dns01ReadinessCipher struct {
	encryptCalls int
}

func (cipher *dns01ReadinessCipher) Encrypt([]byte) (string, []byte, error) {
	cipher.encryptCalls++
	return "test-key", []byte("ciphertext"), nil
}

func (*dns01ReadinessCipher) Decrypt(string, []byte) ([]byte, error) {
	return nil, errors.New("unused")
}
func (*dns01ReadinessCipher) IdempotencyDigest([]byte) [32]byte { return [32]byte{1} }

func TestDNS01ProviderCreateAndUpdateRequireExactCredentialSchemas(t *testing.T) {
	schemas := []struct {
		providerType string
		credentials  map[string]string
	}{
		{providerType: "aliyun", credentials: map[string]string{"access_key_id": "access-key-id", "access_key_secret": "access-key-secret"}},
		{providerType: "cloudflare", credentials: map[string]string{"api_token": "cloudflare-token"}},
		{providerType: "huawei", credentials: map[string]string{"access_key": "ak", "secret_key": "sk", "region": "cn-north-4", "project_id": "0123456789abcdef0123456789abcdef"}},
		{providerType: "dnspod_cn", credentials: map[string]string{"dp_id": "12345", "dp_key": "0123456789abcdef0123456789abcdef"}},
		{providerType: "dns_com", credentials: map[string]string{"api_key": "c7722149110b7492a2e5cf1d8f3f966b", "api_secret": "secret-value"}},
		{providerType: "dns_la", credentials: map[string]string{"api_id": "dnsla-api-id", "api_secret": "dnsla-api-secret"}},
		{providerType: "custom_http", credentials: map[string]string{"endpoint": "https://dns.example.net/cdnca", "secret": "custom-http-secret-01"}},
	}
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}

	for _, schema := range schemas {
		t.Run(schema.providerType, func(t *testing.T) {
			encoded, err := normalizeProviderCredentials(schema.providerType, schema.credentials)
			if err != nil {
				t.Fatalf("valid credentials rejected: %v", err)
			}
			decoded, err := parseProviderCredentials(encoded)
			if err != nil || !reflect.DeepEqual(decoded, schema.credentials) {
				t.Fatalf("normalized credentials = %#v, err=%v", decoded, err)
			}

			missing := cloneDNS01Credentials(schema.credentials)
			for key := range missing {
				delete(missing, key)
				break
			}
			invalid := []map[string]string{
				missing,
				func() map[string]string {
					value := cloneDNS01Credentials(schema.credentials)
					value["extra"] = "forbidden"
					return value
				}(),
				{"wrong_key": "wrong-value"},
			}
			for index, credentials := range invalid {
				if _, err := normalizeProviderCredentials(schema.providerType, credentials); !errors.Is(err, ErrInvalidInput) {
					t.Errorf("invalid[%d] normalization error = %v", index, err)
				}

				cipher := &dns01ReadinessCipher{}
				service := &Service{cipher: cipher}
				assertDNS01RejectedBeforeDependency(t, func() error {
					_, err := service.CreateProvider(t.Context(), actor, CreateProviderRequest{
						Name: "provider", ProviderType: schema.providerType, Credentials: credentials,
						IdempotencyKey: "create-key", RequestID: "create-request",
					})
					return err
				})
				assertDNS01RejectedBeforeDependency(t, func() error {
					_, err := service.UpdateProvider(t.Context(), actor, UpdateProviderRequest{
						ID: uuid.New(), ExpectedRevision: 1, Name: "provider", Status: ProviderStatusUnverified,
						Credentials: credentials, IdempotencyKey: "update-key", RequestID: "update-request",
					})
					return err
				})
				if cipher.encryptCalls != 0 {
					t.Fatalf("invalid[%d] encrypt calls = %d", index, cipher.encryptCalls)
				}
			}
		})
	}
}

func cloneDNS01Credentials(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func assertDNS01RejectedBeforeDependency(t *testing.T, call func() error) {
	t.Helper()
	defer func() {
		if value := recover(); value != nil {
			t.Fatalf("invalid credentials reached a dependency: %v", value)
		}
	}()
	if err := call(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid credentials error = %v", err)
	}
}
