package acmeruntime

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
)

func TestCanonicalKeyReferencesBindTenantPurposeAndIdentity(t *testing.T) {
	tenantID := uuid.New()
	otherTenantID := uuid.New()
	orderID := uuid.New()
	directoryURL := "https://ca.example/directory"

	accountRef, err := AccountKeyRef(tenantID, directoryURL)
	if err != nil {
		t.Fatal(err)
	}
	certificateRef, err := CertificateKeyRef(tenantID, orderID)
	if err != nil {
		t.Fatal(err)
	}
	otherAccountRef, err := AccountKeyRef(otherTenantID, directoryURL)
	if err != nil {
		t.Fatal(err)
	}
	if accountRef == otherAccountRef || accountRef == certificateRef {
		t.Fatal("canonical references did not isolate tenant and purpose")
	}
	parsedTenant, purpose, suffix, err := parseKeyRef(accountRef)
	if err != nil || parsedTenant != tenantID || purpose != purposeAccount || len(suffix) != sha256.Size*2 {
		t.Fatalf("parse account ref = %s %s %q %v", parsedTenant, purpose, suffix, err)
	}
	parsedTenant, purpose, suffix, err = parseKeyRef(certificateRef)
	if err != nil || parsedTenant != tenantID || purpose != purposeCertificate || suffix != orderID.String() {
		t.Fatalf("parse certificate ref = %s %s %q %v", parsedTenant, purpose, suffix, err)
	}
	for _, invalid := range []string{
		"", "acme:v2:" + tenantID.String() + ":certificate:" + orderID.String(),
		"acme:v1:" + tenantID.String() + ":account:not-a-digest",
		"acme:v1:" + tenantID.String() + ":other:" + orderID.String(),
	} {
		if _, _, _, err := parseKeyRef(invalid); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("parseKeyRef(%q) error = %v", invalid, err)
		}
	}
}

func TestWrappingAADBindsEveryImmutableFact(t *testing.T) {
	tenantID := uuid.New()
	keyRef, err := CertificateKeyRef(tenantID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("public-key"))
	baseline, err := wrappingAAD(tenantID, purposeCertificate, keyRef, "ecdsa", digest[:], "kek-v1")
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		tenant      uuid.UUID
		purpose     keyPurpose
		keyRef      string
		algorithm   string
		digest      []byte
		wrappingKey string
	}{
		{uuid.New(), purposeCertificate, keyRef, "ecdsa", digest[:], "kek-v1"},
		{tenantID, purposeAccount, keyRef, "ecdsa", digest[:], "kek-v1"},
		{tenantID, purposeCertificate, keyRef + "x", "ecdsa", digest[:], "kek-v1"},
		{tenantID, purposeCertificate, keyRef, "rsa", digest[:], "kek-v1"},
		{tenantID, purposeCertificate, keyRef, "ecdsa", bytesOf(sha256.Size, 9), "kek-v1"},
		{tenantID, purposeCertificate, keyRef, "ecdsa", digest[:], "kek-v2"},
	}
	baselineDigest := sha256.Sum256(baseline)
	for index, mutation := range mutations {
		value, err := wrappingAAD(mutation.tenant, mutation.purpose, mutation.keyRef,
			mutation.algorithm, mutation.digest, mutation.wrappingKey)
		if err != nil {
			t.Fatalf("mutation %d: %v", index, err)
		}
		if sha256.Sum256(value) == baselineDigest {
			t.Fatalf("mutation %d did not change AAD", index)
		}
	}
}

func TestPKCS8SupportedSignerAlgorithms(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		key  crypto.Signer
		want string
	}{
		"ecdsa":   {ecdsaKey, "ecdsa"},
		"rsa":     {rsaKey, "rsa"},
		"ed25519": {ed25519Key, "ed25519"},
	} {
		t.Run(name, func(t *testing.T) {
			if signerAlgorithm(test.key) != test.want {
				t.Fatalf("algorithm = %q", signerAlgorithm(test.key))
			}
		})
	}
}

func TestFailureClassificationAndBackoff(t *testing.T) {
	workerError := &acmeworker.Error{
		Code: acmeworker.CodeRateLimited, Temporary: true, RetryAfter: 45 * time.Second,
	}
	code, retryAfter := classifyFailure(workerError)
	if code != string(acmeworker.CodeRateLimited) || retryAfter != 45*time.Second {
		t.Fatalf("classification = %q %s", code, retryAfter)
	}
	code, _ = classifyFailure(context.Canceled)
	if code != string(acmeworker.CodeCancelled) {
		t.Fatalf("cancelled code = %q", code)
	}
	code, _ = classifyFailure(codedError("acme_order_unavailable", ErrConflict))
	if code != "acme_order_unavailable" {
		t.Fatalf("runtime code = %q", code)
	}
	dispatcher := &Dispatcher{config: Config{RetryBase: time.Second, RetryMaximum: 5 * time.Second}}
	for attempt, want := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 4: 5 * time.Second} {
		if got := dispatcher.retryDelay(attempt); got != want {
			t.Fatalf("retryDelay(%d) = %s, want %s", attempt, got, want)
		}
	}
}

// fix-certstuck：worker 标为终态的失败（如签发的证书公钥不是本单密钥）要让调度
// 立即把订单转 failed，而不是按 acme_certificate_invalid 一直退避重试到用完 10 次。
func TestDispatchTerminalUsesWorkerTerminalFlag(t *testing.T) {
	if !dispatchTerminal(&acmeworker.Error{Code: acmeworker.CodeCertificateInvalid, Terminal: true}, "acme_certificate_invalid") {
		t.Fatal("worker terminal failure must be terminal for dispatch")
	}
	if dispatchTerminal(&acmeworker.Error{Code: acmeworker.CodeCertificateInvalid}, "acme_certificate_invalid") {
		t.Fatal("plain certificate_invalid stays retryable")
	}
	if !dispatchTerminal(&acmeworker.Error{Code: acmeworker.CodeOrderRejected}, "acme_order_rejected") {
		t.Fatal("listed terminal codes stay terminal")
	}
}

func TestValidIssueResultRejectsEmptySuccess(t *testing.T) {
	request, result := validIssueResultFixture25(t)
	if validIssueResult(acmeworker.IssueResult{}, request) {
		t.Fatal("empty issuer result was accepted")
	}
	if !validIssueResult(result, request) {
		t.Fatal("complete issuer result was rejected")
	}
}

func bytesOf(length int, value byte) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}

// DNS-SEC-20261027-01：租户订单引用平台 DNS 副本，重试也不会变，首次即终态。
func TestPlatformManagedDNSProviderIsTerminal(t *testing.T) {
	err := codedError(codeDNSProviderPlatformManaged, ErrConflict)
	code, _ := classifyFailure(err)
	if code != codeDNSProviderPlatformManaged || !validateErrorCode(code) || !dispatchTerminal(err, code) {
		t.Fatalf("code=%q terminal=%v", code, dispatchTerminal(err, code))
	}
}
