package originauth

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestS3OfficialSDKVector(t *testing.T) {
	now := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	signer := testSigner(t, ProviderS3, now, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "aws-session-token")
	request := mustRequest(t, http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/test.txt?response-content-type=text%2Fplain&versionId=3")
	request.Header.Set("Range", "bytes=0-9")
	if err := signer.Sign("rule-s3", request); err != nil {
		t.Fatal(err)
	}
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=e637c69d93c63e87339a2ce146479644c988dac1da750c997a17c4860d68ce92"
	if got := request.Header.Get("Authorization"); got != want {
		t.Fatalf("S3 authorization mismatch\n got: %s\nwant: %s", got, want)
	}
	if request.Header.Get("X-Amz-Date") != "20130524T000000Z" || request.Header.Get("X-Amz-Security-Token") != "aws-session-token" || request.Header.Get("Range") != "bytes=0-9" {
		t.Fatalf("S3 signed headers missing: %#v", request.Header)
	}
}

func TestOSSOfficialSDKVector(t *testing.T) {
	now := time.Unix(1702743657, 0).UTC()
	signer := testSigner(t, ProviderOSS, now, "ak", "sk", "oss-session-token")
	request := mustRequest(t, http.MethodGet, "https://bucket.oss-cn-hangzhou.aliyuncs.com/1234%2B-/123/1.txt?acl&versionId=versionId")
	request.Header.Set("Range", "bytes=0-9")
	if err := signer.Sign("rule-oss", request); err != nil {
		t.Fatal(err)
	}
	want := "OSS4-HMAC-SHA256 Credential=ak/20231216/cn-hangzhou/oss/aliyun_v4_request,AdditionalHeaders=host;range,Signature=ac22526a736f3a1efe2c6253b05ec249dee9dd09a2d9ddd405700afa8054dd90"
	if got := request.Header.Get("Authorization"); got != want {
		t.Fatalf("OSS authorization mismatch\n got: %s\nwant: %s", got, want)
	}
	if request.Header.Get("X-Oss-Date") != "20231216T162057Z" || request.Header.Get("X-Oss-Security-Token") != "oss-session-token" || request.Header.Get("Range") != "bytes=0-9" {
		t.Fatalf("OSS signed headers missing: %#v", request.Header)
	}
}

func TestCOSOfficialSDKVector(t *testing.T) {
	now := time.Unix(1480932292, 0).UTC()
	headers := map[string]string{
		"host":                "testbucket-125000000.cos.ap-guangzhou.myqcloud.com",
		"x-cos-content-sha1":  "db8ac1c259eb89d4a131b253bacfca5f319d54f2",
		"x-cos-stroage-class": "nearline",
	}
	credential := Credential{AccessKeyID: "QmFzZTY0IGlzIGEgZ2VuZXJp", SecretAccessKey: "AKIDZfbOA78asKUYBcXFrJD0a1ICvR98JM"}
	got, err := cosAuthorization(http.MethodPut, "/testfile2", nil, headers, credential, now, 80000)
	if err != nil {
		t.Fatal(err)
	}
	want := "q-sign-algorithm=sha1&q-ak=QmFzZTY0IGlzIGEgZ2VuZXJp&q-sign-time=1480932292;1481012292&q-key-time=1480932292;1481012292&q-header-list=host;x-cos-content-sha1;x-cos-stroage-class&q-url-param-list=&q-signature=ce4ac0ecbcdb30538b3fee0a97cc6389694ce53a"
	if got != want {
		t.Fatalf("COS authorization mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestSignerSupportsGETHEADRangeAndSessionTokens(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	for _, provider := range []string{ProviderS3, ProviderOSS, ProviderCOS} {
		t.Run(provider, func(t *testing.T) {
			signer := testSigner(t, provider, now, provider+"-access", provider+"-secret", provider+"-token")
			rule := signer.rules["rule-"+provider]
			request := mustRequest(t, http.MethodHead, "https://"+rule.Endpoint.Host+"/asset.txt?versionId=one")
			request.Header.Set("Range", "bytes=-128")
			if err := signer.Sign(rule.RuleID, request); err != nil {
				t.Fatal(err)
			}
			if request.Host != rule.Endpoint.Host || request.Header.Get("Host") != rule.Endpoint.Host || request.Header.Get("Range") != "bytes=-128" {
				t.Fatalf("request binding not preserved: host=%q headers=%#v", request.Host, request.Header)
			}
			authorization := request.Header.Get("Authorization")
			switch provider {
			case ProviderS3:
				if !strings.Contains(authorization, "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date;x-amz-security-token") || request.Header.Get("X-Amz-Security-Token") != provider+"-token" {
					t.Fatalf("S3 token or range was not signed: %s", authorization)
				}
			case ProviderOSS:
				if !strings.Contains(authorization, "AdditionalHeaders=host;range") || request.Header.Get("X-Oss-Security-Token") != provider+"-token" {
					t.Fatalf("OSS token or range was not signed: %s", authorization)
				}
			case ProviderCOS:
				if !strings.Contains(authorization, "q-header-list=host;range;x-cos-security-token") || request.Header.Get("X-Cos-Security-Token") != provider+"-token" {
					t.Fatalf("COS token or range was not signed: %s", authorization)
				}
			}
		})
	}
}

func TestSignerRejectsAmbiguousOrUnsafeRequests(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	directory := testSecretDirectory(t)
	path := writeTestCredential(t, directory, "s3.json", ProviderS3, "access", "secret", "token", 0, 4102444800)
	rule := testRule(ProviderS3, path)
	rule.PathPrefix = "/private/"
	_, policy := compileTestPolicy(t, 1, rule)
	signer, err := NewSigner(policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	host := policy.Rules[0].Endpoint.Host

	tests := map[string]func() *http.Request{
		"post": func() *http.Request { return mustRequest(t, http.MethodPost, "https://"+host+"/private/file") },
		"body": func() *http.Request {
			request := mustRequest(t, http.MethodGet, "https://"+host+"/private/file")
			request.Body = io.NopCloser(strings.NewReader(""))
			return request
		},
		"http":           func() *http.Request { return mustRequest(t, http.MethodGet, "http://"+host+"/private/file") },
		"wrong url host": func() *http.Request { return mustRequest(t, http.MethodGet, "https://other.example/private/file") },
		"wrong host header": func() *http.Request {
			request := mustRequest(t, http.MethodGet, "https://"+host+"/private/file")
			request.Host = "other.example"
			return request
		},
		"authorization conflict": func() *http.Request {
			request := mustRequest(t, http.MethodGet, "https://"+host+"/private/file")
			request.Header.Set("Authorization", "client-value")
			return request
		},
		"provider header conflict": func() *http.Request {
			request := mustRequest(t, http.MethodGet, "https://"+host+"/private/file")
			request.Header.Set("X-Amz-Date", "client-value")
			return request
		},
		"outside prefix": func() *http.Request { return mustRequest(t, http.MethodGet, "https://"+host+"/public/file") },
		"repeated slash": func() *http.Request { return mustRequest(t, http.MethodGet, "https://"+host+"/private//file") },
		"dot segment": func() *http.Request {
			return &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: host, Path: "/private/../file"}, Header: make(http.Header)}
		},
		"encoded slash":     func() *http.Request { return mustRequest(t, http.MethodGet, "https://"+host+"/private/a%2Fb") },
		"encoded backslash": func() *http.Request { return mustRequest(t, http.MethodGet, "https://"+host+"/private/a%5Cb") },
		"literal backslash": func() *http.Request {
			return &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: host, Path: `/private/a\b`}, Header: make(http.Header)}
		},
		"duplicate query": func() *http.Request { return mustRequest(t, http.MethodGet, "https://"+host+"/private/file?a=1&%61=2") },
		"plus query":      func() *http.Request { return mustRequest(t, http.MethodGet, "https://"+host+"/private/file?a+b=1") },
		"credential query": func() *http.Request {
			return mustRequest(t, http.MethodGet, "https://"+host+"/private/file?X-Amz-Signature=value")
		},
		"control query": func() *http.Request { return mustRequest(t, http.MethodGet, "https://"+host+"/private/file?a=%0A") },
		"invalid query escape": func() *http.Request {
			return &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: host, Path: "/private/file", RawQuery: "a=%ZZ"}, Header: make(http.Header)}
		},
		"multiple ranges": func() *http.Request {
			request := mustRequest(t, http.MethodGet, "https://"+host+"/private/file")
			request.Header.Set("Range", "bytes=0-1,4-5")
			return request
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			request := build()
			beforeAuthorization := request.Header.Get("Authorization")
			if err := signer.Sign("rule-s3", request); err == nil {
				t.Fatal("unsafe request accepted")
			}
			if request.Header.Get("Authorization") != beforeAuthorization {
				t.Fatal("rejected request was partially signed")
			}
		})
	}
}

func TestCredentialValidityAndRotationHaveNoFallback(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	directory := testSecretDirectory(t)
	currentPath := writeTestCredential(t, directory, "current.json", ProviderS3, "current-access", "current-secret", "", 0, now.Unix()+3600)
	previousPath := writeTestCredential(t, directory, "previous.json", ProviderS3, "previous-access", "previous-secret", "", 0, now.Unix()+3600)
	rule := testRule(ProviderS3, currentPath)
	rule.PreviousKey = &KeyRef{KeyID: "previous", SecretFile: previousPath}
	rule.ActivateCurrentAtUnix = now.Unix()
	_, policy := compileTestPolicy(t, 1, rule)

	clock := now.Add(-time.Second)
	signer, err := NewSigner(policy, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	before := mustRequest(t, http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/object")
	if err := signer.Sign("rule-s3", before); err != nil || !strings.Contains(before.Header.Get("Authorization"), "Credential=previous-access/") {
		t.Fatalf("previous key was not used before cutover: %v %s", err, before.Header.Get("Authorization"))
	}

	clock = now
	after := mustRequest(t, http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/object")
	if err := signer.Sign("rule-s3", after); err != nil || !strings.Contains(after.Header.Get("Authorization"), "Credential=current-access/") {
		t.Fatalf("current key was not used at cutover: %v %s", err, after.Header.Get("Authorization"))
	}

	if err := os.WriteFile(currentPath, []byte(`{"invalid":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	failed := mustRequest(t, http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/object")
	err = signer.Sign("rule-s3", failed)
	if err == nil || rejectionCode(t, err) != "CREDENTIAL_BINDING_MISMATCH" || failed.Header.Get("Authorization") != "" {
		t.Fatalf("current key failure downgraded or partially signed: %v %#v", err, failed.Header)
	}
}

func TestCredentialTimeBounds(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	tests := []struct {
		name               string
		notBefore, expires int64
		code               string
	}{
		{name: "not yet valid", notBefore: now.Unix() + 1, expires: now.Unix() + 3600, code: "CREDENTIAL_NOT_YET_VALID"},
		{name: "expired", notBefore: 0, expires: now.Unix(), code: "CREDENTIAL_EXPIRED"},
		{name: "expires too soon", notBefore: 0, expires: now.Unix() + 600, code: "CREDENTIAL_EXPIRES_TOO_SOON"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := testSecretDirectory(t)
			path := writeTestCredential(t, directory, "credential.json", ProviderS3, "access", "secret", "token", test.notBefore, test.expires)
			_, policy := compileTestPolicy(t, 1, testRule(ProviderS3, path))
			signer, err := NewSigner(policy, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			err = signer.Sign("rule-s3", mustRequest(t, http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/object"))
			if err == nil || rejectionCode(t, err) != test.code {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
		})
	}
}

func TestSignerErrorsDoNotExposeCredentials(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	accessKey := "ACCESS_MUST_NOT_LEAK"
	secretKey := "SECRET_MUST_NOT_LEAK"
	token := "TOKEN_MUST_NOT_LEAK"
	directory := testSecretDirectory(t)
	path := writeTestCredential(t, directory, "credential.json", ProviderS3, accessKey, secretKey, token, 0, now.Unix()+300)
	_, policy := compileTestPolicy(t, 1, testRule(ProviderS3, path))
	signer, err := NewSigner(policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	err = signer.Sign("rule-s3", mustRequest(t, http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/private-name"))
	if err == nil {
		t.Fatal("near-expiry credential accepted")
	}
	for _, value := range []string{accessKey, secretKey, token, "private-name", path} {
		if strings.Contains(err.Error(), value) {
			t.Fatalf("error exposed sensitive value %q: %v", value, err)
		}
	}
}

func TestConcurrentSigning(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	signer := testSigner(t, ProviderS3, now, "access", "secret", "token")
	var wait sync.WaitGroup
	errors := make(chan error, 128)
	for index := 0; index < cap(errors); index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			request := mustRequest(t, http.MethodGet, fmt.Sprintf("https://examplebucket.s3.us-east-1.amazonaws.com/object-%d?a=%d", index, index))
			if err := signer.Sign("rule-s3", request); err != nil {
				errors <- err
				return
			}
			if request.Header.Get("Authorization") == "" {
				errors <- fmt.Errorf("request %d has no authorization", index)
			}
		}(index)
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

func testSigner(t *testing.T, provider string, now time.Time, accessKey, secretKey, token string) *Signer {
	t.Helper()
	directory := testSecretDirectory(t)
	path := writeTestCredential(t, directory, provider+".json", provider, accessKey, secretKey, token, 0, 4102444800)
	_, policy := compileTestPolicy(t, 1, testRule(provider, path))
	signer, err := NewSigner(policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func mustRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}
