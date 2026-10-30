package challenge

import (
	"context"
	"errors"
	"testing"
)

type verifierStub struct {
	result       ExternalResult
	err          error
	beforeReturn func()
	calls        int
}

func (stub *verifierStub) Verify(_ context.Context, _ ExternalRequest) (ExternalResult, error) {
	stub.calls++
	if stub.beforeReturn != nil {
		stub.beforeReturn()
	}
	return stub.result, stub.err
}

func TestVerifyExternalFailsClosed(t *testing.T) {
	request := validExternalRequest(ProviderTencent)
	for _, test := range []struct {
		name     string
		verifier ExternalVerifier
	}{
		{name: "missing adapter"},
		{name: "provider timeout", verifier: &verifierStub{err: context.DeadlineExceeded}},
		{name: "provider error", verifier: &verifierStub{err: errors.New("vendor body must not escape")}},
		{name: "rejected proof", verifier: &verifierStub{result: ExternalResult{Valid: false, AppID: request.AppID, ReplayKey: "r-1"}}},
		{name: "wrong app id", verifier: &verifierStub{result: ExternalResult{Valid: true, AppID: "other-app", ReplayKey: "r-1"}}},
		{name: "missing replay key", verifier: &verifierStub{result: ExternalResult{Valid: true, AppID: request.AppID}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyExternal(context.Background(), request, test.verifier); !errors.Is(err, ErrExternalVerification) {
				t.Fatalf("VerifyExternal() error = %v", err)
			}
		})
	}
}

func TestVerifyExternalAcceptsBoundOneTimeResult(t *testing.T) {
	for _, provider := range []ExternalProvider{ProviderTencent, ProviderGeetestV4} {
		t.Run(string(provider), func(t *testing.T) {
			request := validExternalRequest(provider)
			stub := &verifierStub{result: ExternalResult{Valid: true, AppID: request.AppID, ReplayKey: "provider-one-time-id"}}
			result, err := VerifyExternal(context.Background(), request, stub)
			if err != nil || result.ReplayKey != "provider-one-time-id" || stub.calls != 1 {
				t.Fatalf("VerifyExternal() = (%+v, %v), calls=%d", result, err, stub.calls)
			}
		})
	}
}

func TestVerifyExternalRejectsContextCanceledByAdapter(t *testing.T) {
	request := validExternalRequest(ProviderTencent)
	ctx, cancel := context.WithCancel(context.Background())
	stub := &verifierStub{
		result:       ExternalResult{Valid: true, AppID: request.AppID, ReplayKey: "provider-one-time-id"},
		beforeReturn: cancel,
	}
	if _, err := VerifyExternal(ctx, request, stub); !errors.Is(err, ErrExternalVerification) || stub.calls != 1 {
		t.Fatalf("canceled adapter result = (%v, calls=%d)", err, stub.calls)
	}
}

func TestVerifyExternalRejectsUnboundedOrUnknownInputBeforeAdapter(t *testing.T) {
	request := validExternalRequest("other")
	stub := &verifierStub{result: ExternalResult{Valid: true, AppID: request.AppID, ReplayKey: "r-1"}}
	if _, err := VerifyExternal(context.Background(), request, stub); !errors.Is(err, ErrExternalVerification) || stub.calls != 0 {
		t.Fatalf("unknown provider = (%v, calls=%d)", err, stub.calls)
	}
	request = validExternalRequest(ProviderTencent)
	request.Proof = string(make([]byte, MaxExternalProofBytes+1))
	if _, err := VerifyExternal(context.Background(), request, stub); !errors.Is(err, ErrExternalVerification) || stub.calls != 0 {
		t.Fatalf("oversized proof = (%v, calls=%d)", err, stub.calls)
	}
}

func validExternalRequest(provider ExternalProvider) ExternalRequest {
	return ExternalRequest{
		Provider: provider,
		AppID:    "app-123",
		Proof:    "opaque-vendor-proof",
		ClientIP: "2001:db8::10",
		SiteID:   "site-a",
	}
}
