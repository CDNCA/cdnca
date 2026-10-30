package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type renewalRPCFunc func(context.Context, *agentv1.RenewCertificateRequest) (*agentv1.RenewCertificateResponse, error)

func (function renewalRPCFunc) RenewCertificate(ctx context.Context, request *agentv1.RenewCertificateRequest, _ ...grpc.CallOption) (*agentv1.RenewCertificateResponse, error) {
	return function(ctx, request)
}

func TestRenewerReplaysStableRequestAndAtomicallyInstallsCertificate(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	config.Dial = fixture.fakeDial(nil)
	result, err := Run(context.Background(), config, testToken)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(result.ClientCertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	now := fixture.now.Add(45 * time.Minute)
	renewer := &Renewer{identityDir: config.IdentityDir, now: func() time.Time { return now }, random: rand.Reader}
	var requests []*agentv1.RenewCertificateRequest
	rpc := renewalRPCFunc(func(_ context.Context, request *agentv1.RenewCertificateRequest) (*agentv1.RenewCertificateResponse, error) {
		requests = append(requests, proto.Clone(request).(*agentv1.RenewCertificateRequest))
		if len(requests) == 1 {
			return nil, status.Error(codes.Unavailable, "retry")
		}
		return renewedResponse(t, fixture, result.NodeID, request, now), nil
	})
	if renewed, _, err := renewer.renew(context.Background(), rpc); renewed || !errors.Is(err, ErrRenewalRejected) {
		t.Fatalf("first Renew() = %v, %v", renewed, err)
	}
	if !exists(filepath.Join(config.IdentityDir, renewalStateFileName)) {
		t.Fatal("failed renewal did not preserve durable request state")
	}
	now = now.Add(31 * time.Second)
	renewed, certificateSHA, err := renewer.renew(context.Background(), rpc)
	if err != nil || !renewed || len(certificateSHA) != 64 {
		t.Fatalf("second Renew() = %v, %q, %v", renewed, certificateSHA, err)
	}
	if len(requests) != 2 || requests[0].GetRequest().GetRequestId() != requests[1].GetRequest().GetRequestId() ||
		requests[0].GetCurrentSerialNumber() != requests[1].GetCurrentSerialNumber() ||
		!bytes.Equal(requests[0].GetCertificateSigningRequestDer(), requests[1].GetCertificateSigningRequestDer()) {
		t.Fatalf("renewal retry changed its idempotent request: %#v / %#v", requests[0], requests[1])
	}
	after, err := os.ReadFile(result.ClientCertificateFile)
	if err != nil || bytes.Equal(before, after) {
		t.Fatalf("renewed certificate was not installed: equal=%v err=%v", bytes.Equal(before, after), err)
	}
	if exists(filepath.Join(config.IdentityDir, renewalStateFileName)) {
		t.Fatal("successful renewal left durable request state")
	}
	identity, err := LoadIdentity(config.IdentityDir, now)
	if err != nil || identity.NodeID != result.NodeID {
		t.Fatalf("renewed identity did not reload: %+v, %v", identity, err)
	}
}

func TestRenewerRejectsInvalidResponseWithoutReplacingCertificate(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	config.Dial = fixture.fakeDial(nil)
	result, err := Run(context.Background(), config, testToken)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(result.ClientCertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	now := fixture.now.Add(45 * time.Minute)
	renewer := &Renewer{identityDir: config.IdentityDir, now: func() time.Time { return now }, random: rand.Reader}
	_, _, err = renewer.renew(context.Background(), renewalRPCFunc(func(_ context.Context, request *agentv1.RenewCertificateRequest) (*agentv1.RenewCertificateResponse, error) {
		response := renewedResponse(t, fixture, result.NodeID, request, now)
		response.Certificate.SerialNumber = "deadbeef"
		return response, nil
	}))
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("Renew(invalid response) error = %v", err)
	}
	after, readErr := os.ReadFile(result.ClientCertificateFile)
	if readErr != nil || !bytes.Equal(before, after) {
		t.Fatalf("invalid response changed the active certificate: equal=%v err=%v", bytes.Equal(before, after), readErr)
	}
}

func TestRenewerDoesNotCallGatewayBeforeCertificateMidpoint(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	config.Dial = fixture.fakeDial(nil)
	if _, err := Run(context.Background(), config, testToken); err != nil {
		t.Fatal(err)
	}
	called := false
	renewer := &Renewer{identityDir: config.IdentityDir, now: func() time.Time { return fixture.now }, random: rand.Reader}
	renewed, _, err := renewer.renew(context.Background(), renewalRPCFunc(func(context.Context, *agentv1.RenewCertificateRequest) (*agentv1.RenewCertificateResponse, error) {
		called = true
		return nil, nil
	}))
	if err != nil || renewed || called {
		t.Fatalf("early Renew() = %v, called=%v, err=%v", renewed, called, err)
	}
}

func TestRenewerHonorsTooEarlyRetryWithoutChangingRequest(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	config.Dial = fixture.fakeDial(nil)
	result, err := Run(context.Background(), config, testToken)
	if err != nil {
		t.Fatal(err)
	}
	now := fixture.now.Add(45 * time.Minute)
	retryAt := now.Add(2 * time.Minute)
	renewer := &Renewer{identityDir: config.IdentityDir, now: func() time.Time { return now }, random: rand.Reader}
	var requests []*agentv1.RenewCertificateRequest
	rpc := renewalRPCFunc(func(_ context.Context, request *agentv1.RenewCertificateRequest) (*agentv1.RenewCertificateResponse, error) {
		requests = append(requests, proto.Clone(request).(*agentv1.RenewCertificateRequest))
		if len(requests) == 1 {
			return nil, renewalDirectiveError(t, renewalReasonTooEarly, retryAt)
		}
		return renewedResponse(t, fixture, result.NodeID, request, now), nil
	})
	if renewed, _, err := renewer.renew(context.Background(), rpc); err != nil || renewed {
		t.Fatalf("too-early Renew() = %v, %v", renewed, err)
	}
	now = retryAt.Add(-time.Second)
	if renewed, _, err := renewer.renew(context.Background(), rpc); err != nil || renewed || len(requests) != 1 {
		t.Fatalf("pre-deadline Renew() = %v, calls=%d, %v", renewed, len(requests), err)
	}
	now = retryAt
	if renewed, _, err := renewer.renew(context.Background(), rpc); err != nil || !renewed {
		t.Fatalf("deadline Renew() = %v, %v", renewed, err)
	}
	if len(requests) != 2 || requests[0].GetRequest().GetRequestId() != requests[1].GetRequest().GetRequestId() ||
		!bytes.Equal(requests[0].GetCertificateSigningRequestDer(), requests[1].GetCertificateSigningRequestDer()) {
		t.Fatalf("too-early retry changed its durable request: %#v", requests)
	}
}

func TestRenewerRotatesOnlyExpiredRequestAtRetryDeadline(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	config.Dial = fixture.fakeDial(nil)
	result, err := Run(context.Background(), config, testToken)
	if err != nil {
		t.Fatal(err)
	}
	now := fixture.now.Add(45 * time.Minute)
	retryAt := now.Add(2 * time.Minute)
	renewer := &Renewer{identityDir: config.IdentityDir, now: func() time.Time { return now }, random: rand.Reader}
	var requests []*agentv1.RenewCertificateRequest
	oldRequestID := ""
	rpc := renewalRPCFunc(func(_ context.Context, request *agentv1.RenewCertificateRequest) (*agentv1.RenewCertificateResponse, error) {
		requests = append(requests, proto.Clone(request).(*agentv1.RenewCertificateRequest))
		if oldRequestID == "" {
			oldRequestID = request.GetRequest().GetRequestId()
		}
		if request.GetRequest().GetRequestId() == oldRequestID {
			return nil, renewalDirectiveError(t, renewalReasonRequestExpired, retryAt)
		}
		return renewedResponse(t, fixture, result.NodeID, request, now), nil
	})
	if renewed, _, err := renewer.renew(context.Background(), rpc); err != nil || renewed {
		t.Fatalf("expired-future Renew() = %v, %v", renewed, err)
	}
	statePath := filepath.Join(config.IdentityDir, renewalStateFileName)
	oldState := readRenewalState(t, statePath)
	now = retryAt.Add(-time.Second)
	if renewed, _, err := renewer.renew(context.Background(), rpc); err != nil || renewed || len(requests) != 1 {
		t.Fatalf("expired pre-deadline Renew() = %v, calls=%d, %v", renewed, len(requests), err)
	}
	if current := readRenewalState(t, statePath); current != oldState {
		t.Fatal("future expired directive changed renewal state")
	}
	now = retryAt
	if renewed, _, err := renewer.renew(context.Background(), rpc); err != nil || renewed {
		t.Fatalf("expired rotation Renew() = %v, %v", renewed, err)
	}
	newState := readRenewalState(t, statePath)
	if newState.RequestID == oldState.RequestID || newState.CSRDER == oldState.CSRDER ||
		newState.CurrentSerialNumber != oldState.CurrentSerialNumber ||
		newState.CurrentCertificateSHA256 != oldState.CurrentCertificateSHA256 {
		t.Fatalf("rotated renewal state = %#v, old %#v", newState, oldState)
	}
	if renewed, _, err := renewer.renew(context.Background(), rpc); err != nil || !renewed {
		t.Fatalf("replacement Renew() = %v, %v", renewed, err)
	}
	if len(requests) != 3 || requests[0].GetRequest().GetRequestId() != requests[1].GetRequest().GetRequestId() ||
		requests[2].GetRequest().GetRequestId() != newState.RequestID {
		t.Fatalf("expired request rotation calls = %#v", requests)
	}
	if exists(statePath) {
		t.Fatal("successful replacement left renewal state")
	}
}

func TestParseRenewalRetryDirectiveRejectsAmbiguousDetails(t *testing.T) {
	retryAt := time.Date(2026, 9, 16, 1, 7, 21, 0, time.UTC)
	valid := renewalDirectiveError(t, renewalReasonRequestExpired, retryAt)
	if directive, ok := parseRenewalRetryDirective(valid); !ok || directive.reason != renewalReasonRequestExpired || !directive.retryAt.Equal(retryAt) {
		t.Fatalf("valid directive = %#v, %v", directive, ok)
	}
	for name, infos := range map[string][]*errdetails.ErrorInfo{
		"wrong domain": {{Reason: renewalReasonRequestExpired, Domain: "example.invalid", Metadata: map[string]string{"retry_at": retryAt.Format(time.RFC3339)}}},
		"bad time":     {{Reason: renewalReasonRequestExpired, Domain: renewalErrorDomain, Metadata: map[string]string{"retry_at": "soon"}}},
		"unknown":      {{Reason: "rotate_now", Domain: renewalErrorDomain, Metadata: map[string]string{"retry_at": retryAt.Format(time.RFC3339)}}},
		"duplicate": {
			{Reason: renewalReasonRequestExpired, Domain: renewalErrorDomain, Metadata: map[string]string{"retry_at": retryAt.Format(time.RFC3339)}},
			{Reason: renewalReasonRequestExpired, Domain: renewalErrorDomain, Metadata: map[string]string{"retry_at": retryAt.Format(time.RFC3339)}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			base := status.New(codes.FailedPrecondition, "retry")
			var withDetails *status.Status
			var err error
			if len(infos) == 1 {
				withDetails, err = base.WithDetails(infos[0])
			} else {
				withDetails, err = base.WithDetails(infos[0], infos[1])
			}
			if err != nil {
				t.Fatal(err)
			}
			if directive, ok := parseRenewalRetryDirective(withDetails.Err()); ok {
				t.Fatalf("directive = %#v, want rejected", directive)
			}
		})
	}
}

func renewalDirectiveError(t *testing.T, reason string, retryAt time.Time) error {
	t.Helper()
	withDetails, err := status.New(codes.FailedPrecondition, "retry").WithDetails(&errdetails.ErrorInfo{
		Reason: reason, Domain: renewalErrorDomain,
		Metadata: map[string]string{"retry_at": retryAt.UTC().Format(time.RFC3339)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return withDetails.Err()
}

func readRenewalState(t *testing.T, path string) renewalState {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeRenewalState(content)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func renewedResponse(t *testing.T, fixture *fixture, nodeID string, request *agentv1.RenewCertificateRequest, now time.Time) *agentv1.RenewCertificateResponse {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(request.GetCertificateSigningRequestDer())
	if err != nil || csr.CheckSignature() != nil {
		t.Fatal("invalid renewal CSR")
	}
	spiffe, err := url.Parse(nodeSPIFFEPrefix + nodeID)
	if err != nil {
		t.Fatal(err)
	}
	notBefore, notAfter := now.Add(-time.Minute), fixture.now.Add(2*time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(43), NotBefore: notBefore, NotAfter: notAfter,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{spiffe},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, fixture.root, csr.PublicKey, fixture.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.RenewCertificateResponse{Certificate: &agentv1.CertificateBundle{
		LeafCertificatePem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		IssuingChainPem:    [][]byte{bytes.Clone(fixture.rootPEM)}, SerialNumber: "2b",
		NotBeforeTime: timestamppb.New(notBefore), ExpirationTime: timestamppb.New(notAfter),
		RenewalTime: timestamppb.New(now.Add(30 * time.Minute)),
	}}
}
