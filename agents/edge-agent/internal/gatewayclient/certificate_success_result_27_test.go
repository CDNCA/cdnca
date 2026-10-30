package gatewayclient

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
)

type certificateResultConsumer27 struct {
	result certstore.Result
}

func (consumer certificateResultConsumer27) ApplyWithActivation(
	context.Context,
	certstore.Bundle,
	certstore.ActivationMetadata,
) (certstore.Result, error) {
	return consumer.result, nil
}

func TestCertificateGatewayRejectsUnverifiedSuccessResult27(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*certstore.Result)
	}{
		{name: "zero result", mutate: func(result *certstore.Result) { *result = certstore.Result{} }},
		{name: "foreign version", mutate: func(result *certstore.Result) { result.VersionID = "foreign-version" }},
		{name: "digest mismatch", mutate: func(result *certstore.Result) { result.ActiveDigest = strings.Repeat("b", 64) }},
		{name: "active identity mismatch", mutate: func(result *certstore.Result) { result.ActiveVersionID = "old-version" }},
		{name: "changed contradiction", mutate: func(result *certstore.Result) { result.RunningVersionUnchanged = true }},
		{name: "zero applied time", mutate: func(result *certstore.Result) { result.AppliedAt = time.Time{} }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			harness := newCertificateHarness(t)
			bundle := certificateBundle(t, "cert-result-27", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
			command, wire := encryptedCertificateCommand(
				t, harness.signingKey, harness.recipientKey, harness.recipientID, bundle, 27, nil,
			)
			result := validCertificateResult27(bundle.VersionID, true)
			mutation.mutate(&result)
			harness.client.certificate = certificateResultConsumer27{result: result}

			statuses := harness.execute(t, command, wire)
			failed := lastStatus(t, statuses)
			if failed.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED ||
				failed.Error == nil || failed.Error.Code != commonv1.ErrorCode_ERROR_CODE_INTERNAL ||
				failed.RunningConfigUnchanged {
				t.Fatalf("invalid success status = %#v", failed)
			}
			for _, status := range statuses {
				if status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
					t.Fatal("invalid consumer success produced a healthy status")
				}
			}
		})
	}
}

func TestCertificateGatewayPreservesVerifiedChangedAndNoChangeSuccess27(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "no change", true: "changed"}[changed], func(t *testing.T) {
			harness := newCertificateHarness(t)
			bundle := certificateBundle(t, "cert-valid-result-27", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
			command, wire := encryptedCertificateCommand(
				t, harness.signingKey, harness.recipientKey, harness.recipientID, bundle, 27, nil,
			)
			harness.client.certificate = certificateResultConsumer27{
				result: validCertificateResult27(bundle.VersionID, changed),
			}
			statuses := harness.execute(t, command, wire)
			assertCertificateStates(t, statuses, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY)
			for _, status := range statuses[1:] {
				if status.RunningConfigUnchanged != !changed {
					t.Fatalf("status unchanged = %t, want %t", status.RunningConfigUnchanged, !changed)
				}
			}
		})
	}
}

func validCertificateResult27(versionID string, changed bool) certstore.Result {
	digest := strings.Repeat("a", 64)
	return certstore.Result{
		VersionID: versionID, Digest: digest, ActiveVersionID: versionID, ActiveDigest: digest,
		Changed: changed, RunningVersionUnchanged: !changed,
		AppliedAt: time.Date(2026, time.August, 7, 5, 6, 7, 0, time.UTC),
	}
}
