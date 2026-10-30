package securityactivation

import (
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
)

// P11 (live-waf): a failed candidate showed no reason; the node's text was
// only in deployment_status_events. deploymentFailure reads it back.
func TestDeploymentFailureReadsTheNodeText(t *testing.T) {
	encode := func(status *agentv1.DeploymentStatus) []byte {
		payload, err := proto.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	summary := encode(&agentv1.DeploymentStatus{Checks: []*agentv1.CheckResult{
		{Name: "edge_deployment_transition", Succeeded: false, Summary: "managed WAF unavailable: no waf engine module is installed"}}})
	if code, message := deploymentFailure(summary); code != "" || message != "managed WAF unavailable: no waf engine module is installed" {
		t.Fatalf("check summary = %q %q", code, message)
	}
	protocol := encode(&agentv1.DeploymentStatus{Error: &commonv1.ProtocolError{
		Code: commonv1.ErrorCode(1), Message: "precheck\nfailed"}})
	if code, message := deploymentFailure(protocol); code == "" || message != "precheck failed" {
		t.Fatalf("protocol error = %q %q", code, message)
	}
	long := encode(&agentv1.DeploymentStatus{Checks: []*agentv1.CheckResult{{Summary: strings.Repeat("界", 300)}}})
	if _, message := deploymentFailure(long); len(message) > maxFailureMessageLength || !strings.HasPrefix(message, "界") {
		t.Fatalf("bounded length = %d", len(message))
	}
	if code, message := deploymentFailure([]byte{0xff}); code != "" || message != "" {
		t.Fatalf("corrupt payload = %q %q", code, message)
	}
}

// sec-ui-polish: the page explains "缺 WAF 引擎" by reason code, not by
// matching the English text.
func TestFailureReasonCodesTheMissingWAFEngine(t *testing.T) {
	for message, want := range map[string]string{
		"managed WAF unavailable: no waf engine module is installed": FailureReasonWAFEngineUnavailable,
		"Managed WAF unavailable":                                    FailureReasonWAFEngineUnavailable,
		"precheck failed":                                            "",
		"":                                                           "",
		"reload failed: managed WAF unavailable":                     FailureReasonWAFEngineUnavailable,
		"waf engine ok":                                              "",
	} {
		if got := failureReason(message); got != want {
			t.Errorf("failureReason(%q) = %q, want %q", message, got, want)
		}
	}
}
