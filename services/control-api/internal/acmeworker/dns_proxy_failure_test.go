package acmeworker

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsapiproxy"
)

// a  publish that could not use the http代理 keeps its own code and is retried.
func TestPhaseFailureNamesDNSProxy(t *testing.T) {
	err := phaseFailure(CodeChallengePublishFailed, fmt.Errorf("present: %w", dnsapiproxy.ErrProxyUnavailable))
	if ErrorCodeOf(err) != CodeDNSProxyUnavailable || !retryableFailure(err) {
		t.Fatalf("proxy failure = %v (%q)", err, ErrorCodeOf(err))
	}
	if ErrorCodeOf(phaseFailure(CodeChallengePublishFailed, errors.New("other"))) != CodeChallengePublishFailed {
		t.Fatal("other failures keep the phase code")
	}
}
