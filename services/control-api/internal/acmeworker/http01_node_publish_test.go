package acmeworker

import (
	"context"
	"errors"
	"testing"
	"time"
)

// slowHTTP01Provider confirms after delay, as the node provider does once
// every target node serves the token; it records the time Publish had left.
type slowHTTP01Provider struct {
	delay     time.Duration
	remaining time.Duration
	records   challengeRecords
}

func (p *slowHTTP01Provider) Publish(ctx context.Context, challenge ChallengeIdentity) error {
	deadline, _ := ctx.Deadline()
	p.remaining = time.Until(deadline)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(p.delay):
	}
	return p.records.Publish(ctx, challenge)
}

func (p *slowHTTP01Provider) Delete(ctx context.Context, challenge ChallengeIdentity) error {
	return p.records.Delete(ctx, challenge)
}

// FX05①: HTTP-01 Publish waits for every node, which takes longer than one
// CA request; HTTP01PublishTimeout bounds it instead of ChallengeTimeout.
func TestHTTP01PublishUsesItsOwnTimeout(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	provider := &slowHTTP01Provider{delay: 1500 * time.Millisecond}
	worker := newTestWorker(t, protocol, provider, nil,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, func(config *Config) {
			config.ChallengeTimeout = time.Second
			config.HTTP01PublishTimeout = 5 * time.Second
			config.OrderTimeout = 10 * time.Second
		})
	if _, err := worker.Issue(t.Context(), validIssueRequest(ChallengeHTTP01, "slow.example.test")); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if provider.remaining < 4*time.Second {
		t.Fatalf("publish had %s, want the HTTP-01 publish timeout", provider.remaining)
	}
	if len(provider.records.published) != 1 || len(provider.records.deleted) != 1 {
		t.Fatalf("published %v deleted %v", provider.records.published, provider.records.deleted)
	}
}

// The node provider's refusals keep their code and are not retried.
func TestHTTP01NodeRefusalsAreTerminal(t *testing.T) {
	for _, code := range []ErrorCode{CodeHTTP01NodeUnsupported, CodeHTTP01NoServingNode} {
		err := phaseFailure(CodeChallengePublishFailed, &Error{Code: code})
		if ErrorCodeOf(err) != code || retryableFailure(err) {
			t.Fatalf("%s mapped to %v retryable=%t", code, err, retryableFailure(err))
		}
	}
	err := phaseFailure(CodeChallengePublishFailed, errors.New("node 1 did not confirm"))
	if ErrorCodeOf(err) != CodeChallengePublishFailed || !retryableFailure(err) {
		t.Fatalf("delivery failure mapped to %v", err)
	}
}
