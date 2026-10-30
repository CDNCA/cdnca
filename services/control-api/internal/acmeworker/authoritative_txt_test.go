package acmeworker

import (
	"context"
	"sync"
	"testing"
	"time"
)

// scriptedAuthoritativeTXT reports the TXT value visible on the zone's
// authoritative name servers after visibleAfter checks.
type scriptedAuthoritativeTXT struct {
	mu           sync.Mutex
	visibleAfter int
	checks       []string
}

func (fake *scriptedAuthoritativeTXT) TXTVisible(_ context.Context, name, value string) (bool, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.checks = append(fake.checks, name+"|"+value)
	return fake.visibleAfter >= 0 && len(fake.checks) > fake.visibleAfter, nil
}

// FX05②: the CA is asked to validate only once every authoritative name
// server of the zone serves the TXT value, not as soon as the provider API
// accepted the write.
func TestIssueDNS01WaitsForAuthoritativeNameServers(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{}
	worker := newTestWorker(t, protocol, nil, records, &memoryCertificates{items: make(map[string]IssuedCertificate)},
		func(config *Config) { config.PropagationPollInterval = time.Millisecond })
	authoritative := &scriptedAuthoritativeTXT{visibleAfter: 2}
	worker.deps.AuthoritativeTXT = authoritative
	if _, err := worker.Issue(context.Background(), validIssueRequest(ChallengeDNS01, "example.test")); err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if len(authoritative.checks) != 3 || authoritative.checks[0] != records.identities[0].RecordName+"|"+records.identities[0].ExactValue {
		t.Fatalf("authoritative checks = %v", authoritative.checks)
	}
}

func TestIssueDNS01FailsRetryablyWhenAuthoritativeNameServersLag(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{}
	worker := newTestWorker(t, protocol, nil, records, &memoryCertificates{items: make(map[string]IssuedCertificate)},
		func(config *Config) {
			config.PropagationPollInterval = time.Millisecond
			config.PropagationTimeout = 50 * time.Millisecond
		})
	authoritative := &scriptedAuthoritativeTXT{visibleAfter: -1}
	worker.deps.AuthoritativeTXT = authoritative
	_, err := worker.Issue(context.Background(), validIssueRequest(ChallengeDNS01, "example.test"))
	if ErrorCodeOf(err) != CodeChallengePropagationFailed || !retryableFailure(err) {
		t.Fatalf("Issue() error = %v (code %s, retryable %v)", err, ErrorCodeOf(err), retryableFailure(err))
	}
	if len(authoritative.checks) < 2 || len(records.deleted) != 1 {
		t.Fatalf("checks=%d deletes=%v", len(authoritative.checks), records.deleted)
	}
}
