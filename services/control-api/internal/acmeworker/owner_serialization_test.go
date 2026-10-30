package acmeworker

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// FX03③: the apex and *. authorizations of one order both write
// _acme-challenge.<domain>. On Huawei that owner is a single record set, so
// overlapping challenges turn it into a shared two-value set the adapter
// refuses to touch. They run one after the other; other owners still overlap.
func TestIssueDNS01SerializesChallengesOfOneOwner(t *testing.T) {
	for _, test := range []struct {
		name    string
		domains []string
		want    int32
	}{
		{"apex_and_wildcard_share_an_owner", []string{"example.test", "*.example.test"}, 1},
		{"different_owners_overlap", []string{"a.example.test", "b.example.test"}, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newProtocolServer(t, testNow, protocolOptions{})
			records := &challengeRecords{}
			var active, peak atomic.Int32
			var both sync.WaitGroup
			both.Add(len(test.domains))
			records.onObserve = func(ChallengeIdentity) {
				now := active.Add(1)
				for {
					old := peak.Load()
					if now <= old || peak.CompareAndSwap(old, now) {
						break
					}
				}
				// Give a parallel challenge the chance to start.
				done := make(chan struct{})
				go func() { both.Wait(); close(done) }()
				both.Done()
				select {
				case <-done:
				case <-time.After(200 * time.Millisecond):
				}
				active.Add(-1)
			}
			worker := newTestWorker(t, protocol, nil, records, &memoryCertificates{items: make(map[string]IssuedCertificate)},
				func(config *Config) {
					config.MaxConcurrentAuthorizations = 4
					config.PropagationTimeout = 2 * time.Second
				})
			if _, err := worker.Issue(context.Background(), validIssueRequest(ChallengeDNS01, test.domains...)); err != nil {
				t.Fatalf("Issue() error = %v", err)
			}
			if got := peak.Load(); got != test.want {
				t.Fatalf("peak concurrent challenges = %d, want %d", got, test.want)
			}
			if len(records.deleted) != 2 {
				t.Fatalf("deletes = %v", records.deleted)
			}
		})
	}
}
