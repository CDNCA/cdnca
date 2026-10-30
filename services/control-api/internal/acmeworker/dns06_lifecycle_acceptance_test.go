package acmeworker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type dns06FixedClockScheduleStore struct {
	cancel        context.CancelFunc
	asOf          time.Time
	renewBefore   time.Duration
	leaseDuration time.Duration
	retryMaximum  time.Duration
}

func (store *dns06FixedClockScheduleStore) ScheduleDueRenewal(
	_ context.Context,
	renewBefore time.Duration,
	leaseDuration time.Duration,
) (bool, error) {
	return false, errors.New("database-clock scheduler path must not be used")
}

func (store *dns06FixedClockScheduleStore) ScheduleDueRenewalDetailed(
	_ context.Context,
	renewBefore time.Duration,
	leaseDuration time.Duration,
	retryMaximum time.Duration,
) (RenewalScheduleOutcome, error) {
	return RenewalScheduleOutcome{}, errors.New("database-clock detailed scheduler path must not be used")
}

func (store *dns06FixedClockScheduleStore) ScheduleDueRenewalAt(
	_ context.Context,
	asOf time.Time,
	renewBefore time.Duration,
	leaseDuration time.Duration,
) (bool, error) {
	store.asOf = asOf
	store.renewBefore = renewBefore
	store.leaseDuration = leaseDuration
	store.cancel()
	return false, nil
}

func (store *dns06FixedClockScheduleStore) ScheduleDueRenewalDetailedAt(
	_ context.Context,
	asOf time.Time,
	renewBefore time.Duration,
	leaseDuration time.Duration,
	retryMaximum time.Duration,
) (RenewalScheduleOutcome, error) {
	store.asOf = asOf
	store.renewBefore = renewBefore
	store.leaseDuration = leaseDuration
	store.retryMaximum = retryMaximum
	store.cancel()
	return RenewalScheduleOutcome{}, nil
}

func TestDNS06RenewalSchedulerPassesFixedClockToDurableClaim(t *testing.T) {
	fixed := time.Date(2026, time.August, 7, 8, 9, 10, 123456000, time.UTC)
	ctx, cancel := context.WithCancel(t.Context())
	store := &dns06FixedClockScheduleStore{cancel: cancel}
	config := DefaultRenewalSchedulerConfig()
	config.Clock = func() time.Time { return fixed }

	scheduler, err := NewRenewalScheduler(store, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation after fixed-clock claim", err)
	}
	if !store.asOf.Equal(fixed) || store.renewBefore != config.RenewBefore ||
		store.leaseDuration != config.LeaseDuration || store.retryMaximum != config.RetryMaximum {
		t.Fatalf("durable claim received as_of=%s renew_before=%s lease=%s retry_max=%s",
			store.asOf, store.renewBefore, store.leaseDuration, store.retryMaximum)
	}
}

func TestDNS06ChallengeContractPreservesHTTPDNSWildcardAndMultiLevelNames(t *testing.T) {
	httpRequest := validIssueRequest(ChallengeHTTP01, "api.deep.example.test", "www.example.test")
	httpDomains, err := normalizeIssueRequest(&httpRequest)
	if err != nil || len(httpDomains) != 2 || httpDomains[0] != "api.deep.example.test" {
		t.Fatalf("HTTP-01 multi-level normalization = %v, %v", httpDomains, err)
	}

	dnsRequest := validIssueRequest(ChallengeDNS01, "*.deep.example.test", "deep.example.test")
	dnsDomains, err := normalizeIssueRequest(&dnsRequest)
	if err != nil || len(dnsDomains) != 2 || dnsDomains[0] != "*.deep.example.test" {
		t.Fatalf("DNS-01 wildcard normalization = %v, %v", dnsDomains, err)
	}

	httpWildcard := validIssueRequest(ChallengeHTTP01, "*.deep.example.test")
	if _, err := normalizeIssueRequest(&httpWildcard); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("HTTP-01 wildcard error = %v, want %s", err, CodeInvalidInput)
	}

	dnsWithoutProvider := validIssueRequest(ChallengeDNS01, "deep.example.test")
	dnsWithoutProvider.ProviderID = uuid.Nil
	dnsWithoutProvider.ZoneID = uuid.Nil
	dnsWithoutProvider.ProviderRef = ""
	if _, err := normalizeIssueRequest(&dnsWithoutProvider); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("DNS-01 unknown provider error = %v, want fail-closed %s", err, CodeInvalidInput)
	}
}
