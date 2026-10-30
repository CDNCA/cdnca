package dnsproviderlive

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

var errProviderUnknown = &dnsproviderremote.Error{Code: dnsproviderremote.CodeUnavailable, Temporary: true}

type fakeProvider struct {
	records                     map[string]acmeworker.RemoteTXTHandle
	valuesByHandle              map[string]string
	presented                   []acmeworker.ChallengeIdentity
	recovered                   []acmeworker.ChallengeIdentity
	observedChallenges          []acmeworker.ChallengeIdentity
	deletedChallenges           []acmeworker.ChallengeIdentity
	deleted                     []string
	observed                    []string
	recoverCalls                map[string]int
	targetPresentMode           string
	sentinelPresentMode         string
	targetObserveFailures       int
	keepTargetOnDelete          bool
	replaceTargetOnFirstDelete  bool
	keepRecoveredTargetOnDelete bool
	targetDeleteCalls           int
	deleteSentinelWithTarget    bool
	sawSentinelRetained         bool
}

func newFakeProvider() *fakeProvider {
	return &fakeProvider{
		records:        make(map[string]acmeworker.RemoteTXTHandle),
		valuesByHandle: make(map[string]string),
		recoverCalls:   make(map[string]int),
	}
}

func (p *fakeProvider) PresentTXT(_ context.Context, challenge acmeworker.ChallengeIdentity) (acmeworker.RemoteTXTHandle, error) {
	p.presented = append(p.presented, challenge)
	kind := valueKind(challenge.ExactValue)
	mode := p.targetPresentMode
	if kind == "sentinel" {
		mode = p.sentinelPresentMode
	}
	if mode != "" {
		if mode == "recovered" {
			p.add(challenge.ExactValue)
		}
		return acmeworker.RemoteTXTHandle{}, errProviderUnknown
	}
	return p.add(challenge.ExactValue), nil
}

func (p *fakeProvider) RecoverTXT(_ context.Context, challenge acmeworker.ChallengeIdentity) (acmeworker.RemoteTXTHandle, bool, error) {
	p.recovered = append(p.recovered, challenge)
	kind := valueKind(challenge.ExactValue)
	p.recoverCalls[kind]++
	mode := p.targetPresentMode
	if kind == "sentinel" {
		mode = p.sentinelPresentMode
	}
	if mode == "ambiguous" {
		return acmeworker.RemoteTXTHandle{}, false, &dnsproviderremote.Error{Code: dnsproviderremote.CodeRecordMismatch}
	}
	handle, ok := p.records[challenge.ExactValue]
	return handle, ok, nil
}

func (p *fakeProvider) ObserveTXT(_ context.Context, challenge acmeworker.ChallengeIdentity) error {
	p.observedChallenges = append(p.observedChallenges, challenge)
	kind := valueKind(challenge.ExactValue)
	p.observed = append(p.observed, kind)
	if kind == "target" && p.targetObserveFailures > 0 {
		p.targetObserveFailures--
		return errProviderUnknown
	}
	value, ok := p.valuesByHandle[challenge.TXTHandle.RecordRef]
	if !ok || value != challenge.ExactValue {
		return &dnsproviderremote.Error{Code: dnsproviderremote.CodeRecordNotFound, Temporary: true}
	}
	if kind == "sentinel" {
		_, targetExists := p.recordByKind("target")
		p.sawSentinelRetained = !targetExists
	}
	return nil
}

func (p *fakeProvider) DeleteTXT(_ context.Context, challenge acmeworker.ChallengeIdentity) error {
	p.deletedChallenges = append(p.deletedChallenges, challenge)
	kind := valueKind(challenge.ExactValue)
	p.deleted = append(p.deleted, kind)
	if kind == "target" {
		p.targetDeleteCalls++
	}
	if kind == "target" && p.keepTargetOnDelete {
		return nil
	}
	if kind == "target" && p.replaceTargetOnFirstDelete && p.targetDeleteCalls == 1 {
		if current, ok := p.records[challenge.ExactValue]; ok {
			delete(p.valuesByHandle, current.RecordRef)
		}
		handle := acmeworker.RemoteTXTHandle{ProviderRef: "fake", RecordRef: "handle-target-recovered"}
		p.records[challenge.ExactValue] = handle
		p.valuesByHandle[handle.RecordRef] = challenge.ExactValue
		return nil
	}
	if kind == "target" && p.keepRecoveredTargetOnDelete && p.targetDeleteCalls > 1 {
		return nil
	}
	if kind == "target" && p.deleteSentinelWithTarget {
		if sentinel, ok := p.recordByKind("sentinel"); ok {
			handle := p.records[sentinel]
			delete(p.records, sentinel)
			delete(p.valuesByHandle, handle.RecordRef)
		}
	}
	if current, ok := p.records[challenge.ExactValue]; ok && current == challenge.TXTHandle {
		delete(p.records, challenge.ExactValue)
	}
	delete(p.valuesByHandle, challenge.TXTHandle.RecordRef)
	return nil
}

func (p *fakeProvider) add(value string) acmeworker.RemoteTXTHandle {
	handle := acmeworker.RemoteTXTHandle{ProviderRef: "fake", RecordRef: "handle-" + valueKind(value)}
	p.records[value] = handle
	p.valuesByHandle[handle.RecordRef] = value
	return handle
}

func (p *fakeProvider) recordByKind(kind string) (string, bool) {
	for value := range p.records {
		if valueKind(value) == kind {
			return value, true
		}
	}
	return "", false
}

type fakeDNS struct {
	provider                       *fakeProvider
	guardOwner                     string
	guardValue                     string
	labels                         map[netip.AddrPort]string
	guardOverrides                 map[netip.AddrPort]TXTObservation
	authoritative                  map[netip.AddrPort]bool
	public                         map[netip.AddrPort]bool
	authMismatchSweeps             int
	publicMismatchSweeps           int
	authQueries                    int
	publicQueries                  int
	extraPropagationValue          bool
	cleanupNeverAbsent             bool
	publicPropagationRecursive     bool
	publicPropagationAuthoritative bool
	publicCleanupRecursive         bool
	publicCleanupAuthoritative     bool
	events                         []string
}

func (d *fakeDNS) LookupTXT(_ context.Context, endpoint Endpoint, owner string) (TXTObservation, error) {
	label := d.labels[endpoint.Address]
	if owner == d.guardOwner {
		d.events = append(d.events, "guard:"+label)
		if observation, ok := d.guardOverrides[endpoint.Address]; ok {
			return observation, nil
		}
		return TXTObservation{Authoritative: true, Values: []string{d.guardValue}}, nil
	}

	values := make([]string, 0, len(d.provider.records))
	for value := range d.provider.records {
		values = append(values, value)
	}
	sort.Strings(values)
	if len(values) == 0 {
		if d.cleanupNeverAbsent {
			values = []string{"stale"}
		}
		if d.authoritative[endpoint.Address] {
			d.events = append(d.events, "cleanup:"+label)
			return TXTObservation{Authoritative: true, Values: values}, nil
		}
		d.events = append(d.events, "cleanup:"+label)
		return TXTObservation{
			Authoritative: d.publicCleanupAuthoritative,
			Recursive:     d.publicCleanupRecursive,
			Values:        values,
		}, nil
	}
	if d.authoritative[endpoint.Address] {
		d.events = append(d.events, "propagate:"+label)
		sweep := d.authQueries / len(d.authoritative)
		d.authQueries++
		if sweep < d.authMismatchSweeps {
			values = []string{"not-ready"}
		}
		if d.extraPropagationValue && len(d.provider.records) == 2 {
			values = append(values, "unexpected")
		}
		return TXTObservation{Authoritative: true, Values: values}, nil
	}
	d.events = append(d.events, "propagate:"+label)
	sweep := d.publicQueries / len(d.public)
	d.publicQueries++
	if sweep < d.publicMismatchSweeps {
		values = []string{"not-ready"}
	}
	if d.extraPropagationValue && len(d.provider.records) == 2 {
		values = append(values, "unexpected")
	}
	return TXTObservation{
		Authoritative: d.publicPropagationAuthoritative,
		Recursive:     d.publicPropagationRecursive,
		Values:        values,
	}, nil
}

type fakeClock struct {
	now      time.Time
	sleeps   []time.Duration
	cancel   context.CancelFunc
	canceled bool
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Sleep(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.sleeps = append(c.sleeps, duration)
	c.now = c.now.Add(duration)
	if c.cancel != nil && !c.canceled {
		c.canceled = true
		c.cancel()
		return context.Canceled
	}
	return nil
}

func TestRunRejectsInvalidConfigWithoutSideEffects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "provider", mutate: func(c *Config) { c.ProviderCode = "" }},
		{name: "unsupported provider", mutate: func(c *Config) { c.ProviderCode = "dnsdun" }},
		{name: "zone", mutate: func(c *Config) { c.Zone = "Example.test" }},
		{name: "guard outside zone", mutate: func(c *Config) { c.GuardOwner = "guard.other.test." }},
		{name: "guard digest", mutate: func(c *Config) { c.GuardSHA256 = [32]byte{} }},
		{name: "authoritative", mutate: func(c *Config) { c.Authoritative = nil }},
		{name: "public", mutate: func(c *Config) { c.Public = nil }},
		{name: "timeout low", mutate: func(c *Config) { c.Timeout = 59 * time.Second }},
		{name: "timeout high", mutate: func(c *Config) { c.Timeout = 1801 * time.Second }},
		{name: "cleanup timeout", mutate: func(c *Config) { c.CleanupTimeout = 0 }},
		{name: "tenant", mutate: func(c *Config) { c.TenantID = uuid.Nil }},
		{name: "scope", mutate: func(c *Config) { c.ScopeID = uuid.Nil }},
		{name: "tenant equals scope", mutate: func(c *Config) { c.ScopeID = c.TenantID }},
		{name: "provider id", mutate: func(c *Config) { c.ProviderID = uuid.Nil }},
		{name: "zone id", mutate: func(c *Config) { c.ZoneID = uuid.Nil }},
		{name: "endpoint", mutate: func(c *Config) { c.Public[0].Address = netip.AddrPort{} }},
		{name: "duplicate endpoint", mutate: func(c *Config) { c.Public[0] = c.Authoritative[0] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, provider, dns, clock := validFixture()
			test.mutate(&config)
			evidence := Run(t.Context(), config, provider, dns, clock, strings.NewReader(strings.Repeat("x", 32)))
			if evidence.Status != StatusFail || evidence.Phase != PhaseConfig || evidence.Reason != ReasonInvalidConfig {
				t.Fatalf("evidence = %+v", evidence)
			}
			if len(provider.presented) != 0 || len(dns.events) != 0 {
				t.Fatalf("side effects: presented=%d dns=%v", len(provider.presented), dns.events)
			}
		})
	}
}

func TestRunGuardRequiresExactDigestAndEveryAuthoritativeEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		observation TXTObservation
	}{
		{name: "not authoritative", observation: TXTObservation{Values: []string{"guard-proof"}}},
		{name: "wrong digest", observation: TXTObservation{Authoritative: true, Values: []string{"wrong"}}},
		{name: "extra value", observation: TXTObservation{Authoritative: true, Values: []string{"guard-proof", "extra"}}},
		{name: "rcode", observation: TXTObservation{Authoritative: true, RCode: 2, Values: []string{"guard-proof"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, provider, dns, clock := validFixture()
			dns.guardOverrides[config.Authoritative[1].Address] = test.observation
			evidence := Run(t.Context(), config, provider, dns, clock, strings.NewReader(strings.Repeat("x", 32)))
			if evidence.Status != StatusFail || evidence.Phase != PhaseGuard || evidence.Reason != ReasonGuardMismatch {
				t.Fatalf("evidence = %+v", evidence)
			}
			if len(provider.presented) != 0 {
				t.Fatalf("guard failure mutated provider %d times", len(provider.presented))
			}
			if got := dns.events; !reflect.DeepEqual(got, []string{"guard:auth-1", "guard:auth-2"}) {
				t.Fatalf("guard queries = %v", got)
			}
		})
	}
}

func TestRunPassesOnlyAfterAuthorityThenPublicAndCompleteCleanup(t *testing.T) {
	config, provider, dns, clock := validFixture()
	dns.authMismatchSweeps = 1
	dns.publicMismatchSweeps = 1

	evidence := Run(t.Context(), config, provider, dns, clock, strings.NewReader(strings.Repeat("x", 32)))
	if evidence.Status != StatusPass || evidence.Reason != ReasonVerified || evidence.Phase != PhaseComplete {
		t.Fatalf("evidence = %+v", evidence)
	}
	if !evidence.CleanupAttempted || !evidence.CleanupComplete || len(provider.records) != 0 {
		t.Fatalf("cleanup evidence=%+v records=%v", evidence, provider.records)
	}
	if got, want := provider.deleted, []string{"target", "sentinel"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("delete order = %v, want %v", got, want)
	}
	if !provider.sawSentinelRetained {
		t.Fatal("sentinel was not observed after target deletion")
	}
	cleanup := filterPrefix(dns.events, "cleanup:")
	if got, want := cleanup, []string{"cleanup:auth-1", "cleanup:auth-2", "cleanup:public-1", "cleanup:public-2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cleanup proof = %v, want %v", got, want)
	}
	propagation := filterPrefix(dns.events, "propagate:")
	want := []string{
		"propagate:auth-1", "propagate:auth-2",
		"propagate:auth-1", "propagate:auth-2", "propagate:public-1", "propagate:public-2",
		"propagate:auth-1", "propagate:auth-2", "propagate:public-1", "propagate:public-2",
	}
	if !reflect.DeepEqual(propagation, want) {
		t.Fatalf("propagation order = %v, want %v", propagation, want)
	}
	assertCompleteIdentities(t, config, provider.presented)
	assertIdentityAuthority(t, config, provider.recovered)
	assertIdentityAuthority(t, config, provider.observedChallenges)
	assertIdentityAuthority(t, config, provider.deletedChallenges)
}

func TestRunUsesCappedBackoffAndNeverQueriesPublicBeforeAuthority(t *testing.T) {
	config, provider, dns, clock := validFixture()
	dns.authMismatchSweeps = 100

	evidence := Run(t.Context(), config, provider, dns, clock, strings.NewReader(strings.Repeat("x", 32)))
	if evidence.Status != StatusFail || evidence.Reason != ReasonPropagationTimeout || !evidence.CleanupComplete {
		t.Fatalf("evidence = %+v", evidence)
	}
	wantSleeps := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second, 30 * time.Second}
	if !reflect.DeepEqual(clock.sleeps, wantSleeps) {
		t.Fatalf("sleeps = %v, want %v", clock.sleeps, wantSleeps)
	}
	if dns.publicQueries != 0 {
		t.Fatalf("public queries = %d before authoritative convergence", dns.publicQueries)
	}
}

func TestRunUnknownPresentRecoveryOutcomes(t *testing.T) {
	tests := []struct {
		name            string
		mode            string
		wantStatus      string
		wantReason      string
		wantCleanupDone bool
	}{
		{name: "zero", mode: "absent", wantStatus: StatusFail, wantReason: ReasonPresentNotApplied, wantCleanupDone: true},
		{name: "one", mode: "recovered", wantStatus: StatusPass, wantReason: ReasonVerified, wantCleanupDone: true},
		{name: "more than one", mode: "ambiguous", wantStatus: StatusCleanupPending, wantReason: ReasonRecoveryAmbiguous},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, provider, dns, clock := validFixture()
			provider.targetPresentMode = test.mode
			evidence := Run(t.Context(), config, provider, dns, clock, strings.NewReader(strings.Repeat("x", 32)))
			if evidence.Status != test.wantStatus || evidence.Reason != test.wantReason || evidence.CleanupComplete != test.wantCleanupDone {
				t.Fatalf("evidence = %+v", evidence)
			}
		})
	}
}

func TestRunSentinelUnknownPresentRecoveryZeroNeedsNoHandleToProveCleanup(t *testing.T) {
	config, provider, dns, clock := validFixture()
	provider.sentinelPresentMode = "absent"
	evidence := Run(t.Context(), config, provider, dns, clock, strings.NewReader(strings.Repeat("x", 32)))
	if evidence.Status != StatusFail || evidence.Reason != ReasonPresentNotApplied || !evidence.CleanupComplete {
		t.Fatalf("evidence = %+v", evidence)
	}
	if len(provider.presented) != 1 || len(provider.records) != 0 {
		t.Fatalf("presented=%d records=%v", len(provider.presented), provider.records)
	}
}

func TestRunObserveFailureStillCleansUp(t *testing.T) {
	config, provider, dns, clock := validFixture()
	provider.targetObserveFailures = 1
	evidence := Run(t.Context(), config, provider, dns, clock, strings.NewReader(strings.Repeat("x", 32)))
	if evidence.Status != StatusFail || evidence.Reason != ReasonProviderObserve || !evidence.CleanupComplete || len(provider.records) != 0 {
		t.Fatalf("evidence = %+v records=%v", evidence, provider.records)
	}
}

func TestRunFailsClosedOnHuaweiExtraTXT(t *testing.T) {
	config, provider, dns, clock := validFixture()
	config.ProviderCode = "huawei"
	dns.extraPropagationValue = true
	evidence := Run(t.Context(), config, provider, dns, clock, strings.NewReader(strings.Repeat("x", 32)))
	if evidence.Status != StatusFail || evidence.Reason != ReasonPropagationTimeout || !evidence.CleanupComplete {
		t.Fatalf("evidence = %+v", evidence)
	}
	if dns.publicQueries != 0 {
		t.Fatalf("public queries = %d with authoritative multi-value drift", dns.publicQueries)
	}
}

func TestRunRejectsNonRecursiveOrAuthoritativePublicEvidence(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*fakeDNS)
		wantStatus string
	}{
		{name: "propagation recursive unavailable", mutate: func(d *fakeDNS) { d.publicPropagationRecursive = false }, wantStatus: StatusFail},
		{name: "propagation authoritative", mutate: func(d *fakeDNS) { d.publicPropagationAuthoritative = true }, wantStatus: StatusFail},
		{name: "cleanup recursive unavailable", mutate: func(d *fakeDNS) { d.publicCleanupRecursive = false }, wantStatus: StatusCleanupPending},
		{name: "cleanup authoritative", mutate: func(d *fakeDNS) { d.publicCleanupAuthoritative = true }, wantStatus: StatusCleanupPending},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, provider, dns, clock := validFixture()
			test.mutate(dns)
			evidence := Run(t.Context(), config, provider, dns, clock, strings.NewReader(strings.Repeat("x", 32)))
			if evidence.Status != test.wantStatus || evidence.Status == StatusPass {
				t.Fatalf("evidence = %+v", evidence)
			}
		})
	}
}

func TestRunCancellationUsesIndependentCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	config, provider, dns, clock := validFixture()
	dns.authMismatchSweeps = 100
	clock.cancel = cancel

	evidence := Run(ctx, config, provider, dns, clock, strings.NewReader(strings.Repeat("x", 32)))
	if evidence.Status != StatusFail || evidence.Reason != ReasonCanceled || !evidence.CleanupComplete || len(provider.records) != 0 {
		t.Fatalf("evidence = %+v records=%v", evidence, provider.records)
	}
}

func TestRunMarksCleanupPendingUnlessProviderAndDNSAbsenceAreProven(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeProvider, *fakeDNS)
	}{
		{name: "provider remains", mutate: func(p *fakeProvider, _ *fakeDNS) { p.keepTargetOnDelete = true }},
		{name: "target delete removes sentinel", mutate: func(p *fakeProvider, _ *fakeDNS) { p.deleteSentinelWithTarget = true }},
		{name: "dns remains", mutate: func(_ *fakeProvider, d *fakeDNS) { d.cleanupNeverAbsent = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, provider, dns, clock := validFixture()
			test.mutate(provider, dns)
			evidence := Run(t.Context(), config, provider, dns, clock, strings.NewReader(strings.Repeat("x", 32)))
			if evidence.Status != StatusCleanupPending || evidence.CleanupComplete {
				t.Fatalf("evidence = %+v", evidence)
			}
		})
	}
}

func TestRunCleanupReconcilesSameExactValueUnderReplacementHandle(t *testing.T) {
	tests := []struct {
		name          string
		keepRecovered bool
		wantStatus    string
		wantComplete  bool
	}{
		{name: "recovered handle is removed", wantStatus: StatusPass, wantComplete: true},
		{name: "recovered handle remains", keepRecovered: true, wantStatus: StatusCleanupPending},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, provider, dns, clock := validFixture()
			provider.replaceTargetOnFirstDelete = true
			provider.keepRecoveredTargetOnDelete = test.keepRecovered
			evidence := Run(t.Context(), config, provider, dns, clock, strings.NewReader(strings.Repeat("x", 32)))
			if evidence.Status != test.wantStatus || evidence.CleanupComplete != test.wantComplete {
				t.Fatalf("evidence = %+v", evidence)
			}
			if got := provider.recoverCalls["target"]; got != 2 {
				t.Fatalf("target RecoverTXT calls = %d, want bounded 2", got)
			}
			if test.keepRecovered {
				if _, exists := provider.recordByKind("target"); !exists {
					t.Fatal("replacement target unexpectedly absent")
				}
			} else if _, exists := provider.recordByKind("target"); exists {
				t.Fatal("replacement target was not cleaned")
			}
		})
	}
}

func TestEvidenceIsRedactedAndWriteEvidenceIsAtomic0600(t *testing.T) {
	config, provider, dns, clock := validFixture()
	evidence := Run(t.Context(), config, provider, dns, clock, strings.NewReader(strings.Repeat("x", 32)))
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{config.Zone, config.GuardOwner, config.TenantID.String(), config.ProviderID.String()}
	for endpoint := range dns.labels {
		forbidden = append(forbidden, endpoint.String())
	}
	for _, challenge := range provider.presented {
		forbidden = append(forbidden, challenge.RecordName, challenge.ExactValue, challenge.OperationID, challenge.AttemptID.String(), challenge.AuthorizationURL, challenge.ChallengeURL, challenge.TXTHandle.RecordRef)
	}
	for _, value := range forbidden {
		if value != "" && strings.Contains(string(raw), value) {
			t.Fatalf("evidence contains forbidden value %q: %s", value, raw)
		}
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteEvidence(path, evidence); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	var decoded Evidence
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil || !reflect.DeepEqual(decoded, evidence) {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".evidence.json.tmp-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files = %v, err=%v", matches, err)
	}

	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteEvidence(link, evidence); err == nil {
		t.Fatal("WriteEvidence accepted symlink")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "keep" {
		t.Fatalf("symlink target changed: %q, %v", got, err)
	}
	injected := evidence
	injected.Reason = "SENTINEL-SECRET"
	if err := WriteEvidence(filepath.Join(dir, "injected.json"), injected); err == nil {
		t.Fatal("WriteEvidence accepted unbounded evidence classification")
	}
}

func TestWriteEvidenceRejectsUnreachableStateCombinations(t *testing.T) {
	valid := Evidence{
		Schema:             EvidenceSchema,
		Status:             StatusPass,
		Reason:             ReasonVerified,
		Phase:              PhaseComplete,
		ProviderCode:       "cloudflare",
		AuthoritativeCount: 2,
		PublicCount:        2,
		CleanupAttempted:   true,
		CleanupComplete:    true,
		ElapsedSeconds:     1,
	}
	tests := []struct {
		name   string
		mutate func(*Evidence)
	}{
		{name: "pass reason", mutate: func(e *Evidence) { e.Reason = ReasonProviderObserve }},
		{name: "pass phase", mutate: func(e *Evidence) { e.Phase = PhaseCleanup }},
		{name: "pass cleanup not attempted", mutate: func(e *Evidence) { e.CleanupAttempted = false }},
		{name: "pass cleanup incomplete", mutate: func(e *Evidence) { e.CleanupComplete = false }},
		{name: "verified fail", mutate: func(e *Evidence) { e.Status = StatusFail }},
		{name: "verified cleanup pending", mutate: func(e *Evidence) { e.Status = StatusCleanupPending; e.CleanupComplete = false }},
		{name: "cleanup pending not attempted", mutate: func(e *Evidence) {
			e.Status = StatusCleanupPending
			e.Reason = ReasonRecoveryAmbiguous
			e.Phase = PhaseCleanup
			e.CleanupAttempted = false
			e.CleanupComplete = false
		}},
		{name: "cleanup pending complete", mutate: func(e *Evidence) {
			e.Status = StatusCleanupPending
			e.Reason = ReasonRecoveryAmbiguous
			e.Phase = PhaseCleanup
			e.CleanupComplete = true
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := valid
			test.mutate(&evidence)
			path := filepath.Join(t.TempDir(), "evidence.json")
			if err := WriteEvidence(path, evidence); err == nil {
				t.Fatalf("WriteEvidence accepted unreachable evidence: %+v", evidence)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected evidence created target: %v", err)
			}
		})
	}
}

func validFixture() (Config, *fakeProvider, *fakeDNS, *fakeClock) {
	authoritative := []Endpoint{
		{Address: netip.MustParseAddrPort("192.0.2.10:53")},
		{Address: netip.MustParseAddrPort("192.0.2.11:53")},
	}
	public := []Endpoint{
		{Address: netip.MustParseAddrPort("198.51.100.10:53")},
		{Address: netip.MustParseAddrPort("198.51.100.11:53")},
	}
	config := Config{
		ProviderCode:   "cloudflare",
		Zone:           "example.test",
		GuardOwner:     "_cdnca-live-guard.example.test.",
		GuardSHA256:    sha256.Sum256([]byte("guard-proof")),
		Authoritative:  authoritative,
		Public:         public,
		Timeout:        60 * time.Second,
		CleanupTimeout: 60 * time.Second,
		TenantID:       uuid.MustParse("10000000-0000-4000-8000-000000000001"),
		ScopeID:        uuid.MustParse("11000000-0000-4000-8000-000000000001"),
		ProviderID:     uuid.MustParse("20000000-0000-4000-8000-000000000001"),
		ZoneID:         uuid.MustParse("30000000-0000-4000-8000-000000000001"),
	}
	provider := newFakeProvider()
	labels := map[netip.AddrPort]string{
		authoritative[0].Address: "auth-1",
		authoritative[1].Address: "auth-2",
		public[0].Address:        "public-1",
		public[1].Address:        "public-2",
	}
	dns := &fakeDNS{
		provider:       provider,
		guardOwner:     config.GuardOwner,
		guardValue:     "guard-proof",
		labels:         labels,
		guardOverrides: make(map[netip.AddrPort]TXTObservation),
		authoritative: map[netip.AddrPort]bool{
			authoritative[0].Address: true,
			authoritative[1].Address: true,
		},
		public: map[netip.AddrPort]bool{
			public[0].Address: true,
			public[1].Address: true,
		},
		publicPropagationRecursive: true,
		publicCleanupRecursive:     true,
	}
	clock := &fakeClock{now: time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)}
	return config, provider, dns, clock
}

func assertCompleteIdentities(t *testing.T, config Config, identities []acmeworker.ChallengeIdentity) {
	t.Helper()
	if len(identities) != 2 {
		t.Fatalf("identities = %d", len(identities))
	}
	if identities[0].RecordName != identities[1].RecordName || identities[0].ExactValue == identities[1].ExactValue {
		t.Fatalf("same-owner identities invalid: %+v", identities)
	}
	assertIdentityAuthority(t, config, identities)
	for _, identity := range identities {
		if identity.ChallengeType != acmeworker.ChallengeDNS01 || identity.OperationID == "" || identity.AttemptID == uuid.Nil ||
			identity.AuthorizationURL == "" || identity.ChallengeURL == "" || identity.Identifier != config.Zone || identity.Token == "" ||
			!strings.HasSuffix(identity.RecordName, "."+config.Zone+".") {
			t.Fatalf("incomplete identity: %+v", identity)
		}
	}
}

func assertIdentityAuthority(t *testing.T, config Config, identities []acmeworker.ChallengeIdentity) {
	t.Helper()
	for _, identity := range identities {
		if identity.TenantID != config.TenantID || identity.ScopeID != config.ScopeID || identity.ProviderID != config.ProviderID ||
			identity.ZoneID != config.ZoneID || identity.ProviderRef != config.ProviderID.String() {
			t.Fatalf("identity authority changed: %+v", identity)
		}
	}
}

func filterPrefix(values []string, prefix string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			result = append(result, value)
		}
	}
	return result
}

func valueKind(value string) string {
	switch {
	case strings.HasPrefix(value, "cdnca-live-sentinel-"):
		return "sentinel"
	case strings.HasPrefix(value, "cdnca-live-target-"):
		return "target"
	default:
		return "unknown"
	}
}

var _ Provider = (*fakeProvider)(nil)
var _ DNS = (*fakeDNS)(nil)
var _ Clock = (*fakeClock)(nil)
