package dnspropagation

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

const n21TXTName, n21TXTValue = "_acme-challenge.www.868yun.com.", "token-value"

// n21TXTSource reuses partialSource with the twelve 868yun.com endpoints, all
// serving the ACME token unless overridden, and the zone found at 868yun.com.
func n21TXTSource() *partialSource {
	source := n21Fixture()
	for _, resolver := range source.delegation.Authorities {
		observation := n21Answer(RoleAuthoritative, resolver.ID,
			[]RRSet{{Type: dnscheck.RecordTXT, Values: []string{n21TXTValue}}})
		source.observations[resolver.ID] = observation
	}
	return source
}

type n21TXTZoneSource struct{ *partialSource }

func (source n21TXTZoneSource) Discover(_ context.Context, _ string, zone string) (Delegation, error) {
	if zone != "868yun.com." {
		return Delegation{}, errInvalidWireResponse
	}
	return source.delegation, nil
}

func n21TXTChecker(t *testing.T, source *partialSource, timeout time.Duration) *AuthoritativeTXT {
	t.Helper()
	checker, err := NewAuthoritativeTXT(n21TXTZoneSource{source})
	if err != nil {
		t.Fatal(err)
	}
	if timeout > 0 {
		checker.endpointTimeout = timeout
	}
	return checker
}

// N21 for ACME DNS-01: two unreachable AAAA authorities and one timed-out
// anycast node must not keep the token invisible forever.
func TestN21AuthoritativeTXTThreeOfTwelveUnreachableStillVisible(t *testing.T) {
	t.Parallel()
	source := n21TXTSource()
	source.errs["[2001:db8::6]:53"] = unreachable()
	source.errs["[2001:db8::16]:53"] = unreachable()
	source.errs["192.0.2.13:53"] = context.DeadlineExceeded
	visible, err := n21TXTChecker(t, source, 0).TXTVisible(context.Background(), n21TXTName, n21TXTValue)
	if err != nil || !visible {
		t.Fatalf("TXTVisible() = %v, %v; want visible over the nine reachable authorities", visible, err)
	}
}

func TestN21AuthoritativeTXTAllUnreachableNotVisible(t *testing.T) {
	t.Parallel()
	source := n21TXTSource()
	for _, resolver := range source.delegation.Authorities {
		source.errs[resolver.ID] = unreachable()
	}
	visible, err := n21TXTChecker(t, source, 0).TXTVisible(context.Background(), n21TXTName, n21TXTValue)
	if err != nil || visible {
		t.Fatalf("TXTVisible() = %v, %v; want not visible", visible, err)
	}
}

// Two NS names: one fully unreachable leaves no strict majority.
func TestN21AuthoritativeTXTOneOfTwoNameServersUnreachableNotVisible(t *testing.T) {
	t.Parallel()
	source := n21TXTSource()
	for _, resolver := range source.delegation.Authorities {
		if resolver.Name == "permanent.dnspod.net." {
			source.errs[resolver.ID] = errAddressFamilyUnavailable
		}
	}
	visible, err := n21TXTChecker(t, source, 0).TXTVisible(context.Background(), n21TXTName, n21TXTValue)
	if err != nil || visible {
		t.Fatalf("TXTVisible() = %v, %v; want not visible", visible, err)
	}
}

func TestN21AuthoritativeTXTReachableLaggingAuthorityNotVisible(t *testing.T) {
	t.Parallel()
	source := n21TXTSource()
	source.errs["[2001:db8::6]:53"] = unreachable()
	source.observations["192.0.2.14:53"] = n21Answer(RoleAuthoritative, "192.0.2.14:53",
		[]RRSet{{Type: dnscheck.RecordTXT, Values: []string{"stale"}}})
	visible, err := n21TXTChecker(t, source, 0).TXTVisible(context.Background(), n21TXTName, n21TXTValue)
	if err != nil || visible {
		t.Fatalf("TXTVisible() = %v, %v; want not visible", visible, err)
	}
}

func TestN21AuthoritativeTXTSlowEndpointBoundedByTimeout(t *testing.T) {
	t.Parallel()
	source := n21TXTSource()
	source.block["192.0.2.3:53"] = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	visible, err := n21TXTChecker(t, source, 50*time.Millisecond).TXTVisible(ctx, n21TXTName, n21TXTValue)
	if err != nil || !visible {
		t.Fatalf("TXTVisible() = %v, %v; want visible", visible, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("TXTVisible() took %v, want bounded by the endpoint timeout", elapsed)
	}
}
