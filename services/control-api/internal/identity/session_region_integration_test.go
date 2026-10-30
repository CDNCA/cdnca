//go:build integration

package identity_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// fakeRegions: 203.0.113.0/24 is CN-11, 198.51.100.0/24 is CN-31, 192.0.2.0/24 unknown.
type fakeRegions struct{}

func (fakeRegions) Region(_ context.Context, address netip.Addr) (string, bool) {
	switch {
	case strings.HasPrefix(address.String(), "203.0.113."):
		return "CN-11", true
	case strings.HasPrefix(address.String(), "198.51.100."):
		return "CN-31", true
	}
	return "", false
}

func TestSessionRegionChangeRequiresPassword(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	fixture.service.SetRegionResolver(fakeRegions{})
	ctx := t.Context()
	from := func(address string) context.Context { return audit.WithSourceIP(ctx, netip.MustParseAddr(address)) }
	login, err := fixture.service.Login(ctx, identity.LoginInput{Username: fixture.username, Password: fixture.password},
		identity.RequestInfo{RequestID: "region-login", SourceIP: "203.0.113.4"})
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"203.0.113.200", "192.0.2.9", "10.0.0.1"} {
		if _, err := fixture.service.Authenticate(from(address), login.AccessToken); err != nil {
			t.Fatalf("same or unknown region %s: %v", address, err)
		}
	}
	for range 2 {
		if _, err := fixture.service.AuthenticateSession(from("198.51.100.7"), login.AccessToken); !errors.Is(err, identity.ErrSessionRegionChanged) {
			t.Fatalf("region change: %v", err)
		}
	}
	if err := fixture.service.VerifySessionRegion(ctx, login.AccessToken, "wrong", identity.RequestInfo{RequestID: "v1", SourceIP: "198.51.100.7"}); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if err := fixture.service.VerifySessionRegion(ctx, login.AccessToken, fixture.password, identity.RequestInfo{RequestID: "v2", SourceIP: "198.51.100.7"}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := fixture.service.Authenticate(from("198.51.100.7"), login.AccessToken); err != nil {
		t.Fatalf("after verify: %v", err)
	}
	// Back in the first region is again a change.
	if _, err := fixture.service.Authenticate(from("203.0.113.4"), login.AccessToken); !errors.Is(err, identity.ErrSessionRegionChanged) {
		t.Fatalf("change back: %v", err)
	}
	var challenges, verifies int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action='auth.session_region.challenge'),
		count(*) FILTER (WHERE action='auth.session_region.verify' AND result='success') FROM audit_events`).Scan(&challenges, &verifies); err != nil {
		t.Fatal(err)
	}
	if challenges != 2 || verifies != 1 {
		t.Fatalf("challenges=%d verifies=%d (one challenge per new region)", challenges, verifies)
	}
}

func TestSessionRegionCheckFollowsPlatformSetting(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	fixture.service.SetRegionResolver(fakeRegions{})
	fixture.service.SetPublicSettingsReader(throttleSettings{limit: 30, threshold: 30}) // SessionRegionCheck false
	login, err := fixture.service.Login(t.Context(), identity.LoginInput{Username: fixture.username, Password: fixture.password},
		identity.RequestInfo{RequestID: "region-off", SourceIP: "203.0.113.4"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Authenticate(audit.WithSourceIP(t.Context(), netip.MustParseAddr("198.51.100.7")), login.AccessToken); err != nil {
		t.Fatalf("check off: %v", err)
	}
}
