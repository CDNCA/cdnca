package cachefreshness

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFollowOriginPublisherBindsRootToTenantAndSite(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Policy)
	}{
		{"tenant", func(policy *Policy) { policy.TenantID = "tenant-b" }},
		{"site", func(policy *Policy) { policy.SiteID = "site-b" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublisherFixture(t)
			first := followOriginPublicationPolicy(1)
			applyFollowOriginPolicy(t, fixture, first)
			currentBefore := fixture.pointer(t, "current")
			lkgBefore := fixture.pointer(t, "lkg")
			callsBefore := fixture.runtime.callCount()

			candidate := followOriginPublicationPolicy(2)
			test.mutate(&candidate)
			raw, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.publisher.ApplyJSON(context.Background(), raw); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("ApplyJSON error = %v, want ErrInvalidPolicy", err)
			}
			if fixture.pointer(t, "current") != currentBefore || fixture.pointer(t, "lkg") != lkgBefore {
				t.Fatal("foreign scope candidate changed current or LKG")
			}
			if fixture.runtime.callCount() != callsBefore {
				t.Fatal("foreign scope candidate reached the runtime")
			}
			if _, err := os.Lstat(filepath.Join(fixture.root, "versions", versionDirectory(2))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("foreign scope release was persisted: %v", err)
			}
		})
	}
}

func TestFollowOriginPublisherAllowsConfigurationVersionAdvanceWithinScope(t *testing.T) {
	fixture := newPublisherFixture(t)
	first := followOriginPublicationPolicy(1)
	first.ConfigurationVersion = 11
	applyFollowOriginPolicy(t, fixture, first)

	second := followOriginPublicationPolicy(2)
	second.ConfigurationVersion = 12
	publication := applyFollowOriginPolicy(t, fixture, second)
	if !publication.Changed || publication.PolicyVersion != 2 {
		t.Fatalf("publication = %#v", publication)
	}
	current := string(fixture.readCurrent(t))
	if !strings.Contains(current, "tenant=tenant-a|site=site-a|config=12|") {
		t.Fatalf("current config does not isolate configuration version 12: %s", current)
	}
}

func TestFollowOriginInvalidNewerPolicyPreservesLKG(t *testing.T) {
	fixture := newPublisherFixture(t)
	applyFollowOriginPolicy(t, fixture, followOriginPublicationPolicy(1))
	currentBefore := fixture.pointer(t, "current")
	lkgBefore := fixture.pointer(t, "lkg")
	callsBefore := fixture.runtime.callCount()

	candidate := followOriginPublicationPolicy(2)
	candidate.FollowOriginHeaders = false
	candidate.FreshSeconds = 0
	raw, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.publisher.ApplyJSON(context.Background(), raw); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("ApplyJSON error = %v, want ErrInvalidPolicy", err)
	}
	if fixture.pointer(t, "current") != currentBefore || fixture.pointer(t, "lkg") != lkgBefore {
		t.Fatal("invalid newer policy changed current or LKG")
	}
	if fixture.runtime.callCount() != callsBefore {
		t.Fatal("invalid newer policy reached the runtime")
	}
}

func followOriginPublicationPolicy(version uint64) Policy {
	policy := validPolicy()
	policy.PolicyVersion = version
	policy.FollowOriginHeaders = true
	return policy
}

func applyFollowOriginPolicy(t *testing.T, fixture *publisherFixture, policy Policy) Publication {
	t.Helper()
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := fixture.publisher.ApplyJSON(context.Background(), raw)
	if err != nil {
		t.Fatalf("ApplyJSON version %d: %v", policy.PolicyVersion, err)
	}
	return publication
}
