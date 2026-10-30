package controlupgrade

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

func TestMaintenanceCurrentVersionUsesOnlyRunningBuild(t *testing.T) {
	for _, test := range []struct {
		build, configured, want string
		matches                 *bool
	}{
		{"2.4.1", "2.4.1", "2.4.1", boolValue(true)},
		{"2.4.1", "2.4.9", "2.4.1", boolValue(false)},
		{"development", "2.4.9", "", nil},
		{"", "2.4.9", "", nil},
		{"2.4.1", "", "2.4.1", nil},
	} {
		status := maintenanceControlFacts(MaintenanceRuntime{CurrentVersion: test.build, ConfiguredVersion: test.configured})
		if test.want == "" && status.CurrentVersion != nil || test.want != "" && (status.CurrentVersion == nil || *status.CurrentVersion != test.want) {
			t.Fatalf("build %q = %+v", test.build, status)
		}
		if test.matches == nil && status.ConfiguredVersionMatches != nil || test.matches != nil && (status.ConfiguredVersionMatches == nil || *status.ConfiguredVersionMatches != *test.matches) {
			t.Fatalf("configuration provenance = %+v", status)
		}
		if status.Runtime.Ready {
			t.Fatal("read status incorrectly enabled control-plane execution")
		}
	}
}

func boolValue(value bool) *bool { return &value }

type maintenanceReaderFunc func(context.Context, string, string, int) (MaintenanceCandidate, error)

func (f maintenanceReaderFunc) ReadCandidate(ctx context.Context, component, version string, protocol int) (MaintenanceCandidate, error) {
	return f(ctx, component, version, protocol)
}

func TestMaintenanceCandidateExpiryAuthorizationAndDependencyFailure(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	expires := now.Add(time.Minute)
	target := "2.5.0"
	grant := entitlementguard.VersionGrant{Channel: "stable", MinVersion: "2.0.0", MaxVersion: "3.0.0"}
	authorization := MaintenanceAuthorization{State: "valid", Reason: "eligible", Channel: "stable"}
	for _, test := range []struct {
		name    string
		modify  func(*MaintenanceCandidate)
		failure error
		want    string
	}{
		{"fresh", func(*MaintenanceCandidate) {}, nil, "upgrade_available"},
		{"expired", func(c *MaintenanceCandidate) { c.ExpiresAt = &now }, nil, "candidate_expired"},
		{"missing time", func(c *MaintenanceCandidate) { c.ExpiresAt = nil }, nil, "candidate_expired"},
		{"channel mismatch", func(c *MaintenanceCandidate) { c.Channel = "beta" }, nil, "candidate_not_authorized"},
		{"range denied", func(c *MaintenanceCandidate) { v := "4.0.0"; c.Version = &v }, nil, "candidate_not_authorized"},
		{"withdrawn", func(c *MaintenanceCandidate) {
			c.State = "unavailable"
			c.Reason = "artifact_unavailable"
			c.Version = nil
		}, nil, "artifact_unavailable"},
		{"offline", func(*MaintenanceCandidate) {}, errors.New("upstream offline"), "candidate_service_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := MaintenanceCandidate{State: "available", Reason: "upgrade_available", Version: &target, ExpiresAt: &expires, Channel: "stable"}
			test.modify(&candidate)
			reader := maintenanceReaderFunc(func(_ context.Context, component, version string, protocol int) (MaintenanceCandidate, error) {
				if component != "control-api" || version != "2.4.1" || protocol != 1 {
					t.Fatal("request provenance was substituted")
				}
				return candidate, test.failure
			})
			got := maintenanceReadCandidate(t.Context(), reader, "control-api", "2.4.1", 1, authorization, grant, func() time.Time { return now })
			if got.Reason != test.want {
				t.Fatalf("got %+v want %s", got, test.want)
			}
			if got.State == "unavailable" && got.Version != nil {
				t.Fatal("unavailable candidate retained a target")
			}
		})
	}
	for _, state := range []string{"unavailable", "invalid", "denied"} {
		called := false
		reader := maintenanceReaderFunc(func(context.Context, string, string, int) (MaintenanceCandidate, error) {
			called = true
			return MaintenanceCandidate{}, nil
		})
		result := maintenanceReadCandidate(t.Context(), reader, "control-api", "2.4.1", 1, MaintenanceAuthorization{State: state, Reason: "blocked"}, grant, func() time.Time { return now })
		if called || result.State != "unavailable" || result.Reason != "blocked" {
			t.Fatal("authorization denial contacted upstream")
		}
	}
}

func TestMaintenanceNodeEligibilityDoesNotTreatDifferentVersionsAsUpgradeAuthority(t *testing.T) {
	for _, state := range []string{"up_to_date", "rollback_required", "unavailable"} {
		got := maintenanceNodeEligibility(MaintenanceNodeStatus{Candidate: MaintenanceCandidate{State: state, Reason: state}, Runtime: MaintenanceRuntimeState{Ready: true}})
		if got.Eligible {
			t.Fatalf("%s node marked eligible", state)
		}
	}
	for _, blocker := range []string{"node_offline", "node_disabled", "node_capability_unavailable"} {
		got := maintenanceNodeEligibility(MaintenanceNodeStatus{Reason: blocker, Candidate: MaintenanceCandidate{State: "available"}, Runtime: MaintenanceRuntimeState{Ready: true}})
		if got.Eligible || got.Reason != blocker {
			t.Fatalf("lost node facts: %+v", got)
		}
	}
	got := maintenanceNodeEligibility(MaintenanceNodeStatus{Candidate: MaintenanceCandidate{State: "available"}, Runtime: MaintenanceRuntimeState{Reason: "node_upgrade_runtime_unavailable"}})
	if got.Eligible || got.Reason != "node_upgrade_runtime_unavailable" {
		t.Fatal("unavailable runtime accepted")
	}
}

func TestMaintenanceStatusValidatesScopeAndNodeIDsBeforeReading(t *testing.T) {
	var service *Service
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	if _, err := service.ReadMaintenanceStatus(t.Context(), Actor{}, MaintenanceRuntime{}, nil); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal(err)
	}
	for _, ids := range [][]string{{"bad"}, {uuid.Nil.String()}, {actor.UserID.String(), actor.UserID.String()}, make([]string, 101)} {
		if _, err := service.ReadMaintenanceStatus(t.Context(), actor, MaintenanceRuntime{}, ids); !errors.Is(err, ErrInvalidInput) {
			t.Fatal(err)
		}
	}
}

func TestMaintenanceCandidateRejectsInconsistentReaderStates(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	expires := now.Add(time.Minute)
	for _, test := range []struct{ state, reason, version string }{
		{"available", "upgrade_available", "2.3.0"},
		{"up_to_date", "same_version", "2.5.0"},
		{"rollback_required", "target_is_older", "2.5.0"},
		{"available", "same_version", "2.5.0"},
		{"unexpected", "upgrade_available", "2.5.0"},
		{"unavailable", "artifact_unavailable", "2.5.0"},
	} {
		t.Run(test.state+"/"+test.reason+"/"+test.version, func(t *testing.T) {
			reader := maintenanceReaderFunc(func(context.Context, string, string, int) (MaintenanceCandidate, error) {
				return MaintenanceCandidate{State: test.state, Reason: test.reason, Version: &test.version, ExpiresAt: &expires, Channel: "stable"}, nil
			})
			result := maintenanceReadCandidate(t.Context(), reader, "control-api", "2.4.1", 1,
				MaintenanceAuthorization{State: "valid"}, entitlementguard.VersionGrant{Channel: "stable", MinVersion: "2.0.0", MaxVersion: "3.0.0"}, func() time.Time { return now })
			if result.State != "unavailable" || result.Version != nil {
				t.Fatalf("inconsistent candidate accepted: %+v", result)
			}
		})
	}
}
