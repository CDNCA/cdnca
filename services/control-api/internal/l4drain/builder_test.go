package l4drain

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBuildCommandProducesStableNormalizedCanonicalPlan(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	input := CommandInput{CommandID: uuid.NewString(), NodeID: uuid.NewString(), RequestID: uuid.NewString(),
		OccurredAt: now, Deadline: now.Add(time.Hour), Plan: Plan{
			SchemaVersion: SchemaVersionV1, PlanID: "l4-plan", Revision: 3,
			Old: Version{VersionID: "old-v1", Listeners: []Listener{
				{ID: "tcp-b", Protocol: "tcp", Address: "127.0.0.1", Port: 18081, UpstreamAddress: "127.0.0.1", UpstreamPort: 19081},
				{ID: "tcp-a", Protocol: "tcp", Address: "127.0.0.1", Port: 18080, UpstreamAddress: "127.0.0.1", UpstreamPort: 19080},
			}},
			New: Version{VersionID: "new-v1", Listeners: []Listener{
				{ID: "tcp-b", Protocol: "tcp", Address: "127.0.0.1", Port: 18081, UpstreamAddress: "127.0.0.1", UpstreamPort: 29081},
				{ID: "tcp-a", Protocol: "tcp", Address: "127.0.0.1", Port: 18080, UpstreamAddress: "127.0.0.1", UpstreamPort: 29080},
			}},
			HealthTimeoutSeconds: 10, HealthChecks: []HealthCheck{
				{ListenerID: "tcp-b", Payload: "ping-b", ExpectedBodyPrefix: "pong-b"},
				{ListenerID: "tcp-a", Payload: "ping-a", ExpectedBodyPrefix: "pong-a"},
			}, Drain: DrainPolicy{MaxDrainSeconds: 60, Force: "never"},
		}}
	first, err := BuildCommand(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildCommand(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.CanonicalPlanJson, second.CanonicalPlanJson) || !bytes.Equal(first.PlanSha256, second.PlanSha256) ||
		!bytes.Contains(first.CanonicalPlanJson, []byte(`"listeners":[{"id":"tcp-a"`)) ||
		!bytes.Contains(first.CanonicalPlanJson, []byte(`"health_checks":[{"listener_id":"tcp-a"`)) {
		t.Fatalf("canonical plan is unstable or unsorted: %s", first.CanonicalPlanJson)
	}
	digest := sha256.Sum256(first.CanonicalPlanJson)
	if !bytes.Equal(first.PlanSha256, digest[:]) || first.Event.EventId != second.Event.EventId {
		t.Fatal("command digest or deterministic event identity is invalid")
	}
}

func TestBuildCommandAllowsRetiringTheLastListenerWithoutFakeHealthCheck(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	command, err := BuildCommand(CommandInput{
		CommandID: uuid.NewString(), NodeID: uuid.NewString(), RequestID: uuid.NewString(),
		OccurredAt: now, Deadline: now.Add(time.Hour), Plan: Plan{
			SchemaVersion: SchemaVersionV1, PlanID: "retire-last", Revision: 4,
			Old: Version{VersionID: "old", Listeners: []Listener{{
				ID: "tcp", Protocol: "tcp", Address: "0.0.0.0", Port: 443,
				UpstreamAddress: "192.0.2.10", UpstreamPort: 8443,
			}}},
			New:                  Version{VersionID: "retired", Listeners: []Listener{}},
			HealthTimeoutSeconds: 10, HealthChecks: []HealthCheck{},
			Drain: DrainPolicy{MaxDrainSeconds: 60, Force: "never"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(command.CanonicalPlanJson, []byte(`"new":{"version_id":"retired","listeners":[]}`)) ||
		!bytes.Contains(command.CanonicalPlanJson, []byte(`"health_checks":[]`)) {
		t.Fatalf("last-listener retirement was not frozen exactly: %s", command.CanonicalPlanJson)
	}
}
