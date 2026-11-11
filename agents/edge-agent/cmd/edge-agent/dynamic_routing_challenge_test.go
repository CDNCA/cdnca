package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/challenge"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
)

// on a dynamic routing node the challenge artifact
// installer must write under <dynamic state root>/challenge, the directory
// the skeleton's challenge_root hands to the workers' Lua. dynamicRoutingManager
// has no StateRoot(), so the daemon passes the consumer explicitly.
func TestDynamicRoutingChallengeConsumerWritesWhereTheSkeletonReads(t *testing.T) {
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var config fileConfig
	config.DeploymentRoot = filepath.Join(t.TempDir(), "deployment")
	config.DynamicRouting.StateRoot = state
	if got, _ := dynamicRoutingRoots(config); got != state {
		t.Fatalf("state root = %q, want %q", got, state)
	}
	consumer, err := dynamicRoutingChallengeConsumer(config)
	if err != nil {
		t.Fatal(err)
	}
	binding := challenge.ArtifactBinding{
		EventID: "01990000-0000-7000-8000-000000000001", DeploymentID: "01990000-0000-7000-8000-000000000002",
		Attempt: 1, ConfigVersionID: "01990000-0000-7000-8000-000000000003",
		ArtifactID: "01990000-0000-7000-8000-000000000004", RecipientKeyID: "x25519:" + strings.Repeat("a", 64),
		PolicyID: "01990000-0000-7000-8000-000000000005", TenantID: "01990000-0000-7000-8000-000000000006", PolicyVersion: 3,
	}
	raw, err := json.Marshal(challenge.ArtifactDocument{
		SchemaVersion: challenge.ArtifactSchemaVersion,
		Activation: challenge.ArtifactActivation{
			SchemaVersion: challenge.ActivationSchemaVersion, EventID: binding.EventID, DeploymentID: binding.DeploymentID,
			Attempt: binding.Attempt, ConfigVersionID: binding.ConfigVersionID, ArtifactID: binding.ArtifactID,
			RecipientKeyID: binding.RecipientKeyID, PolicyID: binding.PolicyID, TenantID: binding.TenantID, PolicyVersion: binding.PolicyVersion,
		},
		Policy: challenge.Policy{
			SchemaVersion: challenge.SchemaVersion, PolicyVersion: binding.PolicyVersion, Algorithm: challenge.AlgorithmHMACSHA256,
			CookieName: "__Host-cdnca_challenge", TrustedProxies: []string{}, BypassRoutes: []challenge.BypassRoute{},
			CurrentKey: challenge.KeyRef{KeyID: "key-current"},
			Rules: []challenge.Rule{{RuleID: "01990000-0000-7000-8000-000000000007", Priority: 10,
				TenantID: binding.TenantID, SiteID: "01990000-0000-7000-8000-000000000008", Host: "edge.example.test",
				Mode: challenge.ModeClick, ChallengeTTLSeconds: 60, PassTTLSeconds: 300, ClockSkewSeconds: 10,
				AttemptsPerNonce: 1, FailureWindowSeconds: 60, MaxFailuresPerWindow: 5, IPBinding: challenge.IPBindingExact, BindUserAgent: true}},
		},
		Keys: []challenge.ArtifactKey{{KeyID: "key-current", Secret: []byte("current-challenge-secret-material-01")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := consumer.InstallJSON(raw, binding)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	// the skeleton renders challenge_root = <state root>/<ChallengeDirectory>
	luaRoot := filepath.Join(state, edgeskeleton.ChallengeDirectory)
	want := filepath.Join(luaRoot, "policies", binding.PolicyID, "versions", "00000000000000000003.json")
	if result.CurrentPath != want {
		t.Fatalf("policy installed at %q, Lua reads %q", result.CurrentPath, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(config.DeploymentRoot, "challenge")); !os.IsNotExist(err) {
		t.Fatalf("nothing may be written under the deployment root: %v", err)
	}
}

func TestDynamicRoutingChallengeConsumerNeedsTheStateRoot(t *testing.T) {
	var config fileConfig
	config.DeploymentRoot = filepath.Join(t.TempDir(), "deployment")
	config.DynamicRouting.StateRoot = filepath.Join(t.TempDir(), "missing")
	if _, err := dynamicRoutingChallengeConsumer(config); err == nil {
		t.Fatal("a missing state root must be refused")
	}
}
