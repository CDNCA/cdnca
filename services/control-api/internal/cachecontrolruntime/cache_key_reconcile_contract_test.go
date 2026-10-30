package cachecontrolruntime

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func TestBuildCommandRejectsNonCanonicalCacheKeyIdentity(t *testing.T) {
	base := testClaim(cachecontrol.ActionPrewarm, cachecontrol.TargetExactURL)
	base.Targets[0] = cachecontrol.Target{
		Ordinal: 1, CanonicalURL: "https://cache.example/assets/app.css?lang=zh&v=2",
		CanonicalPath: "/assets/app.css",
	}
	for _, test := range []struct {
		name   string
		mutate func(*cachecontrol.Claim)
	}{
		{name: "path mismatch", mutate: func(claim *cachecontrol.Claim) {
			claim.Targets[0].CanonicalPath = "/assets/old.css"
		}},
		{name: "uppercase host", mutate: func(claim *cachecontrol.Claim) {
			claim.Targets[0].CanonicalURL = "https://CACHE.example/assets/app.css?lang=zh&v=2"
		}},
		{name: "default port", mutate: func(claim *cachecontrol.Claim) {
			claim.Targets[0].CanonicalURL = "https://cache.example:443/assets/app.css?lang=zh&v=2"
		}},
		{name: "fragment", mutate: func(claim *cachecontrol.Claim) {
			claim.Targets[0].CanonicalURL += "#stale-listener"
		}},
		{name: "duplicate cache key", mutate: func(claim *cachecontrol.Claim) {
			claim.Targets = append(claim.Targets, cachecontrol.Target{
				Ordinal: 2, CanonicalURL: claim.Targets[0].CanonicalURL,
				CanonicalPath: claim.Targets[0].CanonicalPath,
			})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			claim := base
			claim.Targets = append([]cachecontrol.Target(nil), base.Targets...)
			test.mutate(&claim)
			if _, err := buildCommand(claim); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("buildCommand() error = %v, want ErrInvalidConfig", err)
			}
		})
	}

	wholeSite := testClaim(cachecontrol.ActionPurge, cachecontrol.TargetWholeSite)
	wholeSite.Targets[0].CanonicalURL = "https://cache.example/"
	if _, err := buildCommand(wholeSite); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("whole-site target error = %v, want ErrInvalidConfig", err)
	}
}

func TestCommandAndStatusBindImmutableCacheIdentity(t *testing.T) {
	claim := testClaim(cachecontrol.ActionPrewarm, cachecontrol.TargetExactURL)
	claim.Targets[0].CanonicalURL = "https://cache.example:8443/assets/app.css?lang=zh&v=2"
	command, err := buildCommand(claim)
	if err != nil {
		t.Fatal(err)
	}
	wantTargetDigest := sha256.Sum256([]byte(claim.Targets[0].CanonicalURL))
	if !bytes.Equal(command.RequestDigest, claim.RequestDigest[:]) ||
		command.ConfigVersionId != claim.ConfigVersionID.String() || command.ConfigRevision != claim.ConfigRevision ||
		!bytes.Equal(command.Targets[0].Sha256, wantTargetDigest[:]) {
		t.Fatalf("command identity is not bound to the immutable claim: %+v", command)
	}

	valid := testStatus(command, agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED,
		agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS)
	for _, test := range []struct {
		name   string
		mutate func(*agentv1.CacheControlStatus)
	}{
		{name: "scope", mutate: func(status *agentv1.CacheControlStatus) { status.ScopeId = uuid.NewString() }},
		{name: "tenant", mutate: func(status *agentv1.CacheControlStatus) { status.TenantId = uuid.NewString() }},
		{name: "site", mutate: func(status *agentv1.CacheControlStatus) { status.SiteId = uuid.NewString() }},
		{name: "node", mutate: func(status *agentv1.CacheControlStatus) { status.NodeId = uuid.NewString() }},
		{name: "attempt", mutate: func(status *agentv1.CacheControlStatus) { status.Attempt++ }},
		{name: "lease", mutate: func(status *agentv1.CacheControlStatus) { status.LeaseId = uuid.NewString() }},
		{name: "config version", mutate: func(status *agentv1.CacheControlStatus) { status.ConfigVersionId = uuid.NewString() }},
		{name: "config revision", mutate: func(status *agentv1.CacheControlStatus) { status.ConfigRevision++ }},
		{name: "request digest", mutate: func(status *agentv1.CacheControlStatus) { status.RequestDigest[0] ^= 0xff }},
	} {
		t.Run(test.name, func(t *testing.T) {
			status := proto.Clone(valid).(*agentv1.CacheControlStatus)
			test.mutate(status)
			if commandMatchesStatus(command, status) {
				t.Fatal("mutated status matched immutable command identity")
			}
		})
	}

	status := proto.Clone(valid).(*agentv1.CacheControlStatus)
	status.Results[0].Sha256[0] ^= 0xff
	if _, err := terminalResults(command, status); !errors.Is(err, cachecontrol.ErrInvalidInput) {
		t.Fatalf("target digest mismatch error = %v, want ErrInvalidInput", err)
	}
}
