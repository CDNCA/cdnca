package securitybinding

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybundle"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

var (
	scopedCommandTenantID = uuid.MustParse("018f2000-0000-7000-8000-000000000001")
	scopedCommandSiteID   = uuid.MustParse("018f2000-0000-7000-8000-000000000002")
	scopedCommandPolicyID = uuid.MustParse("018f2000-0000-7000-8000-000000000003")
	scopedCommandRollout  = uuid.MustParse("018f2000-0000-7000-8000-000000000004")
	scopedCommandNodeA    = uuid.MustParse("018f2000-0000-7000-8000-000000000005")
	scopedCommandNodeB    = uuid.MustParse("018f2000-0000-7000-8000-000000000006")
	scopedCommandRuleV4   = uuid.MustParse("018f2000-0000-7000-8000-000000000007")
	scopedCommandRuleV6   = uuid.MustParse("018f2000-0000-7000-8000-000000000008")
	scopedCommandNow      = time.Date(2026, 8, 6, 7, 0, 0, 0, time.UTC)
)

type scopedCommandSigner struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func newScopedCommandSigner() scopedCommandSigner {
	seed := sha256.Sum256([]byte("securitybinding-scoped-command-test"))
	private := ed25519.NewKeyFromSeed(seed[:])
	return scopedCommandSigner{private: private, public: private.Public().(ed25519.PublicKey)}
}

func (signer scopedCommandSigner) KeyID() string { return "securitybinding-scoped-v1" }
func (signer scopedCommandSigner) PublicKey() ed25519.PublicKey {
	return bytes.Clone(signer.public)
}
func (signer scopedCommandSigner) Sign(_ context.Context, value []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, value), nil
}

type scopedCommandConsumerFunc func(context.Context, *agentv1.FirewallCommand) error

func (consume scopedCommandConsumerFunc) ConsumeScopedCommand(ctx context.Context, command *agentv1.FirewallCommand) error {
	return consume(ctx, command)
}

var _ ScopedCommandConsumer = scopedCommandConsumerFunc(nil)

func TestProjectScopedCommandProducesExactFirewallCarrier(t *testing.T) {
	publication := validScopedCommandPublication(t, validScopedCommandPolicy())
	original := cloneScopedPublication(publication)
	first, err := ProjectScopedCommand(publication, scopedCommandNodeA)
	if err != nil {
		t.Fatalf("ProjectScopedCommand: %v", err)
	}
	second, err := ProjectScopedCommand(publication, scopedCommandNodeA)
	if err != nil || !proto.Equal(first, second) {
		t.Fatalf("deterministic projection = (%v, %v)", second, err)
	}
	if !reflect.DeepEqual(publication, original) {
		t.Fatal("ProjectScopedCommand mutated Publication")
	}
	if first.Schema != agentv1.FirewallSchema_FIREWALL_SCHEMA_V1 ||
		first.TaskId != scopedCommandRollout.String() || first.TaskRevision != 2 ||
		first.TenantId != scopedCommandTenantID.String() || first.SiteId != scopedCommandSiteID.String() ||
		first.NodeId != scopedCommandNodeA.String() || first.PolicyVersion != 2 ||
		first.ExpectedActivePolicyVersion != 1 ||
		first.Operation != agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY ||
		first.RecoveryReason != agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE ||
		first.IdempotencyKey != scopedCommandUUID(publication.BundleID, "firewall-idempotency", scopedCommandNodeA).String() {
		t.Fatalf("firewall command identity = %+v", first)
	}
	if first.Event == nil || first.Event.EventId != scopedCommandUUID(publication.BundleID, "firewall-event", scopedCommandNodeA).String() ||
		first.Event.RequestId != scopedCommandRollout.String() || first.Event.GetTaskId() != first.TaskId ||
		first.Event.CorrelationId != publication.BundleID.String() ||
		first.Event.OccurredTime == nil || !first.Event.OccurredTime.AsTime().Equal(scopedCommandNow) ||
		first.DeadlineTime == nil || !first.DeadlineTime.AsTime().Equal(scopedCommandNow.Add(5*time.Minute)) {
		t.Fatalf("firewall command event/deadline = %+v / %+v", first.Event, first.DeadlineTime)
	}
	wantTargets := []*agentv1.FirewallCIDRTarget{
		{Ordinal: 1, TenantId: scopedCommandTenantID.String(), SiteId: scopedCommandSiteID.String(),
			Action: agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_DENY, Cidr: "198.51.100.0/24",
			Source: "policy:" + scopedCommandPolicyID.String(), ReasonCode: "rule:" + scopedCommandRuleV4.String()},
		{Ordinal: 2, TenantId: scopedCommandTenantID.String(), SiteId: scopedCommandSiteID.String(),
			Action: agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_ALLOW, Cidr: "2001:db8::/48",
			Source: "policy:" + scopedCommandPolicyID.String(), ReasonCode: "rule:" + scopedCommandRuleV6.String()},
	}
	if !proto.Equal(&agentv1.FirewallCommand{Targets: first.Targets}, &agentv1.FirewallCommand{Targets: wantTargets}) {
		t.Fatalf("firewall targets = %#v, want %#v", first.Targets, wantTargets)
	}
	if want := scopedCommandDigest(t, first); !bytes.Equal(first.CommandSha256, want) {
		t.Fatalf("command digest = %x, want %x", first.CommandSha256, want)
	}

	first.Targets[0].Cidr = "203.0.113.0/24"
	first.CommandSha256[0] ^= 0xff
	third, err := ProjectScopedCommand(publication, scopedCommandNodeA)
	if err != nil || third.Targets[0].Cidr != "198.51.100.0/24" || bytes.Equal(first.CommandSha256, third.CommandSha256) {
		t.Fatalf("output mutation affected deterministic reprojection: (%+v, %v)", third, err)
	}
}

func TestProjectScopedCommandRejectsUnboundNodeAndVersionOrdering(t *testing.T) {
	publication := validScopedCommandPublication(t, validScopedCommandPolicy())
	if _, err := ProjectScopedCommand(publication, uuid.New()); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unbound node error = %v", err)
	}
	for name, expected := range map[string]int64{"gap": 0, "same": 2, "newer": 3} {
		t.Run(name, func(t *testing.T) {
			value := mutateScopedPayload(t, publication, func(payload *securitybundle.Payload) {
				payload.ExpectedActiveVersion = expected
			})
			value.ExpectedActiveVersion = expected
			if _, err := ProjectScopedCommand(value, scopedCommandNodeA); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("ordering error = %v", err)
			}
		})
	}
}

func TestProjectScopedCommandRejectsMalformedOrDriftedPublication(t *testing.T) {
	base := validScopedCommandPublication(t, validScopedCommandPolicy())
	tests := map[string]func(*Publication){
		"unknown field": func(value *Publication) {
			value.BundleJSON = append(append([]byte(nil), value.BundleJSON[:len(value.BundleJSON)-1]...), []byte(`,"unknown":true}`)...)
			value.BundleSHA256 = sha256.Sum256(value.BundleJSON)
		},
		"trailing document": func(value *Publication) {
			value.BundleJSON = append(bytes.Clone(value.BundleJSON), []byte(`{}`)...)
			value.BundleSHA256 = sha256.Sum256(value.BundleJSON)
		},
		"noncanonical bytes": func(value *Publication) {
			value.BundleJSON = append([]byte("\n"), value.BundleJSON...)
			value.BundleSHA256 = sha256.Sum256(value.BundleJSON)
		},
		"bundle digest":  func(value *Publication) { value.BundleSHA256[0] ^= 0xff },
		"payload digest": func(value *Publication) { value.CanonicalPayloadSHA256[0] ^= 0xff },
		"runtime digest": func(value *Publication) { value.RuntimeSnapshotSHA256[0] ^= 0xff },
		"bundle id":      func(value *Publication) { value.BundleID = uuid.New() },
		"tenant":         func(value *Publication) { value.TenantScopeID = uuid.New() },
		"site":           func(value *Publication) { value.SiteID = uuid.New() },
		"policy":         func(value *Publication) { value.PolicyID = uuid.New() },
		"kind":           func(value *Publication) { value.PolicyKind = securitypolicy.KindWAF },
		"version":        func(value *Publication) { value.PolicyVersion++ },
		"target":         func(value *Publication) { value.TargetNodeIDs[0] = uuid.New() },
		"expected":       func(value *Publication) { value.ExpectedActiveVersion++ },
		"rollout":        func(value *Publication) { value.RolloutID = uuid.New() },
		"key":            func(value *Publication) { value.SigningKeyID = "other-key" },
		"issued":         func(value *Publication) { value.IssuedAt = value.IssuedAt.Add(time.Second) },
		"expires":        func(value *Publication) { value.ExpiresAt = value.ExpiresAt.Add(time.Second) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := cloneScopedPublication(base)
			mutate(&value)
			if _, err := ProjectScopedCommand(value, scopedCommandNodeA); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("ProjectScopedCommand error = %v", err)
			}
		})
	}
}

func TestProjectScopedCommandRejectsUnrepresentableACL(t *testing.T) {
	tests := map[string]func(*securitypolicy.Policy){
		"default block": func(policy *securitypolicy.Policy) { policy.DefaultAction = securitypolicy.ActionBlock },
		"nonterminal":   func(policy *securitypolicy.Policy) { policy.Rules[0].Flow = securitypolicy.FlowContinue },
		"multiple conditions": func(policy *securitypolicy.Policy) {
			policy.Rules[0].Conditions = append(policy.Rules[0].Conditions, securitypolicy.Condition{
				Field: "method", Operator: "equals", Values: []string{"GET"},
			})
		},
		"non CIDR": func(policy *securitypolicy.Policy) {
			policy.Rules[0].Conditions[0] = securitypolicy.Condition{Field: "path", Operator: "prefix", Values: []string{"/admin"}}
		},
		"duplicate CIDR": func(policy *securitypolicy.Policy) {
			duplicate := policy.Rules[0]
			duplicate.ID = uuid.New()
			duplicate.Priority++
			policy.Rules = append(policy.Rules, duplicate)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			policy := validScopedCommandPolicy()
			mutate(&policy)
			publication := validScopedCommandPublication(t, policy)
			if _, err := ProjectScopedCommand(publication, scopedCommandNodeA); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("unsupported ACL error = %v", err)
			}
		})
	}
	waf := validScopedCommandPolicy()
	waf.Kind = securitypolicy.KindWAF
	if _, err := ProjectScopedCommand(validScopedCommandPublication(t, waf), scopedCommandNodeA); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("WAF projection error = %v", err)
	}
}

func TestProjectScopedCommandDigestBindsScopeAndOwnership(t *testing.T) {
	command, err := ProjectScopedCommand(validScopedCommandPublication(t, validScopedCommandPolicy()), scopedCommandNodeA)
	if err != nil {
		t.Fatal(err)
	}
	original := scopedCommandDigest(t, command)
	tampered := proto.Clone(command).(*agentv1.FirewallCommand)
	tampered.Targets[0].TenantId = uuid.NewString()
	if bytes.Equal(original, scopedCommandDigest(t, tampered)) {
		t.Fatal("deterministic command digest did not bind CIDR ownership")
	}
}

func validScopedCommandPublication(t *testing.T, policy securitypolicy.Policy) Publication {
	t.Helper()
	signer := newScopedCommandSigner()
	publisher, err := securitybundle.NewPublisher(signer, securitybundle.Config{
		Clock: func() time.Time { return scopedCommandNow }, Validity: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	planned, err := publisher.Plan(context.Background(), securitybundle.PublishRequest{
		TenantScopeID: scopedCommandTenantID, SiteID: scopedCommandSiteID, Policy: policy,
		TargetNodeIDs: []uuid.UUID{scopedCommandNodeB, scopedCommandNodeA}, ExpectedActiveVersion: 1,
		RolloutID: scopedCommandRollout, IdempotencyKey: "false-positive-recovery-v2",
	}, nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	plan := planned.Plan
	return Publication{
		BundleID: plan.BundleID, BindingID: uuid.New(), BindingRevision: 4,
		TenantScopeID: scopedCommandTenantID, SiteID: scopedCommandSiteID,
		PolicyID: policy.ID, PolicyKind: policy.Kind, PolicyVersion: policy.Revision,
		ExpectedActiveVersion: 1, RolloutID: scopedCommandRollout,
		TargetNodeIDs: append([]uuid.UUID(nil), plan.Bundle.Payload.TargetNodeIDs...),
		BundleJSON:    bytes.Clone(plan.BundleJSON), BundleSHA256: sha256.Sum256(plan.BundleJSON),
		CanonicalPayloadSHA256: plan.CanonicalPayloadSHA256, RuntimeSnapshotSHA256: plan.RuntimeSnapshotSHA256,
		SigningKeyID: signer.KeyID(), IssuedAt: scopedCommandNow,
		ExpiresAt: scopedCommandNow.Add(5 * time.Minute), CreatedAt: scopedCommandNow,
	}
}

func validScopedCommandPolicy() securitypolicy.Policy {
	return securitypolicy.Policy{
		ID: scopedCommandPolicyID, ScopeID: scopedCommandTenantID, Kind: securitypolicy.KindACL,
		Name: "false-positive-recovery", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 2,
		Rules: []securitypolicy.Rule{
			{ID: scopedCommandRuleV4, Name: "deny-v4", Priority: 10, Enabled: true,
				Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
				Conditions: []securitypolicy.Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"198.51.100.0/24"}}}},
			{ID: scopedCommandRuleV6, Name: "allow-v6", Priority: 20, Enabled: true,
				Action: securitypolicy.ActionAllow, Flow: securitypolicy.FlowStop,
				Conditions: []securitypolicy.Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"2001:db8::/48"}}}},
		},
	}
}

func cloneScopedPublication(value Publication) Publication {
	value.BundleJSON = bytes.Clone(value.BundleJSON)
	value.TargetNodeIDs = append([]uuid.UUID(nil), value.TargetNodeIDs...)
	return value
}

func mutateScopedPayload(t *testing.T, publication Publication, mutate func(*securitybundle.Payload)) Publication {
	t.Helper()
	value := cloneScopedPublication(publication)
	var bundle securitybundle.SignedBundle
	if err := json.Unmarshal(value.BundleJSON, &bundle); err != nil {
		t.Fatal(err)
	}
	mutate(&bundle.Payload)
	runtime, err := json.Marshal(bundle.Payload.RuntimeSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	runtimeDigest := sha256.Sum256(runtime)
	bundle.Payload.RuntimeSnapshotSHA256 = hex.EncodeToString(runtimeDigest[:])
	payload, err := json.Marshal(bundle.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(payload)
	bundle.PayloadSHA256 = hex.EncodeToString(payloadDigest[:])
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	value.BundleJSON = encoded
	value.BundleSHA256 = sha256.Sum256(encoded)
	value.CanonicalPayloadSHA256 = payloadDigest
	value.RuntimeSnapshotSHA256 = runtimeDigest
	return value
}

func scopedCommandUUID(bundleID uuid.UUID, kind string, nodeID uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(bundleID, []byte(kind+"\x00"+nodeID.String()))
}

func scopedCommandDigest(t *testing.T, command *agentv1.FirewallCommand) []byte {
	t.Helper()
	identity := proto.Clone(command).(*agentv1.FirewallCommand)
	identity.CommandSha256 = nil
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return digest[:]
}
