package edgeautopublish

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestL4DigestCharacterContract(t *testing.T) {
	valueType := reflect.TypeOf(enqueueDigestInput{})
	for name, jsonName := range map[string]string{
		"PublishIntentID":             "publish_intent_id,omitempty",
		"ConfigurationSourceRevision": "configuration_source_revision,omitempty",
	} {
		field, found := valueType.FieldByName(name)
		if !found {
			t.Errorf("enqueueDigestInput.%s is missing", name)
			continue
		}
		if field.Tag.Get("json") != jsonName {
			t.Errorf("enqueueDigestInput.%s json=%q want %q", name, field.Tag.Get("json"), jsonName)
		}
	}
}

func TestConfigurationSourceBindingContract(t *testing.T) {
	intentID := uuid.New()
	for _, test := range []struct {
		name                  string
		kind                  string
		publishIntentID       uuid.UUID
		configurationRevision int64
		currentSourceRevision int64
		want                  bool
	}{
		{name: "L4 exact match", kind: SourceL4, publishIntentID: intentID, configurationRevision: 41, currentSourceRevision: 41, want: true},
		{name: "L4 mismatch", kind: SourceL4, publishIntentID: intentID, configurationRevision: 40, currentSourceRevision: 41},
		{name: "L4 nil intent", kind: SourceL4, configurationRevision: 41, currentSourceRevision: 41},
		{name: "L4 zero configuration revision", kind: SourceL4, publishIntentID: intentID, currentSourceRevision: 41},
		{name: "L4 zero current revision", kind: SourceL4, publishIntentID: intentID, configurationRevision: 41},
		{name: "site zero binding", kind: SourceSite, currentSourceRevision: 41, want: true},
		{name: "site nonzero intent", kind: SourceSite, publishIntentID: intentID, currentSourceRevision: 41},
		{name: "site nonzero configuration revision", kind: SourceSite, configurationRevision: 41, currentSourceRevision: 41},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validConfigurationSourceBinding(test.kind, test.publishIntentID,
				test.configurationRevision, test.currentSourceRevision); got != test.want {
				t.Fatalf("validConfigurationSourceBinding()=%t want %t", got, test.want)
			}
		})
	}
}

func TestSiteDigestRetainsLegacyShapeWithoutL4Binding(t *testing.T) {
	input := EnqueueInput{
		Actor: Actor{
			UserID:  uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7101"),
			ScopeID: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7102"), ScopeKind: ScopeKindTenant,
		},
		TargetScopeID:    uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103"),
		SourceKind:       SourceSite,
		SourceResourceID: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7104"),
		Operation:        "site.update", Reason: ReasonResourceMutation,
		Permission: PermissionSitesManage, SourceRequestID: "request-site",
	}
	policy := Policy{
		TargetScopeID: input.TargetScopeID, Revision: 7, Mode: ModeAutomatic,
		ActivationTimeout: 30 * time.Second, ObservationWindow: 15 * time.Second,
		RequiredConsecutiveSuccesses: 2, MaxAttempts: 3, DeadlineWindow: 10 * time.Minute,
	}
	got, err := automaticRequestDigest(input, policy, 41)
	if err != nil {
		t.Fatal(err)
	}
	legacyJSON := `{"target_scope_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7103","actor_scope_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7102","actor_user_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7101","actor_scope_kind":"tenant","source_kind":"site","source_resource_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7104","source_revision":41,"operation":"site.update","reason":"resource_mutation","permission":"sites.manage","source_request_id":"request-site","policy_revision":7,"node_ids":[],"activation_timeout_ms":30000,"observation_window_ms":15000,"required_consecutive_successes":2,"max_attempts":3,"deadline_window_seconds":600}`
	if want := sha256.Sum256([]byte(legacyJSON)); got != want {
		t.Fatalf("site digest=%x want legacy shape digest=%x", got, want)
	}
}

func TestAutomaticRequestDigestIsCanonicalAndIdentitySensitive(t *testing.T) {
	nodes := []uuid.UUID{uuid.New(), uuid.New()}
	input := EnqueueInput{
		Actor:         Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopeKindTenant},
		TargetScopeID: uuid.New(), SourceKind: SourceL4, SourceResourceID: uuid.New(),
		Operation: "stream.update", Reason: ReasonResourceMutation,
		Permission: PermissionStreamsManage, SourceRequestID: "request-1",
		PublishIntentID: uuid.New(), ConfigurationSourceRevision: 41,
	}
	policy := Policy{
		TargetScopeID: input.TargetScopeID, Revision: 7, Mode: ModeAutomatic,
		NodeIDs: nodes, ActivationTimeout: 30 * time.Second, ObservationWindow: 15 * time.Second,
		RequiredConsecutiveSuccesses: 2, MaxAttempts: 3, DeadlineWindow: 10 * time.Minute,
	}
	want, err := automaticRequestDigest(input, policy, 41)
	if err != nil {
		t.Fatal(err)
	}
	policy.NodeIDs[0], policy.NodeIDs[1] = policy.NodeIDs[1], policy.NodeIDs[0]
	reordered, err := automaticRequestDigest(input, policy, 41)
	if err != nil || reordered != want {
		t.Fatalf("node reorder digest=%x want=%x err=%v", reordered, want, err)
	}

	changes := []struct {
		name   string
		mutate func(*EnqueueInput, *Policy, *int64)
	}{
		{name: "publish intent", mutate: func(value *EnqueueInput, _ *Policy, _ *int64) {
			value.PublishIntentID = uuid.New()
		}},
		{name: "source resource", mutate: func(value *EnqueueInput, _ *Policy, _ *int64) { value.SourceResourceID = uuid.New() }},
		{name: "source request", mutate: func(value *EnqueueInput, _ *Policy, _ *int64) { value.SourceRequestID = "request-2" }},
		{name: "operation", mutate: func(value *EnqueueInput, _ *Policy, _ *int64) { value.Operation = "stream.delete" }},
		{name: "policy revision", mutate: func(_ *EnqueueInput, value *Policy, _ *int64) { value.Revision++ }},
		{name: "configuration source revision", mutate: func(value *EnqueueInput, _ *Policy, revision *int64) {
			*revision = 42
			value.ConfigurationSourceRevision = 42
		}},
	}
	for _, change := range changes {
		t.Run(change.name, func(t *testing.T) {
			changedInput, changedPolicy, revision := input, policy, int64(41)
			change.mutate(&changedInput, &changedPolicy, &revision)
			got, err := automaticRequestDigest(changedInput, changedPolicy, revision)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatalf("changed identity retained digest %x", got)
			}
		})
	}

	mismatched := input
	mismatched.ConfigurationSourceRevision = 42
	if _, err := automaticRequestDigest(mismatched, policy, 41); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("L4 source revision mismatch error=%v want %v", err, ErrInvalidInput)
	}
	missingIntent := input
	missingIntent.PublishIntentID = uuid.Nil
	if _, err := automaticRequestDigest(missingIntent, policy, 41); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil L4 publish intent error=%v want %v", err, ErrInvalidInput)
	}
	zeroRevision := input
	zeroRevision.ConfigurationSourceRevision = 0
	if _, err := automaticRequestDigest(zeroRevision, policy, 41); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero L4 configuration source revision error=%v want %v", err, ErrInvalidInput)
	}
	site := input
	site.SourceKind, site.Operation, site.Permission = SourceSite, "site.update", PermissionSitesManage
	site.PublishIntentID, site.ConfigurationSourceRevision = uuid.Nil, 0
	if _, err := automaticRequestDigest(site, policy, 41); err != nil {
		t.Fatalf("site compatibility rejected zero L4 binding: %v", err)
	}
	site.PublishIntentID = uuid.New()
	if _, err := automaticRequestDigest(site, policy, 41); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("site nonzero publish intent error=%v want %v", err, ErrInvalidInput)
	}
	site.PublishIntentID, site.ConfigurationSourceRevision = uuid.Nil, 41
	if _, err := automaticRequestDigest(site, policy, 41); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("site nonzero configuration source revision error=%v want %v", err, ErrInvalidInput)
	}
}

func TestL4SourceOperationContractIsClosed(t *testing.T) {
	resourceID := uuid.New()
	for _, operation := range []string{"stream.create", "stream.update", "stream.delete"} {
		if !validSourceOperation(SourceL4, operation, PermissionStreamsManage, resourceID) {
			t.Fatalf("valid operation %q rejected", operation)
		}
	}
	for _, operation := range []string{"stream.enable", "stream.batch", "site.update", ""} {
		if validSourceOperation(SourceL4, operation, PermissionStreamsManage, resourceID) {
			t.Fatalf("unknown operation %q accepted", operation)
		}
	}
	if validSourceOperation(SourceL4, "stream.update", PermissionSitesManage, resourceID) ||
		validSourceOperation(SourceL4, "stream.update", PermissionStreamsManage, uuid.Nil) {
		t.Fatal("L4 operation accepted the wrong permission or nil resource identity")
	}
}

// A rule catalog republication is the delivery's (resource) and needs the
// policy actor's sites.manage, like the other system sources (migration 339).
func TestRuleCatalogSourceOperationContractIsClosed(t *testing.T) {
	deliveryID := uuid.New()
	if !validSourceOperation(SourceRuleCatalog, OperationRuleCatalogUpdated, PermissionSitesManage, deliveryID) ||
		sourceReason(SourceRuleCatalog) != ReasonCatalogChange ||
		!validConfigurationSourceBinding(SourceRuleCatalog, uuid.Nil, 0, 0) {
		t.Fatal("rule catalog republication contract rejected")
	}
	if validSourceOperation(SourceRuleCatalog, OperationRuleCatalogUpdated, PermissionSitesManage, uuid.Nil) ||
		validSourceOperation(SourceRuleCatalog, OperationNodeCapabilitiesChange, PermissionSitesManage, deliveryID) ||
		validSourceOperation(SourceRuleCatalog, OperationRuleCatalogUpdated, PermissionStreamsManage, deliveryID) ||
		validConfigurationSourceBinding(SourceRuleCatalog, uuid.New(), 0, 0) {
		t.Fatal("rule catalog republication accepted a wrong operation, permission, resource or intent")
	}
}

// A challenge delivery republication is the redelivered node's (resource)
// and needs the policy actor's sites.manage, like the other system sources
// (migration 343).
func TestChallengeDeliverySourceOperationContractIsClosed(t *testing.T) {
	nodeID := uuid.New()
	if !validSourceOperation(SourceChallengeDelivery, OperationNodeChallengeDelivered, PermissionSitesManage, nodeID) ||
		sourceReason(SourceChallengeDelivery) != ReasonChallengeDelivered ||
		!validConfigurationSourceBinding(SourceChallengeDelivery, uuid.Nil, 0, 0) {
		t.Fatal("challenge delivery republication contract rejected")
	}
	if validSourceOperation(SourceChallengeDelivery, OperationNodeChallengeDelivered, PermissionSitesManage, uuid.Nil) ||
		validSourceOperation(SourceChallengeDelivery, OperationRuleCatalogUpdated, PermissionSitesManage, nodeID) ||
		validSourceOperation(SourceChallengeDelivery, OperationNodeChallengeDelivered, PermissionStreamsManage, nodeID) ||
		validConfigurationSourceBinding(SourceChallengeDelivery, uuid.New(), 0, 0) {
		t.Fatal("challenge delivery republication accepted a wrong operation, permission, resource or intent")
	}
}
