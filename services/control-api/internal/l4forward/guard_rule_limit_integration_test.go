package l4forward

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

// ge-waf (logic 5): the platform's stream ACL rule limit (acl_max_limit) is
// read on stream writes (it was stored and shown but never read). A fresh
// installation uses the project bootstrap (1000), so a stream's 64 node rules
// pass; a limit below the count refuses with an invalid-input error.
func TestGuardRulesReadPlatformACLRuleLimit(t *testing.T) {
	fixture := newStreamAddonFixture(t)
	service, actor := NewService(NewStore(fixture.pool)), fixture.actor
	subscription := fixture.subscription(t, actor.UserID, -1)
	key := uuid.NewString()
	created, err := service.Create(t.Context(), actor, CreateRequest{Fields: Fields{PackageSubscriptionID: new(subscription),
		Name: "guarded", Protocol: ProtocolTCP, ListenAddress: "*", ListenPort: 23000,
		UpstreamAddress: "192.0.2.10", UpstreamPort: 80, ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000,
		MaxConnectionsPerClient: 100, Enabled: true,
		GuardRules: []GuardRule{{ID: "66666666-6666-4666-8666-6666666666a1", Action: "drop", ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{"198.51.100.1/32"}}}}},
		IdempotencyKey: key, RequestID: key})
	if err != nil || len(created.Forward.GuardRules) != 1 {
		t.Fatalf("guarded stream under the bootstrap limit: %+v %v", created.Forward.GuardRules, err)
	}
	if err := guardRuleLimitError(2, 1); !errors.Is(err, ErrGuardRuleLimit) || !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("over the limit: %v", err)
	}
	if err := guardRuleLimitError(1, 1); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
}
