//go:build integration

package edgedeployment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// 证书和验证密钥走 secret rollout（见 docs/architecture/multi-tenant-node-sharing.md）。迁移 287 之后：
// 租户可以发到自己的节点，以及承载它的 platform 节点；不承载它的 platform 节点仍然拒绝。
func TestTenantSecretRolloutFollowsNodeCarriage(t *testing.T) {
	fixture, tenantScopeID, tenantUserID, actor := newSecretRolloutIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	// The platform scope already exists: the operator actor lives in it.
	platformScopeID := actor.ScopeID
	platformNode := uuid.New()
	seedCohortNode(t, pool, platformScopeID, tenantUserID, platformNode)
	seedActiveArtifactKey(t, pool, platformNode, tenantUserID, nil)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	builder := func(_ context.Context, binding SecretArtifactBinding) (ArtifactInput, error) {
		calls++
		return testSecretArtifact(t, binding, "platform-node-secret", publicKey, privateKey), nil
	}
	request := testSecretRolloutRequest(actor, tenantScopeID, []uuid.UUID{platformNode}, "tenant-secret-platform-node")
	if _, err := store.CreateSecretRollout(t.Context(), request, builder); !errors.Is(err, ErrConfigurationScopeConflict) {
		t.Fatalf("tenant secret rollout to an uncarried platform node err=%v, want ErrConfigurationScopeConflict", err)
	}
	if calls != 0 {
		t.Fatalf("rejected rollout still built %d artifacts", calls)
	}
	assertSecretRolloutRowCounts(t, pool, request.IdempotencyKey, 0, 0, 0, 0, 0, 0)

	// 租户认领了这个 platform 节点之后（它的配置在上面），同样的请求就能发出去。
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at)
		VALUES($1,$2,now())`, platformNode, tenantScopeID); err != nil {
		t.Fatal(err)
	}
	carried := testSecretRolloutRequest(actor, tenantScopeID, []uuid.UUID{platformNode}, "tenant-secret-carried-platform-node")
	if created, err := store.CreateSecretRollout(t.Context(), carried, builder); err != nil || len(created.Rollout.Deployments) != 1 {
		t.Fatalf("tenant secret rollout to a carried platform node: created=%+v err=%v", created, err)
	}

	// 租户自己 scope 里的节点照旧可以。
	tenantNode := uuid.New()
	seedCohortNode(t, pool, tenantScopeID, tenantUserID, tenantNode)
	_, tenantRecipientKey := seedActiveArtifactKey(t, pool, tenantNode, tenantUserID, nil)
	control := testSecretRolloutRequest(actor, tenantScopeID, []uuid.UUID{tenantNode}, "tenant-secret-tenant-node")
	var recipient []byte
	created, err := store.CreateSecretRollout(t.Context(), control, func(ctx context.Context, binding SecretArtifactBinding) (ArtifactInput, error) {
		recipient = bytes.Clone(binding.RecipientPublicKey)
		return builder(ctx, binding)
	})
	if err != nil || len(created.Rollout.Deployments) != 1 || !bytes.Equal(recipient, tenantRecipientKey) {
		t.Fatalf("tenant secret rollout to tenant-scoped node: created=%+v err=%v", created, err)
	}
}
