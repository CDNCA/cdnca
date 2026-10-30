//go:build integration

package securitybinding

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// D3 (live-waf 实测): deleting a policy a site still enforces returned 204 and
// left the nodes running a rule no page could change. The delete is refused
// while the binding's active version is enabled, and allowed once the site
// runs a disabled version of it.
func TestDeleteRefusesPolicyActiveOnSite(t *testing.T) {
	fixture := newBindingFixture(t)
	clock := &testClock{now: bindingTestNow}
	store := newBindingStore(t, fixture.pool, newRecordingSigner(), clock, 5*time.Minute)
	resources := fixture.tenantA
	actor := tenantActor(resources)
	publication, err := store.Publish(context.Background(), actor, publishRequest(resources, "in-use-v1", 1, 0, 0))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `UPDATE security_policy_site_bindings
		SET active_policy_version=1,revision=revision+1,updated_at=$2 WHERE id=$1`, publication.BindingID, clock.Now()); err != nil {
		t.Fatalf("simulate activation: %v", err)
	}
	service := securitypolicy.NewService(securitypolicy.NewStoreWithClock(fixture.pool, clock.Now))
	_, err = service.Delete(t.Context(), actor, securitypolicy.DeleteRequest{
		ID: resources.policyID, ExpectedRevision: 1, IdempotencyKey: "delete-in-use", RequestID: "delete-in-use"})
	var inUse *securitypolicy.InUseError
	if !errors.Is(err, securitypolicy.ErrInUse) || !errors.As(err, &inUse) || len(inUse.Domains) != 1 || inUse.Domains[0] != "a.example.test" || len(inUse.SiteIDs) != 1 || inUse.SiteIDs[0] == uuid.Nil {
		t.Fatalf("delete active policy = %v, want ErrInUse naming a.example.test", err)
	}
	var deleted bool
	if err := fixture.pool.QueryRow(context.Background(), `SELECT deleted_at IS NOT NULL FROM security_policies WHERE id=$1`,
		resources.policyID).Scan(&deleted); err != nil || deleted {
		t.Fatalf("refused delete left deleted=%v (%v)", deleted, err)
	}

	// The site now runs a disabled version (nodes enforce nothing): deletable.
	disabled := policyDocument(resources.policyID, resources.scopeID, resources.kind, "policy-a", 2)
	disabled.Enabled = false
	document, err := json.Marshal(disabled)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `UPDATE security_policies SET enabled=false,revision=2 WHERE id=$1`, resources.policyID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at)
		VALUES($1,2,$2,$3,$4)`, resources.policyID, document, resources.userID, bindingTestNow); err != nil {
		t.Fatal(err)
	}
	// 470 绑定触发器要求申领/生效版本有对应发布记录：走正常发布 v2 再模拟生效。
	// v1 的节点申领超过有效期（5 分钟）后才释放，v2 才能申领同一节点。
	clock.Advance(6 * time.Minute)
	second, err := store.Publish(context.Background(), actor, publishRequest(resources, "in-use-v2", 2, 2, 1))
	if err != nil {
		t.Fatalf("Publish v2: %v", err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `UPDATE security_policy_site_bindings
		SET active_policy_version=2,revision=revision+1,updated_at=$2 WHERE id=$1`, second.BindingID, clock.Now()); err != nil {
		t.Fatalf("simulate v2 activation: %v", err)
	}
	if _, err := service.Delete(t.Context(), actor, securitypolicy.DeleteRequest{
		ID: resources.policyID, ExpectedRevision: 2, IdempotencyKey: "delete-disabled", RequestID: "delete-disabled"}); err != nil {
		t.Fatalf("delete policy whose active version is disabled: %v", err)
	}
}
