//go:build integration

package cachecontrol

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A cache operation accepts URLs under every name the site serves (its
// active site_domain_facts: alias, "*." wildcard) and stores the URL's own
// host; the wildcard as a host and names the site does not serve are refused.
func TestCreateOperationAcceptsTheSitesServedNames(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	fixture := seedCacheFixture(t, pool, "served-names", 1)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		INSERT INTO site_domain_facts(
			scope_id,site_id,site_revision,action,canonical_domain,
			actor_scope_id,actor_user_id,request_id,occurred_at
		) VALUES
			($1,$2,1,'activate',$3,$1,$4,'served-names',$5),
			($1,$2,1,'activate','alias-served.example',$1,$4,'served-names',$5),
			($1,$2,1,'activate','*.wild-served.example',$1,$4,'served-names',$5)`,
		fixture.actor.ScopeID, fixture.siteID, fixture.domain, fixture.actor.UserID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	create := func(key string, targets ...string) (OperationWriteResult, error) {
		return store.CreateOperation(ctx, fixture.actor, CreateOperationRequest{
			SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
			Targets: targets, NodeIDs: fixture.nodeIDs, IdempotencyKey: key, RequestID: key + "-request",
		})
	}
	result, err := create("served-names-ok", "http://"+fixture.domain+"/a", "http://alias-served.example/a",
		"http://www.wild-served.example/a")
	if err != nil {
		t.Fatalf("served names refused: %v", err)
	}
	rows, err := pool.Query(ctx, `SELECT canonical_url FROM cache_operation_targets
		WHERE operation_id=$1 ORDER BY ordinal`, result.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	var stored []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, value)
	}
	rows.Close()
	want := []string{"http://" + fixture.domain + "/a", "http://alias-served.example/a", "http://www.wild-served.example/a"}
	if len(stored) != len(want) || stored[0] != want[0] || stored[1] != want[1] || stored[2] != want[2] {
		t.Fatalf("stored targets = %q, want %q", stored, want)
	}
	// Q4（fp-site2）：刷新可填本站服务的通配主机；夹具节点未声明 CACHE_WILDCARD_PURGE，
	// 因此在受理前以 ErrWildcardPurgeUnsupported 拒绝（有能力时见 wildcard_quota_integration_test.go）。
	if _, err := create("served-names-wildcard", "http://*.wild-served.example/a"); !errors.Is(err, ErrWildcardPurgeUnsupported) {
		t.Fatalf("wildcard host: %v, want ErrWildcardPurgeUnsupported", err)
	}
	for index, raw := range []string{"http://wild-served.example/a", "http://other.example/a"} {
		if _, err := create("served-names-outside-"+string(rune('a'+index)), raw); !errors.Is(err, ErrInvalidInput) ||
			errors.Is(err, ErrWildcardTargetHost) {
			t.Fatalf("%s: %v, want ErrInvalidInput", raw, err)
		}
	}
}
