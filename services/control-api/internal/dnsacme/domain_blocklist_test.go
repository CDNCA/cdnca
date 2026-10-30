package dnsacme

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/google/uuid"
)

// G6 #11: certificate orders check the blocklist before anything else, and
// the renewal scheduler skips blocked certificates.
func TestCertificateOrdersHonourDomainBlocklistSource(t *testing.T) {
	source, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	start := strings.Index(text, "func (s *Store) CreateOrder(")
	block := text[start : start+strings.Index(text[start:], "func (s *Store) checkCreateOrderEntitlement(")]
	blockAt := strings.Index(block, "domaintrust.BlockedDomain(ctx, tx, request.Domains)")
	if blockAt < 0 || blockAt > strings.Index(block, "s.checkCreateOrderEntitlement(") ||
		blockAt > strings.Index(block, "INSERT INTO certificate_orders") {
		t.Fatal("CreateOrder must check the blocklist before entitlement and the insert")
	}
	if strings.Count(text, "AND NOT `+renewalBlockedPredicate+`") != 1 {
		t.Fatal("the renewal scheduler must exclude blocked certificates")
	}
}

func TestRenewalBlockedPredicateMatchesBlockedDomain(t *testing.T) {
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		t.Skip("TEST_DATABASE_TEMPLATE is not set")
	}
	ctx := context.Background()
	user := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'acme-block','acme-block','x')`, user); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct{ pattern, kind string }{{"evil.test", "root"}, {"only.exact.test", "exact"}} {
		if _, err := pool.Exec(ctx, `INSERT INTO platform_domain_blocklist(id,pattern,match_type,reason,created_by_user_id,
			updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,'',$4,$4,now(),now())`, uuid.New(), entry.pattern, entry.kind, user); err != nil {
			t.Fatal(err)
		}
	}
	for domains, want := range map[string]bool{
		"evil.test": true, "a.b.evil.test": true, "*.evil.test": true, "ok.test,www.evil.test": true,
		"only.exact.test": true, "*.only.exact.test": false, "x.only.exact.test": false, "notevil.test": false, "exact.test": false,
	} {
		list := strings.Split(domains, ",")
		var got bool
		if err := pool.QueryRow(ctx, `SELECT `+renewalBlockedPredicate+` FROM (SELECT $1::text[] AS domains) source`, list).Scan(&got); err != nil {
			t.Fatal(err)
		}
		_, inGo, err := domaintrust.BlockedDomain(ctx, pool, list)
		if err != nil {
			t.Fatal(err)
		}
		if got != want || inGo != want {
			t.Fatalf("%s: SQL=%t Go=%t want %t", domains, got, inGo, want)
		}
	}
	if !errors.Is(&domaintrust.DomainError{Err: domaintrust.ErrDomainBlocked}, domaintrust.ErrDomainBlocked) {
		t.Fatal("DomainError must match ErrDomainBlocked")
	}
}
