package marketsubscribe

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/card"
	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/secdigest"
	"github.com/cdnca/cdnca/services/control-api/internal/securityanalytics"
	"github.com/google/uuid"
)

type fakeCards map[uuid.UUID]ed25519.PublicKey

func (f fakeCards) Card(_ context.Context, member uuid.UUID) (card.Card, error) {
	return card.Card{MemberID: member, SigningPublicKey: f[member]}, nil
}

type fakeDigestStore struct {
	rows []securityanalytics.MarketSecurity
}

func (f *fakeDigestStore) WriteMarketSecurity(_ context.Context, m securityanalytics.MarketSecurity) error {
	f.rows = append(f.rows, m)
	return nil
}

// ADR 0012 ML-21: a digest is bound to the local site that has the sender's
// leaf_site_id; another leaf's site, a forged signature or a mismatched key
// is dropped (acknowledged, never stored).
func TestReceiveDigestBindsToLocalSite(t *testing.T) {
	pool := testPool(t)
	ctx := t.Context()
	platform, site := seedSite(t, pool)
	supply, sub := uuid.New(), uuid.New()
	leaf, other := uuid.New(), uuid.New()
	leafSite, grantID := uuid.New(), uuid.New()
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO site_supplies(id,owner_scope_id,kind,name,market_subscription_id,status,created_at,updated_at)
		VALUES($1,$2,'market_subscription','m',$3,'active',$4,$4)`, supply, platform, sub, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO site_supply_leaf_sites(site_id,supply_id,leaf_member_id,node_pool_ref,leaf_site_id,state,updated_at)
		VALUES($1,$2,$3,'pa',$4,'applied',$5)`, site, supply, leaf, leafSite, now); err != nil {
		t.Fatal(err)
	}
	leafPub, leafKey, _ := ed25519.GenerateKey(nil)
	otherPub, otherKey, _ := ed25519.GenerateKey(nil)
	store := &fakeDigestStore{}
	svc := New(pool, fakeMarket{}, nil).WithDigests(fakeCards{leaf: leafPub, other: otherPub}, store)

	window := now.Truncate(5 * time.Minute).Add(-5 * time.Minute).Unix()
	digest := func(member, leafSiteID uuid.UUID) secdigest.Digest {
		return secdigest.Digest{Schema: secdigest.SchemaV1, LeafMemberID: member, GrantID: grantID, LeafSiteID: leafSiteID,
			WindowStart: window, WindowSeconds: secdigest.WindowSeconds,
			Summary: secdigest.Summary{Events: 12, Blocked: 12, Clients: 2, TopDetector: "sqli", TopClientIP: "203.0.113.7"},
			Logs: []secdigest.Log{{AtMS: window*1000 + 5, ClientIP: "203.0.113.7", Host: "www.subscriber.example", Path: "/login",
				Action: "block", Detector: "sqli", RuleID: "942100"}}}
	}
	send := func(sender uuid.UUID, key ed25519.PrivateKey, d secdigest.Digest, idem string) {
		t.Helper()
		signed, err := secdigest.Sign(d, key)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(signed)
		h := envelope.Header{MessageID: uuid.New(), SenderMemberID: sender, GrantID: grantID, Operation: secdigest.Operation,
			IdempotencyKey: idem}
		if err := svc.ReceiveDigest(ctx, h, body); err != nil {
			t.Fatal(err)
		}
	}
	good := digest(leaf, leafSite)
	send(leaf, leafKey, good, secdigest.IdempotencyKey(leafSite, window))
	if len(store.rows) != 1 {
		t.Fatalf("stored %d", len(store.rows))
	}
	got := store.rows[0]
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT scope.tenant_id FROM sites JOIN access_scopes scope ON scope.id=sites.scope_id
		WHERE sites.id=$1`, site).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if got.SiteID != site || got.TenantID != tenant || got.SupplyID != supply || got.LeafMemberID != leaf ||
		got.LeafRef != leaf.String()[:8] || got.Digest.Logs[0].RuleID != "942100" {
		t.Fatalf("stored %+v", got)
	}
	// Another leaf naming this leaf's site: not its site.
	send(other, otherKey, digest(other, leafSite), secdigest.IdempotencyKey(leafSite, window))
	// Signed by another key than the sender's card.
	send(leaf, otherKey, good, secdigest.IdempotencyKey(leafSite, window))
	// Key of another site.
	send(leaf, leafKey, good, secdigest.IdempotencyKey(uuid.New(), window))
	// Unknown leaf site of the right leaf.
	unknown := uuid.New()
	send(leaf, leafKey, digest(leaf, unknown), secdigest.IdempotencyKey(unknown, window))
	if len(store.rows) != 1 {
		t.Fatalf("foreign digests stored: %d", len(store.rows))
	}
	if store.rows[0].Extension != (secdigest.Extension{}) {
		t.Fatalf("a leaf without the extension stored %+v", store.rows[0].Extension)
	}

	// a leaf that sends the observe-only count; its log lines ride
	// in Logs with action log and the enforced summary is unchanged.
	extended := good
	extended.Logs = append(extended.Logs, secdigest.Log{AtMS: window*1000 + 9, ClientIP: "203.0.113.8",
		Host: "www.subscriber.example", Path: "/search", Action: "log", Detector: "xss", RuleID: "941100"})
	signed, err := secdigest.SignExtended(extended, secdigest.Extension{Logged: 30}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(signed)
	h := envelope.Header{MessageID: uuid.New(), SenderMemberID: leaf, GrantID: grantID, Operation: secdigest.Operation,
		IdempotencyKey: secdigest.IdempotencyKey(leafSite, window)}
	if err := svc.ReceiveDigest(ctx, h, body); err != nil {
		t.Fatal(err)
	}
	if len(store.rows) != 2 || store.rows[1].Extension.Logged != 30 || store.rows[1].Digest.Summary.Events != 12 ||
		len(store.rows[1].Digest.Logs) != 2 || store.rows[1].Digest.Logs[1].Action != "log" {
		t.Fatalf("extended digest stored %+v", store.rows)
	}
	// The extension signed by another key: dropped, not stored without it.
	forged, _ := secdigest.SignExtended(extended, secdigest.Extension{Logged: 30}, otherKey)
	signed.ExtensionSignature = forged.ExtensionSignature
	body, _ = json.Marshal(signed)
	if err := svc.ReceiveDigest(ctx, h, body); err != nil {
		t.Fatal(err)
	}
	if len(store.rows) != 2 {
		t.Fatalf("digest with a forged extension stored: %d", len(store.rows))
	}
}
