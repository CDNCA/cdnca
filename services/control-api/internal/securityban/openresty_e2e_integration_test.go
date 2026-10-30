//go:build integration

package securityban_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"github.com/google/uuid"
)

// TestSecurityBanControlToOpenResty (edge/openresty/lua/banlist_control_e2e.sh
// starts the real OpenResty and sets the environment): a manual ban made
// through the control plane reaches a real node runtime as a signed snapshot
// and refuses the client; the release reaches it and lets the client through.
// The node side is the Agent's path (securityban.Open with the node's trust,
// POST of list.Runtime to <health>/security-bans, receipt from the answer).
func TestSecurityBanControlToOpenResty(t *testing.T) {
	health, siteURL, rawSite := os.Getenv("SECURITY_BAN_E2E_HEALTH"), os.Getenv("SECURITY_BAN_E2E_SITE_URL"), os.Getenv("SECURITY_BAN_E2E_SITE_ID")
	if health == "" || siteURL == "" || rawSite == "" {
		t.Skip("run through edge/openresty/lua/banlist_control_e2e.sh")
	}
	pool := newPool(t)
	ctx := t.Context()
	// The node's rendered site has a fixed ID.
	fixture := seedTenantSite(t, pool, "sbe-"+uuid.NewString()[:6], uuid.MustParse(rawSite))
	nodeID, siteID := seedNode(t, pool, fixture), fixture.site

	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	carrier := &transport{}
	distributor, err := securityban.NewDistributor(securityban.DistributorConfig{Pool: pool, Transport: carrier, KeyID: "edge-publish",
		Sign: func(_ context.Context, payload []byte) ([]byte, error) { return ed25519.Sign(private, payload), nil },
		Interval: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	trusted := func(keyID string) (ed25519.PublicKey, bool) { return public, keyID == "edge-publish" }
	service := securityban.NewService(securityban.NewStore(pool, time.Now))
	actor := securityban.Actor{UserID: fixture.owner, ScopeID: fixture.scope, ScopeKind: "tenant"}
	client := &http.Client{Timeout: 5 * time.Second}

	request := func(ip string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, siteURL, nil)
		req.Header.Set("X-Real-IP", ip)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode, response.Header.Get("X-Cdnca-Ban")
	}
	// deliver is the Agent: verify, apply, answer.
	deliver := func() contract.List {
		t.Helper()
		before := len(carrier.published)
		if err := distributor.PublishOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if len(carrier.published) != before+1 {
			t.Fatalf("published %d snapshots, want one more", len(carrier.published)-before)
		}
		sent := carrier.published[len(carrier.published)-1]
		list, err := contract.Open(sent.encoded, nodeID.String(), trusted)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(list.Runtime(time.Now()))
		response, err := client.Post(health+"/security-bans", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		var applied struct {
			Revision uint64 `json:"revision"`
			Bans     uint32 `json:"bans"`
			Releases uint32 `json:"releases"`
		}
		raw, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || json.Unmarshal(raw, &applied) != nil || applied.Revision != list.Revision {
			t.Fatalf("node apply = %d %s", response.StatusCode, raw)
		}
		distributor.HandleReceipt(ctx, &receipt{report: &agentv1.SecurityBanStatus{NodeId: nodeID.String(),
			Revision: list.Revision, ListSha256: contract.Digest(sent.encoded), Applied: true, Bans: applied.Bans,
			Releases: applied.Releases}})
		var appliedRevision int64
		if err := pool.QueryRow(ctx, `SELECT applied_revision FROM security_ban_node_state WHERE node_id=$1`, nodeID).
			Scan(&appliedRevision); err != nil || appliedRevision != int64(list.Revision) {
			t.Fatalf("receipt not recorded: %d %v", appliedRevision, err)
		}
		return list
	}

	const banned, other = "198.51.100.77", "198.51.100.78"
	if status, _ := request(banned); status != http.StatusOK {
		t.Fatalf("before the ban: %d", status)
	}
	entry, err := service.Create(ctx, actor, securityban.CreateRequest{SiteID: siteID, ClientIP: banned, DurationSecond: 600,
		Reason: "e2e", IdempotencyKey: "e2e-1", RequestID: "e2e-1"})
	if err != nil {
		t.Fatal(err)
	}
	if list := deliver(); list.Revision != 1 || len(list.Bans) != 1 {
		t.Fatalf("ban snapshot = %+v", list)
	}
	if status, header := request(banned); status != http.StatusForbidden || header != "listed" {
		t.Fatalf("banned client: %d %q, want 403 listed", status, header)
	}
	if status, _ := request(other); status != http.StatusOK {
		t.Fatalf("other client: %d", status)
	}
	if _, err := service.Release(ctx, actor, securityban.ReleaseRequest{EntryID: entry.ID, RequestID: "e2e-2"}); err != nil {
		t.Fatal(err)
	}
	if list := deliver(); list.Revision != 2 || len(list.Bans) != 0 || len(list.Releases) != 1 {
		t.Fatalf("release snapshot = %+v", list)
	}
	if status, _ := request(banned); status != http.StatusOK {
		t.Fatalf("released client: %d, want 200", status)
	}
}
