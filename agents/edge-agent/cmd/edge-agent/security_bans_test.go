package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/cdnca/cdnca/libs/edgeconfig/securityban"
)

const (
	banTestNode = "11111111-1111-4111-8111-111111111111"
	banTestSite = "22222222-2222-4222-8222-222222222222"
)

func signedBanList(t *testing.T, private ed25519.PrivateKey, revision uint64, now time.Time) []byte {
	t.Helper()
	list := securityban.List{Schema: securityban.Schema, NodeID: banTestNode, Revision: revision, IssuedAt: now.Unix(),
		Bans: []securityban.Ban{{SiteID: banTestSite, Client: "198.51.100.7", Until: now.Unix() + 600, Source: "waf"},
			{SiteID: banTestSite, Client: "198.51.100.8", Until: now.Unix() - 1, Source: "cc"}},
		Releases:  []securityban.Release{{SiteID: banTestSite, Client: "203.0.113.5", ReleasedAt: now.Unix() - 10}},
		Algorithm: securityban.Algorithm, KeyID: "edge-publish"}
	payload, err := securityban.SigningPayload(list)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := securityban.Seal(list, ed25519.Sign(private, payload))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// The runtime verifies the snapshot, posts its live part to the node's ban
// list endpoint, keeps revision order, queues listed bans for the kernel and
// re-posts the applied snapshot.
func TestSecurityBanRuntimeAppliesVerifiedSnapshots(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	var posted []securityban.RuntimeSnapshot
	held := uint64(0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz"+securityBansSuffix || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var snapshot securityban.RuntimeSnapshot
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if snapshot.Revision < held {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"stale_revision"}`))
			return
		}
		held = snapshot.Revision
		posted = append(posted, snapshot)
		_, _ = w.Write([]byte(`{"revision":` + strings.TrimSpace(string(mustJSON(snapshot.Revision))) + `,"bans":1,"releases":1}`))
	}))
	defer server.Close()
	clock := now
	runtime := newSecurityBanRuntime(banTestNode, func(key string) (ed25519.PublicKey, bool) { return public, key == "edge-publish" },
		server.URL+"/healthz", time.Second, func() time.Time { return clock })

	result := runtime.ApplySecurityBans(signedBanList(t, private, 4, now))
	if !result.Applied || result.Bans != 1 || result.Releases != 1 || result.ErrorCode != "" {
		t.Fatalf("snapshot not applied: %+v", result)
	}
	mu.Lock()
	if len(posted) != 1 || len(posted[0].Bans) != 1 || posted[0].Bans[0].Client != "198.51.100.7" || len(posted[0].Releases) != 1 {
		t.Fatalf("posted %+v, want the live ban and the release", posted)
	}
	mu.Unlock()
	if lines := string(runtime.drainKernel()); lines != banTestSite+"|198.51.100.7|1800000600\n" {
		t.Fatalf("kernel lines = %q", lines)
	}
	if lines := runtime.drainKernel(); len(lines) != 0 {
		t.Fatalf("kernel lines drained twice: %q", lines)
	}
	if result := runtime.ApplySecurityBans(signedBanList(t, private, 3, now)); result.Applied || result.ErrorCode != securityban.ErrorStale {
		t.Fatalf("older revision = %+v", result)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	if result := runtime.ApplySecurityBans(signedBanList(t, other, 9, now)); result.Applied || result.ErrorCode != securityban.ErrorUntrusted {
		t.Fatalf("foreign signature = %+v", result)
	}
	if result := runtime.ApplySecurityBans([]byte(`{}`)); result.Applied || result.ErrorCode != securityban.ErrorInvalid {
		t.Fatalf("garbage = %+v", result)
	}
	// The applied snapshot is posted again (an OpenResty restart lost it).
	clock = now.Add(securityBanReapplyInterval)
	runtime.reapply(context.Background())
	runtime.reapply(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if len(posted) != 2 || posted[1].Revision != 4 {
		t.Fatalf("re-apply posted %d snapshots", len(posted))
	}
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

// WAF queue lines gain the site's running tenant scope; others are dropped.
func TestWAFKernelBanLinesNameTheTenantScope(t *testing.T) {
	tenant := func(site string) string {
		if site == banTestSite {
			return "33333333-3333-4333-8333-333333333333"
		}
		return ""
	}
	got := string(wafKernelBanLines([]byte(banTestSite+"|198.51.100.7|1800000600\n44444444-4444-4444-8444-444444444444|198.51.100.9|1\nbad\n"), tenant, kernelBanSourceWAF))
	want := "33333333-3333-4333-8333-333333333333|" + banTestSite + "|198.51.100.7|1800000600|waf\n"
	if got != want {
		t.Fatalf("lines = %q, want %q", got, want)
	}
	if _, client, _, kind, err := parseCCKernelBan(strings.TrimSpace(got)); err != nil || client.Addr().String() != "198.51.100.7" || kind != firewall.PolicyKindWAFBan {
		t.Fatalf("converted line does not parse as a kernel ban: %v", err)
	}
}
