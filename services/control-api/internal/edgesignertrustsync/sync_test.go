package edgesignertrustsync

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

func seededKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func signedDocument(t *testing.T, revision uint64, revoked ...string) []byte {
	t.Helper()
	der, _ := x509.MarshalPKIXPublicKey(seededKey("release").Public())
	document := edgesignertrust.Document{Schema: edgesignertrust.DocumentSchema, Revision: revision,
		IssuedAt:    "2026-10-17T08:00:00Z",
		TrustedKeys: []edgesignertrust.TrustedKey{{KeyID: "release-new", PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}},
		RevokedKeys: []edgesignertrust.RevokedKey{}}
	for _, keyID := range revoked {
		document.RevokedKeys = append(document.RevokedKeys, edgesignertrust.RevokedKey{KeyID: keyID,
			RevokedAt: "2026-10-17T07:00:00Z", Reason: "signer_compromise"})
	}
	document, err := edgesignertrust.Normalize(document)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := edgesignertrust.Sign(document, "offline-root", 1, seededKey("root"))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type fakeDocumentStore struct {
	mu       sync.Mutex
	accepted [][]byte
	events   []string
	reject   string
}

func (store *fakeDocumentStore) Accept(_ context.Context, encoded []byte, source string) (Accepted, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if source != SourceFetch {
		panic(source)
	}
	if store.reject != "" {
		store.events = append(store.events, "rejected:"+store.reject)
		return Accepted{}, &RejectedError{Reason: store.reject}
	}
	store.accepted = append(store.accepted, encoded)
	return Accepted{Revision: uint64(len(store.accepted)), Document: encoded}, nil
}

func (store *fakeDocumentStore) Latest(context.Context) (Accepted, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.accepted) == 0 {
		return Accepted{}, false, nil
	}
	return Accepted{Revision: uint64(len(store.accepted)), Document: store.accepted[len(store.accepted)-1]}, true, nil
}

func (store *fakeDocumentStore) RecordEvent(_ context.Context, event, reason string, _ uint64, _ []byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.events = append(store.events, event+":"+reason)
	return nil
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestFetcherAcceptsAndKeepsLKGOnOutage(t *testing.T) {
	document := signedDocument(t, 1, "release-old")
	var mode string
	var mu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		current := mode
		mu.Unlock()
		switch current {
		case "missing":
			http.NotFound(response, request)
		case "error":
			http.Error(response, "busy", http.StatusServiceUnavailable)
		case "redirect":
			http.Redirect(response, request, "https://attacker.invalid/x", http.StatusFound)
		default:
			_, _ = response.Write(document)
		}
	}))
	defer server.Close()
	store := &fakeDocumentStore{}
	woken := 0
	fetcher, err := NewFetcher(FetcherConfig{URL: server.URL + DefaultDocumentPath, TLSConfig: server.Client().Transport.(*http.Transport).TLSClientConfig,
		Interval: time.Minute, Timeout: 5 * time.Second, Store: store, Logger: quietLogger(), OnAccepted: func() { woken++ }})
	if err != nil {
		t.Fatal(err)
	}
	if reason := fetcher.FetchOnce(t.Context()); reason != ReasonAccepted || woken != 1 || len(store.accepted) != 1 {
		t.Fatalf("first fetch = %s woken=%d", reason, woken)
	}
	for _, step := range []struct{ mode, want string }{{"missing", ReasonNotPublished}, {"missing", ReasonNotPublished},
		{"error", ReasonServer}, {"redirect", ReasonServer}} {
		mu.Lock()
		mode = step.mode
		mu.Unlock()
		if reason := fetcher.FetchOnce(t.Context()); reason != step.want {
			t.Fatalf("%s: reason = %s", step.mode, reason)
		}
	}
	if got := store.events; len(got) != 2 || got[0] != "unavailable:not_published" || got[1] != "unavailable:server_unavailable" {
		t.Fatalf("outage events (recorded on change) = %v", got)
	}
	mu.Lock()
	mode = ""
	mu.Unlock()
	store.reject = ReasonStale
	if reason := fetcher.FetchOnce(t.Context()); reason != ReasonStale {
		t.Fatalf("rejected reason = %s", reason)
	}
	if reason := fetcher.FetchOnce(t.Context()); reason != ReasonStale || len(store.events) != 3 {
		t.Fatalf("the same rejected bytes were audited again: %v", store.events)
	}
	if _, err := NewFetcher(FetcherConfig{URL: "http://x/y", Interval: time.Minute, Timeout: time.Second, Store: store}); err == nil {
		t.Fatal("plain http accepted")
	}
	if got, err := DocumentURL("https://auth.example.com"); err != nil || got != "https://auth.example.com"+DefaultDocumentPath {
		t.Fatalf("DocumentURL = %q, %v", got, err)
	}
}

type fakeDistributionStore struct {
	latest   Accepted
	enforced map[string]uint64
	receipts []edgesignertrust.Receipt
}

func (store *fakeDistributionStore) Latest(context.Context) (Accepted, bool, error) {
	return store.latest, store.latest.Revision > 0, nil
}
func (store *fakeDistributionStore) EnforcedRevisions(context.Context) (map[string]uint64, error) {
	return store.enforced, nil
}
func (store *fakeDistributionStore) RecordReceipt(_ context.Context, receipt edgesignertrust.Receipt) error {
	store.receipts = append(store.receipts, receipt)
	return nil
}

type fakeTransport struct {
	published map[string][]byte
}

func (transport *fakeTransport) PublishBundle(_ context.Context, nodeID string, _ uint64, encoded []byte) error {
	transport.published[nodeID] = encoded
	return nil
}
func (transport *fakeTransport) NextReceipt(context.Context) (ReceiptDelivery, error) {
	return nil, nil
}

type fakeDelivery struct {
	nodeID string
	body   []byte
	acked  bool
	naked  bool
}

func (delivery *fakeDelivery) NodeID() string            { return delivery.nodeID }
func (delivery *fakeDelivery) ReceiptJSON() []byte       { return delivery.body }
func (delivery *fakeDelivery) Ack(context.Context) error { delivery.acked = true; return nil }
func (delivery *fakeDelivery) Nak(context.Context) error { delivery.naked = true; return nil }

func TestDistributorPublishesUntilNodesEnforce(t *testing.T) {
	document := signedDocument(t, 2, "release-old")
	control := seededKey("control publisher")
	store := &fakeDistributionStore{latest: Accepted{Revision: 2, Document: document},
		enforced: map[string]uint64{"node-current": 2, "node-behind": 1}}
	transport := &fakeTransport{published: map[string][]byte{}}
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	distributor, err := NewDistributor(DistributorConfig{Store: store, Transport: transport, KeyID: "edge-publish",
		Nodes: func(context.Context) ([]NodeTarget, error) {
			return []NodeTarget{{ID: "node-current", Capable: true}, {ID: "node-behind", Capable: true},
				{ID: "node-new", Capable: true}, {ID: "node-old-agent"}}, nil
		},
		Sign:     func(_ context.Context, payload []byte) ([]byte, error) { return ed25519.Sign(control, payload), nil },
		Interval: time.Minute, RetryAfter: 10 * time.Minute, Logger: quietLogger(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := distributor.PublishOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	// node-old-agent did not declare EDGE_SIGNER_TRUST: no bundle.
	if len(transport.published) != 2 || transport.published["node-current"] != nil || transport.published["node-old-agent"] != nil {
		t.Fatalf("published to %v", keys(transport.published))
	}
	trusted := func(keyID string) (ed25519.PublicKey, bool) {
		return control.Public().(ed25519.PublicKey), keyID == "edge-publish"
	}
	bundle, signed, _, err := edgesignertrust.OpenBundle(transport.published["node-new"], "node-new", trusted)
	if err != nil || bundle.Revision != 2 || !signed.Document.Revokes("release-old", nil) {
		t.Fatalf("bundle = %v", err)
	}
	transport.published = map[string][]byte{}
	if err := distributor.PublishOnce(t.Context()); err != nil || len(transport.published) != 0 {
		t.Fatalf("republished before RetryAfter: %v", keys(transport.published))
	}
	now = now.Add(11 * time.Minute)
	if err := distributor.PublishOnce(t.Context()); err != nil || len(transport.published) != 2 {
		t.Fatalf("not retried after RetryAfter: %v", keys(transport.published))
	}
	receipt, _ := edgesignertrust.EncodeReceipt(edgesignertrust.Receipt{Schema: edgesignertrust.ReceiptSchema,
		NodeID: "node-new", BundleSHA256: edgesignertrust.Digest(transport.published["node-new"]), Revision: 2,
		Result: edgesignertrust.ResultApplied, ReportedAt: "2026-10-17T09:11:00Z"})
	delivery := &fakeDelivery{nodeID: "node-new", body: receipt}
	distributor.HandleReceipt(t.Context(), delivery)
	if !delivery.acked || len(store.receipts) != 1 || store.receipts[0].Revision != 2 {
		t.Fatalf("receipt not recorded: %#v", store.receipts)
	}
	spoofed := &fakeDelivery{nodeID: "node-behind", body: receipt}
	distributor.HandleReceipt(t.Context(), spoofed)
	if !spoofed.acked || len(store.receipts) != 1 {
		t.Fatal("receipt for another node was recorded")
	}
}

func keys(values map[string][]byte) []string {
	result := []string{}
	for key := range values {
		result = append(result, key)
	}
	return result
}

// The node source reads the latest session's capability snapshot.
func TestSnapshotDeclaresSignerTrust(t *testing.T) {
	encode := func(features ...*agentv1.Capability) []byte {
		encoded, err := proto.Marshal(&agentv1.AgentCapabilities{AgentVersion: "1.0.35", Features: features})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	for name, test := range map[string]struct {
		snapshot []byte
		want     bool
	}{
		"declared": {encode(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_MONITORING, ApiVersion: 1},
			&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST, ApiVersion: 1}), true},
		"older agent":      {encode(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_MONITORING, ApiVersion: 1}), false},
		"unknown version":  {encode(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST, ApiVersion: 2}), false},
		"never connected":  {nil, false},
		"corrupt snapshot": {[]byte{0xff, 0xff}, false},
	} {
		if got := snapshotDeclaresSignerTrust(test.snapshot); got != test.want {
			t.Errorf("%s: %v, want %v", name, got, test.want)
		}
	}
}

// 验收 acc-a DA-1：节点回执签名者信任已应用后立即通知（唤醒票据分发），拒绝不通知。
func TestDistributorNotifiesAppliedReceipts(t *testing.T) {
	store := &fakeDistributionStore{latest: Accepted{Revision: 1}, enforced: map[string]uint64{}}
	distributor, err := NewDistributor(DistributorConfig{Store: store, Transport: &fakeTransport{published: map[string][]byte{}},
		KeyID: "edge-publish", Nodes: func(context.Context) ([]NodeTarget, error) { return nil, nil },
		Sign:     func(context.Context, []byte) ([]byte, error) { return nil, nil },
		Interval: time.Minute, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	notified := 0
	distributor.OnApplied(func() { notified++ })
	for _, result := range []string{edgesignertrust.ResultRejected, edgesignertrust.ResultApplied} {
		reason := ""
		if result == edgesignertrust.ResultRejected {
			reason = "bad_signature"
		}
		receipt, err := edgesignertrust.EncodeReceipt(edgesignertrust.Receipt{Schema: edgesignertrust.ReceiptSchema,
			NodeID: "node-new", BundleSHA256: edgesignertrust.Digest([]byte("bundle")), Revision: 1,
			Result: result, Reason: reason, ReportedAt: "2026-10-17T09:11:00Z"})
		if err != nil {
			t.Fatal(err)
		}
		distributor.HandleReceipt(t.Context(), &fakeDelivery{nodeID: "node-new", body: receipt})
	}
	if len(store.receipts) != 2 || notified != 1 {
		t.Fatalf("receipts=%d notified=%d", len(store.receipts), notified)
	}
}
