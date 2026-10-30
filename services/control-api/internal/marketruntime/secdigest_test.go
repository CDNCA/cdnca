package marketruntime

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/secdigest"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/google/uuid"
)

type fakeDigestSource struct {
	windows     []time.Time
	subscribers map[string]uuid.UUID
	site        uuid.UUID
	subscriber  uuid.UUID
	grant       uuid.UUID
}

func (f *fakeDigestSource) SecurityDigests(_ context.Context, leaf uuid.UUID, start time.Time) ([]marketsupply.DigestTarget, error) {
	f.windows = append(f.windows, start)
	if !start.Equal(f.windows[0]) {
		return nil, nil // only the first window had an attack
	}
	d := secdigest.Digest{Schema: secdigest.SchemaV1, LeafMemberID: leaf, GrantID: f.grant, LeafSiteID: f.site,
		WindowStart: start.Unix(), WindowSeconds: secdigest.WindowSeconds,
		Summary: secdigest.Summary{Events: 1, Blocked: 1, Clients: 1}}
	return []marketsupply.DigestTarget{{Grant: grant.Grant{GrantID: f.grant}, Subscriber: f.subscriber,
		Domains: []string{"www.example.com"}, Digest: d}}, nil
}
func (f *fakeDigestSource) Subscribers() map[string]uuid.UUID { return f.subscribers }
func (f *fakeDigestSource) RememberSubscriber(key string, member uuid.UUID) {
	if f.subscribers == nil {
		f.subscribers = map[string]uuid.UUID{}
	}
	f.subscribers[key] = member
}

type fakeDigestReceiver struct{ got []envelope.Header }

func (f *fakeDigestReceiver) ReceiveDigest(_ context.Context, h envelope.Header, _ []byte) error {
	f.got = append(f.got, h)
	return nil
}

func TestDigestsSentOncePerWindowWithStableKeys(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(nil)
	source := &fakeDigestSource{site: uuid.New(), subscriber: uuid.New(), grant: uuid.New(),
		subscribers: map[string]uuid.UUID{"k1": uuid.New()}}
	market := &fakeMarket{sendErr: errTransient}
	r := New(Config{StateDir: t.TempDir()}, nil, market, nil, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithSecDigest(source, nil)
	r.id = marketclient.Identity{MemberID: uuid.New(), SigningKey: key}

	if err := r.sendDigests(t.Context()); err == nil {
		t.Fatal("a market failure must surface and keep the window")
	}
	if err := r.sendDigests(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Catch-up is bounded to an hour of settled windows (the failed first
	// pass stopped at the first window and retried it).
	if n := len(source.windows); n < 13 || n > 14 {
		t.Fatalf("windows evaluated %d", n)
	}
	if len(market.sent) != 1 {
		t.Fatalf("sent %d digests, want 1", len(market.sent))
	}
	out := market.sent[0]
	window, ok := secdigest.WindowOfKey(out.IdempotencyKey)
	if out.Operation != secdigest.Operation || out.To != source.subscriber || out.GrantID != source.grant || !ok ||
		window != source.windows[0].Unix() || out.MessageID == uuid.Nil {
		t.Fatalf("outbound %+v", out)
	}
	var signed secdigest.Signed
	if err := json.Unmarshal(out.Payload, &signed); err != nil {
		t.Fatal(err)
	}
	if d, _, err := secdigest.Verify(key.Public().(ed25519.PublicKey), signed); err != nil || d.LeafSiteID != source.site {
		t.Fatalf("payload %v %+v", err, d)
	}
	// Settled windows are not evaluated again, also after a restart, and the
	// learned subscribers come back.
	before := len(source.windows)
	if err := r.sendDigests(t.Context()); err != nil || len(source.windows) != before {
		t.Fatalf("re-evaluated: %d %v", len(source.windows), err)
	}
	fresh := &fakeDigestSource{}
	again := New(Config{StateDir: r.cfg.StateDir}, nil, market, nil, r.log).WithSecDigest(fresh, nil)
	again.restoreSubscribers()
	if fresh.subscribers["k1"] != source.subscribers["k1"] {
		t.Fatalf("subscribers not restored: %v", fresh.subscribers)
	}
}

func TestDigestRelayedToReceiverNotLeafHandler(t *testing.T) {
	supply := &fakeSupply{}
	receiver := &fakeDigestReceiver{}
	market := &fakeMarket{}
	r := New(Config{StateDir: t.TempDir()}, nil, market, supply, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithSecDigest(nil, receiver)
	h := envelope.Header{MessageID: uuid.New(), Operation: secdigest.Operation, GrantID: uuid.New(), SenderMemberID: uuid.New()}
	if err := r.answer(t.Context(), marketclient.Identity{}, marketclient.Inbound{Seq: 1, Header: h, Payload: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if len(receiver.got) != 1 || len(supply.handled) != 0 || len(market.sent) != 0 {
		t.Fatalf("receiver %d, leaf handler %d, replies %d", len(receiver.got), len(supply.handled), len(market.sent))
	}
}

var errTransient = &marketclient.RejectedError{Status: 503, Code: "unavailable"}

// A leaf that just restarted (or holds a grant no subscriber request has used
// yet) learns the root subscriber from the grant fetch itself (ML-20b).
func TestGrantFetchTeachesRootSubscriber(t *testing.T) {
	g := grant.Grant{GrantID: uuid.New(), SubscriptionPath: []uuid.UUID{uuid.New(), uuid.New()}, NodePoolRef: "p"}
	other := grant.Grant{GrantID: uuid.New(), SubscriptionPath: []uuid.UUID{uuid.New()}, NodePoolRef: "q"}
	root := uuid.New()
	// The market names a subscriber only for g; a stray ID for an unknown
	// grant must not be remembered under any key.
	market := &fakeMarket{grants: []grant.Grant{g, other},
		grantSubscribers: map[uuid.UUID]uuid.UUID{g.GrantID: root, uuid.New(): uuid.New()}}
	source := &fakeDigestSource{}
	r := New(Config{StateDir: t.TempDir(), GrantEvery: time.Hour}, nil, market, &fakeSupply{},
		slog.New(slog.NewTextHandler(io.Discard, nil))).WithSecDigest(source, nil)
	// A cancelled context runs exactly one grant round.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r.grantLoop(ctx)
	if got := source.Subscribers(); len(got) != 1 || got[marketsupply.Key(g)] != root {
		t.Fatalf("subscribers %v, want %s under %s", got, root, marketsupply.Key(g))
	}
}
