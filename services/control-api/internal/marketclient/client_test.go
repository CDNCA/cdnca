package marketclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/card"
	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/nodeload"
	"github.com/cdnca/cdnca/libs/marketproto/notice"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
)

// fakeMarket mimics the market-service contract with real signatures.
type fakeMarket struct {
	t           *testing.T
	key         ed25519.PrivateKey
	mu          sync.Mutex
	members     map[uuid.UUID]card.Card
	grants      []grant.Signed
	subscribers map[uuid.UUID]uuid.UUID
	inbox       map[uuid.UUID][]json.RawMessage
	seq         int64
	sawClient   bool
	forgeCard   bool
}

func (f *fakeMarket) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/members/register", func(w http.ResponseWriter, r *http.Request) {
		f.sawClient = len(r.TLS.PeerCertificates) == 1
		var body struct {
			SigningPublicKey []byte `json:"signing_public_key"`
			BoxPublicKey     []byte `json:"box_public_key"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := uuid.New()
		f.mu.Lock()
		f.members[id] = card.Card{MemberID: id, SigningPublicKey: body.SigningPublicKey, BoxPublicKey: body.BoxPublicKey}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
	})
	mux.HandleFunc("GET /v1/members/{id}/card", func(w http.ResponseWriter, r *http.Request) {
		id, _ := uuid.Parse(r.PathValue("id"))
		f.mu.Lock()
		c, ok := f.members[id]
		f.mu.Unlock()
		if !ok {
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
			return
		}
		if f.forgeCard {
			c.MemberID = uuid.New()
		}
		signed, _ := card.Sign(c, "m1", f.key)
		_ = json.NewEncoder(w).Encode(signed)
	})
	mux.HandleFunc("GET /v1/grants", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"items": f.grants, "subscribers": f.subscribers})
	})
	mux.HandleFunc("POST /v1/relay/messages", func(w http.ResponseWriter, r *http.Request) {
		var raw json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&raw)
		var sealed envelope.Sealed
		_ = json.Unmarshal(raw, &sealed)
		var header envelope.Header
		_ = json.Unmarshal(sealed.HeaderBytes, &header)
		f.mu.Lock()
		f.seq++
		item, _ := json.Marshal(map[string]any{"seq": f.seq, "sealed": raw})
		f.inbox[header.RecipientMember] = append(f.inbox[header.RecipientMember], item)
		seq := f.seq
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]int64{"seq": seq})
	})
	mux.HandleFunc("GET /v1/relay/inbox", func(w http.ResponseWriter, r *http.Request) {
		// Identity is inferred from the single registered recipient with mail.
		f.mu.Lock()
		defer f.mu.Unlock()
		for id, items := range f.inbox {
			if r.Header.Get("X-Test-Member") == id.String() {
				_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
	})
	return mux
}

func newIdentity(t *testing.T) Identity {
	t.Helper()
	_, signing, _ := ed25519.GenerateKey(rand.Reader)
	boxPriv := make([]byte, 32)
	_, _ = rand.Read(boxPriv)
	boxPub, _ := curve25519.X25519(boxPriv, curve25519.Basepoint)
	return Identity{SigningKey: signing, BoxPrivate: boxPriv, BoxPublic: boxPub}
}

func pki(t *testing.T) (*x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	issue := func(serial int64, usage x509.ExtKeyUsage, server bool) tls.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if server {
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, _ := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	return pool, issue(2, x509.ExtKeyUsageServerAuth, true), issue(3, x509.ExtKeyUsageClientAuth, false)
}

func setup(t *testing.T) (*fakeMarket, *Client, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakeMarket{t: t, key: priv, members: map[uuid.UUID]card.Card{}, inbox: map[uuid.UUID][]json.RawMessage{}}
	pool, serverCert, clientCert := pki(t)
	server := httptest.NewUnstartedServer(f.handler())
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	client, err := New(Config{BaseURL: server.URL, RootCAs: pool, MarketKeys: map[string]ed25519.PublicKey{"m1": pub},
		ClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &clientCert, nil }})
	if err != nil {
		t.Fatal(err)
	}
	return f, client, priv
}

func TestRegisterUsesInstallationCertificate(t *testing.T) {
	f, client, _ := setup(t)
	id, err := client.Register(context.Background(), newIdentity(t), []byte("lease"), "node seller")
	if err != nil || id == uuid.Nil || !f.sawClient {
		t.Fatalf("id=%s err=%v sawClient=%v", id, err, f.sawClient)
	}
}

func TestGrantsAreVerifiedAndScopedToSelf(t *testing.T) {
	f, client, marketKey := setup(t)
	self, other := uuid.New(), uuid.New()
	mint := func(leaf uuid.UUID, key ed25519.PrivateKey) grant.Signed {
		now := time.Now().Unix()
		signed, err := grant.Sign(grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: leaf,
			SubscriptionPath: []uuid.UUID{uuid.New()}, OfferSnapshotDigest: strings.Repeat("a", 64), NodePoolRef: "p",
			Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared}, LoadThresholds: spec.DefaultLoadFloor,
			IssuedAt: now, NotBefore: now, NotAfter: now + 3600}, "m1", key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	f.grants = []grant.Signed{mint(self, marketKey), mint(other, marketKey), mint(self, rogue)}
	root := uuid.New()
	ids := make([]uuid.UUID, 0, len(f.grants))
	f.subscribers = map[uuid.UUID]uuid.UUID{}
	for _, s := range f.grants {
		var g grant.Grant
		raw, _ := base64.StdEncoding.DecodeString(s.Payload)
		_ = json.Unmarshal(raw, &g)
		ids = append(ids, g.GrantID)
		f.subscribers[g.GrantID] = root
	}
	got, subscribers, err := client.Grants(context.Background(), self)
	if err != nil || len(got) != 1 || got[0].LeafMemberID != self {
		t.Fatalf("got %d grants, %v", len(got), err)
	}
	// Only grants that passed verification keep their root subscriber.
	if len(subscribers) != 1 || subscribers[ids[0]] != root {
		t.Fatalf("subscribers %v", subscribers)
	}
}

func TestSendReceiveEndToEnd(t *testing.T) {
	_, client, _ := setup(t)
	ctx := context.Background()
	buyer, seller := newIdentity(t), newIdentity(t)
	var err error
	if buyer.MemberID, err = client.Register(ctx, buyer, nil, "b"); err != nil {
		t.Fatal(err)
	}
	if seller.MemberID, err = client.Register(ctx, seller, nil, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Send(ctx, buyer, Outbound{To: seller.MemberID, GrantID: uuid.New(), Operation: "supply.prepare_site",
		Domains: []string{"www.example.com"}, IdempotencyKey: "site:1", Payload: []byte(`{"rev":1}`)}); err != nil {
		t.Fatal(err)
	}
	// The fake inbox keys on a header the real relay derives from mTLS.
	client.http.Transport.(*http.Transport).Proxy = nil
	reader := &headerTransport{base: client.http.Transport, member: seller.MemberID.String()}
	client.http.Transport = reader
	messages, next, errs := client.Receive(ctx, seller, 0)
	if len(errs) != 0 || len(messages) != 1 || next != 1 || string(messages[0].Payload) != `{"rev":1}` ||
		messages[0].Header.SenderMemberID != buyer.MemberID {
		t.Fatalf("messages=%+v next=%d errs=%v", messages, next, errs)
	}
	// A misrouted envelope (seller's mail delivered to the buyer) is refused,
	// and the cursor still advances past it.
	if messages, next, errs := client.Receive(ctx, buyer, 0); len(messages) != 0 || next != 1 || !errors.Is(errors.Join(errs...), envelope.ErrInvalid) {
		t.Fatalf("misrouted mail: messages=%d next=%d errs=%v", len(messages), next, errs)
	}
	reader.member = buyer.MemberID.String()
	if messages, _, errs := client.Receive(ctx, buyer, 0); len(errs) != 0 || len(messages) != 0 {
		t.Fatalf("buyer's own inbox is empty: %d %v", len(messages), errs)
	}
}

func TestForgedCardRejected(t *testing.T) {
	f, client, _ := setup(t)
	ctx := context.Background()
	peer := newIdentity(t)
	id, err := client.Register(ctx, peer, nil, "p")
	if err != nil {
		t.Fatal(err)
	}
	f.forgeCard = true
	if _, err := client.Card(ctx, id); !errors.Is(err, ErrProtocol) {
		t.Fatalf("card for a different member must be rejected: %v", err)
	}
}

func TestConfigRejectsPlainHTTP(t *testing.T) {
	pool := x509.NewCertPool()
	if _, err := New(Config{BaseURL: "http://my.cdnca.com", RootCAs: pool, MarketKeys: map[string]ed25519.PublicKey{"m": nil},
		ClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return nil, nil }}); !errors.Is(err, ErrConfig) {
		t.Fatalf("want ErrConfig, got %v", err)
	}
}

type headerTransport struct {
	base   http.RoundTripper
	member string
}

func (h *headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Test-Member", h.member)
	return h.base.RoundTrip(r)
}

func TestForwardCarriesIdempotencyKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pool, serverCert, clientCert := pki(t)
	var seen []string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI()+" key="+r.Header.Get("Idempotency-Key"))
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"order":{}}`))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	client, err := New(Config{BaseURL: server.URL, RootCAs: pool, MarketKeys: map[string]ed25519.PublicKey{"m1": pub},
		ClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &clientCert, nil }})
	if err != nil {
		t.Fatal(err)
	}
	status, raw, err := client.Forward(context.Background(), http.MethodPost, "/v1/orders", "order-1", []byte(`{}`))
	if err != nil || status != http.StatusCreated || string(raw) != `{"order":{}}` {
		t.Fatalf("forward: %d %s %v", status, raw, err)
	}
	if _, _, err := client.Forward(context.Background(), http.MethodGet, "/v1/plugins?q=a", "", nil); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"has space", "-leading", strings.Repeat("a", 129), "a\nb"} {
		if _, _, err := client.Forward(context.Background(), http.MethodPost, "/v1/orders", bad, nil); !errors.Is(err, ErrConfig) {
			t.Errorf("key %q: %v", bad, err)
		}
	}
	want := "POST /v1/orders key=order-1|GET /v1/plugins?q=a key="
	if got := strings.Join(seen, "|"); got != want {
		t.Fatalf("seen %q, want %q", got, want)
	}
}

// ReportNodeLoad signs as this member (any leaf ID in the report is replaced)
// and posts to the node load route.
func TestReportNodeLoadSignsAsSelf(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	signPub, signKey, _ := ed25519.GenerateKey(rand.Reader)
	pool, serverCert, clientCert := pki(t)
	self := Identity{MemberID: uuid.New(), SigningKey: signKey}
	var got nodeload.Report
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var signed nodeload.Signed
		if r.Method != http.MethodPost || r.URL.Path != "/v1/node-load/reports" || json.NewDecoder(r.Body).Decode(&signed) != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		report, _, err := nodeload.Verify(signPub, signed)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		got = report
		_, _ = w.Write([]byte(`{"accepted":1,"duplicates":0,"rejected":0}`))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	client, err := New(Config{BaseURL: server.URL, RootCAs: pool, MarketKeys: map[string]ed25519.PublicKey{"m1": pub},
		ClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &clientCert, nil }})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Truncate(time.Minute).Unix()
	result, err := client.ReportNodeLoad(context.Background(), self, nodeload.Report{Schema: nodeload.SchemaV1, ReportID: uuid.New(),
		LeafMemberID: uuid.New(), CreatedAt: at, Items: []nodeload.Item{{NodePoolRef: "p", NodeID: uuid.New(), ObservedAt: at,
			CPUPercent: 50, MemoryPercent: 40, SampleCount: 6}}})
	if err != nil || result.Accepted != 1 || got.LeafMemberID != self.MemberID {
		t.Fatalf("report: %+v %v leaf %s", result, err, got.LeafMemberID)
	}
}

// Market notices arrive unsealed but market-signed; a forged or misaddressed
// one is refused and skipped.
func TestReceiveMarketNotice(t *testing.T) {
	f, client, marketKey := setup(t)
	self := newIdentity(t)
	self.MemberID = uuid.New()
	sub := uuid.New()
	n := notice.Notice{Schema: notice.SchemaV1, ID: uuid.New(), MemberID: self.MemberID, SubscriptionID: &sub,
		Role: notice.RoleBuyer, Kind: notice.KindLimitReached, Stage: "qps", PeriodKey: "h1", CreatedAt: time.Now().Unix(),
		Values: map[string]string{notice.ValueOffer: "o"}}
	good, _ := notice.Sign(n, "m1", marketKey)
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := notice.Sign(n, "m1", rogue)
	other := n
	other.MemberID = uuid.New()
	misaddressed, _ := notice.Sign(other, "m1", marketKey)
	for i, s := range []notice.Signed{forged, misaddressed, good} {
		item, _ := json.Marshal(map[string]any{"seq": i + 1, "operation": notice.Operation, "notice": s})
		f.inbox[self.MemberID] = append(f.inbox[self.MemberID], item)
	}
	client.http.Transport = &headerTransport{base: client.http.Transport, member: self.MemberID.String()}
	messages, next, errs := client.Receive(context.Background(), self, 0)
	if next != 3 || len(errs) != 2 || len(messages) != 1 || messages[0].Notice == nil ||
		messages[0].Notice.Kind != notice.KindLimitReached || messages[0].Notice.ID != n.ID {
		t.Fatalf("messages=%+v next=%d errs=%v", messages, next, errs)
	}
}
