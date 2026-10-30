package nodegatewayaddr

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/gatewayaddr"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

type fakeStore struct {
	due       []PendingDocument
	published map[uuid.UUID][]byte
	issued    map[uuid.UUID]time.Time
	expired   []uuid.UUID
	reports   []Report
	reportErr error
}

func (s *fakeStore) Due(context.Context, time.Time, int) ([]PendingDocument, error) {
	return s.due, nil
}
func (s *fakeStore) MarkPublished(_ context.Context, document PendingDocument, digest []byte, issued time.Time) error {
	if s.published == nil {
		s.published, s.issued = map[uuid.UUID][]byte{}, map[uuid.UUID]time.Time{}
	}
	s.published[document.NodeID], s.issued[document.NodeID] = digest, issued
	return nil
}
func (s *fakeStore) MarkExpired(_ context.Context, document PendingDocument) error {
	s.expired = append(s.expired, document.NodeID)
	return nil
}
func (s *fakeStore) Report(_ context.Context, report Report) (bool, error) {
	if s.reportErr != nil {
		return false, s.reportErr
	}
	s.reports = append(s.reports, report)
	return true, nil
}

type fakeTransport struct{ sent map[string][]byte }

func (t *fakeTransport) Publish(_ context.Context, nodeID string, _ uint64, encoded []byte) error {
	if t.sent == nil {
		t.sent = map[string][]byte{}
	}
	t.sent[nodeID] = encoded
	return nil
}
func (*fakeTransport) NextReceipt(context.Context) (ReceiptDelivery, error) { return nil, nil }

type fakeDelivery struct {
	receipt    *agentv1.GatewayAddressChangeReceipt
	acked, nak bool
}

func (d *fakeDelivery) Receipt() *agentv1.GatewayAddressChangeReceipt { return d.receipt }
func (d *fakeDelivery) Ack(context.Context) error                     { d.acked = true; return nil }
func (d *fakeDelivery) Nak(context.Context) error                     { d.nak = true; return nil }

func newTestDistributor(t *testing.T, store *fakeStore, now time.Time) (*Distributor, *fakeTransport, ed25519.PublicKey) {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(nil)
	transport := &fakeTransport{}
	distributor, err := NewDistributor(DistributorConfig{Store: store, Transport: transport, KeyID: "edge-1",
		Sign:     func(_ context.Context, payload []byte) ([]byte, error) { return ed25519.Sign(private, payload), nil },
		Interval: time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return distributor, transport, public
}

// A pending row is signed for its node (the node verifies with the edge
// publication key) and the digest recorded matches the published bytes.
func TestPublishSignsVerifiableDocumentPerNode(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	node := uuid.New()
	store := &fakeStore{due: []PendingDocument{{ChangeID: uuid.New(), NodeID: node, Revision: 3,
		Address: "gateway.cdnca.com:9443", ServerName: "gateway.cdnca.com", State: StatePending}}}
	distributor, transport, public := newTestDistributor(t, store, now)
	if err := distributor.PublishOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	encoded := transport.sent[node.String()]
	change, err := contract.Open(encoded, node.String(), func(string) (ed25519.PublicKey, bool) { return public, true })
	if err != nil || change.Revision != 3 || change.Address != "gateway.cdnca.com:9443" ||
		change.ExpiresAt-change.IssuedAt != int64(DocumentLifetime/time.Second) {
		t.Fatalf("document = %+v %v", change, err)
	}
	if digest := sha256.Sum256(encoded); !bytes.Equal(store.published[node], digest[:]) {
		t.Fatal("recorded digest differs from the published document")
	}
	carrier, err := Carrier(node.String(), 3, encoded)
	if err != nil || !bytes.Equal(carrier.DocumentSha256, digest(encoded)) {
		t.Fatalf("carrier = %v", err)
	}
	if _, err := Carrier(uuid.NewString(), 3, encoded); err == nil {
		t.Fatal("carrier for another node accepted")
	}
}

func digest(encoded []byte) []byte { value := sha256.Sum256(encoded); return value[:] }

// A republish of a delivered row signs the same bytes (same issued_at), so a
// node that already handled it answers its stored outcome; once the
// lifetime is over the row fails as undelivered instead.
func TestRepublishKeepsBytesAndExpiresUndelivered(t *testing.T) {
	first := time.Unix(1_800_000_000, 0)
	node := uuid.New()
	document := PendingDocument{ChangeID: uuid.New(), NodeID: node, Revision: 2, Address: "gateway.cdnca.com:9443",
		ServerName: "gateway.cdnca.com", State: StatePending}
	store := &fakeStore{due: []PendingDocument{document}}
	distributor, transport, _ := newTestDistributor(t, store, first)
	if err := distributor.PublishOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	original := transport.sent[node.String()]
	published := store.issued[node]
	document.State, document.Published = StateDelivered, &published
	store.due = []PendingDocument{document}
	later, _, _ := newTestDistributor(t, store, first.Add(time.Hour))
	later.config.Sign = distributor.config.Sign
	later.config.Transport = transport
	if err := later.PublishOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(transport.sent[node.String()], original) {
		t.Fatal("republish changed the document")
	}
	expired, _, _ := newTestDistributor(t, store, first.Add(DocumentLifetime))
	if err := expired.PublishOnce(context.Background()); err != nil || len(store.expired) != 1 || store.expired[0] != node {
		t.Fatalf("expired = %v %v", store.expired, err)
	}
}

func TestHandleReceiptValidatesAndRecords(t *testing.T) {
	store := &fakeStore{}
	distributor, _, _ := newTestDistributor(t, store, time.Now())
	node := uuid.New()
	good := &agentv1.GatewayAddressChangeReceipt{NodeId: node.String(), Revision: 2, DocumentSha256: make([]byte, 32),
		State: contract.StateFailed, ErrorCode: contract.ErrorDial, ActiveAddress: "old.cdnca.com:443"}
	delivery := &fakeDelivery{receipt: good}
	distributor.HandleReceipt(context.Background(), delivery)
	if !delivery.acked || len(store.reports) != 1 || store.reports[0].ErrorCode != contract.ErrorDial || store.reports[0].NodeID != node {
		t.Fatalf("good receipt = %+v acked=%v", store.reports, delivery.acked)
	}
	for name, bad := range map[string]*agentv1.GatewayAddressChangeReceipt{
		"failed no code":  {NodeId: node.String(), Revision: 2, DocumentSha256: make([]byte, 32), State: contract.StateFailed},
		"switched + code": {NodeId: node.String(), Revision: 2, DocumentSha256: make([]byte, 32), State: contract.StateSwitched, ErrorCode: "x"},
		"bad digest":      {NodeId: node.String(), Revision: 2, DocumentSha256: []byte{1}, State: contract.StateProbing},
		"bad node":        {NodeId: "x", Revision: 2, DocumentSha256: make([]byte, 32), State: contract.StateProbing},
		"bad state":       {NodeId: node.String(), Revision: 2, DocumentSha256: make([]byte, 32), State: "done"},
	} {
		delivery := &fakeDelivery{receipt: bad}
		distributor.HandleReceipt(context.Background(), delivery)
		if !delivery.acked || len(store.reports) != 1 {
			t.Fatalf("%s: recorded or not acked", name)
		}
	}
	store.reportErr = errors.New("db down")
	delivery = &fakeDelivery{receipt: good}
	distributor.HandleReceipt(context.Background(), delivery)
	if !delivery.nak || delivery.acked {
		t.Fatal("a store failure must nak (redelivered)")
	}
}
