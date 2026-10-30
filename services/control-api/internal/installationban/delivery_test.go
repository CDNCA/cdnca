package installationban

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	transport "github.com/cdnca/cdnca/libs/edgeconfig/installationban"
	contract "github.com/cdnca/cdnca/libs/entitlement/installationban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

type fakeDeliveryStore struct {
	state      State
	deliveries map[string]NodeDelivery
	recorded   []*agentv1.InstallationBanReceipt
}

func (store *fakeDeliveryStore) Current(context.Context, time.Time) (State, error) {
	return store.state, nil
}
func (store *fakeDeliveryStore) NodeDeliveries(context.Context) (map[string]NodeDelivery, error) {
	return store.deliveries, nil
}

// RecordReceipt folds the receipt as the PostgreSQL store does (NextNodeDelivery).
func (store *fakeDeliveryStore) RecordReceipt(_ context.Context, receipt *agentv1.InstallationBanReceipt, now time.Time) error {
	store.recorded = append(store.recorded, receipt)
	var previous *NodeDelivery
	if stored, ok := store.deliveries[receipt.NodeId]; ok {
		previous = &stored
	}
	if next, ok := NextNodeDelivery(previous, receipt, now); ok {
		store.deliveries[receipt.NodeId] = next
	}
	return nil
}

type fakeCommands struct {
	published []*agentv1.InstallationBanCommand
}

func (commands *fakeCommands) Publish(_ context.Context, command *agentv1.InstallationBanCommand) error {
	commands.published = append(commands.published, command)
	return nil
}
func (*fakeCommands) NextReceipt(context.Context) (ReceiptDelivery, error) { return nil, nil }

type fakeReceipt struct {
	receipt    *agentv1.InstallationBanReceipt
	acked, nak bool
}

func (receipt *fakeReceipt) Receipt() *agentv1.InstallationBanReceipt { return receipt.receipt }
func (receipt *fakeReceipt) Ack(context.Context) error                { receipt.acked = true; return nil }
func (receipt *fakeReceipt) Nak(context.Context) error                { receipt.nak = true; return nil }

func TestDistributorPublishesUntilNodesReport(t *testing.T) {
	notice, ticket := []byte(`notice-bytes`), []byte(`ticket-bytes`)
	store := &fakeDeliveryStore{state: State{Notice: notice, NoticeBody: banned(5, nil), Ticket: ticket,
		TicketBody: &contract.ServiceTicket{Revision: 4}}, deliveries: map[string]NodeDelivery{"done": {Revision: 5, AppliedRevision: 5}}}
	commands := &fakeCommands{}
	now := testNow
	distributor := &Distributor{Store: store, Commands: commands, Interval: time.Minute, Now: func() time.Time { return now },
		Nodes: func(context.Context) ([]NodeTarget, error) {
			return []NodeTarget{{ID: "behind", Capable: true}, {ID: "done", Capable: true}, {ID: "old-agent"}}, nil
		}}
	if err := distributor.PublishOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(commands.published) != 1 || commands.published[0].NodeId != "behind" || commands.published[0].Revision != 5 {
		t.Fatalf("published %v", commands.published)
	}
	command := commands.published[0]
	noticeSum, ticketSum := sha256.Sum256(notice), sha256.Sum256(ticket)
	if !bytes.Equal(command.NoticeJson, notice) || !bytes.Equal(command.NoticeSha256, noticeSum[:]) ||
		!bytes.Equal(command.TicketJson, ticket) || !bytes.Equal(command.TicketSha256, ticketSum[:]) {
		t.Fatal("the command must carry the stored bytes unchanged")
	}
	// within RetryAfter: not republished; after it: republished
	if err := distributor.PublishOnce(t.Context()); err != nil || len(commands.published) != 1 {
		t.Fatalf("republished too early: %d", len(commands.published))
	}
	now = now.Add(11 * time.Minute)
	if err := distributor.PublishOnce(t.Context()); err != nil || len(commands.published) != 2 {
		t.Fatalf("not republished after RetryAfter: %d", len(commands.published))
	}
	receipt := &fakeReceipt{receipt: &agentv1.InstallationBanReceipt{NodeId: "behind", Revision: 5, Applied: true, Status: "banned"}}
	distributor.HandleReceipt(t.Context(), receipt)
	if !receipt.acked || len(store.recorded) != 1 {
		t.Fatalf("receipt acked %v recorded %d", receipt.acked, len(store.recorded))
	}
	now = now.Add(time.Hour)
	if err := distributor.PublishOnce(t.Context()); err != nil || len(commands.published) != 2 {
		t.Fatalf("a node that reported the revision got it again: %d", len(commands.published))
	}
}

// A node that could not apply a revision (persistence or
// enforcement failed) gets the same revision again after a capped backoff and
// is applied once it succeeds; a refusal of the bytes themselves is not retried.
func TestDistributorRetriesRecoverableRefusalsWithTheSameRevision(t *testing.T) {
	store := &fakeDeliveryStore{state: State{Ticket: []byte(`ticket-bytes`), TicketBody: &contract.ServiceTicket{Revision: 7}},
		deliveries: map[string]NodeDelivery{}}
	commands := &fakeCommands{}
	now := testNow
	distributor := &Distributor{Store: store, Commands: commands, Interval: time.Minute, Now: func() time.Time { return now },
		Nodes: func(context.Context) ([]NodeTarget, error) { return []NodeTarget{{ID: "node", Capable: true}}, nil }}
	publish := func(want int, label string) {
		t.Helper()
		if err := distributor.PublishOnce(t.Context()); err != nil || len(commands.published) != want {
			t.Fatalf("%s: published %d, want %d (%v)", label, len(commands.published), want, err)
		}
		if last := commands.published[len(commands.published)-1]; last.Revision != 7 {
			t.Fatalf("%s: revision %d", label, last.Revision)
		}
	}
	answer := func(applied bool, reason string) {
		t.Helper()
		receipt := &fakeReceipt{receipt: &agentv1.InstallationBanReceipt{NodeId: "node", Revision: 7, Applied: applied,
			Status: "no_ticket", Reason: reason}}
		distributor.HandleReceipt(t.Context(), receipt)
		if !receipt.acked {
			t.Fatal("receipt not acknowledged")
		}
	}
	publish(1, "first delivery")
	for attempt, reason := range []string{transport.ReasonPersistence, transport.ReasonEnforce, transport.ReasonPersistence} {
		answer(false, reason)
		delivery := store.deliveries["node"]
		backoff := RetryBackoff(attempt + 1)
		if delivery.FailureClass != FailureRetryable || delivery.AppliedRevision != 0 || delivery.FailedAttempts != attempt+1 ||
			delivery.Reason != reason || delivery.NextRetryAt == nil || !delivery.NextRetryAt.Equal(now.Add(backoff)) {
			t.Fatalf("after %s: %+v", reason, delivery)
		}
		// not before the backoff, even though the unanswered-command timer would allow it
		now = now.Add(backoff - time.Second)
		publish(attempt+1, "within backoff")
		now = now.Add(time.Second)
		publish(attempt+2, "after backoff")
	}
	answer(true, "")
	if delivery := store.deliveries["node"]; delivery.AppliedRevision != 7 || delivery.FailureClass != FailureNone ||
		delivery.FailedAttempts != 0 || delivery.NextRetryAt != nil {
		t.Fatalf("applied: %+v", delivery)
	}
	now = now.Add(24 * time.Hour)
	publish(4, "after applied")
	// a late refusal of the applied revision does not reopen it
	answer(false, transport.ReasonPersistence)
	if delivery := store.deliveries["node"]; delivery.AppliedRevision != 7 || delivery.FailureClass != FailureNone {
		t.Fatalf("late refusal: %+v", delivery)
	}
}

func TestDistributorDoesNotRetryPermanentRefusals(t *testing.T) {
	for _, reason := range []string{transport.ReasonInvalid, transport.ReasonInstallation, transport.ReasonStale,
		transport.ReasonConflict, transport.ReasonExpired} {
		store := &fakeDeliveryStore{state: State{Ticket: []byte(`ticket`), TicketBody: &contract.ServiceTicket{Revision: 3}},
			deliveries: map[string]NodeDelivery{"node": {Revision: 2, AppliedRevision: 2}}}
		commands := &fakeCommands{}
		now := testNow
		distributor := &Distributor{Store: store, Commands: commands, Interval: time.Minute, Now: func() time.Time { return now },
			Nodes: func(context.Context) ([]NodeTarget, error) { return []NodeTarget{{ID: "node", Capable: true}}, nil }}
		if err := distributor.PublishOnce(t.Context()); err != nil || len(commands.published) != 1 {
			t.Fatalf("%s: first delivery %d (%v)", reason, len(commands.published), err)
		}
		distributor.HandleReceipt(t.Context(), &fakeReceipt{receipt: &agentv1.InstallationBanReceipt{NodeId: "node", Revision: 3,
			Status: "serving", Reason: reason}})
		delivery := store.deliveries["node"]
		if delivery.FailureClass != FailurePermanent || delivery.Revision != 3 || delivery.AppliedRevision != 2 ||
			delivery.NextRetryAt != nil || delivery.Reason != reason {
			t.Fatalf("%s: %+v", reason, delivery)
		}
		now = now.Add(48 * time.Hour)
		if err := distributor.PublishOnce(t.Context()); err != nil || len(commands.published) != 1 {
			t.Fatalf("%s: a permanently refused revision was sent again: %d", reason, len(commands.published))
		}
		// a new revision is delivered
		store.state = State{Ticket: []byte(`ticket-4`), TicketBody: &contract.ServiceTicket{Revision: 4}}
		if err := distributor.PublishOnce(t.Context()); err != nil || len(commands.published) != 2 || commands.published[1].Revision != 4 {
			t.Fatalf("%s: new revision not delivered: %d", reason, len(commands.published))
		}
	}
}

func TestRetryBackoffIsCapped(t *testing.T) {
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for index, expected := range want {
		if got := RetryBackoff(index + 1); got != expected {
			t.Fatalf("attempt %d: %s, want %s", index+1, got, expected)
		}
	}
	if got := RetryBackoff(1 << 20); got != RetryBackoffMax {
		t.Fatalf("large attempt count: %s", got)
	}
}

// The classes match the edge agent's reasons (agents/edge-agent/internal/installationban
// uses the same transport constants): untrusted_signature and unknown reasons are retried.
func TestReasonClasses(t *testing.T) {
	for reason, permanent := range map[string]bool{transport.ReasonInvalid: true, transport.ReasonInstallation: true,
		transport.ReasonStale: true, transport.ReasonConflict: true, transport.ReasonExpired: true,
		transport.ReasonPersistence: false, transport.ReasonEnforce: false, transport.ReasonUntrusted: false, "future_reason": false} {
		if transport.PermanentReason(reason) != permanent {
			t.Errorf("%s permanent = %v", reason, !permanent)
		}
	}
}

func TestNodeTicketShowsTheRefusedDelivery(t *testing.T) {
	retry := testNow.Add(4 * time.Minute)
	view := EvaluateNodeTicket("node", &NodeTicketRow{Status: "no_ticket", ReportedAt: testNow,
		Delivery: NodeDelivery{Revision: 7, FailureClass: FailureRetryable, Reason: transport.ReasonPersistence,
			FailedAttempts: 3, NextRetryAt: &retry}}, testNow)
	if view.Delivery == nil || view.Delivery.Revision != 7 || view.Delivery.Reason != transport.ReasonPersistence ||
		view.Delivery.FailedAttempts != 3 || view.Delivery.NextRetryAt == nil || !view.Delivery.NextRetryAt.Equal(retry) {
		t.Fatalf("delivery view %+v", view.Delivery)
	}
	if view := EvaluateNodeTicket("node", &NodeTicketRow{Status: "serving", ReportedAt: testNow,
		Delivery: NodeDelivery{Revision: 7, AppliedRevision: 7}}, testNow); view.Delivery != nil {
		t.Fatalf("an applied revision shows a delivery failure: %+v", view.Delivery)
	}
}

// 验收 acc-a DA-1：新节点初始化后票据比签名者信任早约 5ms 到，节点无验票密钥回
// untrusted_signature，要等 1–2 分钟重试。签名者信任尚未在节点应用时先不发。
func TestDistributorWaitsForTheNodeSignerTrust(t *testing.T) {
	store := &fakeDeliveryStore{state: State{Notice: []byte(`notice`), NoticeBody: banned(5, nil)},
		deliveries: map[string]NodeDelivery{}}
	commands := &fakeCommands{}
	applied := map[string]uint64{"trusted": 1}
	distributor := &Distributor{Store: store, Commands: commands, Interval: time.Minute, Now: func() time.Time { return testNow },
		Nodes: func(context.Context) ([]NodeTarget, error) {
			return []NodeTarget{{ID: "trusted", Capable: true}, {ID: "fresh", Capable: true}}, nil
		},
		TrustApplied: func(context.Context) (map[string]uint64, error) { return applied, nil }}
	if err := distributor.PublishOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(commands.published) != 1 || commands.published[0].NodeId != "trusted" {
		t.Fatalf("published before the node applied signer trust: %v", commands.published)
	}
	applied["fresh"] = 1
	if err := distributor.PublishOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(commands.published) != 2 || commands.published[1].NodeId != "fresh" {
		t.Fatalf("not published once signer trust applied: %v", commands.published)
	}
}
