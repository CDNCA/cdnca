package marketruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/google/uuid"
)

type fakeMarket struct {
	mu      sync.Mutex
	inbox   []marketclient.Inbound
	sent    []marketclient.Outbound
	acked   []int64
	sendErr error
	// cursor / cursorErr: what Cursor reports.
	cursor    int64
	cursorErr error

	grants           []grant.Grant
	grantSubscribers map[uuid.UUID]uuid.UUID
	community        []byte
}

func (f *fakeMarket) Register(context.Context, marketclient.Identity, []byte, string) (uuid.UUID, error) {
	return uuid.New(), nil
}

func (f *fakeMarket) RegisterCommunity(ctx context.Context, id marketclient.Identity, document []byte, name string) (uuid.UUID, error) {
	f.community = append([]byte(nil), document...)
	return f.Register(ctx, id, nil, name)
}
func (f *fakeMarket) Grants(context.Context, uuid.UUID) ([]grant.Grant, map[uuid.UUID]uuid.UUID, map[uuid.UUID]string, error) {
	return f.grants, f.grantSubscribers, nil, nil
}
func (f *fakeMarket) Receive(ctx context.Context, _ marketclient.Identity, cursor int64) ([]marketclient.Inbound, int64, []error) {
	f.mu.Lock()
	var out []marketclient.Inbound
	next := cursor
	for _, m := range f.inbox {
		if m.Seq > cursor {
			out = append(out, m)
			next = m.Seq
		}
	}
	f.mu.Unlock()
	if len(out) == 0 {
		<-ctx.Done()
	}
	return out, next, nil
}
func (f *fakeMarket) Send(_ context.Context, _ marketclient.Identity, out marketclient.Outbound) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		err := f.sendErr
		f.sendErr = nil
		return 0, err
	}
	f.sent = append(f.sent, out)
	return int64(len(f.sent)), nil
}
func (f *fakeMarket) Cursor(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cursor, f.cursorErr
}
func (f *fakeMarket) Ack(_ context.Context, seq int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acked = append(f.acked, seq)
	return nil
}

type fakeSupply struct{ handled []uuid.UUID }

func (f *fakeSupply) SyncNamed(context.Context, []grant.Grant, map[uuid.UUID]string) ([]marketsupply.Outcome, error) {
	return nil, nil
}
func (f *fakeSupply) Handle(_ context.Context, h envelope.Header, _ []byte) (siteconf.Reply, error) {
	f.handled = append(f.handled, h.MessageID)
	return siteconf.Reply{Operation: h.Operation, OK: true}, nil
}

func TestIdentityPersistsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir}, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	first, err := r.loadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	first.MemberID = uuid.New()
	if err := r.saveIdentity(first); err != nil {
		t.Fatal(err)
	}
	second, err := r.loadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if second.MemberID != first.MemberID || !bytes.Equal(second.SigningKey, first.SigningKey) ||
		!bytes.Equal(second.BoxPublic, first.BoxPublic) {
		t.Fatal("identity changed across reload")
	}
}

func TestRelayRepliesAndRedeliversAfterFailedReply(t *testing.T) {
	sender := uuid.New()
	msg := func(seq int64) marketclient.Inbound {
		return marketclient.Inbound{Seq: seq, Header: envelope.Header{MessageID: uuid.New(), SenderMemberID: sender,
			GrantID: uuid.New(), Operation: siteconf.OpStatus}}
	}
	market := &fakeMarket{inbox: []marketclient.Inbound{msg(1), msg(2), msg(3)}, sendErr: nil}
	supply := &fakeSupply{}
	r := New(Config{StateDir: t.TempDir()}, nil, market, supply, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Fail the second reply once: message 2 must be redelivered, not acked.
	calls := 0
	market.sendErr = nil
	wrapped := &failOnce{fakeMarket: market, at: 2, calls: &calls}
	r.market = wrapped
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { r.relayLoop(ctx); close(done) }()
	deadline := time.After(11 * time.Second)
	for {
		market.mu.Lock()
		n := len(market.sent)
		market.mu.Unlock()
		if n == 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("replies sent = %d", n)
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancel()
	<-done
	if market.acked[0] != 1 {
		t.Fatalf("first ack must stop before the failed message: %v", market.acked)
	}
	if market.acked[len(market.acked)-1] != 3 {
		t.Fatalf("final ack = %v", market.acked)
	}
	for i, out := range market.sent {
		if out.To != sender || out.Operation != siteconf.OpReply {
			t.Fatalf("reply %d = %+v", i, out)
		}
		var reply siteconf.Reply
		if json.Unmarshal(out.Payload, &reply) != nil || !reply.OK {
			t.Fatalf("reply payload %d = %s", i, out.Payload)
		}
	}
	if len(supply.handled) != 4 {
		t.Fatalf("message 2 must be handled twice (idempotent redelivery), handled %d", len(supply.handled))
	}
}

type failOnce struct {
	*fakeMarket
	at    int
	calls *int
}

func (f *failOnce) Send(ctx context.Context, id marketclient.Identity, out marketclient.Outbound) (int64, error) {
	*f.calls++
	if *f.calls == f.at {
		return 0, errors.New("market unreachable")
	}
	return f.fakeMarket.Send(ctx, id, out)
}

// A reply the market refuses for good (403: the grant was reissued since the
// request) is dropped: the messages behind it are still answered and acked
// instead of the loop retrying the refused reply forever.
func TestRelaySkipsReplyTheMarketRefuses(t *testing.T) {
	sender := uuid.New()
	msg := func(seq int64) marketclient.Inbound {
		return marketclient.Inbound{Seq: seq, Header: envelope.Header{MessageID: uuid.New(), SenderMemberID: sender,
			GrantID: uuid.New(), Operation: siteconf.OpStatus}}
	}
	inbox := []marketclient.Inbound{msg(1), msg(2), msg(3)}
	market := &fakeMarket{inbox: inbox}
	r := New(Config{StateDir: t.TempDir()}, nil, market, &fakeSupply{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.market = &refuseKey{fakeMarket: market, key: "reply-" + inbox[0].Header.MessageID.String()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { r.relayLoop(ctx); close(done) }()
	for {
		market.mu.Lock()
		n, acked := len(market.sent), append([]int64(nil), market.acked...)
		market.mu.Unlock()
		if n == 2 && len(acked) > 0 && acked[len(acked)-1] == 3 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("replies sent = %d, acked %v", n, acked)
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

type refuseKey struct {
	*fakeMarket
	key string
}

func (f *refuseKey) Send(ctx context.Context, id marketclient.Identity, out marketclient.Outbound) (int64, error) {
	if out.IdempotencyKey == f.key {
		return 0, &marketclient.RejectedError{Status: 403, Code: "forbidden"}
	}
	return f.fakeMarket.Send(ctx, id, out)
}

// seqSupply records the relay sequence each handled message carried.
type seqSupply struct {
	mu   sync.Mutex
	seqs []int64
}

func (s *seqSupply) SyncNamed(context.Context, []grant.Grant, map[uuid.UUID]string) ([]marketsupply.Outcome, error) {
	return nil, nil
}
func (s *seqSupply) Handle(ctx context.Context, h envelope.Header, _ []byte) (siteconf.Reply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seqs = append(s.seqs, marketsupply.RelaySeq(ctx))
	return siteconf.Reply{Operation: h.Operation, OK: true}, nil
}

func (s *seqSupply) handled() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.seqs...)
}

// The loop resumes after the acknowledged cursor instead of
// running the whole relay history again on every boot, and hands the leaf
// each message's relay sequence; a market that refuses the cursor for good
// starts from the first message.
func TestRelayResumesAfterAcknowledgedCursor(t *testing.T) {
	sender := uuid.New()
	msg := func(seq int64) marketclient.Inbound {
		return marketclient.Inbound{Seq: seq, Header: envelope.Header{MessageID: uuid.New(), SenderMemberID: sender,
			GrantID: uuid.New(), Operation: siteconf.OpStatus}}
	}
	for _, test := range []struct {
		name      string
		cursor    int64
		cursorErr error
		want      []int64
	}{
		{name: "resume", cursor: 2, want: []int64{3}},
		{name: "older market", cursorErr: &marketclient.RejectedError{Status: 404, Code: "not_found"}, want: []int64{1, 2, 3}},
	} {
		t.Run(test.name, func(t *testing.T) {
			market := &fakeMarket{inbox: []marketclient.Inbound{msg(1), msg(2), msg(3)}, cursor: test.cursor,
				cursorErr: test.cursorErr}
			supply := &seqSupply{}
			r := New(Config{StateDir: t.TempDir()}, nil, market, supply, slog.New(slog.NewTextHandler(io.Discard, nil)))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() { r.relayLoop(ctx); close(done) }()
			for len(supply.handled()) < len(test.want) && ctx.Err() == nil {
				time.Sleep(20 * time.Millisecond)
			}
			cancel()
			<-done
			if got := supply.handled(); !slices.Equal(got, test.want) {
				t.Fatalf("handled sequences = %v, want %v", got, test.want)
			}
		})
	}
}
