package firewalldispatch

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/securitycoordmetrics"
	"google.golang.org/protobuf/proto"
)

func TestDispatcherExportsPublishPubACKAndTerminalMetrics(t *testing.T) {
	claim := validClaim(t, StatePending, 0)
	tx := &fakeTx{claims: []claimedCommand{claim}}
	messages := &fakeMessages{ack: &publishAck{stream: CommandStream, sequence: 7, duplicate: true}}
	dispatcher := testDispatcher(t, tx, messages)
	if _, err := dispatcher.DispatchBatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot := dispatcher.MetricsSnapshot().Firewall
	if snapshot.Published != 1 || snapshot.PubACKDuplicates != 1 || snapshot.Retryable != 0 {
		t.Fatalf("publish metrics = %+v", snapshot)
	}

	status := validStatus(t, withState(claim, StatePublished))
	status.Operation = status.GetOperation()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	ackTx := &metricsFakeTx{fakeTx: &fakeTx{loaded: withState(claim, StatePublished), ackDisposition: AckSettled}, outcome: securitycoordmetrics.GlobalActive}
	dispatcher.db = metricsFakeDB{tx: ackTx}
	if _, err := dispatcher.HandleStatus(context.Background(), payload); err != nil {
		t.Fatal(err)
	}
	snapshot = dispatcher.MetricsSnapshot().Firewall
	if snapshot.ACKSettled != 1 || snapshot.Applied != 1 || snapshot.GlobalActive != 1 {
		t.Fatalf("ACK metrics = %+v", snapshot)
	}
}

type metricsFakeDB struct{ tx dispatchTx }

func (db metricsFakeDB) begin(context.Context) (dispatchTx, error) { return db.tx, nil }

type metricsFakeTx struct {
	*fakeTx
	outcome securitycoordmetrics.GlobalOutcome
}

func (tx *metricsFakeTx) securityCoordinationOutcome() securitycoordmetrics.GlobalOutcome {
	return tx.outcome
}
