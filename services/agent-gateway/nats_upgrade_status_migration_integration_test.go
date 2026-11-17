package gateway

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// Real-JetStream replay: AGENT_DEPLOYMENT_STATUS held 8391 deployment statuses
// and no legacy upgrade.<node> message. The first v2 upgrade status publish must succeed in
// one call; before the fix it returned "migration in progress" twice and the node's session
// dropped each time.
func TestUpgradeStatusFirstPublishOverUnrelatedHistoryOnJetStream(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	connection, err := nats.Connect(natsURL, nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	// Closed after the stream cleanup below (cleanups run last-registered first); a deferred
	// Close ran before it and left the stream behind for the next tests.
	t.Cleanup(connection.Close)
	js, err := connection.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.StreamInfo(UpgradeStatusStream); !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatalf("task-owned NATS already contains stream %s (%v); refusing to mutate or reuse it", UpgradeStatusStream, err)
	}
	prefix := "cdnca.agent.deployment-status"
	if _, err := js.AddStream(&nats.StreamConfig{Name: UpgradeStatusStream, Storage: nats.FileStorage,
		Subjects: []string{prefix + ".generic-v2.*.*", UpgradeStatusSubjectPrefix + ".*", UpgradeStatusV2SubjectPrefix + ".*",
			UpgradeStatusProofSubjectPrefix + ".>"}, Duplicates: 10 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(UpgradeStatusStream) })

	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	for sequence := 1; sequence <= 8391; sequence++ {
		if _, err := js.PublishAsync(fmt.Sprintf("%s.generic-v2.%s.%d", prefix, command.NodeID, sequence), []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(30 * time.Second):
		t.Fatal("seeding the deployment status history timed out")
	}

	bus, err := NewNATSUpgradeCommandBus(connection, DefaultNATSCommandBusConfig())
	if err != nil {
		t.Fatal(err)
	}
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if err != nil || publication.Stream != UpgradeStatusStream || publication.Sequence <= 8391 {
		t.Fatalf("first status over 8391 unrelated messages = (%+v, %v)", publication, err)
	}
	next := distinctUpgradeStatusRecord(t, status, 2)
	if second, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, next.Encoded); err != nil ||
		second.Sequence <= publication.Sequence {
		t.Fatalf("second status = (%+v, %v)", second, err)
	}
	progress, found, err := bus.loadUpgradeStatusMigrationState(t.Context())
	if err != nil || !found || !progress.Complete || progress.HorizonSequence != 8391 {
		t.Fatalf("migration progress = (%+v, found=%t, err=%v)", progress, found, err)
	}
	// A legacy upgrade.<node> message from an older gateway must still route to the scan.
	if _, err := js.Publish(UpgradeStatusSubjectPrefix+"."+command.NodeID, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if _, present, err := bus.legacyUpgradeStatusHorizon(t.Context()); err != nil || !present {
		t.Fatalf("legacy subject after an old-gateway publish = (present=%t, %v)", present, err)
	}
}
