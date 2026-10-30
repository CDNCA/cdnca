//go:build integration

package edgeoutbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

// Faults affect only the fixture schema or the connection running its trigger.
// This verifies real pgx errors and durable outbox/NATS state, not a server restart.
func TestPostgresJetStreamRunRecovery(t *testing.T) {
	databaseURL, natsURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("CDNCA_TEST_NATS_URL")
	if databaseURL == "" || natsURL == "" {
		t.Skip("TEST_DATABASE_URL and CDNCA_TEST_NATS_URL are required")
	}
	fixture := newIntegrationFixture(t, databaseURL)
	defer fixture.close(t)
	connection, err := nats.Connect(natsURL, nats.Name("edge-outbox-recovery-integration"), nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	jetstream, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		status        string
		fault         string
		publishFails  int
		minAttempts   int
		maxAttempts   int
		wantCalls     int
		wantDuplicate int
	}{
		{"claim recovery", "publishing", "RAISE EXCEPTION 'injected recovery' USING ERRCODE = '57P03';", 0, 1, 1, 1, 0},
		// Termination can race the commit acknowledgement; a committed claim is reclaimed after its lease.
		{"claim connection terminated", "publishing", "PERFORM pg_terminate_backend(pg_backend_pid());", 0, 1, 2, 1, 0},
		{"puback finalize recovery", "published", "RAISE EXCEPTION 'injected recovery' USING ERRCODE = '57P03';", 0, 2, 2, 2, 1},
		{"failure finalize recovery", "failed", "RAISE EXCEPTION 'injected recovery' USING ERRCODE = '57P03';", 1, 2, 2, 2, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deployment := fixture.seedDeployment(t, uuid.New())
			stream := "EDGE_RECOVERY_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			if _, err := jetstream.AddStream(&nats.StreamConfig{
				Name: stream, Subjects: []string{deployment.subject}, Retention: nats.LimitsPolicy,
				Storage: nats.FileStorage, Duplicates: time.Minute,
			}); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = jetstream.DeleteStream(stream) }()
			_, err := fixture.pool.Exec(t.Context(), fmt.Sprintf(`
				CREATE SEQUENCE recovery_fault_count;
				CREATE FUNCTION recovery_fault() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN
					IF NEW.status = '%s' AND nextval('recovery_fault_count') = 1 THEN
						%s
					END IF;
					RETURN NEW;
				END $$;
				CREATE TRIGGER recovery_fault BEFORE UPDATE ON edge_command_outbox
				FOR EACH ROW EXECUTE FUNCTION recovery_fault();`, test.status, test.fault))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := fixture.pool.Exec(context.Background(), `
					DROP TRIGGER recovery_fault ON edge_command_outbox;
					DROP FUNCTION recovery_fault();
					DROP SEQUENCE recovery_fault_count;`); err != nil {
					t.Error(err)
				}
			}()
			config := DefaultConfig()
			config.Stream = stream
			config.BatchSize = 1
			config.OperationTimeout = time.Second
			config.LeaseTimeout = 3 * time.Second
			config.PollInterval = 10 * time.Millisecond
			config.BaseBackoff = 10 * time.Millisecond
			config.MaxBackoff = 40 * time.Millisecond
			messages := &recoveryMessages{
				delegate: &natsPublisher{jetstream: jetstream}, remainingFailures: test.publishFails,
			}
			publisher, err := newPublisher(&postgresStore{pool: fixture.pool}, messages, config)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			done := make(chan error, 1)
			go func() { done <- publisher.Run(ctx) }()
			defer cancel()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				var status string
				if err := fixture.pool.QueryRow(ctx, `SELECT status FROM edge_command_outbox WHERE id=$1`, deployment.outboxID).Scan(&status); err != nil {
					cancel()
					<-done
					t.Fatal(err)
				}
				if status == "published" {
					break
				}
				select {
				case err := <-done:
					t.Fatalf("publisher stopped before recovery: %v", err)
				case <-ticker.C:
				case <-ctx.Done():
					cancel()
					<-done
					t.Fatal("publisher did not recover before deadline")
				}
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("publisher shutdown = %v", err)
			}
			var attempts int
			if err := fixture.pool.QueryRow(t.Context(), `SELECT publish_attempts FROM edge_command_outbox WHERE id=$1`, deployment.outboxID).Scan(&attempts); err != nil {
				t.Fatal(err)
			}
			if attempts < test.minAttempts || attempts > test.maxAttempts {
				t.Fatalf("publish attempts=%d, want %d..%d", attempts, test.minAttempts, test.maxAttempts)
			}
			assertOutboxState(t, fixture.pool, deployment.outboxID, "published", attempts, true, "")
			if len(messages.ids) != test.wantCalls || messages.duplicates != test.wantDuplicate {
				t.Fatalf("publish calls=%d duplicates=%d, want %d/%d", len(messages.ids), messages.duplicates, test.wantCalls, test.wantDuplicate)
			}
			for _, id := range messages.ids {
				if id != deployment.eventID.String() {
					t.Fatal("recovery changed immutable message identity")
				}
			}
			if count := streamMessageCount(t, jetstream, stream); count != 1 {
				t.Fatalf("stream messages=%d, want one stored message", count)
			}
			assertPublishedMessage(t, jetstream, stream, deployment)
		})
	}
}

type recoveryMessages struct {
	delegate          messagePublisher
	remainingFailures int
	ids               []string
	duplicates        int
}

func (p *recoveryMessages) publish(ctx context.Context, subject string, payload []byte, messageID, expectedStream string) (publishAck, error) {
	p.ids = append(p.ids, messageID)
	if p.remainingFailures > 0 {
		p.remainingFailures--
		return publishAck{}, nats.ErrTimeout
	}
	ack, err := p.delegate.publish(ctx, subject, payload, messageID, expectedStream)
	if ack.duplicate {
		p.duplicates++
	}
	return ack, err
}
