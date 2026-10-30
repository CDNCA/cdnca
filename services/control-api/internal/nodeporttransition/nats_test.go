package nodeporttransition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type statusRuntimeTestStore struct {
	memoryStore
	failOnce bool
	applied  chan StatusReport
}

func (s *statusRuntimeTestStore) ApplyStatus(_ context.Context, report StatusReport) (Transition, error) {
	if s.failOnce {
		s.failOnce = false
		return Transition{}, errors.New("temporary database outage")
	}
	s.applied <- report
	return s.transition, nil
}

func TestStatusConsumerContinuesAfterPermanentRejectionAndRetriesTemporaryFailure(t *testing.T) {
	for _, temporary := range []bool{false, true} {
		t.Run(fmt.Sprint(temporary), func(t *testing.T) {
			connection, js := newPortTransitionTestNATS(t)
			old := Endpoint{Address: "gateway.example.com:7443", ServerName: "gateway.example.com", ListenAddress: "0.0.0.0:7443"}
			next := Endpoint{Address: "gateway.example.com:8443", ServerName: old.ServerName, ListenAddress: "0.0.0.0:8443"}
			store := &statusRuntimeTestStore{memoryStore: memoryStore{transition: Transition{ID: uuid.New(), NodeID: uuid.New(), Revision: 1, State: StateSwitching, OldEndpoint: old, NewEndpoint: next, CertificateSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}, failOnce: temporary, applied: make(chan StatusReport, 1)}
			config := DefaultNATSRuntimeConfig()
			config.FetchTimeout = 100 * time.Millisecond
			config.RetryDelay = 25 * time.Millisecond
			runtime, err := NewNATSRuntime(&PostgresStore{}, NewService(store, time.Now, uuid.New), connection, config, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- runtime.runStatuses(ctx) }()
			defer func() {
				cancel()
				select {
				case <-result:
				case <-time.After(time.Second):
					t.Error("consumer did not stop")
				}
			}()
			if !temporary {
				if _, err := js.Publish(portTransitionStatusPrefix+".invalid", []byte("invalid proto")); err != nil {
					t.Fatal(err)
				}
			}
			status := &agentv1.GatewayPortTransitionStatus{Schema: agentv1.GatewayPortTransitionSchema_GATEWAY_PORT_TRANSITION_SCHEMA_V1, TransitionId: store.transition.ID.String(), NodeId: store.transition.NodeID.String(), Revision: 1, StatusRevision: 1, State: agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_SWITCHED, ActiveEndpoint: &agentv1.GatewayEndpoint{Address: next.Address, ServerName: next.ServerName}, CertificateSha256: store.transition.CertificateSHA256, Event: &commonv1.EventMetadata{EventId: uuid.NewString(), OccurredTime: timestamppb.Now()}}
			payload, err := proto.Marshal(status)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := js.Publish(fmt.Sprintf("%s.%s_%s_1", portTransitionStatusPrefix, status.NodeId, status.TransitionId), payload); err != nil {
				t.Fatal(err)
			}
			select {
			case <-store.applied:
			case err := <-result:
				result <- err
				t.Fatalf("consumer exited before applying next valid status: %v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("status was not applied")
			}
		})
	}
}

func newPortTransitionTestNATS(t *testing.T) (*nats.Conn, nats.JetStreamContext) {
	t.Helper()
	binary := os.Getenv("NATS_SERVER_BIN")
	if binary == "" {
		t.Skip("NATS_SERVER_BIN is required for real JetStream verification")
	}
	directory := t.TempDir()
	logFile, err := os.Create(filepath.Join(directory, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-js", "-sd", filepath.Join(directory, "store"), "-a", "127.0.0.1", "-p", "-1", "--ports_file_dir", directory)
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-done
			t.Error("NATS did not stop")
		}
		_ = logFile.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		matches, _ := filepath.Glob(filepath.Join(directory, "*.ports"))
		for _, path := range matches {
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var ports struct {
				NATS []string `json:"nats"`
			}
			if json.Unmarshal(raw, &ports) != nil || len(ports.NATS) != 1 {
				continue
			}
			connection, err := nats.Connect(ports.NATS[0], nats.Timeout(time.Second))
			if err != nil {
				continue
			}
			t.Cleanup(connection.Close)
			js, err := connection.JetStream()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := js.AddStream(&nats.StreamConfig{Name: portTransitionStatusStream, Subjects: []string{portTransitionStatusPrefix + ".*"}}); err != nil {
				t.Fatal(err)
			}
			return connection, js
		}
		time.Sleep(10 * time.Millisecond)
	}
	raw, _ := os.ReadFile(filepath.Join(directory, "server.log"))
	t.Fatalf("NATS did not become ready: %s", raw)
	return nil, nil
}

func TestStatusRuntimeDeadlineStopsBothWorkers(t *testing.T) {
	connection, _ := newPortTransitionTestNATS(t)
	config := DefaultNATSRuntimeConfig()
	config.PollInterval = 10 * time.Millisecond
	runtime, err := NewNATSRuntime(&PostgresStore{}, NewService(&memoryStore{}, time.Now, uuid.New), connection, config, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- runtime.Run(ctx) }()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime kept a worker after deadline")
	}
}
