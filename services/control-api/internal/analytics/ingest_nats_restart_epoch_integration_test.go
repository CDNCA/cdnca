package analytics

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestNATSIngestConsumerPreservesEpochAcrossServerRestart(t *testing.T) {
	binary, store, connection, config, stop := epochTestFixture(t)
	js, err := connection.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	before, err := js.ConsumerInfo(config.Stream, config.Durable)
	if err != nil {
		t.Fatal(err)
	}
	streamBefore, err := js.StreamInfo(config.Stream)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := consumer.stateStore.Get("consumer_created")
	if err != nil {
		t.Fatal(err)
	}
	if string(entry.Value()) != before.Created.UTC().Format(time.RFC3339Nano) {
		t.Fatal("initial epoch does not match initial consumer INFO")
	}
	var metadata struct {
		Created time.Time `json:"created"`
	}
	var metadataPath string
	err = filepath.WalkDir(store, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Name() == "meta.inf" && filepath.Base(filepath.Dir(path)) == config.Durable {
			if metadataPath != "" {
				return fmt.Errorf("duplicate consumer metadata")
			}
			metadataPath = path
		}
		return nil
	})
	if err != nil || metadataPath == "" {
		t.Fatalf("locate private consumer metadata: path=%q err=%v", metadataPath, err)
	}
	data, err := os.ReadFile(metadataPath)
	if err != nil || json.Unmarshal(data, &metadata) != nil || metadata.Created.IsZero() {
		t.Fatalf("read private consumer metadata: %v", err)
	}
	t.Logf("server=%s initial_INFO=%s persisted_meta=%s delta=%s KV=%s",
		connection.ConnectedServerVersion(), before.Created.Format(time.RFC3339Nano),
		metadata.Created.Format(time.RFC3339Nano), metadata.Created.Sub(before.Created), entry.Value())
	if !metadata.Created.Equal(before.Created) {
		t.Errorf("initial consumer INFO differs from persisted creation epoch")
	}
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}
	connection.Close()
	stop()

	for restart := 1; restart <= 2; restart++ {
		url, stopServer := startEpochTestServer(t, binary, store)
		connection, err := nats.Connect(url, nats.NoReconnect(), nats.Timeout(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(connection.Close)
		js, err := connection.JetStream()
		if err != nil {
			t.Fatal(err)
		}
		after, err := js.ConsumerInfo(config.Stream, config.Durable)
		if err != nil {
			t.Fatal(err)
		}
		streamAfter, err := js.StreamInfo(config.Stream)
		if err != nil || !streamAfter.Created.Equal(streamBefore.Created) {
			t.Fatalf("stream epoch changed: %v", err)
		}
		consumer, openErr := NewNATSIngestConsumer(connection, config)
		t.Logf("restart=%d INFO=%s matches_original=%t open_error=%v", restart,
			after.Created.Format(time.RFC3339Nano), after.Created.Equal(before.Created), openErr)
		if !after.Created.Equal(before.Created) {
			t.Errorf("consumer creation epoch changed across normal restart")
		}
		if openErr != nil {
			t.Errorf("normal NATS restart must preserve the strict analytics epoch: %v", openErr)
		} else if err := consumer.Close(); err != nil {
			t.Error(err)
		}
		connection.Close()
		stopServer()
	}
}

func TestNATSIngestConsumerRejectsRecreatedConsumer(t *testing.T) {
	_, _, connection, config, _ := epochTestFixture(t)
	consumer, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}
	js, err := connection.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	if err := js.DeleteConsumer(config.Stream, config.Durable); err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddConsumer(config.Stream, expectedConsumer(config)); err != nil {
		t.Fatal(err)
	}
	consumer, err = NewNATSIngestConsumer(connection, config)
	if err == nil {
		_ = consumer.Close()
		t.Fatal("a genuinely recreated consumer must not inherit the previous epoch")
	}
	if !strings.Contains(err.Error(), "analytics ingest consumer epoch: changed from") {
		t.Fatalf("unexpected rejection: %v", err)
	}
	t.Logf("recreated consumer rejected without epoch mutation: %v", err)
}

func TestNATSIngestConsumerPreservesEpochAfterRestartAndConfigUpdate(t *testing.T) {
	binary, store, connection, config, stop := epochTestFixture(t)
	js, err := connection.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	before, err := js.ConsumerInfo(config.Stream, config.Durable)
	if err != nil {
		t.Fatal(err)
	}
	streamBefore, err := js.StreamInfo(config.Stream)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}
	connection.Close()
	stop()

	for restart := 1; restart <= 2; restart++ {
		url, stopServer := startEpochTestServer(t, binary, store)
		connection, err := nats.Connect(url, nats.NoReconnect(), nats.Timeout(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(connection.Close)
		js, err := connection.JetStream()
		if err != nil {
			t.Fatal(err)
		}
		after, err := js.ConsumerInfo(config.Stream, config.Durable)
		if err != nil {
			t.Fatal(err)
		}
		streamAfter, err := js.StreamInfo(config.Stream)
		if err != nil || !streamAfter.Created.Equal(streamBefore.Created) {
			t.Fatalf("stream creation epoch changed after restart/config update: %v", err)
		}
		consumer, openErr := NewNATSIngestConsumer(connection, config)
		t.Logf("server=%s restart=%d after_update=%t initial_INFO=%s current_INFO=%s open_error=%v",
			connection.ConnectedServerVersion(), restart, restart == 2,
			before.Created.Format(time.RFC3339Nano), after.Created.Format(time.RFC3339Nano), openErr)
		if !after.Created.Equal(before.Created) {
			t.Error("consumer creation epoch changed after restart and config update")
		}
		if openErr != nil {
			t.Errorf("restart and config update must preserve the strict analytics epoch: %v", openErr)
		} else if err := consumer.Close(); err != nil {
			t.Error(err)
		}
		if restart == 1 {
			config.AckWait += time.Second
			updated, err := js.UpdateConsumer(config.Stream, expectedConsumer(config))
			if err != nil || updated == nil {
				t.Fatalf("update private consumer AckWait: %v", err)
			}
			// Some server versions return their cached recovery response on update;
			// verify the effective configuration with a separate INFO request.
			t.Logf("update response AckWait=%s Created=%s", updated.Config.AckWait, updated.Created.Format(time.RFC3339Nano))
			updated, err = js.ConsumerInfo(config.Stream, config.Durable)
			if err != nil {
				t.Fatal(err)
			}
			if updated.Config.AckWait != config.AckWait || !updated.Created.Equal(before.Created) {
				t.Errorf("consumer config update: AckWait=%s want=%s Created=%s want=%s", updated.Config.AckWait,
					config.AckWait, updated.Created.Format(time.RFC3339Nano), before.Created.Format(time.RFC3339Nano))
			}
			streamConfig := streamAfter.Config
			streamConfig.Description = "restart epoch regression"
			if _, err := js.UpdateStream(&streamConfig); err != nil {
				t.Fatal(err)
			}
		}
		connection.Close()
		stopServer()
	}
}

func epochTestFixture(t *testing.T) (string, string, *nats.Conn, JetStreamConfig, func()) {
	t.Helper()
	binary := os.Getenv("ANALYTICS_NATS_RESTART_SERVER")
	if binary == "" {
		t.Skip("set ANALYTICS_NATS_RESTART_SERVER to a real NATS server executable")
	}
	info, err := os.Lstat(binary)
	if !filepath.IsAbs(binary) || err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		t.Fatal("ANALYTICS_NATS_RESTART_SERVER must name an absolute regular executable")
	}
	store := t.TempDir()
	url, stop := startEpochTestServer(t, binary, store)
	connection, err := nats.Connect(url, nats.NoReconnect(), nats.Timeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	config := DefaultJetStreamConfig()
	config.StreamMaxBytes = 16 << 20
	config.IsolationMaxBytes = 16 << 20
	js, err := connection.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.CreateKeyValue(&nats.KeyValueConfig{
		Bucket: isolationEvidenceBucketName(config), History: 1,
		MaxValueSize: isolationEvidenceMaxValueSize, MaxBytes: config.IsolationMaxBytes,
		Storage: nats.FileStorage, Replicas: config.Replicas,
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := EnsureIngestJetStream(ctx, connection, config); err != nil {
		t.Fatal(err)
	}
	return binary, store, connection, config, stop
}

func startEpochTestServer(t *testing.T, binary, store string) (string, func()) {
	t.Helper()
	logs := t.TempDir()
	logFile, err := os.OpenFile(filepath.Join(logs, "server.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-js", "-sd", store, "-a", "127.0.0.1", "-p", "-1", "--ports_file_dir", logs)
	command.Stdout, command.Stderr = logFile, logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = command.Wait(); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				_ = command.Process.Kill()
				<-done
				t.Error("private NATS server did not stop within ten seconds")
			}
			_ = logFile.Close()
			if waitErr != nil {
				t.Errorf("private NATS server exit: %v", waitErr)
			}
		})
	}
	t.Cleanup(stop)
	portsPath := filepath.Join(logs, fmt.Sprintf("%s_%d.ports", filepath.Base(binary), command.Process.Pid))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var ports struct {
			NATS []string `json:"nats"`
		}
		if data, readErr := os.ReadFile(portsPath); readErr == nil && json.Unmarshal(data, &ports) == nil && len(ports.NATS) == 1 {
			if !strings.HasPrefix(ports.NATS[0], "nats://127.0.0.1:") {
				t.Fatalf("private server exposed unexpected listener: %q", ports.NATS[0])
			}
			return ports.NATS[0], stop
		}
		select {
		case <-done:
			t.Fatalf("private NATS server exited before readiness: %v", waitErr)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("private NATS server did not publish its random loopback port")
	return "", stop
}
