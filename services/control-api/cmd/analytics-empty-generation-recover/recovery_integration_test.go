//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

func TestRecoveryFsyncFailureNeverCommits(t *testing.T) {
	for _, failingCall := range []int{1, 2} {
		t.Run(fmt.Sprint(failingCall), func(t *testing.T) {
			pool, nc, p, dir := recoveryTestFixture(t)
			original := syncRecoveryFile
			t.Cleanup(func() { syncRecoveryFile = original })
			calls := 0
			syncRecoveryFile = func(file *os.File) error {
				calls++
				if calls == failingCall {
					return errors.New("injected fsync failure")
				}
				return original(file)
			}
			if err := recoverEmptyGeneration(t.Context(), pool, nc, p, dir, "apply", nil, nil); err == nil || !strings.Contains(err.Error(), "sync_failed") {
				t.Fatalf("fsync failure: %v", err)
			}
			syncRecoveryFile = original
			var count int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM analytics_history_streams WHERE retired_at IS NULL AND revision=1`).Scan(&count); err != nil || count != 1 {
				t.Fatal("database changed despite failed journal fsync")
			}
			if _, done, err := recoveryBrokerState(nc, p); err != nil || done {
				t.Fatalf("broker changed despite failed journal fsync: %v", err)
			}
			if err := recoverEmptyGeneration(t.Context(), pool, nc, p, dir, "resume", nil, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecoveryPostgresResumeAndRefusal(t *testing.T) {
	for _, failure := range []string{"", "prepared", "before_pg_commit", "after_pg_commit", "before_kv_cas", "after_kv_cas"} {
		t.Run("resume_"+failure, func(t *testing.T) {
			pool, nc, p, dir := recoveryTestFixture(t)
			if err := recoverEmptyGeneration(t.Context(), pool, nc, p, dir, "check", nil, nil); err != nil {
				t.Fatal(err)
			}
			if files, err := os.ReadDir(dir); err != nil || len(files) != 0 {
				t.Fatalf("check created a journal: %v", err)
			}
			injected := errors.New("injected interruption")
			err := recoverEmptyGeneration(t.Context(), pool, nc, p, dir, "apply", nil, func(stage string) error {
				if stage == failure {
					return injected
				}
				return nil
			})
			if failure != "" && !errors.Is(err, injected) || failure == "" && err != nil {
				t.Fatalf("apply: %v", err)
			}
			if err := recoverEmptyGeneration(t.Context(), pool, nc, p, dir, "resume", nil, nil); err != nil {
				t.Fatal(err)
			}
			if err := recoverEmptyGeneration(t.Context(), pool, nc, p, dir, "resume", nil, nil); err != nil {
				t.Fatalf("idempotent resume: %v", err)
			}
			var total, retired int
			if err := pool.QueryRow(t.Context(), `SELECT count(*),count(retired_at) FROM analytics_history_streams`).Scan(&total, &retired); err != nil || total != 2 || retired != 1 {
				t.Fatalf("history count=%d retired=%d err=%v", total, retired, err)
			}
			var epoch string
			if err := pool.QueryRow(t.Context(), `SELECT consumer_created_unix_nano::text FROM analytics_history_streams WHERE history_epoch=$1`, p.OldHistory).Scan(&epoch); err != nil || epoch != fmt.Sprint(p.OldConsumerEpoch) {
				t.Fatal("old identity changed")
			}
			if _, done, err := recoveryBrokerState(nc, p); err != nil || !done {
				t.Fatalf("final broker: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "completed.json")); err != nil {
				t.Fatal(err)
			}
			if recoverEmptyGeneration(t.Context(), pool, nc, p, dir, "apply", nil, nil) == nil {
				t.Fatal("repeat apply was allowed")
			}
		})
	}
	for _, problem := range []string{"facts", "queue", "kv", "journal_permissions", "journal_exists", "unsafe_role", "cas_drift", "plan_drift", "fact_race_after_commit"} {
		t.Run("refuse_"+problem, func(t *testing.T) {
			pool, nc, p, dir := recoveryTestFixture(t)
			js, _ := nc.JetStream()
			kv, _ := js.KeyValue(p.StateBucket)
			var hook func(string) error
			switch problem {
			case "facts":
				if _, err := pool.Exec(t.Context(), `INSERT INTO analytics_history_recoveries(recovery_id,history_epoch,reason,scheduled_at,created_at,updated_at) VALUES($1,$2,'test',now(),now(),now())`, uuid.NewString(), p.OldHistory); err != nil {
					t.Fatal(err)
				}
			case "queue":
				if _, err := js.Publish("cdnca.analytics.ingest.v1.test", []byte("test")); err != nil {
					t.Fatal(err)
				}
			case "kv":
				if _, err := kv.Put("consumer_created", []byte("unexpected")); err != nil {
					t.Fatal(err)
				}
			case "journal_permissions":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "journal_exists":
				if err := writeRecoveryJournal(filepath.Join(dir, "prepared.json"), map[string]string{"unknown": "existing"}); err != nil {
					t.Fatal(err)
				}
			case "unsafe_role":
				config := pool.Config()
				delete(config.ConnConfig.RuntimeParams, "role")
				unsafePool, err := pgxpool.NewWithConfig(t.Context(), config)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(unsafePool.Close)
				pool = unsafePool
				var super bool
				if err := pool.QueryRow(t.Context(), `SELECT rolsuper FROM pg_roles WHERE rolname=current_user`).Scan(&super); err != nil || !super {
					t.Fatalf("unsafe-role fixture is not superuser: %v", err)
				}
			case "cas_drift":
				hook = func(stage string) error {
					if stage == "before_kv_cas" {
						_, err := kv.Put("consumer_created", []byte(epochRecoveryTime(p.OldConsumerEpoch).Format(time.RFC3339Nano)))
						return err
					}
					return nil
				}
			case "plan_drift":
				if err := recoverEmptyGeneration(t.Context(), pool, nc, p, dir, "apply", nil, func(string) error { return errors.New("stop") }); err == nil {
					t.Fatal("missing interruption")
				}
				p.SourceCommit = strings.Repeat("f", 40)
				if err := recoverEmptyGeneration(t.Context(), pool, nc, p, dir, "resume", nil, nil); err == nil {
					t.Fatal("resumed a different plan")
				}
			case "fact_race_after_commit":
				hook = func(stage string) error {
					if stage != "after_pg_commit" {
						return nil
					}
					_, err := pool.Exec(t.Context(), `INSERT INTO analytics_history_recoveries(recovery_id,history_epoch,reason,scheduled_at,created_at,updated_at) SELECT $1,history_epoch,'test',now(),now(),now() FROM analytics_history_streams WHERE retired_at IS NULL`, uuid.NewString())
					return err
				}
			}
			if err := recoverEmptyGeneration(t.Context(), pool, nc, p, dir, "apply", nil, hook); err == nil {
				t.Fatal("unsafe recovery succeeded")
			}
			var count int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM analytics_history_streams`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 1
			if problem == "cas_drift" || problem == "fact_race_after_commit" {
				want = 2
			}
			if count != want {
				t.Fatalf("history count=%d want=%d", count, want)
			}
			if problem == "fact_race_after_commit" {
				entry, err := kv.Get("consumer_created")
				if err != nil || entry.Revision() != 2 {
					t.Fatal("KV changed after competing fact write")
				}
			}
		})
	}
	t.Run("fact_write_blocked_during_prepare", func(t *testing.T) {
		pool, nc, p, dir := recoveryTestFixture(t)
		err := recoverEmptyGeneration(t.Context(), pool, nc, p, dir, "apply", nil, func(stage string) error {
			if stage != "prepared" {
				return nil
			}
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			_, err := pool.Exec(ctx, `INSERT INTO analytics_history_recoveries(recovery_id,history_epoch,reason,scheduled_at,created_at,updated_at) VALUES($1,$2,'blocked',now(),now(),now())`, uuid.NewString(), p.OldHistory)
			if err == nil {
				return errors.New("concurrent fact write was not blocked")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func recoveryTestFixture(t *testing.T) (*pgxpool.Pool, *nats.Conn, recoveryPlan, string) {
	t.Helper()
	pool := recoveryTestDatabase(t)
	nc := startRecoveryTestBroker(t)
	js, err := nc.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	s, err := js.AddStream(&nats.StreamConfig{Name: "ANALYTICS_INGEST_V1", Subjects: []string{"cdnca.analytics.ingest.v1.*"}, Storage: nats.FileStorage, Retention: nats.WorkQueuePolicy, MaxConsumers: 1})
	if err != nil {
		t.Fatal(err)
	}
	c, err := js.AddConsumer(s.Config.Name, &nats.ConsumerConfig{Durable: "control_api_analytics_ingest_v1", AckPolicy: nats.AckExplicitPolicy, FilterSubject: "cdnca.analytics.ingest.v1.*"})
	if err != nil {
		t.Fatal(err)
	}
	p := recoveryPlan{Schema: "cdnca.analytics-empty-recovery/v1", InstallationID: uuid.NewString(), OldHistory: uuid.NewString(), Stream: s.Config.Name, Durable: c.Name,
		StreamEpoch: uint64(s.Created.UnixNano()), OldConsumerEpoch: uint64(c.Created.UnixNano()) - 1, NewConsumerEpoch: uint64(c.Created.UnixNano()),
		NATSVersion: nc.ConnectedServerVersion(), StateBucket: "AISTATE_2dcd3c381ead92f3", StreamRevision: 1, ConsumerRevision: 2,
		Current: "releases/" + strings.Repeat("a", 64), SourceCommit: strings.Repeat("b", 40), ControlVersion: "1.0.5", EnvSHA256: strings.Repeat("c", 64)}
	for _, item := range []struct {
		subject string
		target  *string
	}{
		{"$JS.API.STREAM.INFO." + p.Stream, &p.StreamConfigSHA256},
		{"$JS.API.CONSUMER.INFO." + p.Stream + "." + p.Durable, &p.ConsumerConfigSHA256},
	} {
		message, err := nc.Request(item.subject, []byte("{}"), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		var raw struct {
			Config json.RawMessage `json:"config"`
		}
		if err := json.Unmarshal(message.Data, &raw); err != nil {
			t.Fatal(err)
		}
		var config map[string]any
		decoder := json.NewDecoder(bytes.NewReader(raw.Config))
		decoder.UseNumber()
		if err := decoder.Decode(&config); err != nil {
			t.Fatal(err)
		}
		*item.target = digestRecoveryJSON(config)
	}
	for _, bucket := range []string{p.StateBucket, "AILEASE_2dcd3c381ead92f3", "AIEVIDENCE_2dcd3c381ead92f3"} {
		store, err := js.CreateKeyValue(&nats.KeyValueConfig{Bucket: bucket, Storage: nats.FileStorage, History: 1})
		if err != nil {
			t.Fatal(err)
		}
		if bucket == p.StateBucket {
			if _, err := store.Create("stream_created", []byte(epochRecoveryTime(p.StreamEpoch).Format(time.RFC3339Nano))); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Create("consumer_created", []byte(epochRecoveryTime(p.OldConsumerEpoch).Format(time.RFC3339Nano))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO control_installation_entitlement(singleton,installation_id) VALUES(true,$1)`, p.InstallationID); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), `INSERT INTO analytics_history_streams(installation_id,nats_domain,stream_name,durable_name,stream_created_unix_nano,consumer_created_unix_nano,history_epoch,
		history_start_sequence,history_start_at,legacy_baseline_kind,broker_consumer_ack_floor,broker_stream_ack_floor,prepared_stream_floor,revision,last_reconciled_at,created_at,updated_at)
		VALUES($1,'',$2,$3,$4,$5,$6,1,$7,'none',0,0,0,1,$8,$8,$8)`, p.InstallationID, p.Stream, p.Durable, p.StreamEpoch, p.OldConsumerEpoch, p.OldHistory, epochRecoveryTime(p.OldConsumerEpoch), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return pool, nc, p, dir
}

func recoveryTestDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	name := "empty_recovery_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier+"; CREATE ROLE "+identifier+" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE; DROP ROLE "+identifier); err != nil {
			t.Error(err)
		}
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = name
	migration, err := pgxpool.NewWithConfig(t.Context(), config.Copy())
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(t.Context(), migration, "up"); err != nil {
		migration.Close()
		t.Fatal(err)
	}
	if _, err := migration.Exec(t.Context(), "GRANT USAGE ON SCHEMA "+identifier+" TO "+identifier+"; GRANT ALL ON ALL TABLES IN SCHEMA "+identifier+" TO "+identifier+"; GRANT ALL ON ALL SEQUENCES IN SCHEMA "+identifier+" TO "+identifier+"; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA "+identifier+" TO "+identifier); err != nil {
		migration.Close()
		t.Fatal(err)
	}
	migration.Close()
	config.ConnConfig.RuntimeParams["role"] = name
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func startRecoveryTestBroker(t *testing.T) *nats.Conn {
	t.Helper()
	binary := os.Getenv("ANALYTICS_NATS_RESTART_SERVER")
	if binary == "" {
		t.Skip("ANALYTICS_NATS_RESTART_SERVER required")
	}
	dir := t.TempDir()
	log, err := os.OpenFile(filepath.Join(dir, "server.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-js", "-sd", filepath.Join(dir, "store"), "-a", "127.0.0.1", "-p", "-1", "--ports_file_dir", dir)
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	var once sync.Once
	t.Cleanup(func() {
		once.Do(func() {
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(10 * time.Second):
				_ = command.Process.Kill()
				<-done
				t.Error("private NATS did not stop")
			}
			log.Close()
		})
	})
	ports := filepath.Join(dir, fmt.Sprintf("%s_%d.ports", filepath.Base(binary), command.Process.Pid))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var value struct {
			NATS []string `json:"nats"`
		}
		if data, err := os.ReadFile(ports); err == nil && json.Unmarshal(data, &value) == nil && len(value.NATS) == 1 && strings.HasPrefix(value.NATS[0], "nats://127.0.0.1:") {
			nc, err := nats.Connect(value.NATS[0], nats.NoReconnect(), nats.Timeout(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(nc.Close)
			return nc
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("private NATS did not start")
	return nil
}
