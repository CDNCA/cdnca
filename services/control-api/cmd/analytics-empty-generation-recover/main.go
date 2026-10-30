// This operator-only command retires one proven-empty analytics generation after
// a NATS creation-time persistence defect. It never resets a stream or consumer.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const recoveryRoot = "/data/cdnca-native-root/cdnca"
const recoveryEnv = "/etc/cdnca-control/control.env"

var recoveryUnits = []string{"cdnca-control-api.service", "cdnca-agent-gateway.service", "cdnca-native-control-upgrade-runner.service"}
var recoveryFacts = []string{"analytics_ingest_receipts", "analytics_history_recoveries", "analytics_ingest_watermarks_107", "analytics_ingest_watermark_decisions_107", "analytics_realtime_expected_counts_131", "analytics_access_source_window_contributions_208"}
var syncRecoveryFile = (*os.File).Sync // Replaced only by non-parallel fault-injection tests.

type recoveryPlan struct {
	Schema               string `json:"schema"`
	InstallationID       string `json:"installation_id"`
	OldHistory           string `json:"old_history_epoch"`
	Stream               string `json:"stream"`
	Durable              string `json:"durable"`
	StreamEpoch          uint64 `json:"stream_epoch"`
	OldConsumerEpoch     uint64 `json:"old_consumer_epoch"`
	NewConsumerEpoch     uint64 `json:"new_consumer_epoch"`
	NATSVersion          string `json:"nats_version"`
	StateBucket          string `json:"state_bucket"`
	StreamRevision       uint64 `json:"stream_revision"`
	ConsumerRevision     uint64 `json:"consumer_revision"`
	StreamConfigSHA256   string `json:"stream_config_sha256"`
	ConsumerConfigSHA256 string `json:"consumer_config_sha256"`
	Current              string `json:"current"`
	SourceCommit         string `json:"source_commit"`
	ControlVersion       string `json:"control_version"`
	EnvSHA256            string `json:"env_sha256"`
}

type recoveryJournal struct {
	Schema     string          `json:"schema"`
	PlanSHA256 string          `json:"plan_sha256"`
	NewHistory string          `json:"new_history_epoch"`
	At         time.Time       `json:"at"`
	OldRow     json.RawMessage `json:"old_row"`
}

func main() {
	if err := runRecoveryCommand(); err != nil {
		// Errors are stable local codes: database URLs and server responses are never logged.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runRecoveryCommand() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || len(os.Args) < 2 {
		return errors.New("recovery_root_linux_required")
	}
	mode := os.Args[1]
	if mode != "check" && mode != "apply" && mode != "resume" {
		return errors.New("recovery_mode_invalid")
	}
	flags := flag.NewFlagSet("analytics-empty-generation-recover", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planFile := flags.String("plan-file", "", "private plan")
	journalDir := flags.String("journal-dir", "", "existing private journal directory")
	if flags.Parse(os.Args[2:]) != nil || flags.NArg() != 0 {
		return errors.New("recovery_arguments_invalid")
	}
	var plan recoveryPlan
	if _, err := readPrivateJSON(*planFile, &plan); err != nil {
		return err
	}
	if err := validateRecoveryPlan(plan); err != nil {
		return err
	}
	locks, err := frozenRecoveryHost(plan)
	if err != nil {
		return err
	}
	defer func() {
		for _, lock := range locks {
			_ = lock.Close()
		}
	}()
	if os.Getenv("CONTROL_INSTALLATION_ID") != plan.InstallationID || os.Getenv("DATABASE_URL") == "" {
		return errors.New("recovery_environment_mismatch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return errors.New("recovery_database_connect_failed")
	}
	defer pool.Close()
	nc, err := nats.Connect("nats://127.0.0.1:4222", nats.Name("cdnca-empty-generation-recover"), nats.NoReconnect(), nats.Timeout(3*time.Second))
	if err != nil {
		return errors.New("recovery_broker_connect_failed")
	}
	defer nc.Close()
	guard := func() error {
		if err := verifyRecoveryServices(plan); err != nil {
			return err
		}
		client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := client.Get("http://127.0.0.1:8222/connz?limit=2")
		if err != nil {
			return errors.New("recovery_clients_unverifiable")
		}
		defer response.Body.Close()
		var state struct {
			Connections int `json:"num_connections"`
			Total       int `json:"total"`
		}
		if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&state) != nil ||
			state.Connections != 1 || state.Total != 1 {
			return errors.New("recovery_other_broker_clients_present")
		}
		return nil
	}
	if err := recoverEmptyGeneration(ctx, pool, nc, plan, *journalDir, mode, guard, nil); err != nil {
		return err
	}
	fmt.Println("recovery_" + mode + "_verified; services remain stopped")
	return nil
}

func validateRecoveryPlan(p recoveryPlan) error {
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if p.Schema != "cdnca.analytics-empty-recovery/v1" || p.InstallationID == "" || p.OldHistory == "" ||
		p.Stream != "ANALYTICS_INGEST_V1" || p.Durable != "control_api_analytics_ingest_v1" ||
		p.StateBucket != "AISTATE_2dcd3c381ead92f3" || p.StreamRevision != 1 || p.ConsumerRevision != 2 ||
		p.StreamEpoch == 0 || p.OldConsumerEpoch < p.StreamEpoch || p.NewConsumerEpoch <= p.OldConsumerEpoch ||
		p.NewConsumerEpoch > uint64(1<<63-1) || p.NATSVersion == "" || len(p.NATSVersion) > 64 ||
		!regexp.MustCompile(`^releases/[0-9a-f]{64}$`).MatchString(p.Current) ||
		!regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(p.SourceCommit) ||
		!regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(p.ControlVersion) ||
		!hex64.MatchString(p.StreamConfigSHA256) || !hex64.MatchString(p.ConsumerConfigSHA256) || !hex64.MatchString(p.EnvSHA256) {
		return errors.New("recovery_plan_invalid")
	}
	for _, id := range []string{p.InstallationID, p.OldHistory} {
		if parsed, err := uuid.Parse(id); err != nil || parsed == uuid.Nil || parsed.String() != id {
			return errors.New("recovery_identity_invalid")
		}
	}
	return nil
}

func epochRecoveryTime(epoch uint64) time.Time { return time.Unix(0, int64(epoch)).UTC() }

func openRecoveryFile(path string, private bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("recovery_path_invalid")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("recovery_file_unavailable")
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, errors.New("recovery_file_unverifiable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 ||
		info.Mode().Perm()&0027 != 0 || private && info.Mode().Perm() != 0600 {
		file.Close()
		return nil, errors.New("recovery_file_not_private")
	}
	return file, nil
}

func readPrivateJSON(path string, target any) ([]byte, error) {
	dir := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != dir {
		return nil, errors.New("recovery_json_directory_invalid")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("recovery_json_directory_not_private")
	}
	file, err := openRecoveryFile(path, true)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("recovery_json_size_invalid")
	}
	if err := decodeRecoveryJSON(data, target); err != nil {
		return nil, err
	}
	return data, nil
}

func decodeRecoveryJSON(data []byte, target any) error {
	// Plans and journals contain objects, scalars, and a PostgreSQL row object only.
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			if delimiter != '{' {
				return errors.New("object required")
			}
			keys := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || keys[name] {
					return errors.New("duplicate key")
				}
				keys[name] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		}
		return nil
	}
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' || walk() != nil {
		return errors.New("recovery_json_invalid")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("recovery_json_trailing_data")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return errors.New("recovery_json_fields_invalid")
	}
	return nil
}

func digestRecoveryJSON(value any) string {
	data, _ := json.Marshal(value)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func writeRecoveryJournal(path string, value any) error {
	dir := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != dir {
		return errors.New("recovery_journal_directory_invalid")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return errors.New("recovery_journal_directory_not_private")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return errors.New("recovery_journal_encode_failed")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("recovery_journal_create_failed")
	}
	defer file.Close()
	if _, err = file.Write(append(data, '\n')); err != nil {
		return errors.New("recovery_journal_write_failed")
	}
	if syncRecoveryFile(file) != nil {
		return errors.New("recovery_journal_sync_failed")
	}
	directory, err := os.Open(dir)
	if err != nil {
		return errors.New("recovery_journal_directory_open_failed")
	}
	defer directory.Close()
	if syncRecoveryFile(directory) != nil {
		return errors.New("recovery_journal_directory_sync_failed")
	}
	return nil
}

func syncRecoveryJournal(path string) error {
	file, err := openRecoveryFile(path, true)
	if err != nil {
		return err
	}
	defer file.Close()
	if syncRecoveryFile(file) != nil {
		return errors.New("recovery_journal_sync_failed")
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("recovery_journal_directory_open_failed")
	}
	defer dir.Close()
	if syncRecoveryFile(dir) != nil {
		return errors.New("recovery_journal_directory_sync_failed")
	}
	return nil
}

func frozenRecoveryHost(p recoveryPlan) ([]*os.File, error) {
	var locks []*os.File
	for _, path := range []string{"/run/lock/cdnca-management-release.lock", "/var/lib/cdnca-native-upgrade-maintenance/maintenance.json.lock"} {
		file, err := openRecoveryFile(path, false)
		if err == nil {
			err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		}
		if err != nil {
			if file != nil {
				file.Close()
			}
			for _, lock := range locks {
				lock.Close()
			}
			return nil, errors.New("recovery_lock_unavailable")
		}
		locks = append(locks, file)
	}
	if err := verifyRecoveryServices(p); err != nil {
		for _, lock := range locks {
			lock.Close()
		}
		return nil, err
	}
	return locks, nil
}

func validRecoveryCurrentTarget(expected, actual string) bool {
	return actual == expected || actual == filepath.Join(recoveryRoot, expected)
}

func verifyRecoveryServices(p recoveryPlan) error {
	current, err := os.Readlink(filepath.Join(recoveryRoot, "current"))
	if err != nil || !validRecoveryCurrentTarget(p.Current, current) {
		return errors.New("recovery_release_drift")
	}
	data, err := os.ReadFile(filepath.Join(recoveryRoot, p.Current, "release.manifest.json"))
	var manifest struct {
		Version string `json:"version"`
		Source  struct {
			Commit string `json:"commit"`
		} `json:"source"`
	}
	if err != nil || json.Unmarshal(data, &manifest) != nil || manifest.Version != p.ControlVersion || manifest.Source.Commit != p.SourceCommit {
		return errors.New("recovery_source_drift")
	}
	file, err := openRecoveryFile(recoveryEnv, true)
	if err != nil {
		return err
	}
	digest := sha256.New()
	_, copyErr := io.Copy(digest, file)
	file.Close()
	if copyErr != nil || hex.EncodeToString(digest.Sum(nil)) != p.EnvSHA256 {
		return errors.New("recovery_environment_drift")
	}
	data, err = os.ReadFile("/var/lib/cdnca-native-upgrade-maintenance/maintenance.json")
	var maintenance struct {
		Phase  string `json:"phase"`
		PlanID string `json:"plan_id"`
	}
	if err != nil || json.Unmarshal(data, &maintenance) != nil || maintenance.Phase != "active" || maintenance.PlanID != "" {
		return errors.New("recovery_maintenance_busy")
	}
	for _, unit := range recoveryUnits {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		data, err := exec.CommandContext(ctx, "systemctl", "show", unit, "--property=MainPID,ActiveState,SubState").Output()
		cancel()
		lines := strings.Fields(string(data))
		sort.Strings(lines)
		if err != nil || strings.Join(lines, " ") != "ActiveState=inactive MainPID=0 SubState=dead" {
			return errors.New("recovery_service_not_stopped")
		}
	}
	return nil
}

func validateRecoveryBroker(p recoveryPlan, s nats.StreamInfo, c nats.ConsumerInfo) error {
	if s.Config.Name != p.Stream || c.Stream != p.Stream || c.Name != p.Durable || c.Config.Durable != p.Durable ||
		s.Created.UnixNano() != int64(p.StreamEpoch) || c.Created.UnixNano() != int64(p.NewConsumerEpoch) ||
		c.Config.DeliverPolicy != nats.DeliverAllPolicy || c.Config.AckPolicy != nats.AckExplicitPolicy || c.Config.FilterSubject != "cdnca.analytics.ingest.v1.*" ||
		s.State.Msgs != 0 || s.State.Bytes != 0 || s.State.FirstSeq != 0 || s.State.LastSeq != 0 || s.State.Consumers != 1 || s.State.NumDeleted != 0 || len(s.State.Deleted) != 0 ||
		c.Delivered.Consumer != 0 || c.Delivered.Stream != 0 || c.AckFloor.Consumer != 0 || c.AckFloor.Stream != 0 || c.NumAckPending != 0 || c.NumRedelivered != 0 || c.NumWaiting != 0 || c.NumPending != 0 {
		return errors.New("recovery_broker_not_exactly_empty")
	}
	return nil
}

func recoveryBrokerState(nc *nats.Conn, p recoveryPlan) (nats.KeyValue, bool, error) {
	if nc.ConnectedServerVersion() != p.NATSVersion {
		return nil, false, errors.New("recovery_broker_version_drift")
	}
	var stream nats.StreamInfo
	var consumer nats.ConsumerInfo
	for index, request := range []struct {
		subject, hash string
		target        any
	}{
		{"$JS.API.STREAM.INFO." + p.Stream, p.StreamConfigSHA256, &stream},
		{"$JS.API.CONSUMER.INFO." + p.Stream + "." + p.Durable, p.ConsumerConfigSHA256, &consumer},
	} {
		message, err := nc.Request(request.subject, []byte("{}"), 3*time.Second)
		if err != nil {
			return nil, false, errors.New("recovery_broker_read_failed")
		}
		var raw struct {
			Config json.RawMessage `json:"config"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal(message.Data, &raw) != nil || len(raw.Error) != 0 || json.Unmarshal(message.Data, request.target) != nil {
			return nil, false, errors.New("recovery_broker_response_invalid")
		}
		var config map[string]any
		decoder := json.NewDecoder(bytes.NewReader(raw.Config))
		decoder.UseNumber()
		if decoder.Decode(&config) != nil || digestRecoveryJSON(config) != request.hash {
			return nil, false, fmt.Errorf("recovery_broker_config_%d_drift", index)
		}
	}
	if err := validateRecoveryBroker(p, stream, consumer); err != nil {
		return nil, false, err
	}
	js, err := nc.JetStream(nats.MaxWait(3 * time.Second))
	if err != nil {
		return nil, false, errors.New("recovery_kv_unavailable")
	}
	kv, err := js.KeyValue(p.StateBucket)
	if err != nil {
		return nil, false, errors.New("recovery_kv_unavailable")
	}
	keys, err := kv.Keys()
	sort.Strings(keys)
	if err != nil || strings.Join(keys, ",") != "consumer_created,stream_created" {
		return nil, false, errors.New("recovery_kv_keys_drift")
	}
	streamEntry, err := kv.Get("stream_created")
	if err != nil || streamEntry.Revision() != p.StreamRevision || string(streamEntry.Value()) != epochRecoveryTime(p.StreamEpoch).Format(time.RFC3339Nano) {
		return nil, false, errors.New("recovery_stream_kv_drift")
	}
	entry, err := kv.Get("consumer_created")
	if err != nil {
		return nil, false, errors.New("recovery_consumer_kv_unavailable")
	}
	old := entry.Revision() == p.ConsumerRevision && string(entry.Value()) == epochRecoveryTime(p.OldConsumerEpoch).Format(time.RFC3339Nano)
	next := entry.Revision() == p.ConsumerRevision+1 && string(entry.Value()) == epochRecoveryTime(p.NewConsumerEpoch).Format(time.RFC3339Nano)
	if !old && !next {
		return nil, false, errors.New("recovery_consumer_kv_drift")
	}
	state, err := js.StreamInfo("KV_" + p.StateBucket)
	if err != nil || state.State.Msgs != 2 || state.State.LastSeq != entry.Revision() {
		return nil, false, errors.New("recovery_kv_history_drift")
	}
	for _, bucket := range []string{strings.Replace(p.StateBucket, "AISTATE_", "AILEASE_", 1), strings.Replace(p.StateBucket, "AISTATE_", "AIEVIDENCE_", 1)} {
		store, err := js.KeyValue(bucket)
		if err != nil {
			return nil, false, errors.New("recovery_auxiliary_kv_missing")
		}
		keys, err := store.Keys()
		if err != nil && !errors.Is(err, nats.ErrNoKeysFound) || len(keys) != 0 {
			return nil, false, errors.New("recovery_auxiliary_kv_not_empty")
		}
	}
	return kv, next, nil
}

func recoveryDatabaseState(ctx context.Context, tx pgx.Tx, p recoveryPlan, j *recoveryJournal) (json.RawMessage, bool, error) {
	if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='10s'; SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return nil, false, errors.New("recovery_database_setup_failed")
	}
	for _, table := range recoveryFacts {
		if _, err := tx.Exec(ctx, "LOCK TABLE "+table+" IN SHARE MODE"); err != nil {
			return nil, false, errors.New("recovery_fact_lock_failed")
		}
	}
	if _, err := tx.Exec(ctx, "LOCK TABLE analytics_history_streams IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return nil, false, errors.New("recovery_history_lock_failed")
	}
	var unsafe bool
	if err := tx.QueryRow(ctx, `SELECT rolsuper OR rolcreaterole OR rolcreatedb FROM pg_roles WHERE rolname=current_user`).Scan(&unsafe); err != nil || unsafe {
		return nil, false, errors.New("recovery_database_role_unsafe")
	}
	var valid bool
	if err := tx.QueryRow(ctx, `SELECT count(*)=268 AND min(version)=1 AND max(version)=268 AND bool_and(integrity_state='verified') FROM schema_migrations`).Scan(&valid); err != nil || !valid {
		return nil, false, errors.New("recovery_schema_drift")
	}
	var installation string
	if err := tx.QueryRow(ctx, `SELECT installation_id FROM control_installation_entitlement WHERE singleton=true FOR UPDATE`).Scan(&installation); err != nil || installation != p.InstallationID {
		return nil, false, errors.New("recovery_installation_drift")
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || '' || chr(31) || $2 || chr(31) || $3,83))`, p.InstallationID, p.Stream, p.Durable); err != nil {
		return nil, false, errors.New("recovery_identity_lock_failed")
	}
	var row json.RawMessage
	var retired bool
	err := tx.QueryRow(ctx, `SELECT to_jsonb(h),retired_at IS NOT NULL FROM analytics_history_streams h WHERE history_epoch=$1
		AND installation_id=$2 AND nats_domain='' AND stream_name=$3 AND durable_name=$4
		AND stream_created_unix_nano=$5 AND consumer_created_unix_nano=$6 AND history_start_sequence=1
		AND legacy_baseline_kind='none' AND broker_consumer_ack_floor=0 AND broker_stream_ack_floor=0 AND prepared_stream_floor=0
		AND revision=CASE WHEN retired_at IS NULL THEN 1 ELSE 2 END FOR UPDATE`, p.OldHistory, p.InstallationID, p.Stream, p.Durable, p.StreamEpoch, p.OldConsumerEpoch).Scan(&row, &retired)
	if err != nil {
		return nil, false, errors.New("recovery_old_history_drift")
	}
	newHistory := uuid.Nil.String()
	if j != nil {
		newHistory = j.NewHistory
	}
	for _, table := range recoveryFacts {
		if err := tx.QueryRow(ctx, "SELECT NOT EXISTS(SELECT 1 FROM "+table+" WHERE history_epoch=$1 OR history_epoch=$2)", p.OldHistory, newHistory).Scan(&valid); err != nil || !valid {
			return nil, false, errors.New("recovery_history_has_facts")
		}
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM analytics_history_streams WHERE installation_id=$1 AND nats_domain='' AND stream_name=$2 AND durable_name=$3`, p.InstallationID, p.Stream, p.Durable).Scan(&count); err != nil || !retired && count != 1 || retired && count != 2 {
		return nil, false, errors.New("recovery_generation_count_drift")
	}
	if j == nil {
		if retired {
			return nil, false, errors.New("recovery_journal_required")
		}
		return row, false, nil
	}
	if !retired {
		if err := tx.QueryRow(ctx, `SELECT $1::jsonb=$2::jsonb`, []byte(row), []byte(j.OldRow)).Scan(&valid); err != nil || !valid {
			return nil, false, errors.New("recovery_prepared_row_drift")
		}
		return row, false, nil
	}
	if err := tx.QueryRow(ctx, `SELECT $1::jsonb = $2::jsonb || jsonb_build_object('retired_at',$3::timestamptz,'updated_at',$3::timestamptz,'revision',2)`, []byte(row), []byte(j.OldRow), j.At).Scan(&valid); err != nil || !valid {
		return nil, false, errors.New("recovery_retired_row_drift")
	}
	err = tx.QueryRow(ctx, `SELECT count(*)=1 FROM analytics_history_streams WHERE history_epoch=$1 AND installation_id=$2 AND nats_domain='' AND stream_name=$3 AND durable_name=$4
		AND stream_created_unix_nano=$5 AND consumer_created_unix_nano=$6 AND history_start_sequence=1 AND history_start_at=$7
		AND legacy_baseline_kind='none' AND broker_consumer_ack_floor=0 AND broker_stream_ack_floor=0 AND prepared_stream_floor=0
		AND revision=1 AND retired_at IS NULL AND created_at=$8 AND updated_at=$8 AND last_reconciled_at=$8`, j.NewHistory, p.InstallationID, p.Stream, p.Durable, p.StreamEpoch, p.NewConsumerEpoch, epochRecoveryTime(p.NewConsumerEpoch), j.At).Scan(&valid)
	if err != nil || !valid {
		return nil, false, errors.New("recovery_new_history_drift")
	}
	return row, true, nil
}

func transitionRecoveryDatabase(ctx context.Context, tx pgx.Tx, p recoveryPlan, j recoveryJournal) error {
	result, err := tx.Exec(ctx, `UPDATE analytics_history_streams SET retired_at=$2,updated_at=$2,revision=revision+1 WHERE history_epoch=$1 AND retired_at IS NULL AND revision=1`, p.OldHistory, j.At)
	if err != nil || result.RowsAffected() != 1 {
		return errors.New("recovery_retirement_failed")
	}
	_, err = tx.Exec(ctx, `INSERT INTO analytics_history_streams(installation_id,nats_domain,stream_name,durable_name,stream_created_unix_nano,consumer_created_unix_nano,history_epoch,
		history_start_sequence,history_start_at,legacy_baseline_kind,broker_consumer_ack_floor,broker_stream_ack_floor,prepared_stream_floor,revision,last_reconciled_at,created_at,updated_at)
		VALUES($1,'',$2,$3,$4,$5,$6,1,$7,'none',0,0,0,1,$8,$8,$8)`, p.InstallationID, p.Stream, p.Durable, p.StreamEpoch, p.NewConsumerEpoch, j.NewHistory, epochRecoveryTime(p.NewConsumerEpoch), j.At)
	if err != nil {
		return errors.New("recovery_new_generation_failed")
	}
	return nil
}

func recoverEmptyGeneration(ctx context.Context, pool *pgxpool.Pool, nc *nats.Conn, p recoveryPlan, dir, mode string, guard func() error, checkpoint func(string) error) error {
	if mode != "check" && mode != "apply" && mode != "resume" {
		return errors.New("recovery_mode_invalid")
	}
	if err := validateRecoveryPlan(p); err != nil {
		return err
	}
	if guard != nil {
		if err := guard(); err != nil {
			return err
		}
	}
	if checkpoint == nil {
		checkpoint = func(string) error { return nil }
	}
	var journal *recoveryJournal
	if mode == "resume" {
		journal = &recoveryJournal{}
		if _, err := readPrivateJSON(filepath.Join(dir, "prepared.json"), journal); err != nil {
			return err
		}
		id, err := uuid.Parse(journal.NewHistory)
		if err != nil || id == uuid.Nil || journal.NewHistory == p.OldHistory || journal.Schema != "cdnca.analytics-empty-recovery-journal/v1" || journal.PlanSHA256 != digestRecoveryJSON(p) || journal.At.IsZero() || journal.At.After(time.Now().Add(time.Second)) || len(journal.OldRow) == 0 {
			return errors.New("recovery_journal_mismatch")
		}
		// An earlier directory fsync may have failed before any database write.
		if err := syncRecoveryJournal(filepath.Join(dir, "prepared.json")); err != nil {
			return err
		}
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return errors.New("recovery_transaction_failed")
	}
	defer tx.Rollback(context.Background())
	row, committed, err := recoveryDatabaseState(ctx, tx, p, journal)
	if err != nil {
		return err
	}
	kv, kvDone, err := recoveryBrokerState(nc, p)
	if err != nil {
		return err
	}
	if kvDone && !committed {
		return errors.New("recovery_kv_ahead_of_database")
	}
	if mode == "check" {
		return nil
	}
	if journal == nil {
		journal = &recoveryJournal{Schema: "cdnca.analytics-empty-recovery-journal/v1", PlanSHA256: digestRecoveryJSON(p), NewHistory: uuid.NewString(), At: time.Now().UTC().Truncate(time.Microsecond), OldRow: row}
		if err := writeRecoveryJournal(filepath.Join(dir, "prepared.json"), journal); err != nil {
			return err
		}
		if err := checkpoint("prepared"); err != nil {
			return err
		}
	}
	if guard != nil {
		if err := guard(); err != nil {
			return err
		}
	}
	if _, latest, err := recoveryBrokerState(nc, p); err != nil || latest != kvDone {
		return errors.New("recovery_broker_changed_during_prepare")
	}
	if !committed {
		if err := transitionRecoveryDatabase(ctx, tx, p, *journal); err != nil {
			return err
		}
		if err := checkpoint("before_pg_commit"); err != nil {
			return err
		}
	}
	if tx.Commit(ctx) != nil {
		return errors.New("recovery_commit_outcome_unknown_resume_required")
	}
	if err := checkpoint("after_pg_commit"); err != nil {
		return err
	}
	// Reacquire fact locks after the committed transition, before the KV CAS.
	// A concurrent writer that won this gap causes a refusal, not a silent reset.
	verify, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return errors.New("recovery_final_transaction_failed")
	}
	defer verify.Rollback(context.Background())
	if _, done, err := recoveryDatabaseState(ctx, verify, p, journal); err != nil || !done {
		return errors.New("recovery_final_database_mismatch")
	}
	if guard != nil {
		if err := guard(); err != nil {
			return err
		}
	}
	if _, latest, err := recoveryBrokerState(nc, p); err != nil || latest != kvDone {
		return errors.New("recovery_broker_changed_after_commit")
	}
	if !kvDone {
		if err := checkpoint("before_kv_cas"); err != nil {
			return err
		}
		revision, err := kv.Update("consumer_created", []byte(epochRecoveryTime(p.NewConsumerEpoch).Format(time.RFC3339Nano)), p.ConsumerRevision)
		if err != nil || revision != p.ConsumerRevision+1 {
			return errors.New("recovery_kv_cas_outcome_unknown_resume_required")
		}
	}
	if err := checkpoint("after_kv_cas"); err != nil {
		return err
	}
	if _, done, err := recoveryBrokerState(nc, p); err != nil || !done {
		return errors.New("recovery_final_broker_mismatch")
	}
	if guard != nil {
		if err := guard(); err != nil {
			return err
		}
	}
	complete := filepath.Join(dir, "completed.json")
	if _, err := os.Lstat(complete); err == nil {
		var previous recoveryJournal
		if _, err := readPrivateJSON(complete, &previous); err != nil || digestRecoveryJSON(previous) != digestRecoveryJSON(journal) {
			return errors.New("recovery_completion_drift")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return errors.New("recovery_completion_unverifiable")
	}
	return writeRecoveryJournal(complete, journal)
}
