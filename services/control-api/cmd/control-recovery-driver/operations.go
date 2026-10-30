package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackup"
	"github.com/nats-io/nats.go"
)

const (
	freezeRecordSchema    = "cdnca.control-recovery-driver.freeze/v1"
	jetStreamBundleSchema = "cdnca.control-recovery-driver.jetstream/v1"
	jetStreamSnapshotType = "io.nats.jetstream.api.v1.stream_snapshot_response"
	jetStreamRestoreType  = "io.nats.jetstream.api.v1.stream_restore_response"
	maxDriverInput        = 4 << 20
)

type driverRuntime struct {
	plan       driverPlan
	operations *operationStore
}

type freezeOutput struct {
	FreezeID string `json:"freeze_id"`
}

type freezeRecord struct {
	Schema     string           `json:"schema"`
	BackupID   string           `json:"backup_id"`
	FreezeID   string           `json:"freeze_id"`
	Workloads  []frozenWorkload `json:"workloads"`
	AcquiredAt time.Time        `json:"acquired_at"`
}

type frozenWorkload struct {
	Name     string `json:"name"`
	Replicas int32  `json:"replicas"`
}

func newDriverRuntime(plan driverPlan) (*driverRuntime, error) {
	operations, err := newOperationStore(plan.StateDirectory)
	if err != nil {
		return nil, err
	}
	return &driverRuntime{plan: plan, operations: operations}, nil
}

func (runtime *driverRuntime) freeze(ctx context.Context, backupID string) (json.RawMessage, string) {
	if !safeName.MatchString(backupID) {
		return nil, "invalid_backup_id"
	}
	if code := runtime.reconcileStaleFreezes(ctx, backupID); code != "" {
		return nil, code
	}
	return runtime.operations.execute("freeze", backupID, map[string]string{"backup_id": backupID}, true, func() (any, string) {
		freezeID := "freeze-" + safeStateName(backupID)[:32]
		record, code := runtime.prepareFreezeRecord(ctx, backupID, freezeID)
		if code != "" {
			return nil, code
		}
		if code := runtime.freezeWorkloads(ctx, record); code != "" {
			_ = runtime.restoreWorkloads(context.WithoutCancel(ctx), record)
			return nil, code
		}
		return freezeOutput{FreezeID: freezeID}, ""
	})
}

func (runtime *driverRuntime) reconcileStaleFreezes(ctx context.Context, currentBackupID string) string {
	entries, err := os.ReadDir(runtime.plan.StateDirectory)
	if err != nil {
		return "write_freeze_reconciliation_failed"
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "freeze-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		encoded, err := controlbackup.ReadTrustedFile(filepath.Join(runtime.plan.StateDirectory, entry.Name()))
		var candidate freezeRecord
		if err != nil || controlbackup.DecodeStrictJSON(encoded, &candidate) != nil ||
			runtime.freezeRecordPath(candidate.FreezeID) != filepath.Join(runtime.plan.StateDirectory, entry.Name()) {
			return uncertainCode
		}
		record, err := runtime.readFreezeRecord(candidate.FreezeID)
		if err != nil {
			return uncertainCode
		}
		if record.BackupID == currentBackupID {
			continue
		}
		releasePath := filepath.Join(runtime.operations.directory, safeStateName("release-"+record.FreezeID)+".receipt.json")
		if release, found, valid := readOperationReceipt(releasePath); found {
			if !valid {
				return uncertainCode
			}
			if release.State == "succeeded" {
				continue
			}
		}
		_, code := runtime.operations.execute("reconcile-freeze", record.FreezeID, record, true, func() (any, string) {
			if err := runtime.restoreWorkloads(context.WithoutCancel(ctx), record); err != nil {
				return nil, "write_freeze_reconciliation_failed"
			}
			return nil, ""
		})
		if code != "" {
			return code
		}
	}
	return ""
}

func (runtime *driverRuntime) release(ctx context.Context, freezeID string) (json.RawMessage, string) {
	record, err := runtime.readFreezeRecord(freezeID)
	if err != nil {
		return nil, "write_freeze_not_found"
	}
	return runtime.operations.execute("release", freezeID, record, true, func() (any, string) {
		if err := runtime.restoreWorkloads(ctx, record); err != nil {
			return nil, "write_freeze_release_failed"
		}
		return nil, ""
	})
}

func (runtime *driverRuntime) prepareFreezeRecord(ctx context.Context, backupID, freezeID string) (freezeRecord, string) {
	if record, err := runtime.readFreezeRecord(freezeID); err == nil {
		if record.BackupID != backupID {
			return freezeRecord{}, uncertainCode
		}
		return record, ""
	} else if !errors.Is(err, os.ErrNotExist) {
		return freezeRecord{}, uncertainCode
	}
	client, namespace, err := runtime.kubernetesClient()
	if err != nil {
		return freezeRecord{}, "write_freeze_kubernetes_unavailable"
	}
	record := freezeRecord{Schema: freezeRecordSchema, BackupID: backupID, FreezeID: freezeID, AcquiredAt: time.Now().UTC()}
	for _, workload := range runtime.plan.Kubernetes.Workloads {
		replicas, _, err := getScale(ctx, client, runtime.plan.Kubernetes.APIServer, namespace, workload.Name)
		if err != nil {
			return freezeRecord{}, "write_freeze_read_failed"
		}
		record.Workloads = append(record.Workloads, frozenWorkload{Name: workload.Name, Replicas: replicas})
	}
	if err := writeExclusiveJSON(runtime.freezeRecordPath(freezeID), record); err != nil {
		return freezeRecord{}, uncertainCode
	}
	return record, ""
}

func (runtime *driverRuntime) freezeWorkloads(ctx context.Context, record freezeRecord) string {
	client, namespace, err := runtime.kubernetesClient()
	if err != nil {
		return "write_freeze_kubernetes_unavailable"
	}
	for _, workload := range record.Workloads {
		if err := setScale(ctx, client, runtime.plan.Kubernetes.APIServer, namespace, workload.Name, 0); err != nil {
			return "write_freeze_apply_failed"
		}
	}
	if err := runtime.waitForWorkloads(ctx, record, 0); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "write_freeze_cancelled"
		}
		return "write_freeze_timeout"
	}
	return ""
}

func (runtime *driverRuntime) restoreWorkloads(ctx context.Context, record freezeRecord) error {
	client, namespace, err := runtime.kubernetesClient()
	if err != nil {
		return err
	}
	var joined error
	for _, workload := range record.Workloads {
		if err := setScale(ctx, client, runtime.plan.Kubernetes.APIServer, namespace, workload.Name, workload.Replicas); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	if joined == nil {
		joined = runtime.waitForWorkloads(ctx, record, -1)
	}
	return joined
}

func (runtime *driverRuntime) waitForWorkloads(ctx context.Context, record freezeRecord, desired int32) error {
	client, namespace, err := runtime.kubernetesClient()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(time.Duration(runtime.plan.Kubernetes.SettleTimeoutSeconds) * time.Second)
	for _, workload := range record.Workloads {
		want := desired
		if want < 0 {
			want = workload.Replicas
		}
		for {
			spec, observed, readErr := getScale(ctx, client, runtime.plan.Kubernetes.APIServer, namespace, workload.Name)
			if readErr == nil && spec == want && observed == want {
				break
			}
			if time.Now().After(deadline) {
				return errors.New("Kubernetes scale did not converge")
			}
			if !waitContext(ctx, 500*time.Millisecond) {
				return ctx.Err()
			}
		}
	}
	return nil
}

func (runtime *driverRuntime) freezeRecordPath(freezeID string) string {
	return filepath.Join(runtime.plan.StateDirectory, "freeze-"+safeStateName(freezeID)+".json")
}

func (runtime *driverRuntime) readFreezeRecord(freezeID string) (freezeRecord, error) {
	if !safeName.MatchString(freezeID) {
		return freezeRecord{}, errors.New("invalid freeze ID")
	}
	encoded, err := controlbackup.ReadTrustedFile(runtime.freezeRecordPath(freezeID))
	if err != nil {
		return freezeRecord{}, err
	}
	var record freezeRecord
	if controlbackup.DecodeStrictJSON(encoded, &record) != nil || record.Schema != freezeRecordSchema ||
		record.FreezeID != freezeID || !safeName.MatchString(record.BackupID) || record.AcquiredAt.IsZero() ||
		len(record.Workloads) != len(runtime.plan.Kubernetes.Workloads) {
		return freezeRecord{}, errors.New("invalid freeze record")
	}
	for index, workload := range record.Workloads {
		if workload.Name != runtime.plan.Kubernetes.Workloads[index].Name || workload.Replicas < 0 {
			return freezeRecord{}, errors.New("invalid freeze record")
		}
	}
	return record, nil
}

func (runtime *driverRuntime) verifyFreeze(ctx context.Context, backupID, freezeID string) error {
	record, err := runtime.readFreezeRecord(freezeID)
	if err != nil || record.BackupID != backupID {
		return errors.New("freeze identity mismatch")
	}
	receiptPath := filepath.Join(runtime.operations.directory, safeStateName("freeze-"+backupID)+".receipt.json")
	receipt, found, valid := readOperationReceipt(receiptPath)
	if !found || !valid || receipt.State != "succeeded" {
		return errors.New("freeze not durably acquired")
	}
	releasePath := filepath.Join(runtime.operations.directory, safeStateName("release-"+freezeID)+".receipt.json")
	if release, found, valid := readOperationReceipt(releasePath); found && valid && release.State == "succeeded" {
		return errors.New("freeze already released")
	}
	return runtime.waitForWorkloads(ctx, record, 0)
}

func (runtime *driverRuntime) capture(ctx context.Context, component controlbackup.Component, backupID, freezeID string) (json.RawMessage, string) {
	if runtime.verifyFreeze(ctx, backupID, freezeID) != nil {
		return nil, "write_freeze_identity_mismatch"
	}
	identity := backupID + "-" + string(component)
	input := map[string]string{"backup_id": backupID, "write_freeze_id": freezeID, "component": string(component)}
	return runtime.operations.execute("capture", identity, input, false, func() (any, string) {
		if component == controlbackup.ComponentJetStream {
			checkpoint, code := runtime.captureJetStream(ctx, backupID, freezeID)
			return checkpoint, code
		}
		configured, found := runtime.plan.Components[string(component)]
		if !found {
			return nil, "unsupported_component"
		}
		artifact := runtime.artifactPath(backupID, component)
		_ = os.Remove(artifact)
		variables := commandVariables(backupID, freezeID, "", artifact)
		if code := runCommand(ctx, configured.Capture, variables, runtime.plan.OperationTimeoutSeconds); code != "" {
			return nil, code
		}
		checkpoint, err := checkpointForArtifact(component, backupID, freezeID, artifact, time.Now().UTC(), controlbackup.JetStreamTopology{})
		if err != nil {
			return nil, "capture_artifact_invalid"
		}
		return checkpoint, ""
	})
}

func (runtime *driverRuntime) preflight(ctx context.Context, manifest controlbackup.Manifest, targetID string) string {
	if manifest.Validate() != nil || !safeName.MatchString(targetID) {
		return "preflight_manifest_invalid"
	}
	for _, checkpoint := range manifest.Checkpoints {
		artifact := runtime.artifactPath(checkpoint.BackupID, checkpoint.Component)
		if err := verifyArtifact(artifact, checkpoint); err != nil {
			return "preflight_artifact_invalid"
		}
	}
	for _, component := range []controlbackup.Component{controlbackup.ComponentPostgreSQL, controlbackup.ComponentClickHouse} {
		configured := runtime.plan.Components[string(component)]
		artifact := runtime.artifactPath(manifest.BackupID, component)
		if code := runCommand(ctx, configured.Preflight, commandVariables(manifest.BackupID, manifest.WriteFreezeID, targetID, artifact), runtime.plan.OperationTimeoutSeconds); code != "" {
			return "preflight_" + string(component) + "_failed"
		}
	}
	if code := runtime.preflightJetStream(ctx, manifest); code != "" {
		return code
	}
	return ""
}

func (runtime *driverRuntime) restore(ctx context.Context, component controlbackup.Component, checkpoint controlbackup.ComponentCheckpoint, targetID string) (json.RawMessage, string) {
	identity := targetID + "-" + checkpoint.BackupID + "-" + string(component)
	return runtime.operations.execute("restore", identity, checkpoint, false, func() (any, string) {
		if component == controlbackup.ComponentJetStream {
			return nil, runtime.restoreJetStream(ctx, checkpoint)
		}
		configured, found := runtime.plan.Components[string(component)]
		if !found {
			return nil, "unsupported_component"
		}
		artifact := runtime.artifactPath(checkpoint.BackupID, component)
		if verifyArtifact(artifact, checkpoint) != nil {
			return nil, "restore_artifact_invalid"
		}
		code := runCommand(ctx, configured.Restore, commandVariables(checkpoint.BackupID, checkpoint.WriteFreezeID, targetID, artifact), runtime.plan.OperationTimeoutSeconds)
		return nil, code
	})
}

func (runtime *driverRuntime) compensate(ctx context.Context, component controlbackup.Component, backupID, targetID string) (json.RawMessage, string) {
	identity := targetID + "-" + backupID + "-" + string(component)
	input := map[string]string{"target_id": targetID, "backup_id": backupID, "component": string(component)}
	return runtime.operations.execute("compensate", identity, input, true, func() (any, string) {
		if component == controlbackup.ComponentJetStream {
			return nil, runtime.compensateJetStream(ctx)
		}
		configured, found := runtime.plan.Components[string(component)]
		if !found {
			return nil, "unsupported_component"
		}
		artifact := runtime.artifactPath(backupID, component)
		code := runCommand(ctx, configured.Compensate, commandVariables(backupID, "", targetID, artifact), runtime.plan.OperationTimeoutSeconds)
		return nil, code
	})
}

func (runtime *driverRuntime) artifactPath(backupID string, component controlbackup.Component) string {
	return filepath.Join(runtime.plan.ArtifactDirectory, safeStateName(backupID)+"-"+string(component)+".artifact")
}

func commandVariables(backupID, freezeID, targetID, artifact string) map[string]string {
	return map[string]string{"{backup_id}": backupID, "{freeze_id}": freezeID, "{target_id}": targetID, "{artifact}": artifact}
}

func runCommand(parent context.Context, plan commandPlan, variables map[string]string, timeoutSeconds int64) string {
	info, err := os.Lstat(plan.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return "component_command_unavailable"
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()
	arguments := make([]string, len(plan.Arguments))
	for index, argument := range plan.Arguments {
		arguments[index] = expandVariables(argument, variables)
	}
	command := exec.CommandContext(ctx, plan.Path, arguments...)
	command.Env = append([]string(nil), os.Environ()...)
	for key, value := range plan.Environment {
		command.Env = append(command.Env, key+"="+expandVariables(value, variables))
	}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "component_command_timeout"
		}
		return "component_command_failed"
	}
	return ""
}

func expandVariables(value string, variables map[string]string) string {
	for key, replacement := range variables {
		value = strings.ReplaceAll(value, key, replacement)
	}
	return value
}

func checkpointForArtifact(component controlbackup.Component, backupID, freezeID, path string, capturedAt time.Time, topology controlbackup.JetStreamTopology) (controlbackup.ComponentCheckpoint, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 {
		return controlbackup.ComponentCheckpoint{}, errors.New("invalid artifact")
	}
	file, err := os.Open(path)
	if err != nil {
		return controlbackup.ComponentCheckpoint{}, err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return controlbackup.ComponentCheckpoint{}, err
	}
	digestText := hex.EncodeToString(digest.Sum(nil))
	revision := uint64(capturedAt.UnixNano())
	if revision == 0 {
		revision = 1
	}
	return controlbackup.ComponentCheckpoint{
		Component: component, BackupID: backupID, WriteFreezeID: freezeID,
		SnapshotID: string(component) + "-" + digestText[:24], Revision: revision,
		CapturedAt: capturedAt, SHA256: digestText, SizeBytes: info.Size(), JetStreamTopology: topology,
	}, nil
}

func verifyArtifact(path string, checkpoint controlbackup.ComponentCheckpoint) error {
	verified, err := checkpointForArtifact(checkpoint.Component, checkpoint.BackupID, checkpoint.WriteFreezeID, path, checkpoint.CapturedAt, checkpoint.JetStreamTopology)
	if err != nil || verified.SHA256 != checkpoint.SHA256 || verified.SizeBytes != checkpoint.SizeBytes {
		return errors.New("artifact mismatch")
	}
	return nil
}

type jetStreamMetadata struct {
	Schema        string                          `json:"schema"`
	BackupID      string                          `json:"backup_id"`
	WriteFreezeID string                          `json:"write_freeze_id"`
	Topology      controlbackup.JetStreamTopology `json:"topology"`
	Streams       []streamSnapshotMetadata        `json:"streams"`
}

type streamSnapshotMetadata struct {
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"`
	State  json.RawMessage `json:"state"`
}

type apiError struct {
	Code        int    `json:"code"`
	ErrCode     uint16 `json:"err_code,omitempty"`
	Description string `json:"description"`
}

type snapshotResponse struct {
	Type   string          `json:"type"`
	Error  *apiError       `json:"error,omitempty"`
	Config json.RawMessage `json:"config"`
	State  json.RawMessage `json:"state"`
}

type restoreResponse struct {
	Type           string    `json:"type"`
	Error          *apiError `json:"error,omitempty"`
	DeliverSubject string    `json:"deliver_subject"`
}

type topologyContract struct {
	Streams   []topologyStream   `json:"streams"`
	Consumers []topologyConsumer `json:"consumers"`
}

type topologyStream struct {
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"`
}

type topologyConsumer struct {
	Stream string          `json:"stream"`
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"`
}

func (runtime *driverRuntime) captureJetStream(ctx context.Context, backupID, freezeID string) (controlbackup.ComponentCheckpoint, string) {
	nc, js, timeout, code := runtime.connectJetStream()
	if code != "" {
		return controlbackup.ComponentCheckpoint{}, code
	}
	defer nc.Close()
	if code := runtime.verifyJetStreamTopology(js, false); code != "" {
		return controlbackup.ComponentCheckpoint{}, code
	}
	temporary, err := os.MkdirTemp(runtime.plan.ArtifactDirectory, ".jetstream-snapshot-")
	if err != nil {
		return controlbackup.ComponentCheckpoint{}, "jetstream_snapshot_staging_failed"
	}
	defer os.RemoveAll(temporary)
	metadata := jetStreamMetadata{Schema: jetStreamBundleSchema, BackupID: backupID, WriteFreezeID: freezeID, Topology: controlbackup.RequiredJetStreamTopology()}
	for _, stream := range metadata.Topology.Streams {
		entry, code := snapshotStream(ctx, nc, timeout, temporary, stream)
		if code != "" {
			return controlbackup.ComponentCheckpoint{}, code
		}
		metadata.Streams = append(metadata.Streams, entry)
	}
	if code := runtime.verifyJetStreamTopology(js, false); code != "" {
		return controlbackup.ComponentCheckpoint{}, code
	}
	artifact := runtime.artifactPath(backupID, controlbackup.ComponentJetStream)
	if err := writeJetStreamArchive(artifact, temporary, metadata); err != nil {
		return controlbackup.ComponentCheckpoint{}, "jetstream_snapshot_archive_failed"
	}
	checkpoint, err := checkpointForArtifact(controlbackup.ComponentJetStream, backupID, freezeID, artifact, time.Now().UTC(), metadata.Topology)
	if err != nil {
		return controlbackup.ComponentCheckpoint{}, "jetstream_snapshot_invalid"
	}
	return checkpoint, ""
}

func snapshotStream(ctx context.Context, nc *nats.Conn, timeout time.Duration, directory, stream string) (streamSnapshotMetadata, string) {
	inbox := nats.NewInbox()
	subscription, err := nc.SubscribeSync(inbox)
	if err != nil {
		return streamSnapshotMetadata{}, "jetstream_snapshot_subscribe_failed"
	}
	defer subscription.Unsubscribe()
	request, _ := json.Marshal(map[string]any{"deliver_subject": inbox, "no_consumers": false, "chunk_size": 1 << 20, "jsck": true})
	message, err := nc.Request("$JS.API.STREAM.SNAPSHOT."+stream, request, timeout)
	if err != nil {
		return streamSnapshotMetadata{}, "jetstream_snapshot_request_failed"
	}
	var response snapshotResponse
	if controlbackup.DecodeStrictJSON(message.Data, &response) != nil || response.Type != jetStreamSnapshotType ||
		response.Error != nil || len(response.Config) == 0 || len(response.State) == 0 {
		return streamSnapshotMetadata{}, "jetstream_snapshot_rejected"
	}
	path := filepath.Join(directory, stream+".snap")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return streamSnapshotMetadata{}, "jetstream_snapshot_file_failed"
	}
	defer file.Close()
	for {
		message, err := subscription.NextMsgWithContext(ctx)
		if err != nil {
			return streamSnapshotMetadata{}, "jetstream_snapshot_timeout"
		}
		if len(message.Data) == 0 {
			break
		}
		if _, err := file.Write(message.Data); err != nil || message.Respond(nil) != nil {
			return streamSnapshotMetadata{}, "jetstream_snapshot_write_failed"
		}
	}
	if file.Sync() != nil || file.Close() != nil {
		return streamSnapshotMetadata{}, "jetstream_snapshot_sync_failed"
	}
	return streamSnapshotMetadata{Name: stream, Config: response.Config, State: response.State}, ""
}

func writeJetStreamArchive(path, directory string, metadata jetStreamMetadata) error {
	_ = os.Remove(path)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	writer := tar.NewWriter(file)
	encoded, err := json.Marshal(metadata)
	if err != nil || writeTarBytes(writer, "metadata.json", encoded) != nil {
		return errors.New("write JetStream metadata")
	}
	for _, stream := range metadata.Streams {
		if err := writeTarFile(writer, filepath.Join(directory, stream.Name+".snap"), stream.Name+".snap"); err != nil {
			return err
		}
	}
	if writer.Close() != nil || file.Sync() != nil || file.Close() != nil {
		return errors.New("sync JetStream archive")
	}
	ok = true
	return nil
}

func writeTarBytes(writer *tar.Writer, name string, value []byte) error {
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(value))}); err != nil {
		return err
	}
	_, err := writer.Write(value)
	return err
}

func writeTarFile(writer *tar.Writer, path, name string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return errors.New("invalid snapshot file")
	}
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: info.Size()}); err != nil {
		return err
	}
	_, err = io.Copy(writer, file)
	return err
}

func (runtime *driverRuntime) preflightJetStream(ctx context.Context, manifest controlbackup.Manifest) string {
	nc, js, _, code := runtime.connectJetStream()
	if code != "" {
		return "preflight_" + code
	}
	defer nc.Close()
	for _, stream := range controlbackup.RequiredJetStreamTopology().Streams {
		if _, err := js.StreamInfo(stream); err == nil {
			return "preflight_jetstream_target_not_empty"
		} else if !errors.Is(err, nats.ErrStreamNotFound) {
			return "preflight_jetstream_unavailable"
		}
	}
	account, err := js.AccountInfo()
	if err != nil {
		return "preflight_jetstream_capacity_unknown"
	}
	var size int64
	for _, checkpoint := range manifest.Checkpoints {
		if checkpoint.Component == controlbackup.ComponentJetStream {
			size = checkpoint.SizeBytes
		}
	}
	if account.Limits.MaxStore > 0 {
		limit := uint64(account.Limits.MaxStore)
		if account.Store > limit || uint64(size) > limit-account.Store {
			return "preflight_jetstream_capacity_insufficient"
		}
	}
	return ""
}

func (runtime *driverRuntime) restoreJetStream(ctx context.Context, checkpoint controlbackup.ComponentCheckpoint) string {
	artifact := runtime.artifactPath(checkpoint.BackupID, checkpoint.Component)
	if verifyArtifact(artifact, checkpoint) != nil {
		return "jetstream_restore_artifact_invalid"
	}
	temporary, err := os.MkdirTemp(runtime.plan.ArtifactDirectory, ".jetstream-restore-")
	if err != nil {
		return "jetstream_restore_staging_failed"
	}
	defer os.RemoveAll(temporary)
	metadata, err := extractJetStreamArchive(artifact, temporary)
	if err != nil || metadata.BackupID != checkpoint.BackupID || metadata.WriteFreezeID != checkpoint.WriteFreezeID ||
		len(metadata.Streams) != 3 {
		return "jetstream_restore_bundle_invalid"
	}
	nc, js, timeout, code := runtime.connectJetStream()
	if code != "" {
		return code
	}
	defer nc.Close()
	for _, stream := range metadata.Streams {
		request, _ := json.Marshal(map[string]any{"config": stream.Config, "state": stream.State})
		message, err := nc.Request("$JS.API.STREAM.RESTORE."+stream.Name, request, timeout)
		if err != nil {
			return "jetstream_restore_request_failed"
		}
		var response restoreResponse
		if controlbackup.DecodeStrictJSON(message.Data, &response) != nil || response.Type != jetStreamRestoreType ||
			response.Error != nil || response.DeliverSubject == "" {
			return "jetstream_restore_rejected"
		}
		file, err := os.Open(filepath.Join(temporary, stream.Name+".snap"))
		if err != nil {
			return "jetstream_restore_snapshot_missing"
		}
		buffer := make([]byte, 1<<20)
		for {
			count, readErr := file.Read(buffer)
			if count > 0 {
				if _, err := nc.Request(response.DeliverSubject, buffer[:count], timeout); err != nil {
					_ = file.Close()
					return "jetstream_restore_chunk_failed"
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = file.Close()
				return "jetstream_restore_read_failed"
			}
		}
		_ = file.Close()
		if _, err := nc.Request(response.DeliverSubject, nil, timeout); err != nil {
			return "jetstream_restore_finalize_failed"
		}
	}
	return runtime.verifyJetStreamTopology(js, false)
}

func extractJetStreamArchive(path, directory string) (jetStreamMetadata, error) {
	file, err := os.Open(path)
	if err != nil {
		return jetStreamMetadata{}, err
	}
	defer file.Close()
	reader := tar.NewReader(file)
	var metadata jetStreamMetadata
	seen := map[string]bool{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header.Size <= 0 || header.Size > 1<<40 || filepath.Base(header.Name) != header.Name || seen[header.Name] {
			return jetStreamMetadata{}, errors.New("invalid JetStream archive")
		}
		seen[header.Name] = true
		if header.Name == "metadata.json" {
			encoded, err := io.ReadAll(io.LimitReader(reader, 1<<20))
			if err != nil || int64(len(encoded)) != header.Size || controlbackup.DecodeStrictJSON(encoded, &metadata) != nil {
				return jetStreamMetadata{}, errors.New("invalid JetStream metadata")
			}
			continue
		}
		if !strings.HasSuffix(header.Name, ".snap") {
			return jetStreamMetadata{}, errors.New("unexpected JetStream archive entry")
		}
		output, err := os.OpenFile(filepath.Join(directory, header.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return jetStreamMetadata{}, err
		}
		written, copyErr := io.CopyN(output, reader, header.Size)
		closeErr := output.Close()
		if copyErr != nil || closeErr != nil || written != header.Size {
			return jetStreamMetadata{}, errors.New("extract JetStream snapshot")
		}
	}
	if metadata.Schema != jetStreamBundleSchema || !metadata.TopologyEqual(controlbackup.RequiredJetStreamTopology()) || len(seen) != 4 {
		return jetStreamMetadata{}, errors.New("incomplete JetStream archive")
	}
	return metadata, nil
}

func (metadata jetStreamMetadata) TopologyEqual(expected controlbackup.JetStreamTopology) bool {
	return topologyJSON(metadata.Topology) == topologyJSON(expected)
}

func topologyJSON(topology controlbackup.JetStreamTopology) string {
	encoded, _ := json.Marshal(topology)
	return string(encoded)
}

func (runtime *driverRuntime) compensateJetStream(ctx context.Context) string {
	nc, js, _, code := runtime.connectJetStream()
	if code != "" {
		return code
	}
	defer nc.Close()
	streams := controlbackup.RequiredJetStreamTopology().Streams
	for index := len(streams) - 1; index >= 0; index-- {
		if err := js.DeleteStream(streams[index]); err != nil && !errors.Is(err, nats.ErrStreamNotFound) {
			return "jetstream_compensation_failed"
		}
	}
	return ""
}

func (runtime *driverRuntime) verifyJetStreamTopology(js nats.JetStreamContext, allowMissing bool) string {
	contract, code := runtime.loadTopologyContract()
	if code != "" {
		return code
	}
	for _, stream := range contract.Streams {
		info, err := js.StreamInfo(stream.Name)
		if err != nil {
			if allowMissing && errors.Is(err, nats.ErrStreamNotFound) {
				continue
			}
			return "jetstream_topology_stream_mismatch"
		}
		var expected nats.StreamConfig
		if controlbackup.DecodeStrictJSON(stream.Config, &expected) != nil || !sameJSON(expected, info.Config) {
			return "jetstream_topology_stream_mismatch"
		}
	}
	for _, consumer := range contract.Consumers {
		info, err := js.ConsumerInfo(consumer.Stream, consumer.Name)
		if err != nil {
			return "jetstream_topology_consumer_mismatch"
		}
		var expected nats.ConsumerConfig
		if controlbackup.DecodeStrictJSON(consumer.Config, &expected) != nil || !sameJSON(expected, info.Config) {
			return "jetstream_topology_consumer_mismatch"
		}
	}
	return ""
}

func (runtime *driverRuntime) loadTopologyContract() (topologyContract, string) {
	encoded, err := controlbackup.ReadTrustedFile(runtime.plan.JetStream.TopologyFile)
	if err != nil {
		return topologyContract{}, "jetstream_topology_authority_unavailable"
	}
	replacements := map[string]string{
		"${NODE_ID}":            runtime.plan.JetStream.NodeID,
		"${NODE_ID_UNDERSCORE}": runtime.plan.JetStream.NodeIDUnderscore,
	}
	for placeholder, value := range replacements {
		encoded = bytes.ReplaceAll(encoded, []byte(placeholder), []byte(value))
	}
	var contract topologyContract
	if controlbackup.DecodeStrictJSON(encoded, &contract) != nil || len(contract.Streams) != 3 || len(contract.Consumers) != 4 {
		return topologyContract{}, "jetstream_topology_authority_invalid"
	}
	required := controlbackup.RequiredJetStreamTopology()
	for index, stream := range contract.Streams {
		if stream.Name != required.Streams[index] || len(stream.Config) == 0 {
			return topologyContract{}, "jetstream_topology_authority_invalid"
		}
	}
	for index, consumer := range contract.Consumers {
		expectedName := required.Consumers[index].Name
		expectedName = strings.ReplaceAll(expectedName, "${NODE_ID_UNDERSCORE}", runtime.plan.JetStream.NodeIDUnderscore)
		if consumer.Stream != required.Consumers[index].Stream || consumer.Name != expectedName || len(consumer.Config) == 0 {
			return topologyContract{}, "jetstream_topology_authority_invalid"
		}
	}
	return contract, ""
}

func sameJSON(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && canonicalJSONEqual(leftJSON, rightJSON)
}

func (runtime *driverRuntime) connectJetStream() (*nats.Conn, nats.JetStreamContext, time.Duration, string) {
	timeout := time.Duration(runtime.plan.JetStream.RequestTimeoutSeconds) * time.Second
	options := []nats.Option{nats.Timeout(timeout), nats.Name("cdnca-control-recovery-driver")}
	if runtime.plan.JetStream.CredentialsFile != "" {
		options = append(options, nats.UserCredentials(runtime.plan.JetStream.CredentialsFile))
	}
	if runtime.plan.JetStream.CAFile != "" {
		options = append(options, nats.RootCAs(runtime.plan.JetStream.CAFile))
	}
	if runtime.plan.JetStream.ClientCertFile != "" {
		options = append(options, nats.ClientCert(runtime.plan.JetStream.ClientCertFile, runtime.plan.JetStream.ClientKeyFile))
	}
	nc, err := nats.Connect(runtime.plan.JetStream.URL, options...)
	if err != nil {
		return nil, nil, 0, "jetstream_connect_failed"
	}
	js, err := nc.JetStream(nats.MaxWait(timeout))
	if err != nil {
		nc.Close()
		return nil, nil, 0, "jetstream_context_failed"
	}
	return nc, js, timeout, ""
}

func (runtime *driverRuntime) probe(ctx context.Context, name controlbackup.ProbeName, manifest controlbackup.Manifest, targetID string) string {
	switch name {
	case controlbackup.ProbeDNS:
		return runtime.probeDNS(ctx)
	case controlbackup.ProbeAgentReconnect:
		return runtime.probeAgents(ctx, targetID)
	default:
		return "unsupported_probe"
	}
}

func (runtime *driverRuntime) probeDNS(parent context.Context) string {
	deadline := time.Now().Add(time.Duration(runtime.plan.DNSProbe.TimeoutSeconds) * time.Second)
	want := append([]string(nil), runtime.plan.DNSProbe.ExpectedAddresses...)
	sort.Strings(want)
	for {
		ctx, cancel := context.WithTimeout(parent, minDuration(5*time.Second, time.Until(deadline)))
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, runtime.plan.DNSProbe.Hostname)
		cancel()
		got := make([]string, 0, len(addresses))
		for _, address := range addresses {
			got = append(got, address.IP.String())
		}
		sort.Strings(got)
		if err == nil && slicesEqual(got, want) {
			return ""
		}
		if time.Now().After(deadline) || !waitContext(parent, time.Duration(runtime.plan.DNSProbe.IntervalSeconds)*time.Second) {
			return "dns_cutover_timeout"
		}
	}
}

type agentReconnectResponse struct {
	Schema         string    `json:"schema"`
	TargetID       string    `json:"target_id"`
	ExpectedNodes  int       `json:"expected_nodes"`
	ConnectedNodes int       `json:"connected_nodes"`
	ObservedAt     time.Time `json:"observed_at"`
}

func (runtime *driverRuntime) probeAgents(parent context.Context, targetID string) string {
	client, err := mtlsHTTPClient(runtime.plan.AgentProbe.CAFile, runtime.plan.AgentProbe.ClientCertFile, runtime.plan.AgentProbe.ClientKeyFile)
	if err != nil {
		return "agent_reconnect_tls_invalid"
	}
	token, err := controlbackup.ReadTrustedFile(runtime.plan.AgentProbe.BearerTokenFile)
	if err != nil || len(bytes.TrimSpace(token)) == 0 {
		return "agent_reconnect_token_unavailable"
	}
	defer clearBytes(token)
	deadline := time.Now().Add(time.Duration(runtime.plan.AgentProbe.TimeoutSeconds) * time.Second)
	for {
		ctx, cancel := context.WithTimeout(parent, minDuration(10*time.Second, time.Until(deadline)))
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, runtime.plan.AgentProbe.URL, nil)
		request.Header.Set("Authorization", "Bearer "+string(bytes.TrimSpace(token)))
		response, err := client.Do(request)
		var result agentReconnectResponse
		if err == nil && response.Body != nil {
			decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
			decoder.DisallowUnknownFields()
			decodeErr := decoder.Decode(&result)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil && result.Schema == "cdnca.control-recovery.agent-reconnect/v1" &&
				result.TargetID == targetID && result.ExpectedNodes == runtime.plan.AgentProbe.ExpectedNodes &&
				result.ConnectedNodes >= result.ExpectedNodes && !result.ObservedAt.IsZero() {
				cancel()
				return ""
			}
		}
		cancel()
		if time.Now().After(deadline) || !waitContext(parent, time.Duration(runtime.plan.AgentProbe.IntervalSeconds)*time.Second) {
			return "agent_reconnect_timeout"
		}
	}
}

func (runtime *driverRuntime) kubernetesClient() (*http.Client, string, error) {
	namespace, err := controlbackup.ReadTrustedFile(runtime.plan.Kubernetes.NamespaceFile)
	if err != nil || !safeName.MatchString(string(bytes.TrimSpace(namespace))) {
		return nil, "", errors.New("invalid Kubernetes namespace")
	}
	token, err := controlbackup.ReadTrustedFile(runtime.plan.Kubernetes.TokenFile)
	if err != nil || len(bytes.TrimSpace(token)) == 0 {
		return nil, "", errors.New("invalid Kubernetes token")
	}
	client, err := caHTTPClient(runtime.plan.Kubernetes.CAFile)
	if err != nil {
		return nil, "", err
	}
	client.Transport = &bearerTransport{base: client.Transport, token: string(bytes.TrimSpace(token))}
	clearBytes(token)
	return client, string(bytes.TrimSpace(namespace)), nil
}

type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (transport *bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Header.Set("Authorization", "Bearer "+transport.token)
	return transport.base.RoundTrip(copy)
}

type scaleResource struct {
	Spec struct {
		Replicas int32 `json:"replicas"`
	} `json:"spec"`
	Status struct {
		Replicas int32 `json:"replicas"`
	} `json:"status"`
}

func getScale(ctx context.Context, client *http.Client, server, namespace, name string) (int32, int32, error) {
	endpoint := strings.TrimSuffix(server, "/") + "/apis/apps/v1/namespaces/" + url.PathEscape(namespace) + "/deployments/" + url.PathEscape(name) + "/scale"
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	response, err := client.Do(request)
	if err != nil {
		return 0, 0, err
	}
	defer response.Body.Close()
	var scale scaleResource
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusOK || decoder.Decode(&scale) != nil || scale.Spec.Replicas < 0 || scale.Status.Replicas < 0 {
		return 0, 0, errors.New("invalid Kubernetes scale response")
	}
	return scale.Spec.Replicas, scale.Status.Replicas, nil
}

func setScale(ctx context.Context, client *http.Client, server, namespace, name string, replicas int32) error {
	endpoint := strings.TrimSuffix(server, "/") + "/apis/apps/v1/namespaces/" + url.PathEscape(namespace) + "/deployments/" + url.PathEscape(name) + "/scale"
	body := []byte(`{"spec":{"replicas":` + strconv.FormatInt(int64(replicas), 10) + `}}`)
	request, _ := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/merge-patch+json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("Kubernetes scale mutation rejected")
	}
	return nil
}

func caHTTPClient(caFile string) (*http.Client, error) {
	encoded, err := controlbackup.ReadTrustedFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(encoded) {
		return nil, errors.New("invalid CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}, nil
}

func mtlsHTTPClient(caFile, certFile, keyFile string) (*http.Client, error) {
	client, err := caHTTPClient(caFile)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	return client, nil
}

func canonicalIP(value string) string {
	parsed := net.ParseIP(value)
	if parsed == nil || parsed.String() != value {
		return ""
	}
	return parsed.String()
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func minDuration(left, right time.Duration) time.Duration {
	if right <= 0 {
		return time.Millisecond
	}
	if left < right {
		return left
	}
	return right
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
