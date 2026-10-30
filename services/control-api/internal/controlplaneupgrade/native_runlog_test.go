//go:build !windows

package controlplaneupgrade

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

// Set CDNCA_RUNLOG_GOLDEN=1 to refresh the console's parser fixtures.
const runLogGoldenDirectory = "../../../../apps/web/src/pages/testdata/control-upgrade-runlog"

type nativeRunLogScenario struct {
	fixture  *nativeFixture
	server   *httptest.Server
	failures int
	mu       sync.Mutex
}

// newNativeRunLogScenario serves the candidate over HTTPS from a signed URL
// that carries a credential, and uses a clock that advances per reading so
// durations in the log are non-zero.
func newNativeRunLogScenario(t *testing.T) *nativeRunLogScenario {
	t.Helper()
	scenario := &nativeRunLogScenario{fixture: newNativeFixture(t)}
	fixture := scenario.fixture
	filename := filepath.Join(fixture.runner.executor.config.ReleaseRoot, "artifacts", fixture.next.Digest+".tar")
	encoded, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filename); err != nil {
		t.Fatal(err)
	}
	scenario.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scenario.mu.Lock()
		failing := scenario.failures > 0
		if failing {
			scenario.failures--
		}
		scenario.mu.Unlock()
		if failing {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(encoded)
	}))
	t.Cleanup(scenario.server.Close)
	fixture.runner.executor.client = scenario.server.Client()
	fixture.next.URL = scenario.server.URL + "/releases/control-1.5.0.tar?X-Signature=never-emit-signature&token=never-emit-token"
	fixture.bundle = nativeSignedBundleWithURL(t, fixture.bundle, fixture.next)
	base := fixture.runner.runner.now()
	var clockMu sync.Mutex
	tick := 0
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		tick++
		return base.Add(time.Duration(tick) * 700 * time.Millisecond)
	}
	fixture.runner.runner.now, fixture.runner.executor.now = clock, clock
	fixture.runner.runner.runLog.now = clock
	fixture.commands.journal = map[string][]string{
		"cdnca-control-api.service": {
			"2026-10-14T10:00:01+0800 control-api[601]: starting control-api version=1.5.0",
			"2026-10-14T10:00:01+0800 control-api[601]: database dsn=postgres://cdnca:never-emit-db@127.0.0.1:5432/cdnca",
			"2026-10-14T10:00:02+0800 control-api[601]: listening on 127.0.0.1:8080",
		},
		"cdnca-agent-gateway.service": {
			"2026-10-14T10:00:02+0800 agent-gateway[602]: gateway ready on :19444 token=never-emit-gateway",
		},
	}
	return scenario
}

func nativeSignedBundleWithURL(t *testing.T, original []byte, next Artifact) []byte {
	t.Helper()
	signed, err := entitlement.DecodeUpgradePlanArtifactBundle(original)
	if err != nil {
		t.Fatal(err)
	}
	signer := runnerTestSigner{privateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))}
	digest, err := hex.DecodeString(next.Digest)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &signed.Bundle.Forward
	manifest.Manifest.DownloadURL = next.URL
	manifest.Manifest.SHA256Digest = base64.RawURLEncoding.EncodeToString(digest)
	signature, err := entitlement.SignArtifactManifestV3(t.Context(), manifest.Manifest, signer)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ManifestSignature = base64.RawURLEncoding.EncodeToString(signature)
	resigned, err := entitlement.SignUpgradePlanArtifactBundle(t.Context(), signed.Bundle, signer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := resigned.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// publish runs PublishStatus into a fresh status directory and reads the
// projected run log back exactly as the unprivileged API does.
func (scenario *nativeRunLogScenario) publish(t *testing.T, name string) (RunLog, []byte) {
	t.Helper()
	directory := filepath.Join(resolvedTempDir(t), "status")
	if err := os.Mkdir(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(directory, "status.json")
	if err := scenario.fixture.runner.PublishStatus(t.Context(), filename); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filename + ".runlog.json")
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("published run log: %v %v", info, err)
	}
	encoded, err := os.ReadFile(filename + ".runlog.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"never-emit", "X-Signature", "/releases/control"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("published run log exposes %q: %s", secret, encoded)
		}
	}
	log, err := readNativeStandaloneRunLog(filename+".runlog.json", uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("API read: %v", err)
	}
	if os.Getenv("CDNCA_RUNLOG_GOLDEN") == "1" {
		pretty, err := json.MarshalIndent(log, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(runLogGoldenDirectory, name+".json"), append(pretty, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return log, encoded
}

func resolvedTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func runLogEvents(log RunLog) []string {
	events := make([]string, 0, len(log.Entries))
	for _, entry := range log.Entries {
		event := entry.Event
		if entry.Step != "" {
			event += ":" + entry.Step
		}
		if entry.Reason != "" {
			event += "/" + entry.Reason
		}
		events = append(events, event)
	}
	return events
}

func assertRunLogEvents(t *testing.T, log RunLog, want ...string) {
	t.Helper()
	got := strings.Join(runLogEvents(log), " ")
	at := 0
	for _, event := range want {
		index := strings.Index(got[at:], event)
		if index < 0 {
			t.Fatalf("missing %q after offset %d in:\n%s", event, at, strings.ReplaceAll(got, " ", "\n"))
		}
		at += index + len(event)
	}
}

func TestNativeRunLogRecordsSuccessfulUpgrade(t *testing.T) {
	scenario := newNativeRunLogScenario(t)
	receipt, err := scenario.fixture.runner.Run(t.Context(), scenario.fixture.bundle)
	if err != nil || receipt.Result != ResultApplied {
		t.Fatalf("Run() = %+v %v", receipt, err)
	}
	log, _ := scenario.publish(t, "success")
	assertRunLogEvents(t, log, "run_started", "step_started:expand", "services_verified", "artifact_download_started",
		"artifact_downloaded", "artifact_verified", "lineage_verified", "release_staged", "step_succeeded:expand",
		"candidate_version_checked", "maintenance_draining", "release_switched", "services_restarted",
		"health_check_started", "health_check_passed", "maintenance_active", "run_completed")
	for _, entry := range log.Entries {
		if entry.Event == "artifact_downloaded" && (entry.Bytes != scenario.fixture.next.Size || entry.DurationMS <= 0 ||
			entry.Host != "127.0.0.1" || entry.Version != "1.5.0") {
			t.Fatalf("download entry %+v", entry)
		}
	}
	if len(log.Programs) != 3 || log.Programs[0].Unit != "cdnca-control-api.service" || log.Programs[0].Trigger != "run_completed" ||
		len(log.Programs[0].Lines) != 3 || !strings.Contains(log.Programs[0].Lines[1], runLogRedacted) ||
		log.Programs[2].Unit != "control-upgrade-runner" || !log.Programs[2].Unavailable {
		t.Fatalf("programs %+v", log.Programs)
	}
	if !strings.Contains(strings.Join(scenario.fixture.commands.journalCalls, " "), "--unit=cdnca-agent-gateway.service") {
		t.Fatalf("journal calls %v", scenario.fixture.commands.journalCalls)
	}
}

func TestNativeRunLogRecordsDownloadFailureAndRetry(t *testing.T) {
	scenario := newNativeRunLogScenario(t)
	scenario.failures = 1
	if _, err := scenario.fixture.runner.Run(t.Context(), scenario.fixture.bundle); !errors.Is(err, ErrArtifactUnavailable) {
		t.Fatalf("first attempt: %v", err)
	}
	log, _ := scenario.publish(t, "download-failed")
	assertRunLogEvents(t, log, "run_started", "artifact_download_started", "artifact_download_failed/http_status",
		"step_failed:expand/artifact_unavailable", "retry_scheduled:expand")
	if log.Entries[len(log.Entries)-1].Event != "retry_scheduled" || len(log.Programs) != 0 {
		t.Fatalf("a retryable failure must not close the run: %+v", log.Entries[len(log.Entries)-1])
	}
	for _, entry := range log.Entries {
		if entry.Event == "artifact_download_failed" && entry.HTTPStatus != http.StatusServiceUnavailable {
			t.Fatalf("download failure %+v", entry)
		}
	}
	receipt, err := scenario.fixture.runner.Run(t.Context(), scenario.fixture.bundle)
	if err != nil || receipt.Result != ResultApplied {
		t.Fatalf("retry: %+v %v", receipt, err)
	}
	log, _ = scenario.publish(t, "download-retried")
	assertRunLogEvents(t, log, "retry_scheduled:expand", "run_resumed:verified", "artifact_downloaded", "run_completed")
	if log.Attempts != 2 {
		t.Fatalf("attempts=%d", log.Attempts)
	}
}

func TestNativeRunLogExplainsRejectedLineage(t *testing.T) {
	scenario := newNativeRunLogScenario(t)
	fixture := scenario.fixture
	candidate := fixture.manifests[fixture.next.Digest]
	candidate.Source.PreviousCommit = strings.Repeat("8", 40)
	fixture.replaceCandidate(t, candidate, fixture.contents[fixture.next.Digest])
	receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
	if !errors.Is(err, ErrCandidateRejected) || receipt.Result != ResultFailed || receipt.ErrorCode != "expand_failed" {
		t.Fatalf("Run() = %+v %v", receipt, err)
	}
	log, _ := scenario.publish(t, "lineage-rejected")
	assertRunLogEvents(t, log, "run_started", "artifact_cached", "lineage_rejected/previous_commit_mismatch",
		"step_failed:expand/candidate_rejected", "run_failed")
	if last := log.Entries[len(log.Entries)-1]; last.Level != "error" || last.ErrorCode != "expand_failed" {
		t.Fatalf("terminal entry %+v", last)
	}
}

func TestNativeRunLogRecordsHealthFailureRollback(t *testing.T) {
	scenario := newNativeRunLogScenario(t)
	scenario.fixture.commands.failHealth = scenario.fixture.next.Digest
	receipt, err := scenario.fixture.runner.Run(t.Context(), scenario.fixture.bundle)
	if !errors.Is(err, ErrRolledBack) || receipt.Result != ResultRolledBack {
		t.Fatalf("Run() = %+v %v", receipt, err)
	}
	log, _ := scenario.publish(t, "health-rolled-back")
	assertRunLogEvents(t, log, "release_switched", "services_restarted", "health_check_started",
		"health_check_waiting/control_api_not_ready", "health_check_timeout/control_api_not_ready", "step_failed:health/timeout",
		"rollback_started", "release_switched", "services_restarted", "health_check_passed", "maintenance_active",
		"rollback_succeeded", "run_rolled_back")
	if last := log.Entries[len(log.Entries)-1]; last.Level != "warning" || last.ErrorCode != "target_health_failed" {
		t.Fatalf("terminal entry %+v", last)
	}
	if log.Programs[0].Trigger != "run_rolled_back" {
		t.Fatalf("programs %+v", log.Programs)
	}
	// The failing endpoint and its answer, logged once rather than per poll.
	host := strings.TrimPrefix(scenario.fixture.runner.executor.config.ControlHealthURL, "http://")
	host = strings.TrimSuffix(host, "/control")
	waiting := 0
	for _, entry := range log.Entries {
		switch entry.Event {
		case "health_check_waiting":
			waiting++
			if entry.Host != host || entry.HTTPStatus != http.StatusServiceUnavailable {
				t.Fatalf("waiting entry %+v, want host %s HTTP 503", entry, host)
			}
		case "health_check_timeout":
			if entry.Reason != "control_api_not_ready" || entry.Host != host || entry.HTTPStatus != http.StatusServiceUnavailable {
				t.Fatalf("timeout entry %+v", entry)
			}
		}
	}
	if waiting != 1 {
		t.Fatalf("health_check_waiting logged %d times", waiting)
	}
}

func TestNativeRunLogNamesStaleConsoleIndex(t *testing.T) {
	scenario := newNativeRunLogScenario(t)
	scenario.fixture.commands.staleIndex = scenario.fixture.old.Digest
	receipt, err := scenario.fixture.runner.Run(t.Context(), scenario.fixture.bundle)
	if !errors.Is(err, ErrRolledBack) || receipt.Result != ResultRolledBack {
		t.Fatalf("Run() = %+v %v", receipt, err)
	}
	log, _ := scenario.publish(t, "stale-index")
	assertRunLogEvents(t, log, "health_check_waiting/console_index_mismatch", "health_check_timeout/console_index_mismatch",
		"rollback_started", "health_check_passed", "run_rolled_back")
	for _, entry := range log.Entries {
		if entry.Event == "health_check_waiting" && entry.HTTPStatus != http.StatusOK {
			t.Fatalf("stale index answered %+v", entry)
		}
	}
}

func TestNativeRunLogIsNotPublishedForAnotherPlan(t *testing.T) {
	scenario := newNativeRunLogScenario(t)
	if _, err := scenario.fixture.runner.Run(t.Context(), scenario.fixture.bundle); err != nil {
		t.Fatal(err)
	}
	scenario.fixture.runner.runner.runLog.begin("00000000-0000-4000-8000-000000000123", 99)
	scenario.fixture.runner.runner.runLog.add(RunLogEntry{Level: "info", Event: "run_started"})
	directory := filepath.Join(resolvedTempDir(t), "status")
	if err := os.Mkdir(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := scenario.fixture.runner.PublishStatus(t.Context(), filepath.Join(directory, "status.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, "status.json.runlog.json")); !os.IsNotExist(err) {
		t.Fatalf("run log of a different plan published: %v", err)
	}
}
