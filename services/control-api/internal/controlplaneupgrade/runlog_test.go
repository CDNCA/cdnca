package controlplaneupgrade

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func TestSanitizeRunLogLineRedactsCredentials(t *testing.T) {
	cases := map[string]string{
		"GET https://dl.example.com/full.tar?X-Amz-Signature=abc123&token=s3cr3t ok": "s3cr3t",
		"dsn=postgres://cdnca:hunter2@127.0.0.1:5432/cdnca":                          "hunter2",
		"Authorization: Bearer abcdefghijklmnop.qrstuvwx":                            "abcdefghijklmnop",
		`{"level":"info","api_key":"live-key-123","msg":"x"}`:                        "live-key-123",
		"password=Pa55word! user=admin":                                              "Pa55word!",
		"starting --enrollment-token 0123456789abcdef --listen :443":                 "0123456789abcdef",
		"session eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlLXZhbHVl issued":   "eyJzdWIiOiJ4In0",
		"-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXk=":                       "b3BlbnNzaC1rZXk",
	}
	for line, secret := range cases {
		got := SanitizeRunLogLine(line)
		if strings.Contains(got, secret) || !strings.Contains(got, runLogRedacted) {
			t.Errorf("SanitizeRunLogLine(%q) = %q, still exposes %q", line, got, secret)
		}
		if again := SanitizeRunLogLine(got); again != got {
			t.Errorf("sanitizer not idempotent: %q -> %q", got, again)
		}
	}
	plain := "2026-10-14T10:00:00+0800 control-api[42]: listening on 127.0.0.1:8080 version=1.5.0"
	if got := SanitizeRunLogLine(plain); got != plain {
		t.Fatalf("plain line changed: %q", got)
	}
}

func TestSanitizeRunLogLineStripsControlsAndBoundsLength(t *testing.T) {
	got := SanitizeRunLogLine("\x1b[31mred\x1b[0m\x00\rbell\x07\ttab " + strings.Repeat("界", 400) + string([]byte{0xff}))
	if strings.ContainsAny(got, "\x1b\x00\r\x07") || !strings.HasPrefix(got, "redbell\ttab ") {
		t.Fatalf("controls kept: %q", got)
	}
	if len(got) > maxRunLogLineBytes || !utf8.ValidString(got) || !strings.HasSuffix(got, "…") {
		t.Fatalf("len=%d valid=%v suffix=%q", len(got), utf8.ValidString(got), got[len(got)-4:])
	}
	// A secret beyond the display window must not survive the cut either.
	long := strings.Repeat("x", 600) + " token=abcdef0123456789"
	if got := SanitizeRunLogLine(long); strings.Contains(got, "abcdef") {
		t.Fatalf("truncation exposed a secret: %q", got)
	}
}

func TestSanitizeRunLogLinesDropsMultilinePrivateKey(t *testing.T) {
	lines := sanitizeRunLogLines([]string{"before", "-----BEGIN PRIVATE KEY-----", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
		"c2VjcmV0LWJvZHk=", "-----END PRIVATE KEY-----", "after"})
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "MIIEvQ") || strings.Contains(joined, "c2VjcmV0") || len(lines) != 3 || lines[2] != "after" {
		t.Fatalf("private key body kept: %q", lines)
	}
}

func newTestRunLogWriter(t *testing.T) (*runLogWriter, string) {
	t.Helper()
	root := t.TempDir()
	clock := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	return newRunLogWriter(root, func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(time.Second)
		return clock
	}), root
}

func TestRunLogWriterBoundsEntriesAndPersistsDecodableFile(t *testing.T) {
	writer, root := newTestRunLogWriter(t)
	if attempt := writer.begin("plan-a", 7); attempt != 1 {
		t.Fatalf("attempt=%d", attempt)
	}
	writer.add(RunLogEntry{Level: "info", Event: "run_started", Version: "1.5.0"})
	for index := 0; index < 3*maxRunLogEntries; index++ {
		writer.add(RunLogEntry{Level: "warning", Event: "health_check_waiting", Reason: "http_not_ready", DurationMS: int64(index)})
	}
	// Invalid optional fields degrade to a bare event instead of disappearing.
	writer.add(RunLogEntry{Level: "error", Event: "artifact_rejected", Version: "bad version ../.."})
	for unit := 0; unit < maxRunLogPrograms+2; unit++ {
		lines := make([]string, 2*maxRunLogProgramLines)
		for index := range lines {
			lines[index] = strings.Repeat("<&>", 300)
		}
		writer.setProgram(RunLogProgram{Unit: "svc-" + string(rune('a'+unit)) + ".service", Trigger: "run_completed", Lines: lines})
	}
	encoded, err := os.ReadFile(filepath.Join(root, runLogFilename))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, runLogFilename))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode(), err)
	}
	log, err := DecodeRunLog(encoded)
	if err != nil || len(encoded) > maxRunLogBytes {
		t.Fatalf("decode: %v size=%d", err, len(encoded))
	}
	last := log.Entries[len(log.Entries)-1]
	if len(log.Entries) != maxRunLogEntries || log.Dropped != 2*maxRunLogEntries+2 || log.Entries[0].Event != "run_started" ||
		last.Event != "artifact_rejected" || last.Version != "" || len(log.Programs) != maxRunLogPrograms {
		t.Fatalf("entries=%d dropped=%d first=%+v last=%+v programs=%d", len(log.Entries), log.Dropped, log.Entries[0], last, len(log.Programs))
	}
	for _, program := range log.Programs {
		if len(program.Lines) == 0 || len(program.Lines) > maxRunLogProgramLines {
			t.Fatalf("program %s lines=%d", program.Unit, len(program.Lines))
		}
	}
	// A restarted runner continues the same plan's log as a new attempt.
	reopened := newRunLogWriter(root, time.Now)
	if attempt := reopened.begin("plan-a", 7); attempt != 2 {
		t.Fatalf("resumed attempt=%d", attempt)
	}
	if attempt := reopened.begin("plan-b", 8); attempt != 1 {
		t.Fatalf("new plan attempt=%d", attempt)
	}
}

func TestRunLogWriterConcurrentAppendAndSnapshot(t *testing.T) {
	writer, _ := newTestRunLogWriter(t)
	writer.begin("plan-a", 1)
	var group sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		group.Add(2)
		go func() {
			defer group.Done()
			for index := 0; index < 150; index++ {
				writer.add(RunLogEntry{Level: "info", Event: "step_started", Step: "expand"})
				writer.setProgram(RunLogProgram{Unit: "control.service", Trigger: "run_completed", Lines: []string{"line"}})
			}
		}()
		go func() {
			defer group.Done()
			for index := 0; index < 100; index++ {
				if log, ok := writer.snapshot(); ok {
					if encoded, ok := encodeRunLog(&log); !ok {
						t.Error("snapshot not encodable")
					} else if _, err := DecodeRunLog(encoded); err != nil {
						t.Errorf("snapshot invalid: %v", err)
					}
				}
			}
		}()
	}
	group.Wait()
	log, ok := writer.snapshot()
	if !ok || len(log.Entries) != maxRunLogEntries || log.Dropped != 4*150-maxRunLogEntries {
		t.Fatalf("entries=%d dropped=%d", len(log.Entries), log.Dropped)
	}
}

func TestDecodeRunLogRejectsMalformedLogs(t *testing.T) {
	valid := RunLog{Schema: RunLogSchema, PlanID: "plan", Sequence: 1, StartedAt: 10, Attempts: 1,
		Entries:  []RunLogEntry{{At: 10, Level: "info", Event: "run_started"}},
		Programs: []RunLogProgram{{Unit: "a.service", CapturedAt: 11, Trigger: "run_completed", Lines: []string{"ok"}}}}
	encode := func(log RunLog) []byte {
		encoded, err := json.Marshal(log)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	if _, err := DecodeRunLog(encode(valid)); err != nil {
		t.Fatalf("valid log rejected: %v", err)
	}
	mutations := map[string]func(*RunLog){
		"schema":        func(log *RunLog) { log.Schema = "other" },
		"level":         func(log *RunLog) { log.Entries[0].Level = "debug" },
		"event text":    func(log *RunLog) { log.Entries[0].Event = "下载失败" },
		"time order":    func(log *RunLog) { log.Entries = append(log.Entries, RunLogEntry{At: 9, Level: "info", Event: "x"}) },
		"control char":  func(log *RunLog) { log.Programs[0].Lines = []string{"\x1b[31mred"} },
		"line too long": func(log *RunLog) { log.Programs[0].Lines = []string{strings.Repeat("a", maxRunLogLineBytes+1)} },
		"duplicate unit": func(log *RunLog) {
			log.Programs = append(log.Programs, log.Programs[0])
		},
		"nil programs":   func(log *RunLog) { log.Programs = nil },
		"migration name": func(log *RunLog) { log.Entries[0].Migrations = []string{"../004_step"} },
	}
	for name, mutate := range mutations {
		copied := valid
		copied.Entries = append([]RunLogEntry(nil), valid.Entries...)
		copied.Programs = append([]RunLogProgram(nil), valid.Programs...)
		mutate(&copied)
		if _, err := DecodeRunLog(encode(copied)); !errors.Is(err, ErrCorruptState) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	if _, err := DecodeRunLog(append(encode(valid), []byte(`{}`)...)); !errors.Is(err, ErrCorruptState) {
		t.Fatal("trailing data accepted")
	}
}

func TestRunFailureReasonNeverEchoesErrorText(t *testing.T) {
	cases := map[error]string{
		ErrArtifactUnavailable:                               "artifact_unavailable",
		errors.Join(ErrCandidateRejected, ErrTargetMismatch): "candidate_rejected",
		context.DeadlineExceeded:                             "timeout",
		ErrPlanConflict:                                      "plan_conflict",
		ErrTargetMismatch:                                    "target_mismatch",
		errors.New("https://x?t=1"):                          "unexpected",
	}
	for err, want := range cases {
		if got := runFailureReason(err); got != want {
			t.Errorf("runFailureReason(%v) = %q, want %q", err, got, want)
		}
	}
}
