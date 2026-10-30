package controlplaneupgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// RunLogSchema is the operator-readable upgrade log ("script log" plus a
// bounded tail of the affected services' journals). Like history.json it is
// evidence only: recovery never reads it and a write failure never fails a
// step. Entries carry stable event/reason codes; the console renders them per
// locale, so no user-facing text is produced here.
const RunLogSchema = "cdnca.control-plane-upgrade-runlog/v1"

const (
	runLogFilename        = "runlog.json"
	maxRunLogEntries      = 400
	runLogKeptHead        = 40
	maxRunLogBytes        = 1 << 20
	maxRunLogPrograms     = 3
	maxRunLogProgramLines = 80
	maxRunLogLineBytes    = 512
)

type RunLogEntry struct {
	At         int64  `json:"at"`
	Level      string `json:"level"`
	Event      string `json:"event"`
	Step       string `json:"step,omitempty"`
	Reason     string `json:"reason,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
	Version    string `json:"version,omitempty"`
	Host       string `json:"host,omitempty"`
	Unit       string `json:"unit,omitempty"`
	Bytes      int64  `json:"bytes,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Attempt    int    `json:"attempt,omitempty"`
	Count      int    `json:"count,omitempty"`
	// Migrations names the append-only migrations a database step covers.
	Migrations []string `json:"migrations,omitempty"`
}

// RunLogProgram is the latest bounded, redacted journal tail of one unit.
type RunLogProgram struct {
	Unit        string   `json:"unit"`
	CapturedAt  int64    `json:"captured_at"`
	Trigger     string   `json:"trigger"`
	Unavailable bool     `json:"unavailable,omitempty"`
	Lines       []string `json:"lines"`
}

type RunLog struct {
	Schema    string          `json:"schema"`
	PlanID    string          `json:"plan_id"`
	Sequence  uint64          `json:"sequence"`
	StartedAt int64           `json:"started_at"`
	Attempts  int             `json:"attempts"`
	Dropped   int             `json:"dropped"`
	Entries   []RunLogEntry   `json:"entries"`
	Programs  []RunLogProgram `json:"programs"`
}

var (
	runLogCode    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	runLogVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`)
	runLogHost    = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.:\[\]-]{0,252}$`)
	runLogUnit    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,126}$`)
)

func validRunLogEntry(entry RunLogEntry) bool {
	optional := func(value string, pattern *regexp.Regexp) bool { return value == "" || pattern.MatchString(value) }
	return entry.At > 0 && (entry.Level == "info" || entry.Level == "warning" || entry.Level == "error") &&
		runLogCode.MatchString(entry.Event) && optional(entry.Step, runLogCode) && optional(entry.Reason, runLogCode) &&
		optional(entry.ErrorCode, planErrorCode) && optional(entry.Version, runLogVersion) &&
		optional(entry.Host, runLogHost) && optional(entry.Unit, runLogUnit) &&
		entry.Bytes >= 0 && entry.Bytes <= 1<<40 && entry.DurationMS >= 0 && entry.DurationMS <= int64(24*time.Hour/time.Millisecond) &&
		entry.HTTPStatus >= 0 && entry.HTTPStatus <= 999 && entry.Attempt >= 0 && entry.Attempt <= 1<<20 &&
		entry.Count >= 0 && entry.Count <= 1<<20 && validRunLogMigrations(entry.Migrations)
}

func validRunLogMigrations(names []string) bool {
	if names != nil && (len(names) == 0 || len(names) > maxMigrationsPerPlan) {
		return false
	}
	for _, name := range names {
		if len(name) > 96 || !migrationIdentifier.MatchString(name) {
			return false
		}
	}
	return true
}

func validRunLog(log RunLog) bool {
	if log.Schema != RunLogSchema || log.PlanID == "" || len(log.PlanID) > 128 || log.Sequence == 0 ||
		log.StartedAt <= 0 || log.Attempts < 1 || log.Dropped < 0 || len(log.Entries) == 0 ||
		len(log.Entries) > maxRunLogEntries || len(log.Programs) > maxRunLogPrograms || log.Programs == nil {
		return false
	}
	previous := log.StartedAt
	for _, entry := range log.Entries {
		if !validRunLogEntry(entry) || entry.At < previous {
			return false
		}
		previous = entry.At
	}
	units := make(map[string]bool, len(log.Programs))
	for _, program := range log.Programs {
		if !runLogUnit.MatchString(program.Unit) || units[program.Unit] || program.CapturedAt <= 0 ||
			!runLogCode.MatchString(program.Trigger) || program.Lines == nil || len(program.Lines) > maxRunLogProgramLines ||
			(program.Unavailable && len(program.Lines) != 0) {
			return false
		}
		units[program.Unit] = true
		for _, line := range program.Lines {
			if len(line) > maxRunLogLineBytes || !utf8.ValidString(line) || strings.IndexFunc(line, runLogControl) >= 0 {
				return false
			}
		}
	}
	return true
}

// DecodeRunLog strictly decodes a published run log.
func DecodeRunLog(encoded []byte) (RunLog, error) {
	if len(encoded) == 0 || len(encoded) > maxRunLogBytes {
		return RunLog{}, ErrCorruptState
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var log RunLog
	if decoder.Decode(&log) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || !validRunLog(log) {
		return RunLog{}, ErrCorruptState
	}
	return log, nil
}

func runLogControl(r rune) bool {
	return r != '\t' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0))
}

const runLogRedacted = "[REDACTED]"

var (
	runLogANSI       = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]`)
	runLogPEM        = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----`)
	runLogPEMEnd     = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----`)
	runLogUserinfo   = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`)
	runLogURLQuery   = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s?#"']+)\?[^\s"'<>]*`)
	runLogBearer     = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	runLogJWT        = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`)
	runLogFlagSecret = regexp.MustCompile(`(?i)(--?[a-z0-9_-]*(?:password|passwd|token|secret|api[_-]?key|private[_-]?key)[a-z0-9_-]*)(=|\s+)("[^"]*"|'[^']*'|[^\s"']+)`)
	runLogKeySecret  = regexp.MustCompile(`(?i)("?[a-z0-9_.-]*(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|authorization|credential|signature|cookie)[a-z0-9_.-]*"?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;"'}]+)`)
)

// redactRunLogLine hides credentials that service logs may contain: URL query
// strings (signed download URLs), URL userinfo, bearer/basic credentials,
// JWTs, secret-named flags and key/value pairs. It is idempotent.
func redactRunLogLine(line string) string {
	if runLogPEM.MatchString(line) || runLogPEMEnd.MatchString(line) {
		return runLogRedacted + " (private key)"
	}
	line = runLogUserinfo.ReplaceAllString(line, "${1}"+runLogRedacted+"@")
	line = runLogURLQuery.ReplaceAllString(line, "${1}?"+runLogRedacted)
	line = runLogJWT.ReplaceAllString(line, runLogRedacted)
	line = runLogBearer.ReplaceAllString(line, "${1} "+runLogRedacted)
	line = runLogFlagSecret.ReplaceAllString(line, "${1}${2}"+runLogRedacted)
	return runLogKeySecret.ReplaceAllString(line, "${1}"+runLogRedacted)
}

// SanitizeRunLogLine makes one journal line safe to show an operator: valid
// UTF-8, no terminal control sequences, credentials redacted and at most
// maxRunLogLineBytes long. The raw line is capped before redaction so a long
// line cannot hide a secret past the redaction window.
func SanitizeRunLogLine(line string) string {
	if len(line) > 4*maxRunLogLineBytes {
		line = line[:4*maxRunLogLineBytes]
	}
	line = strings.ToValidUTF8(line, "�")
	line = runLogANSI.ReplaceAllString(line, "")
	line = strings.Map(func(r rune) rune {
		if runLogControl(r) {
			return -1
		}
		return r
	}, line)
	line = redactRunLogLine(line)
	if len(line) > maxRunLogLineBytes {
		cut := maxRunLogLineBytes - len("…")
		for cut > 0 && !utf8.RuneStart(line[cut]) {
			cut--
		}
		line = line[:cut] + "…"
	}
	return line
}

// sanitizeRunLogLines sanitizes a journal tail and drops private key bodies
// that span lines between BEGIN and END markers.
func sanitizeRunLogLines(lines []string) []string {
	result := make([]string, 0, len(lines))
	inKey := false
	for _, line := range lines {
		switch {
		case runLogPEMEnd.MatchString(line):
			inKey = false
			continue
		case inKey:
			continue
		case runLogPEM.MatchString(line):
			inKey = true
			result = append(result, runLogRedacted+" (private key)")
			continue
		}
		result = append(result, SanitizeRunLogLine(line))
	}
	if len(result) > maxRunLogProgramLines {
		result = result[len(result)-maxRunLogProgramLines:]
	}
	return result
}

// runLogWriter keeps the current plan's run log. The runner goroutine appends;
// the status publisher reads snapshots concurrently, so every access locks.
type runLogWriter struct {
	mu   sync.Mutex
	root string
	now  func() time.Time
	log  *RunLog
}

func newRunLogWriter(root string, now func() time.Time) *runLogWriter {
	writer := &runLogWriter{root: root, now: now}
	if encoded, err := os.ReadFile(filepath.Join(root, runLogFilename)); err == nil {
		if log, err := DecodeRunLog(encoded); err == nil {
			writer.log = &log
		}
	}
	return writer
}

// begin starts or continues the log for one plan and returns the attempt.
func (writer *runLogWriter) begin(planID string, sequence uint64) int {
	if writer == nil {
		return 0
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.log == nil || writer.log.PlanID != planID || writer.log.Sequence != sequence {
		writer.log = &RunLog{Schema: RunLogSchema, PlanID: planID, Sequence: sequence,
			StartedAt: writer.now().UTC().Unix(), Programs: []RunLogProgram{}}
	}
	writer.log.Attempts++
	return writer.log.Attempts
}

func (writer *runLogWriter) add(entry RunLogEntry) {
	if writer == nil {
		return
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.log == nil {
		return
	}
	entry.At = writer.now().UTC().Unix()
	entry.Migrations = append([]string(nil), entry.Migrations...)
	if count := len(writer.log.Entries); count > 0 && entry.At < writer.log.Entries[count-1].At {
		entry.At = writer.log.Entries[count-1].At
	}
	if entry.At < writer.log.StartedAt {
		entry.At = writer.log.StartedAt
	}
	if !validRunLogEntry(entry) {
		// A malformed field (e.g. an unexpected version string) must not hide
		// the event itself.
		entry = RunLogEntry{At: entry.At, Level: entry.Level, Event: entry.Event, Step: entry.Step, Reason: entry.Reason}
		if !validRunLogEntry(entry) {
			return
		}
	}
	writer.log.Entries = append(writer.log.Entries, entry)
	if len(writer.log.Entries) > maxRunLogEntries {
		// Keep how the run began and its newest lines; count what was skipped.
		excess := len(writer.log.Entries) - maxRunLogEntries
		writer.log.Entries = append(writer.log.Entries[:runLogKeptHead], writer.log.Entries[runLogKeptHead+excess:]...)
		writer.log.Dropped += excess
	}
	writer.persistLocked()
}

func (writer *runLogWriter) setProgram(program RunLogProgram) {
	if writer == nil {
		return
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.log == nil || !runLogUnit.MatchString(program.Unit) || !runLogCode.MatchString(program.Trigger) {
		return
	}
	program.CapturedAt = writer.now().UTC().Unix()
	if program.Unavailable || program.Lines == nil {
		program.Lines = []string{}
	} else {
		program.Lines = sanitizeRunLogLines(program.Lines)
	}
	for index := range writer.log.Programs {
		if writer.log.Programs[index].Unit == program.Unit {
			writer.log.Programs[index] = program
			writer.persistLocked()
			return
		}
	}
	if len(writer.log.Programs) < maxRunLogPrograms {
		writer.log.Programs = append(writer.log.Programs, program)
		writer.persistLocked()
	}
}

func (writer *runLogWriter) startedAt() int64 {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.log == nil {
		return 0
	}
	return writer.log.StartedAt
}

// snapshot returns a deep copy for publication.
func (writer *runLogWriter) snapshot() (RunLog, bool) {
	if writer == nil {
		return RunLog{}, false
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.log == nil || len(writer.log.Entries) == 0 {
		return RunLog{}, false
	}
	copied := *writer.log
	copied.Entries = append([]RunLogEntry(nil), writer.log.Entries...)
	copied.Programs = make([]RunLogProgram, len(writer.log.Programs))
	for index, program := range writer.log.Programs {
		program.Lines = append([]string{}, program.Lines...)
		copied.Programs[index] = program
	}
	return copied, true
}

func (writer *runLogWriter) persistLocked() {
	encoded, ok := encodeRunLog(writer.log)
	if !ok {
		return
	}
	// Evidence only, like history.json: atomic replace without fsync, so a
	// chatty retry loop does not cost one disk flush per line.
	temporary, err := os.CreateTemp(writer.root, ".runlog-*.tmp")
	if err != nil {
		return
	}
	defer os.Remove(temporary.Name())
	if temporary.Chmod(0o600) != nil {
		_ = temporary.Close()
		return
	}
	if _, err := temporary.Write(encoded); err != nil || temporary.Close() != nil {
		_ = temporary.Close()
		return
	}
	_ = os.Rename(temporary.Name(), filepath.Join(writer.root, runLogFilename))
}

// encodeRunLog marshals log within maxRunLogBytes, halving the program tails
// (oldest lines first) if JSON escaping made it too large.
func encodeRunLog(log *RunLog) ([]byte, bool) {
	if log == nil || len(log.Entries) == 0 {
		return nil, false
	}
	for {
		encoded, err := json.Marshal(log)
		if err != nil {
			return nil, false
		}
		if len(encoded) <= maxRunLogBytes {
			return encoded, true
		}
		trimmed := false
		for index := range log.Programs {
			if lines := log.Programs[index].Lines; len(lines) > 0 {
				log.Programs[index].Lines = lines[len(lines)/2+len(lines)%2:]
				trimmed = true
			}
		}
		if !trimmed {
			return nil, false
		}
	}
}

type runLogContextKey struct{}

func withRunLog(ctx context.Context, writer *runLogWriter) context.Context {
	if writer == nil {
		return ctx
	}
	return context.WithValue(ctx, runLogContextKey{}, writer)
}

func runLogFrom(ctx context.Context) *runLogWriter {
	writer, _ := ctx.Value(runLogContextKey{}).(*runLogWriter)
	return writer
}

// logRun appends one event to the run log carried by ctx, if any.
func logRun(ctx context.Context, entry RunLogEntry) {
	runLogFrom(ctx).add(entry)
}
