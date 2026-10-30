package controlbackuphistory

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackup"
	"github.com/google/uuid"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

var (
	ErrInvalidConfig = errors.New("backup history configuration is invalid")
	ErrInvalidInput  = errors.New("backup history input is invalid")
	ErrInvalidCursor = errors.New("backup history cursor is invalid")
	ErrUnavailable   = errors.New("backup history is unavailable")
)

type Record struct {
	BackupID           string     `json:"backup_id"`
	StartedAt          *time.Time `json:"started_at,omitempty"`
	CompletedAt        *time.Time `json:"completed_at,omitempty"`
	State              string     `json:"state"`
	ResultCode         string     `json:"result_code"`
	ManifestSHA256     string     `json:"manifest_sha256,omitempty"`
	RecoveryPointAt    *time.Time `json:"recovery_point_at,omitempty"`
	ObservedRPOSeconds *int64     `json:"observed_rpo_seconds,omitempty"`
	OutcomeUnknown     bool       `json:"outcome_unknown"`
	SignatureValid     bool       `json:"signature_valid"`
	TerminalState      string     `json:"terminal_state"`
	ReasonCode         string     `json:"reason_code"`
}

type Page struct {
	Schema     string    `json:"schema"`
	Items      []Record  `json:"items"`
	TotalCount int       `json:"total_count"`
	NextCursor string    `json:"next_cursor,omitempty"`
	SnapshotAt time.Time `json:"snapshot_at"`
	// Unconfigured marks a control plane with no backup runner bound: the
	// empty page means "no backup target, no history", not "no runs yet".
	Unconfigured bool `json:"unconfigured,omitempty"`
}

// Unconfigured is the reader of an installation whose backup runner (manifest
// directory, source cluster and signing trust) is not provisioned. There is
// nothing to read, so it answers an empty page instead of an outage.
type Unconfigured struct {
	Now func() time.Time
}

func (reader Unconfigured) List(_ context.Context, query Query) (Page, error) {
	if query.Cursor != "" {
		return Page{}, ErrInvalidCursor
	}
	return Page{Schema: "cdnca.control-backup-history/v1", Items: []Record{}, SnapshotAt: reader.Now().UTC(), Unconfigured: true}, nil
}

type Query struct {
	BackupID string
	State    string
	From     time.Time
	To       time.Time
	Limit    int
	Cursor   string
}

type Reader interface {
	List(context.Context, Query) (Page, error)
}

type FileReader struct {
	manifestDirectory string
	installationID    string
	sourceClusterID   string
	keys              map[string]ed25519.PublicKey
	cursorKey         []byte
	now               func() time.Time
}

func NewFileReader(manifestDirectory, installationID, sourceClusterID string, keys map[string]ed25519.PublicKey, cursorKey []byte, now func() time.Time) (*FileReader, error) {
	parsed, err := uuid.Parse(installationID)
	if err != nil || parsed == uuid.Nil || parsed.String() != installationID ||
		!identifierPattern.MatchString(sourceClusterID) || !filepath.IsAbs(manifestDirectory) || filepath.Clean(manifestDirectory) != manifestDirectory || len(keys) == 0 || len(cursorKey) < 32 || now == nil {
		return nil, ErrInvalidConfig
	}
	trusted := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		if !identifierPattern.MatchString(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalidConfig
		}
		trusted[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &FileReader{manifestDirectory: manifestDirectory, installationID: installationID, sourceClusterID: sourceClusterID, keys: trusted, cursorKey: append([]byte(nil), cursorKey...), now: now}, nil
}

type cursorPayload struct {
	StartedAt      time.Time `json:"started_at"`
	BackupID       string    `json:"backup_id"`
	FilterBackupID string    `json:"filter_backup_id"`
	State          string    `json:"state"`
	From           time.Time `json:"from"`
	To             time.Time `json:"to"`
}

func (reader *FileReader) List(ctx context.Context, query Query) (Page, error) {
	if query.Limit == 0 {
		query.Limit = 10
	}
	if query.Limit != 10 && query.Limit != 30 && query.Limit != 100 && query.Limit != 300 || len(query.BackupID) > 128 || (query.BackupID != "" && !identifierPattern.MatchString(query.BackupID)) || query.State != "" && query.State != "succeeded" && query.State != "failed" && query.State != "unknown" || len(query.Cursor) > 4096 {
		return Page{}, ErrInvalidInput
	}
	now := reader.now().UTC()
	var after *cursorPayload
	if query.Cursor != "" {
		decoded, err := decodeCursor(query.Cursor, reader.cursorKey)
		if err != nil {
			return Page{}, ErrInvalidCursor
		}
		after = &decoded
		if query.From.IsZero() {
			query.From = after.From
		}
		if query.To.IsZero() {
			query.To = after.To
		}
	}
	if query.From.IsZero() {
		query.From = now.Add(-31 * 24 * time.Hour)
	}
	if query.To.IsZero() {
		query.To = now
	}
	query.From, query.To = query.From.UTC(), query.To.UTC()
	if after != nil && (query.BackupID != after.FilterBackupID || query.State != after.State || !query.From.Equal(after.From) || !query.To.Equal(after.To)) {
		return Page{}, ErrInvalidCursor
	}
	if query.From.After(query.To) || query.To.After(now.Add(time.Minute)) || query.To.Sub(query.From) > 366*24*time.Hour {
		return Page{}, ErrInvalidInput
	}
	root := filepath.Join(reader.manifestDirectory, "runs")
	entries, err := os.ReadDir(root)
	if err != nil {
		return Page{}, ErrUnavailable
	}
	records := make([]Record, 0, len(entries))
	total := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return Page{}, err
		}
		if !entry.IsDir() || !identifierPattern.MatchString(entry.Name()) {
			continue
		}
		record := reader.readRecord(entry.Name())
		if record.StartedAt != nil && (record.StartedAt.Before(query.From) || record.StartedAt.After(query.To)) {
			continue
		}
		if query.BackupID != "" && record.BackupID != query.BackupID || query.State != "" && record.State != query.State {
			continue
		}
		total++
		if after != nil && !before(record, *after) {
			continue
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		left, right := time.Time{}, time.Time{}
		if records[i].StartedAt != nil {
			left = *records[i].StartedAt
		}
		if records[j].StartedAt != nil {
			right = *records[j].StartedAt
		}
		if left.Equal(right) {
			return records[i].BackupID > records[j].BackupID
		}
		return left.After(right)
	})
	page := Page{Schema: "cdnca.control-backup-history/v1", Items: []Record{}, TotalCount: total, SnapshotAt: now}
	if len(records) > query.Limit {
		page.Items = append(page.Items, records[:query.Limit]...)
		last := page.Items[len(page.Items)-1]
		started := time.Time{}
		if last.StartedAt != nil {
			started = *last.StartedAt
		}
		page.NextCursor, err = encodeCursor(cursorPayload{StartedAt: started, BackupID: last.BackupID, FilterBackupID: query.BackupID, State: query.State, From: query.From, To: query.To}, reader.cursorKey)
		if err != nil {
			return Page{}, ErrUnavailable
		}
	} else {
		page.Items = append(page.Items, records...)
	}
	return page, nil
}

func (reader *FileReader) readRecord(backupID string) Record {
	record := Record{BackupID: backupID, State: "unknown", ResultCode: "backup_outcome_unknown", OutcomeUnknown: true, SignatureValid: false, TerminalState: "unavailable", ReasonCode: "start_unavailable"}
	verified, err := controlbackup.ReadBackupRun(reader.manifestDirectory, backupID, reader.keys, controlbackup.BackupRunExpectation{InstallationID: reader.installationID, SourceClusterID: reader.sourceClusterID})
	if err != nil {
		record.ReasonCode = reasonForError(err)
		return record
	}
	record.SignatureValid = true
	record.StartedAt = timePtr(verified.Start.StartedAt)
	if verified.Terminal == nil {
		record.ReasonCode = "terminal_unavailable"
		return record
	}
	record.CompletedAt = timePtr(verified.Terminal.CompletedAt)
	record.State, record.ResultCode = verified.Terminal.State, verified.Terminal.ResultCode
	record.ManifestSHA256, record.RecoveryPointAt, record.ObservedRPOSeconds = verified.Terminal.ManifestSHA256, verified.Terminal.RecoveryPointAt, verified.Terminal.ObservedRPOSeconds
	record.TerminalState, record.OutcomeUnknown, record.ReasonCode = verified.Terminal.State, false, "terminal_recorded"
	return record
}

func reasonForError(err error) string {
	switch {
	case errors.Is(err, controlbackup.ErrBackupRunConflict):
		return "binding_conflict"
	case errors.Is(err, controlbackup.ErrBackupRunIntegrity):
		return "signature_invalid"
	case errors.Is(err, controlbackup.ErrBackupRunLegacy):
		return "legacy_untracked"
	default:
		return "start_unavailable"
	}
}

func before(record Record, cursor cursorPayload) bool {
	started := time.Time{}
	if record.StartedAt != nil {
		started = *record.StartedAt
	}
	return started.Before(cursor.StartedAt) || started.Equal(cursor.StartedAt) && record.BackupID < cursor.BackupID
}

func timePtr(value time.Time) *time.Time { value = value.UTC(); return &value }

func encodeCursor(value cursorPayload, key []byte) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	encoded := append(payload, mac.Sum(nil)...)
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeCursor(value string, key []byte) (cursorPayload, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(encoded) <= sha256.Size {
		return cursorPayload{}, ErrInvalidCursor
	}
	payload, signature := encoded[:len(encoded)-sha256.Size], encoded[len(encoded)-sha256.Size:]
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return cursorPayload{}, ErrInvalidCursor
	}
	var result cursorPayload
	if err := controlbackup.DecodeStrictJSON(payload, &result); err != nil || !identifierPattern.MatchString(result.BackupID) || result.From.IsZero() || result.To.IsZero() {
		return cursorPayload{}, ErrInvalidCursor
	}
	return result, nil
}

var _ Reader = (*FileReader)(nil)
