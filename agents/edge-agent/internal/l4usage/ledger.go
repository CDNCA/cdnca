// Package l4usage bills TCP L4 sessions while they are in progress
// (L4-USAGE-01): every interval (60 seconds) it reads the
// kernel byte counters of the live sessions the L4 OpenResty registered
// (cdnca_l4_geo session_track) and writes each session's delta since its
// previous checkpoint as an l4_checkpoint.v1 spool record; the session's
// end line then carries the bytes already checkpointed, so ClickHouse bills
// the remainder at the end and no byte twice.
//
// The ledger is a private state file. Checkpoints are written to it before
// the spool (a write-ahead pending list): a failed or interrupted spool
// append is replayed with the same event IDs, which the spool dedupes.
package l4usage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4live"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

// Interval is how often in-progress sessions are checkpointed.
const Interval = 60 * time.Second

const (
	// stateSchema 2: sessions carry the release they were established under
	// (NR-M01); sessions and tombstones are kept per listener and token,
	// apart by start (NR-M02).
	stateSchema = 2
	// tombstoneRetention: a settled session is remembered this long after
	// its settlement for a replayed end line.
	tombstoneRetention = 24 * time.Hour
	// defaultEndLineHorizon is the longest a spool keeps an event (its hard
	// age limit's maximum) when Config.EndLineHorizon is unset.
	defaultEndLineHorizon = 29 * 24 * time.Hour
	// endLineSlack: an end line's start (its time, whole seconds, minus the
	// session time) may precede the registered start by this much.
	endLineSlack   = 2 * time.Second
	maxSessions    = 200_000
	maxStateBytes  = 256 << 20
	maxFilterPorts = 4096
	// registryBatch bounds one control socket read (cdnca_l4_geo control()
	// refuses more than 20000 keys).
	registryBatch = 10000
)

var ErrInvalidConfig = errors.New("invalid L4 usage ledger configuration")

// ErrLedgerFull: the ledger holds maxSessions sessions; a new session is
// not checkpointed (its end line bills it in full), never forgotten after
// being billed, and the round reports it (NR-M02).
var ErrLedgerFull = errors.New("L4 usage ledger is full: new sessions are billed at their end only")

// ErrIdentityMissing: live sessions whose registry entry lacks the release
// they were established under; they are not checkpointed (their end line
// bills them in full) and the round reports it so the node shows the
// attribution needs recovery (NR-M01).
var ErrIdentityMissing = errors.New("L4 usage attribution pending recovery: registry entry without release identity")

// Kernel lists established TCP sockets (l4live.LinuxKernel).
type Kernel interface {
	Established(ctx context.Context, ports []uint16) ([]l4live.Socket, error)
}

// Registry reads the live session registry (l4live.ControlRegistry).
type Registry interface {
	Get(ctx context.Context, keys []string) (map[string]string, error)
}

type Config struct {
	StatePath string
	NodeID    string
	Now       func() time.Time
	Kernel    Kernel
	Registry  Registry
	// Sockets are the TCP sockets of the active L4 configuration by
	// listener ID; nil map = no L4 runtime.
	Sockets func(context.Context) (map[string]l4runtime.UsageSocketV2, error)
	// MaxBatch bounds one spool append (the spool's MaxBatchEvents).
	MaxBatch int
	// EndLineHorizon is the spool's hard age limit: an end line older than it
	// is dropped by the spool, so a session the kernel no longer lists is
	// kept pending settlement until then, and a settled one remembered
	// until its end line can no longer be replayed (NR-M02). 0: 29 days.
	EndLineHorizon time.Duration
}

// releaseIdentity is the release a session was established under, as the
// worker that accepted it recorded it (NR-M01): every checkpoint of the
// session bills it, whatever release is active later.
type releaseIdentity struct {
	TenantID              string `json:"tenant_id"`
	SiteID                string `json:"site_id"`
	ConfigVersionID       string `json:"config_version_id"`
	ConfigRevision        uint64 `json:"config_revision"`
	PackageSubscriptionID string `json:"package_subscription_id"`
}

type session struct {
	ListenerID string          `json:"listener_id"`
	StreamID   string          `json:"stream_id"`
	Token      string          `json:"token"`
	StartedAt  time.Time       `json:"started_at"`
	Identity   releaseIdentity `json:"identity"`
	Sequence   uint32          `json:"sequence"`
	Up         uint64          `json:"up"`
	Down       uint64          `json:"down"`
	SeenAt     time.Time       `json:"seen_at"`
	ListenPort uint16          `json:"listen_port"`
	// MissedAt is the first round the kernel no longer listed the session:
	// it ended before then, so its end line is at most that old. The
	// session is pending settlement until the end line or until no end line
	// that old can reach the spool (NR-M02).
	MissedAt time.Time `json:"missed_at,omitempty"`
}

// tombstone is a settled session: a checkpoint computed from a registry
// read before its end is dropped and a replayed end line settles the same
// bytes. FinalizedAt is its end line's.
type tombstone struct {
	StartedAt   time.Time `json:"started_at"`
	Up          uint64    `json:"up"`
	Down        uint64    `json:"down"`
	FinalizedAt time.Time `json:"finalized_at"`
	At          time.Time `json:"at"`
}

// state keys sessions and tombstones by listener and token; a token (worker
// pid and connection) a later session reuses is another start (NR-M02).
type state struct {
	SchemaVersion int                    `json:"schema_version"`
	Sessions      map[string][]*session  `json:"sessions"`
	Settled       map[string][]tombstone `json:"settled"`
	Pending       []eventspool.Envelope  `json:"pending"`
}

type Ledger struct {
	config   Config
	mu       sync.Mutex
	state    state
	sessions int // live and pending-settlement sessions
	limit    int
	dirty    bool
}

func New(config Config) (*Ledger, error) {
	if config.StatePath == "" || !filepath.IsAbs(config.StatePath) || config.NodeID == "" || config.Now == nil ||
		config.Kernel == nil || config.Registry == nil || config.Sockets == nil || config.MaxBatch < 0 {
		return nil, ErrInvalidConfig
	}
	if config.MaxBatch == 0 {
		config.MaxBatch = 1000
	}
	if config.EndLineHorizon < 0 {
		return nil, ErrInvalidConfig
	}
	if config.EndLineHorizon == 0 {
		config.EndLineHorizon = defaultEndLineHorizon
	}
	ledger := &Ledger{config: config, limit: maxSessions, state: state{SchemaVersion: stateSchema,
		Sessions: map[string][]*session{}, Settled: map[string][]tombstone{}}}
	if err := ledger.load(); err != nil {
		return nil, err
	}
	return ledger, nil
}

func sessionKey(listenerID, token string) string { return listenerID + "|" + token }

// Run checkpoints every Interval until ctx ends; a failed round is retried
// at the next one (its pending checkpoints first).
func (ledger *Ledger) Run(ctx context.Context, sink eventspool.BatchSink, report func(error)) error {
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		err := ledger.Checkpoint(ctx, sink)
		if report != nil && ctx.Err() == nil {
			report(err)
		}
	}
}

// Checkpoint appends the pending checkpoints, then one per live session
// whose bytes moved since its previous checkpoint.
func (ledger *Ledger) Checkpoint(ctx context.Context, sink eventspool.BatchSink) error {
	if ctx == nil || sink == nil {
		return ErrInvalidConfig
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err := ledger.flushPending(ctx, sink); err != nil {
		return err
	}
	now := ledger.config.Now().UTC().Truncate(time.Millisecond)
	ledger.prune(now)
	sockets, err := ledger.config.Sockets(ctx)
	if err != nil {
		return fmt.Errorf("read L4 sockets: %w", err)
	}
	var pending error
	if len(sockets) != 0 || ledger.sessions != 0 {
		if err := ledger.observe(ctx, now, sockets); errors.Is(err, ErrIdentityMissing) || errors.Is(err, ErrLedgerFull) {
			pending = err // the attributable sessions are still checkpointed
		} else if err != nil {
			return err
		}
	}
	if err := ledger.save(); err != nil {
		return err
	}
	if err := ledger.flushPending(ctx, sink); err != nil {
		return err
	}
	return pending
}

// observe records a checkpoint for every attributable live session whose
// kernel counters moved.
func (ledger *Ledger) observe(ctx context.Context, now time.Time, sockets map[string]l4runtime.UsageSocketV2) error {
	ports := map[uint16]bool{}
	var filter []uint16
	add := func(port uint16) {
		if !ports[port] {
			ports[port] = true
			filter = append(filter, port)
		}
	}
	for _, socket := range sockets {
		for port := socket.Port; port <= max(socket.Port, socket.PortEnd); port++ {
			add(uint16(port))
		}
	}
	for _, known := range ledger.state.Sessions {
		for _, current := range known {
			add(current.ListenPort) // sessions a retired worker still serves
		}
	}
	if len(filter) > maxFilterPorts {
		filter = nil // too long for one inet_diag filter: ports filters instead
	}
	established, err := ledger.config.Kernel.Established(ctx, filter)
	if err != nil {
		return fmt.Errorf("list L4 TCP sessions: %w", err)
	}
	keys := make([]string, 0, len(established))
	byKey := make(map[string]l4live.Socket, len(established))
	for _, socket := range established {
		if !ports[socket.Local.Port()] || socket.BytesReceived == nil || socket.BytesSent == nil {
			continue
		}
		key := l4live.SessionKey(socket.Local, socket.Peer)
		if _, seen := byKey[key]; !seen {
			keys = append(keys, key)
		}
		byKey[key] = socket
	}
	if len(keys) == 0 {
		ledger.markMissed(now)
		return nil
	}
	values := make(map[string]string, len(keys))
	for begin := 0; begin < len(keys); begin += registryBatch {
		batch, err := ledger.config.Registry.Get(ctx, keys[begin:min(begin+registryBatch, len(keys))])
		if err != nil {
			return fmt.Errorf("read L4 live registry: %w", err)
		}
		for key, value := range batch {
			values[key] = value
		}
	}
	unidentified, full := 0, 0
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue // not registered: not attributable
		}
		registered, ok := parseEntry(value)
		if !ok {
			continue
		}
		port := int(byKey[key].Local.Port())
		known := ledger.find(sessionKey(registered.listener, registered.token), registered.started)
		socket, active := sockets[registered.listener]
		served := active && socket.StreamID == registered.stream && port >= socket.Port && port <= max(socket.Port, socket.PortEnd)
		// a session this ledger already bills keeps being billed on its own
		// port after a release dropped its listener (the retired worker
		// still serves it)
		continuing := known != nil && known.StreamID == registered.stream && int(known.ListenPort) == port
		if !served && !continuing {
			continue // another configuration's or another forward's session
		}
		if !registered.identified {
			unidentified++ // never billed under a guessed (the current) release
			continue
		}
		if !ledger.record(now, registered, uint16(port), *byKey[key].BytesReceived, *byKey[key].BytesSent) {
			full++
		}
	}
	ledger.markMissed(now)
	if full != 0 {
		return fmt.Errorf("%w: %d live sessions", ErrLedgerFull, full)
	}
	if unidentified != 0 {
		return fmt.Errorf("%w: %d live sessions", ErrIdentityMissing, unidentified)
	}
	return nil
}

// find is the session of key that started at started.
func (ledger *Ledger) find(key string, started time.Time) *session {
	for _, current := range ledger.state.Sessions[key] {
		if current.StartedAt.Equal(started) {
			return current
		}
	}
	return nil
}

// record checkpoints one live session; false when the ledger is full.
func (ledger *Ledger) record(now time.Time, registered entry, port uint16, up, down uint64) bool {
	key := sessionKey(registered.listener, registered.token)
	for _, settled := range ledger.state.Settled[key] {
		if settled.StartedAt.Equal(registered.started) {
			return true // ended: its end line billed the rest
		}
	}
	current := ledger.find(key, registered.started)
	if current == nil {
		if ledger.sessions >= ledger.limit {
			return false
		}
		current = &session{ListenerID: registered.listener, StreamID: registered.stream, Token: registered.token,
			StartedAt: registered.started, Identity: registered.identity, ListenPort: port}
		ledger.state.Sessions[key] = append(ledger.state.Sessions[key], current)
		ledger.sessions++
	}
	current.SeenAt, current.MissedAt = now, time.Time{}
	ledger.dirty = true
	if up < current.Up || down < current.Down || up == current.Up && down == current.Down || current.Sequence == math.MaxUint32 {
		return true // no bytes moved (counters only grow)
	}
	deltaUp, deltaDown := up-current.Up, down-current.Down
	current.Sequence++
	current.Up, current.Down = up, down
	connection := registered.token[strings.IndexByte(registered.token, ':')+1:]
	identity := current.Identity // fixed when the session was established (NR-M01)
	envelope := eventspool.Envelope{
		SchemaVersion: eventspool.SchemaVersion, Type: eventspool.EventL4Checkpoint, OccurredAt: now,
		TenantID: identity.TenantID, SiteID: identity.SiteID, NodeID: ledger.config.NodeID, ConfigVersionID: identity.ConfigVersionID,
		StreamID: current.StreamID, ListenerID: current.ListenerID, ConfigRevision: identity.ConfigRevision,
		PackageSubscriptionID: identity.PackageSubscriptionID, SessionID: connection, Protocol: "tcp", ListenPort: port,
		StartedAt: registered.started, CheckpointSequence: current.Sequence, RequestBytes: deltaUp, ResponseBytes: deltaDown,
	}
	envelope.EventID = checkpointEventID(ledger.config.NodeID, current.ListenerID, registered.token, registered.started, current.Sequence)
	ledger.state.Pending = append(ledger.state.Pending, envelope)
	return true
}

// checkpointEventID is deterministic: a replayed checkpoint is the same event.
func checkpointEventID(nodeID, listenerID, token string, started time.Time, sequence uint32) string {
	digest := sha256.Sum256([]byte("cdnca.l4.usage.checkpoint.v1\x00" + nodeID + "\x00" + listenerID + "\x00" + token + "\x00" +
		strconv.FormatInt(started.UnixMilli(), 10) + "\x00" + strconv.FormatUint(uint64(sequence), 10)))
	return "l4ckpt_" + hex.EncodeToString(digest[:])
}

func (ledger *Ledger) flushPending(ctx context.Context, sink eventspool.BatchSink) error {
	for len(ledger.state.Pending) > 0 {
		count := min(len(ledger.state.Pending), ledger.config.MaxBatch)
		if _, err := sink.AppendBatch(ctx, append([]eventspool.Envelope(nil), ledger.state.Pending[:count]...)); err != nil {
			return fmt.Errorf("spool L4 usage checkpoints: %w", err)
		}
		ledger.state.Pending = ledger.state.Pending[count:]
		ledger.dirty = true
		if err := ledger.save(); err != nil {
			return err
		}
	}
	return nil
}

// Settle gives a TCP session's end event the bytes its checkpoints billed
// and moves the session to a tombstone (a later checkpoint of it is
// dropped; a replayed end line settles the same bytes). The session is the
// one of the event's listener and worker token whose registered start the
// end line spans (a reused token is another session, NR-M02). An event
// without its worker pid, or of a session never checkpointed, is unchanged.
func (ledger *Ledger) Settle(envelope eventspool.Envelope) eventspool.Envelope {
	token := envelope.L4WorkerConnection()
	if token == "" || envelope.Protocol != "tcp" {
		return envelope
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := sessionKey(envelope.ListenerID, token)
	spans := func(started time.Time) bool {
		return !started.Before(envelope.StartedAt.Add(-endLineSlack)) && !started.After(envelope.FinalizedAt.Add(endLineSlack))
	}
	up, down := uint64(0), uint64(0)
	settled := false
	for _, previous := range ledger.state.Settled[key] {
		if previous.FinalizedAt.Equal(envelope.FinalizedAt) && spans(previous.StartedAt) {
			up, down, settled = previous.Up, previous.Down, true // the end line replayed
			break
		}
	}
	if !settled {
		sessions := ledger.state.Sessions[key]
		for index, current := range sessions {
			if !spans(current.StartedAt) {
				continue
			}
			up, down = current.Up, current.Down
			ledger.state.Sessions[key] = append(sessions[:index:index], sessions[index+1:]...)
			if len(ledger.state.Sessions[key]) == 0 {
				delete(ledger.state.Sessions, key)
			}
			ledger.sessions--
			ledger.state.Settled[key] = append(ledger.state.Settled[key], tombstone{StartedAt: current.StartedAt, Up: up, Down: down,
				FinalizedAt: envelope.FinalizedAt, At: ledger.config.Now().UTC().Truncate(time.Millisecond)})
			ledger.dirty = true
			break
		}
	}
	// The kernel may count a few bytes nginx does not (a PROXY header):
	// never more than the session's own.
	envelope.CheckpointedRequestBytes = min(up, envelope.RequestBytes)
	envelope.CheckpointedResponseBytes = min(down, envelope.ResponseBytes)
	return envelope
}

// Save persists what Settle changed.
func (ledger *Ledger) Save() error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	return ledger.save()
}

// markMissed starts the settlement wait of every session this round did
// not see.
func (ledger *Ledger) markMissed(now time.Time) {
	for _, sessions := range ledger.state.Sessions {
		for _, current := range sessions {
			if !current.SeenAt.Equal(now) && current.MissedAt.IsZero() {
				current.MissedAt = now
				ledger.dirty = true
			}
		}
	}
}

// prune drops a pending session once its end line, which is older than
// its MissedAt, can no longer reach the spool (EndLineHorizon, the spool's
// hard age): its checkpoints stay billed (a worker crash lost the end).
func (ledger *Ledger) prune(now time.Time) {
	for key, sessions := range ledger.state.Sessions {
		kept := sessions[:0]
		for _, current := range sessions {
			if !current.MissedAt.IsZero() && now.Sub(current.MissedAt) > ledger.config.EndLineHorizon {
				ledger.sessions--
				ledger.dirty = true
				continue
			}
			kept = append(kept, current)
		}
		if len(kept) == 0 {
			delete(ledger.state.Sessions, key)
		} else {
			ledger.state.Sessions[key] = kept
		}
	}
	for key, settled := range ledger.state.Settled {
		kept := settled[:0]
		for _, previous := range settled {
			if now.Sub(previous.At) > tombstoneRetention {
				ledger.dirty = true
				continue
			}
			kept = append(kept, previous)
		}
		if len(kept) == 0 {
			delete(ledger.state.Settled, key)
		} else {
			ledger.state.Settled[key] = kept
		}
	}
}

// counts are the sessions pending checkpoints or settlement and the
// tombstones.
func (ledger *Ledger) counts() (sessions, settled int) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	for _, previous := range ledger.state.Settled {
		settled += len(previous)
	}
	return ledger.sessions, settled
}

// entry is a registry value "<stream>|<listener>|<client>|<client port>|
// <started>|<tenant>|<site>|<config version>|<config revision>|<package
// subscription>|<worker pid>:<connection>|<killed>" (cdnca_l4_geo
// session_track). A value without the release identity (7 fields) parses
// with identified false: its session is not billed under a guessed release.
type entry struct {
	stream, listener, token string
	started                 time.Time
	identity                releaseIdentity
	identified              bool
}

func parseEntry(value string) (entry, bool) {
	parts := strings.Split(value, "|")
	if len(parts) != 7 && len(parts) != 12 {
		return entry{}, false
	}
	token := parts[len(parts)-2]
	seconds, err := strconv.ParseFloat(parts[4], 64)
	pid, connection, ok := strings.Cut(token, ":")
	if err != nil || seconds <= 0 || !ok || !decimal(pid) || !decimal(connection) || parts[0] == "" || parts[1] == "" {
		return entry{}, false
	}
	parsed := entry{stream: parts[0], listener: parts[1], token: token,
		started: time.UnixMilli(int64(math.Round(seconds * 1000))).UTC()}
	if len(parts) == 12 {
		revision, err := strconv.ParseUint(parts[8], 10, 64)
		if err != nil || revision == 0 || strconv.FormatUint(revision, 10) != parts[8] || parts[5] == "" || parts[6] == "" || parts[7] == "" {
			return entry{}, false
		}
		parsed.identity = releaseIdentity{TenantID: parts[5], SiteID: parts[6], ConfigVersionID: parts[7],
			ConfigRevision: revision, PackageSubscriptionID: parts[9]}
		parsed.identified = true
	}
	return parsed, true
}

func decimal(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed != 0 && strconv.FormatUint(parsed, 10) == value
}

func (ledger *Ledger) load() error {
	content, err := os.ReadFile(ledger.config.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read L4 usage ledger: %w", err)
	}
	if len(content) > maxStateBytes {
		return errors.New("L4 usage ledger is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var loaded state
	if err := decoder.Decode(&loaded); err != nil || decoder.Decode(&struct{}{}) != io.EOF || loaded.SchemaVersion != stateSchema {
		return errors.New("L4 usage ledger is corrupt")
	}
	if loaded.Sessions == nil {
		loaded.Sessions = map[string][]*session{}
	}
	if loaded.Settled == nil {
		loaded.Settled = map[string][]tombstone{}
	}
	count := 0
	for _, sessions := range loaded.Sessions {
		for _, current := range sessions {
			if current == nil || current.Identity.ConfigVersionID == "" || current.Identity.ConfigRevision == 0 || current.StreamID == "" {
				return errors.New("L4 usage ledger is corrupt")
			}
			count++
		}
	}
	for _, pending := range loaded.Pending {
		if pending.Type != eventspool.EventL4Checkpoint || pending.EventID == "" || pending.NodeID != ledger.config.NodeID {
			return errors.New("L4 usage ledger is corrupt")
		}
	}
	ledger.state, ledger.sessions = loaded, count
	return nil
}

func (ledger *Ledger) save() error {
	if !ledger.dirty {
		return nil
	}
	encoded, err := json.Marshal(ledger.state)
	if err != nil {
		return fmt.Errorf("encode L4 usage ledger: %w", err)
	}
	directory := filepath.Dir(ledger.config.StatePath)
	file, err := os.CreateTemp(directory, ".l4-usage-*")
	if err != nil {
		return fmt.Errorf("write L4 usage ledger: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err := file.Write(encoded); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporary, ledger.config.StatePath)
	}
	if err != nil {
		return fmt.Errorf("write L4 usage ledger: %w", err)
	}
	ledger.dirty = false
	return nil
}

// SettlingSink settles every TCP session end event with the ledger before
// next spools it, then persists the ledger.
type SettlingSink struct {
	Ledger *Ledger
	Next   eventspool.BatchSink
}

func (sink SettlingSink) AppendBatch(ctx context.Context, envelopes []eventspool.Envelope) ([]eventspool.AppendResult, error) {
	if sink.Ledger == nil {
		return sink.Next.AppendBatch(ctx, envelopes)
	}
	settled := false
	for index := range envelopes {
		if envelopes[index].Type == eventspool.EventL4Session {
			envelopes[index] = sink.Ledger.Settle(envelopes[index])
			settled = true
		}
	}
	results, err := sink.Next.AppendBatch(ctx, envelopes)
	if settled && err == nil {
		err = sink.Ledger.Save()
	}
	return results, err
}
