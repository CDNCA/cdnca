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
	stateSchema = 1
	// unseenRetention: a session the kernel no longer lists whose end line
	// never matched (worker crash) is forgotten after it; its checkpoints
	// stay billed.
	unseenRetention = 6 * time.Hour
	// tombstoneRetention: a settled session is remembered so a checkpoint
	// computed from a registry read before its end is dropped and a replayed
	// end line settles the same bytes.
	tombstoneRetention = 24 * time.Hour
	maxSessions        = 200_000
	maxStateBytes      = 256 << 20
	maxFilterPorts     = 4096
	// registryBatch bounds one control socket read (cdnca_l4_geo control()
	// refuses more than 20000 keys).
	registryBatch = 10000
)

var ErrInvalidConfig = errors.New("invalid L4 usage ledger configuration")

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
}

type session struct {
	ListenerID string    `json:"listener_id"`
	Token      string    `json:"token"`
	StartedAt  time.Time `json:"started_at"`
	Sequence   uint32    `json:"sequence"`
	Up         uint64    `json:"up"`
	Down       uint64    `json:"down"`
	SeenAt     time.Time `json:"seen_at"`
}

type tombstone struct {
	StartedAt time.Time `json:"started_at"`
	Up        uint64    `json:"up"`
	Down      uint64    `json:"down"`
	At        time.Time `json:"at"`
}

type state struct {
	SchemaVersion int                   `json:"schema_version"`
	Sessions      map[string]*session   `json:"sessions"`
	Settled       map[string]tombstone  `json:"settled"`
	Pending       []eventspool.Envelope `json:"pending"`
}

type Ledger struct {
	config Config
	mu     sync.Mutex
	state  state
	dirty  bool
}

func New(config Config) (*Ledger, error) {
	if config.StatePath == "" || !filepath.IsAbs(config.StatePath) || config.NodeID == "" || config.Now == nil ||
		config.Kernel == nil || config.Registry == nil || config.Sockets == nil || config.MaxBatch < 0 {
		return nil, ErrInvalidConfig
	}
	if config.MaxBatch == 0 {
		config.MaxBatch = 1000
	}
	ledger := &Ledger{config: config, state: state{SchemaVersion: stateSchema, Sessions: map[string]*session{},
		Settled: map[string]tombstone{}}}
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
	if len(sockets) != 0 {
		if err := ledger.observe(ctx, now, sockets); err != nil {
			return err
		}
	}
	if err := ledger.save(); err != nil {
		return err
	}
	return ledger.flushPending(ctx, sink)
}

// observe records a checkpoint for every attributable live session whose
// kernel counters moved.
func (ledger *Ledger) observe(ctx context.Context, now time.Time, sockets map[string]l4runtime.UsageSocketV2) error {
	ports := map[uint16]bool{}
	var filter []uint16
	for _, socket := range sockets {
		for port := socket.Port; port <= max(socket.Port, socket.PortEnd); port++ {
			if !ports[uint16(port)] {
				ports[uint16(port)] = true
				filter = append(filter, uint16(port))
			}
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
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue // not registered: not attributable
		}
		registered, ok := parseEntry(value)
		if !ok {
			continue
		}
		socket, ok := sockets[registered.listener]
		port := int(byKey[key].Local.Port())
		if !ok || socket.StreamID != registered.stream || port < socket.Port || port > max(socket.Port, socket.PortEnd) {
			continue // another configuration's or another forward's session
		}
		ledger.record(now, socket, registered, uint16(port), *byKey[key].BytesReceived, *byKey[key].BytesSent)
	}
	return nil
}

func (ledger *Ledger) record(now time.Time, socket l4runtime.UsageSocketV2, registered entry, port uint16, up, down uint64) {
	key := sessionKey(socket.ListenerID, registered.token)
	if settled, ok := ledger.state.Settled[key]; ok && settled.StartedAt.Equal(registered.started) {
		return // ended: its end line billed the rest
	}
	current := ledger.state.Sessions[key]
	if current == nil || !current.StartedAt.Equal(registered.started) {
		if current == nil && len(ledger.state.Sessions) >= maxSessions {
			return
		}
		current = &session{ListenerID: socket.ListenerID, Token: registered.token, StartedAt: registered.started}
		ledger.state.Sessions[key] = current
	}
	current.SeenAt = now
	ledger.dirty = true
	if up < current.Up || down < current.Down || up == current.Up && down == current.Down || current.Sequence == math.MaxUint32 {
		return // no bytes moved (counters only grow)
	}
	deltaUp, deltaDown := up-current.Up, down-current.Down
	current.Sequence++
	current.Up, current.Down = up, down
	connection := registered.token[strings.IndexByte(registered.token, ':')+1:]
	envelope := eventspool.Envelope{
		SchemaVersion: eventspool.SchemaVersion, Type: eventspool.EventL4Checkpoint, OccurredAt: now,
		TenantID: socket.TenantID, SiteID: socket.SiteID, NodeID: ledger.config.NodeID, ConfigVersionID: socket.ConfigVersionID,
		StreamID: socket.StreamID, ListenerID: socket.ListenerID, ConfigRevision: socket.ConfigRevision,
		PackageSubscriptionID: socket.PackageSubscriptionID, SessionID: connection, Protocol: "tcp", ListenPort: port,
		StartedAt: registered.started, CheckpointSequence: current.Sequence, RequestBytes: deltaUp, ResponseBytes: deltaDown,
	}
	envelope.EventID = checkpointEventID(ledger.config.NodeID, socket.ListenerID, registered.token, registered.started, current.Sequence)
	ledger.state.Pending = append(ledger.state.Pending, envelope)
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
// and forgets the session (a later checkpoint of it is dropped). An event
// without its worker pid, or of a session never checkpointed, is unchanged.
func (ledger *Ledger) Settle(envelope eventspool.Envelope) eventspool.Envelope {
	token := envelope.L4WorkerConnection()
	if token == "" || envelope.Protocol != "tcp" {
		return envelope
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := sessionKey(envelope.ListenerID, token)
	up, down := uint64(0), uint64(0)
	if current := ledger.state.Sessions[key]; current != nil && !current.StartedAt.After(envelope.FinalizedAt) {
		up, down = current.Up, current.Down
		delete(ledger.state.Sessions, key)
		ledger.state.Settled[key] = tombstone{StartedAt: current.StartedAt, Up: up, Down: down,
			At: ledger.config.Now().UTC().Truncate(time.Millisecond)}
		ledger.dirty = true
	} else if settled, ok := ledger.state.Settled[key]; ok && !settled.StartedAt.After(envelope.FinalizedAt) {
		up, down = settled.Up, settled.Down // the end line replayed
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

func (ledger *Ledger) prune(now time.Time) {
	for key, current := range ledger.state.Sessions {
		if now.Sub(current.SeenAt) > unseenRetention {
			delete(ledger.state.Sessions, key)
			ledger.dirty = true
		}
	}
	for key, settled := range ledger.state.Settled {
		if now.Sub(settled.At) > tombstoneRetention {
			delete(ledger.state.Settled, key)
			ledger.dirty = true
		}
	}
}

// entry is a registry value "<stream>|<listener>|<client>|<client port>|
// <started>|<worker pid>:<connection>|<killed>" (cdnca_l4_geo session_track).
type entry struct {
	stream, listener, token string
	started                 time.Time
}

func parseEntry(value string) (entry, bool) {
	parts := strings.Split(value, "|")
	if len(parts) != 7 {
		return entry{}, false
	}
	seconds, err := strconv.ParseFloat(parts[4], 64)
	pid, connection, ok := strings.Cut(parts[5], ":")
	if err != nil || seconds <= 0 || !ok || !decimal(pid) || !decimal(connection) || parts[0] == "" || parts[1] == "" {
		return entry{}, false
	}
	return entry{stream: parts[0], listener: parts[1], token: parts[5],
		started: time.UnixMilli(int64(math.Round(seconds * 1000))).UTC()}, true
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
		loaded.Sessions = map[string]*session{}
	}
	if loaded.Settled == nil {
		loaded.Settled = map[string]tombstone{}
	}
	for _, pending := range loaded.Pending {
		if pending.Type != eventspool.EventL4Checkpoint || pending.EventID == "" || pending.NodeID != ledger.config.NodeID {
			return errors.New("L4 usage ledger is corrupt")
		}
	}
	ledger.state = loaded
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
