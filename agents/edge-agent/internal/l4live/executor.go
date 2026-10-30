// Package l4live executes L4LiveConnectionsCommand (CAPABILITY_NAME_L4_LIVE_CONNECTIONS):
// it lists the TCP sessions the L4 OpenResty serves for one stream from the
// kernel (sock_diag on the stream's ports), names their client and start
// from the live registry the stream's session log keeps (engine.lua
// session_track, read through the control socket), and closes chosen ones
// by taking the worker's socket (pidfd_getfd) and shutting it down.
package l4live

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	MaxConnections = 1000
	MaxCloseKeys   = 1000
	// APIVersionList: listing only; APIVersionClose: closing too (the agent
	// may take the worker's sockets: root, pidfd_getfd available).
	APIVersionList  = 1
	APIVersionClose = 2
)

var ErrInvalidCommand = errors.New("invalid L4 live connections command")

// Socket is one established TCP connection the kernel reports.
type Socket struct {
	Local, Peer   netip.AddrPort
	Inode         uint64
	BytesReceived *uint64
	BytesSent     *uint64
}

// Kernel reads and closes TCP sockets.
type Kernel interface {
	// Established lists ESTABLISHED and CLOSE_WAIT TCP sockets whose local
	// port is one of ports; nil ports lists every one.
	Established(ctx context.Context, ports []uint16) ([]Socket, error)
	// Close shuts down the socket with inode held by one of pids.
	Close(ctx context.Context, pids []int, inode uint64) error
}

// Registry is the live session registry of logging streams.
type Registry interface {
	// Get returns the registry value of each key it holds.
	Get(ctx context.Context, keys []string) (map[string]string, error)
	// Kill marks keys so their session logs say killed.
	Kill(ctx context.Context, keys []string) error
}

// Runtime is the L4 runtime: what it serves and its workers.
type Runtime interface {
	ActiveConfigV2(context.Context) (*l4runtime.ConfigV2, error)
	WorkerPIDs() ([]int, error)
}

type Executor struct {
	runtime  Runtime
	kernel   Kernel
	registry Registry
	canClose bool
	now      func() time.Time
}

func New(runtime Runtime, kernel Kernel, registry Registry, canClose bool) (*Executor, error) {
	if runtime == nil || kernel == nil || registry == nil {
		return nil, ErrInvalidCommand
	}
	return &Executor{runtime: runtime, kernel: kernel, registry: registry, canClose: canClose, now: time.Now}, nil
}

// APIVersion is the capability version to advertise.
func (executor *Executor) APIVersion() uint32 {
	if executor.canClose {
		return APIVersionClose
	}
	return APIVersionList
}

func (executor *Executor) Validate(command *agentv1.L4LiveConnectionsCommand) error {
	if command == nil || command.Event == nil || uuid.Validate(command.Event.EventId) != nil ||
		uuid.Validate(command.StreamId) != nil || command.ExpireTime == nil || command.ExpireTime.CheckValid() != nil ||
		command.Limit < 1 || command.Limit > MaxConnections || len(command.CloseSessionKeys) > MaxCloseKeys {
		return ErrInvalidCommand
	}
	if command.ClientIp != "" {
		if _, err := clientFilter(command.ClientIp); err != nil {
			return ErrInvalidCommand
		}
	}
	for _, key := range command.CloseSessionKeys {
		if _, _, err := ParseSessionKey(key); err != nil {
			return ErrInvalidCommand
		}
	}
	return nil
}

func clientFilter(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return netip.Prefix{}, ErrInvalidCommand
	}
	address = address.Unmap()
	return netip.PrefixFrom(address, address.BitLen()), nil
}

// SessionKey is the registry key of a connection: its kernel tuple.
func SessionKey(local, peer netip.AddrPort) string {
	return local.Addr().Unmap().String() + "|" + strconv.Itoa(int(local.Port())) + "|" +
		peer.Addr().Unmap().String() + "|" + strconv.Itoa(int(peer.Port()))
}

func ParseSessionKey(key string) (netip.AddrPort, netip.AddrPort, error) {
	parts := strings.Split(key, "|")
	if len(parts) != 4 || len(key) > 160 {
		return netip.AddrPort{}, netip.AddrPort{}, ErrInvalidCommand
	}
	parse := func(address, port string) (netip.AddrPort, error) {
		parsed, err := netip.ParseAddr(address)
		value, portErr := strconv.ParseUint(port, 10, 16)
		if err != nil || portErr != nil || parsed.Zone() != "" || value == 0 || parsed.String() != address {
			return netip.AddrPort{}, ErrInvalidCommand
		}
		return netip.AddrPortFrom(parsed, uint16(value)), nil
	}
	local, err := parse(parts[0], parts[1])
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	peer, err := parse(parts[2], parts[3])
	return local, peer, err
}

// entry is a parsed registry value
// "<stream>|<listener>|<client>|<client port>|<started>|<token>|<killed>".
type entry struct {
	stream, listener, client string
	clientPort               uint16
	started                  time.Time
}

func parseEntry(value string) (entry, bool) {
	parts := strings.Split(value, "|")
	if len(parts) != 7 {
		return entry{}, false
	}
	port, _ := strconv.ParseUint(parts[3], 10, 16)
	seconds, err := strconv.ParseFloat(parts[4], 64)
	if err != nil || seconds <= 0 {
		return entry{}, false
	}
	return entry{stream: parts[0], listener: parts[1], client: parts[2], clientPort: uint16(port),
		started: time.UnixMilli(int64(seconds * 1000)).UTC()}, true
}

type candidate struct {
	socket  Socket
	key     string
	entry   entry
	tracked bool
	shared  bool
	port    l4runtime.LiveSocketV2
	// upstream is set when the stream follows the client's port to the
	// origin (the shared upstream is then "").
	upstream string
}

// candidates are the connections of stream: on its own ports every one, on
// shared ports only those its registry names.
func (executor *Executor) candidates(ctx context.Context, streamID string) ([]candidate, string, error) {
	config, err := executor.runtime.ActiveConfigV2(ctx)
	if err != nil || config == nil {
		return nil, "", errors.Join(errUnavailable, err)
	}
	return executor.candidatesIn(ctx, *config, streamID)
}

// candidatesIn is candidates of streamID as config serves it.
func (executor *Executor) candidatesIn(ctx context.Context, config l4runtime.ConfigV2, streamID string) ([]candidate, string, error) {
	sockets, stream, err := l4runtime.LiveSocketsV2(config, streamID)
	if err != nil {
		return nil, "", errNotFound
	}
	upstream := stream.Endpoint.Address
	if upstream == "" {
		upstream = stream.Endpoint.Host
	}
	host := upstream
	upstream = joinHostPort(host, stream.Endpoint.Port)
	if stream.Endpoint.FollowPort {
		upstream = "" // per connection: the port the client connected to
	}
	byPort := map[uint16]l4runtime.LiveSocketV2{}
	var ports []uint16
	for _, socket := range sockets {
		last := max(socket.Port, socket.PortEnd)
		for port := socket.Port; port <= last; port++ {
			if _, seen := byPort[uint16(port)]; !seen {
				ports = append(ports, uint16(port))
			}
			byPort[uint16(port)] = socket
		}
	}
	if len(ports) == 0 {
		return nil, upstream, nil
	}
	filter := ports
	if len(filter) > maxFilterPorts {
		filter = nil // too long for inet_diag bytecode: byPort filters instead
	}
	established, err := executor.kernel.Established(ctx, filter)
	if err != nil {
		return nil, "", errors.Join(errUnavailable, err)
	}
	result := make([]candidate, 0, len(established))
	keys := make([]string, 0, len(established))
	for _, socket := range established {
		port, ok := byPort[socket.Local.Port()]
		if !ok {
			continue
		}
		key := SessionKey(socket.Local, socket.Peer)
		item := candidate{socket: socket, key: key, shared: port.Shared, port: port}
		if upstream == "" {
			item.upstream = joinHostPort(host, int(socket.Local.Port()))
		}
		result = append(result, item)
		keys = append(keys, key)
	}
	values := map[string]string{}
	if stream.SessionLog && len(keys) != 0 {
		// Without the registry the list still shows the kernel's view.
		if values, err = executor.registry.Get(ctx, keys); err != nil {
			values = map[string]string{}
		}
	}
	kept := result[:0]
	for _, item := range result {
		if value, ok := values[item.key]; ok {
			if parsed, valid := parseEntry(value); valid {
				if parsed.stream != streamID {
					continue // another stream behind the same port
				}
				item.entry, item.tracked = parsed, true
			}
		}
		if item.shared && !item.tracked {
			continue // a shared port's connection without an entry is not attributable
		}
		kept = append(kept, item)
	}
	return kept, upstream, nil
}

// maxFilterPorts bounds the ports of one inet_diag filter (12 bytes each in a
// uint16-sized attribute).
const maxFilterPorts = 4096

func joinHostPort(host string, port int) string {
	if address, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(address, uint16(port)).String()
	}
	return host + ":" + strconv.Itoa(port)
}

var (
	errUnavailable = errors.New("L4 runtime unavailable")
	errNotFound    = errors.New("L4 stream not served")
)

// Execute runs command; the result's error_code reports a failure.
func (executor *Executor) Execute(ctx context.Context, command *agentv1.L4LiveConnectionsCommand) *agentv1.L4LiveConnectionsResult {
	result := &agentv1.L4LiveConnectionsResult{}
	if !executor.now().Before(command.ExpireTime.AsTime()) {
		result.ErrorCode = "expired"
		return result
	}
	candidates, upstream, err := executor.candidates(ctx, command.StreamId)
	switch {
	case errors.Is(err, errNotFound):
		if len(command.CloseSessionKeys) == 0 {
			return result // the stream has no sessions here
		}
		candidates = nil
	case err != nil:
		result.ErrorCode = "unavailable"
		return result
	}
	if len(command.CloseSessionKeys) != 0 {
		result.Closed = executor.close(ctx, candidates, command.CloseSessionKeys)
		return result
	}
	var filter *netip.Prefix
	if command.ClientIp != "" {
		prefix, _ := clientFilter(command.ClientIp)
		filter = &prefix
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].key < candidates[j].key })
	for _, item := range candidates {
		upstreamText := upstream
		if upstreamText == "" {
			upstreamText = item.upstream
		}
		connection := &agentv1.L4LiveConnection{SessionKey: item.key, ListenerId: item.port.ListenerID,
			ListenPort: uint32(item.socket.Local.Port()), Upstream: upstreamText,
			ClientIp: item.socket.Peer.Addr().Unmap().String(), ClientPort: uint32(item.socket.Peer.Port()),
			BytesReceived: item.socket.BytesReceived, BytesSent: item.socket.BytesSent}
		if item.tracked {
			client, err := netip.ParseAddr(item.entry.client)
			if err == nil && client.Unmap() != item.socket.Peer.Addr().Unmap() {
				connection.PeerIp, connection.ClientIp, connection.ClientPort = connection.ClientIp, client.Unmap().String(), uint32(item.entry.clientPort)
			}
			connection.ListenerId = item.entry.listener
			connection.StartedAt = timestamppb.New(item.entry.started)
		}
		client, err := netip.ParseAddr(connection.ClientIp)
		if filter != nil && (err != nil || !filter.Contains(client)) {
			continue
		}
		result.Matched++
		if len(result.Connections) < int(command.Limit) {
			result.Connections = append(result.Connections, connection)
		}
	}
	return result
}

func (executor *Executor) close(ctx context.Context, candidates []candidate, keys []string) []*agentv1.L4LiveConnectionClose {
	byKey := make(map[string]candidate, len(candidates))
	for _, item := range candidates {
		byKey[item.key] = item
	}
	closed := make([]*agentv1.L4LiveConnectionClose, 0, len(keys))
	var marked []string
	for _, key := range keys {
		if item, ok := byKey[key]; ok && item.tracked {
			marked = append(marked, key)
		}
	}
	if len(marked) != 0 {
		_ = executor.registry.Kill(ctx, marked) // only the log's reason depends on it
	}
	pids, pidErr := executor.runtime.WorkerPIDs()
	for _, key := range keys {
		item, ok := byKey[key]
		outcome := &agentv1.L4LiveConnectionClose{SessionKey: key}
		switch {
		case !ok:
			outcome.ErrorCode = "not_found"
		case !executor.canClose:
			outcome.ErrorCode = "unsupported"
		case pidErr != nil:
			outcome.ErrorCode = "failed"
		default:
			if err := executor.kernel.Close(ctx, pids, item.socket.Inode); errors.Is(err, ErrSocketGone) {
				outcome.ErrorCode = "not_found"
			} else if err != nil {
				outcome.ErrorCode = "failed"
			}
		}
		closed = append(closed, outcome)
	}
	return closed
}

// CloseStreams closes every open TCP session of streamIDs, forwards that
// previous served and current (the configuration just activated, nil =
// none) no longer does (L4_TRAFFIC_STOP: withdrawn for package traffic, so
// their sessions are not left to drain). The retiring workers still hold
// the sessions; a port current serves again only gives up the sessions the
// registry names as the stream's. It returns the sessions closed.
func (executor *Executor) CloseStreams(ctx context.Context, previous, current *l4runtime.ConfigV2, streamIDs []string) (int, error) {
	if !executor.canClose || previous == nil || len(streamIDs) == 0 {
		return 0, nil
	}
	served := map[uint16]bool{}
	if current != nil {
		for _, listener := range current.Listeners {
			for _, socket := range listenerPorts(listener) {
				served[socket] = true
			}
		}
	}
	closed := 0
	var failures []error
	for _, streamID := range streamIDs {
		if current != nil && servesStream(*current, streamID) {
			continue // still served (recovered meanwhile): nothing withdrawn
		}
		candidates, _, err := executor.candidatesIn(ctx, *previous, streamID)
		if errors.Is(err, errNotFound) {
			continue // previous did not serve it either
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		var keys []string
		kept := candidates[:0]
		for _, item := range candidates {
			if served[item.socket.Local.Port()] && !item.tracked {
				continue // the port's new owner may hold it
			}
			kept = append(kept, item)
			keys = append(keys, item.key)
		}
		for start := 0; start < len(keys); start += MaxCloseKeys {
			end := min(start+MaxCloseKeys, len(keys))
			for _, outcome := range executor.close(ctx, kept, keys[start:end]) {
				switch outcome.ErrorCode {
				case "":
					closed++
				case "not_found": // ended meanwhile
				default:
					failures = append(failures, fmt.Errorf("stream %s session %s: %s", streamID, outcome.SessionKey, outcome.ErrorCode))
				}
			}
		}
	}
	return closed, errors.Join(failures...)
}

func servesStream(config l4runtime.ConfigV2, streamID string) bool {
	for _, listener := range config.Listeners {
		if listener.StreamID == streamID {
			return true
		}
	}
	return false
}

// listenerPorts are the TCP ports listener binds (additional listeners too).
func listenerPorts(listener l4runtime.ListenerV2) []uint16 {
	sockets := append([]l4runtime.AdditionalListenerV2{{Protocol: listener.Protocol, Port: listener.Port, PortEnd: listener.PortEnd}},
		listener.AdditionalListeners...)
	var ports []uint16
	for _, socket := range sockets {
		if socket.Protocol != l4runtime.ProtocolTCP {
			continue
		}
		for port := socket.Port; port <= max(socket.Port, socket.PortEnd); port++ {
			ports = append(ports, uint16(port))
		}
	}
	return ports
}

// ErrSocketGone: no worker holds the socket any more.
var ErrSocketGone = errors.New("socket not held by an L4 worker")
