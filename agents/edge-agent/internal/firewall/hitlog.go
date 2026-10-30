package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const maxKernelHitLine = 64 << 10

type KernelHitSource struct {
	store   *diskStore
	input   *os.File
	nodeID  string
	pending []byte
	now     func() time.Time
}

func NewKernelHitSource(stateRoot, inputPath, nodeID string, now func() time.Time) (*KernelHitSource, error) {
	if inputPath == "" || !strings.HasPrefix(inputPath, "/") || uuid.Validate(nodeID) != nil || strings.ToLower(nodeID) != nodeID {
		return nil, ErrInvalidPath
	}
	store, err := newDiskStore(stateRoot)
	if err != nil {
		return nil, err
	}
	input, err := os.Open(inputPath)
	if err != nil {
		store.close()
		return nil, err
	}
	if err := unix.SetNonblock(int(input.Fd()), true); err != nil {
		_ = input.Close()
		store.close()
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &KernelHitSource{store: store, input: input, nodeID: nodeID, now: now}, nil
}

func (source *KernelHitSource) Close() error {
	if source == nil {
		return nil
	}
	var err error
	if source.input != nil {
		err = source.input.Close()
		source.input = nil
	}
	if source.store != nil {
		source.store.close()
		source.store = nil
	}
	return err
}

func (source *KernelHitSource) ReadBatch(ctx context.Context, limit int) ([]eventspool.Envelope, error) {
	if source == nil || source.store == nil || source.input == nil || limit < 1 || limit > 10_000 {
		return nil, ErrInvalidVersion
	}
	active, err := source.store.loadActive()
	if err != nil {
		return nil, err
	}
	if active == nil {
		return nil, nil
	}
	buffer := make([]byte, 64<<10)
	events := make([]eventspool.Envelope, 0, min(limit, 64))
	for len(events) < limit {
		if err := ctx.Err(); err != nil {
			return events, err
		}
		for len(events) < limit {
			newline := bytes.IndexByte(source.pending, '\n')
			if newline < 0 {
				break
			}
			line := bytes.Clone(source.pending[:newline])
			source.pending = source.pending[newline+1:]
			event, ok := parseKernelHit(line, *active, source.nodeID, source.now().UTC())
			if ok {
				events = append(events, event)
			}
		}
		if len(events) == limit {
			break
		}
		read, readErr := source.input.Read(buffer)
		if read > 0 {
			source.pending = append(source.pending, buffer[:read]...)
			if len(source.pending) > maxKernelHitLine && bytes.IndexByte(source.pending, '\n') < 0 {
				source.pending = nil
				return events, ErrCorruptState
			}
			continue
		}
		if readErr != nil {
			if errors.Is(readErr, unix.EAGAIN) || errors.Is(readErr, unix.EWOULDBLOCK) {
				return events, nil
			}
			return events, readErr
		}
		if read == 0 {
			return events, nil
		}
	}
	return events, nil
}

func parseKernelHit(line []byte, active activeRecord, nodeID string, occurredAt time.Time) (eventspool.Envelope, bool) {
	if separator := bytes.IndexByte(line, ';'); separator >= 0 {
		line = line[separator+1:]
	}
	fields := strings.Fields(string(line))
	marker := -1
	for index, field := range fields {
		if field == "cdnca-fw" {
			marker = index
			break
		}
	}
	if marker < 0 || marker+1 >= len(fields) {
		return eventspool.Envelope{}, false
	}
	values := make(map[string]string)
	for _, field := range fields[marker+2:] {
		key, value, found := strings.Cut(field, "=")
		if found && key != "" && value != "" {
			values[key] = strings.TrimSpace(value)
		}
	}
	client, err := netip.ParseAddr(values["SRC"])
	if err != nil || client.Is4In6() || client.IsUnspecified() || client.IsMulticast() {
		return eventspool.Envelope{}, false
	}
	protocol := strings.ToLower(values["PROTO"])
	if protocol == "ipv6-icmp" {
		protocol = "icmp"
	}
	var destinationPort uint16
	if protocol == "tcp" || protocol == "udp" {
		port, err := strconv.ParseUint(values["DPT"], 10, 16)
		if err != nil || port == 0 {
			return eventspool.Envelope{}, false
		}
		destinationPort = uint16(port)
	} else if protocol != "icmp" {
		return eventspool.Envelope{}, false
	}
	entry, ok := hitEntry(fields[marker+1], client, active)
	if !ok || uuid.Validate(entry.TenantID) != nil || uuid.Validate(entry.SiteID) != nil {
		return eventspool.Envelope{}, false
	}
	ruleID := ""
	if strings.HasPrefix(entry.Reason, "rule:") {
		ruleID = strings.TrimPrefix(entry.Reason, "rule:")
		if uuid.Validate(ruleID) != nil || strings.ToLower(ruleID) != ruleID {
			return eventspool.Envelope{}, false
		}
	} else if entry.Reason != "default-deny" {
		return eventspool.Envelope{}, false
	}
	return eventspool.Envelope{
		SchemaVersion: eventspool.SchemaVersion, Type: eventspool.EventSecurity, EventID: uuid.NewString(), OccurredAt: occurredAt,
		TenantID: entry.TenantID, SiteID: entry.SiteID, NodeID: nodeID, ConfigVersionID: active.Version.VersionID,
		Host: "-", Path: "/", ClientIP: client.String(), Method: "NETWORK", ListenPort: destinationPort,
		DestinationPort: destinationPort, Protocol: protocol, RequestClass: "network", SecurityType: "global_firewall",
		Action: "block", Severity: "medium", RuleID: ruleID,
	}, true
}

func hitEntry(marker string, client netip.Addr, active activeRecord) (Entry, bool) {
	entries := active.Version.Entries
	if marker != "ipset" {
		// "g<index>": the scoped group (compiler scopedGroups) the drop rule
		// matched; the entry is the group's one whose network holds client.
		ordinal, err := strconv.Atoi(strings.TrimPrefix(marker, "g"))
		groups := scopedGroups(entries)
		if !strings.HasPrefix(marker, "g") || err != nil || ordinal < 1 || ordinal > len(groups) {
			return Entry{}, false
		}
		key := groups[ordinal-1].key
		for _, entry := range entries {
			prefix, parseErr := netip.ParsePrefix(entry.Network)
			if parseErr != nil || entry.Protocol == ProtocolAny || entryGroupKey(entry) != key || !prefix.Contains(client) {
				continue
			}
			if global, ok := globalScopeEntry(entry, active); ok {
				return global, true
			}
		}
		return Entry{}, false
	}
	for _, entry := range entries {
		prefix, err := netip.ParsePrefix(entry.Network)
		if err == nil && entry.Action == ActionDeny && entry.Protocol == ProtocolAny && prefix.Contains(client) {
			if global, ok := globalScopeEntry(entry, active); ok {
				return global, true
			}
		}
	}
	return Entry{}, false
}

func globalScopeEntry(entry Entry, active activeRecord) (Entry, bool) {
	if entry.Action != ActionDeny {
		return Entry{}, false
	}
	for _, scope := range active.Scopes {
		if scope.PolicyKind != "global" {
			continue
		}
		for _, candidate := range scope.Entries {
			if equalEntry(candidate, entry) {
				return candidate, true
			}
		}
	}
	return Entry{}, false
}

func (source *KernelHitSource) String() string {
	if source == nil {
		return "firewall.KernelHitSource{}"
	}
	return fmt.Sprintf("firewall.KernelHitSource{node:%s}", source.nodeID)
}
