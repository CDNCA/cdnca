package l4forward

import (
	"context"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Port conflict kinds (PortConflictError.With).
const (
	PortConflictReserved = "reserved" // the node's own ports 80/443/18080/18443
	PortConflictSelf     = "self"     // another listener of the same forward
	PortConflictStream   = "stream"   // another layer-four forward
	PortConflictSite     = "site"     // a website of the scope
)

// PortConflictError says where a save's listen ports collide: Protocol
// Port..PortEnd (PortEnd 0: the single Port) is taken by With, named Name
// when it is in the caller's scope. It unwraps to ErrPortConflict.
type PortConflictError struct {
	Protocol string
	Port     uint16
	PortEnd  uint16
	With     string
	Name     string
}

func (e *PortConflictError) Error() string {
	ports := fmt.Sprint(e.Port)
	if e.PortEnd > e.Port {
		ports = fmt.Sprintf("%d-%d", e.Port, e.PortEnd)
	}
	message := fmt.Sprintf("%s listen ports %s conflict with %s", e.Protocol, ports, e.With)
	if e.Name != "" {
		message += " " + e.Name
	}
	return message
}

func (e *PortConflictError) Unwrap() error { return ErrPortConflict }

// overlap returns the common ports of two port ranges (end 0: single port).
func overlap(port, end, otherPort, otherEnd uint16) (uint16, uint16, bool) {
	last, otherLast := max(port, end), max(otherPort, otherEnd)
	start, stop := max(port, otherPort), min(last, otherLast)
	return start, stop, start <= stop
}

// normalizePortRange checks one listener's range: bounds are invalid input,
// covering a protected port is a reserved-port conflict.
func normalizePortRange(protocol string, port, end uint16) error {
	if end == 0 {
		return nil
	}
	if end <= port || int(end)-int(port)+1 > edgeconfig.L4PortRangeMax {
		return ErrInvalidInput
	}
	if _, ok := edgeconfig.ValidL4PortRange(int(port), int(end)); !ok {
		for _, protected := range edgeconfig.L4RangeProtectedPorts {
			if protected >= int(port) && protected <= int(end) {
				return &PortConflictError{Protocol: protocol, Port: uint16(protected), With: PortConflictReserved}
			}
		}
		return ErrInvalidInput
	}
	return nil
}

// fieldSockets are the listen sockets a save asks for: the primary, then the
// additional listeners.
func fieldSockets(fields *Fields) []AdditionalListener {
	sockets := []AdditionalListener{{Protocol: fields.Protocol, Address: fields.ListenAddress, Port: fields.ListenPort, PortEnd: fields.ListenPortEnd}}
	if fields.AdditionalListeners != nil {
		sockets = append(sockets, (*fields.AdditionalListeners)...)
	}
	return sockets
}

// normalizePortRanges validates port ranges and follow-port (migration 334):
// ranges are v2 only and never TLS passthrough, sockets of one forward may
// not overlap, and follow-port takes upstream_port from listen_port.
func normalizePortRanges(fields *Fields) error {
	ranged := false
	sockets := fieldSockets(fields)
	for index, socket := range sockets {
		if err := normalizePortRange(socket.Protocol, socket.Port, socket.PortEnd); err != nil {
			return err
		}
		ranged = ranged || socket.PortEnd != 0
		for _, other := range sockets[:index] {
			if other.Protocol != socket.Protocol {
				continue
			}
			if start, stop, ok := overlap(socket.Port, socket.PortEnd, other.Port, other.PortEnd); ok {
				return &PortConflictError{Protocol: socket.Protocol, Port: start, PortEnd: stop, With: PortConflictSelf}
			}
		}
	}
	if ranged && fields.TLSPassthrough {
		return ErrInvalidInput
	}
	if fields.UpstreamFollowPort {
		fields.UpstreamPort = fields.ListenPort
	}
	return nil
}

// locateSocketConflict finds, before writing, a reserved listener of another
// forward that the save's sockets collide with, so the refusal can say where
// (the database exclusion constraints stay the guarantee). Two plain sockets
// collide, and a range collides with anything; a passthrough socket shares
// with a plain one and with other passthrough ones (SNI is checked by
// rejectStreamSocketConflict and the database). Other scopes' forwards are
// not named.
func locateSocketConflict(ctx context.Context, tx pgx.Tx, scopeID, streamID uuid.UUID, fields *Fields) error {
	for _, socket := range fieldSockets(fields) {
		ranged := socket.PortEnd != 0
		var port, end int
		var name string
		var otherScope uuid.UUID
		err := tx.QueryRow(ctx, `
			SELECT listener.port, COALESCE(listener.port_end, listener.port), forward.name, forward.scope_id
			FROM l4_forward_listeners listener JOIN l4_forwards forward ON forward.id=listener.stream_id
			WHERE listener.reserved AND listener.stream_id<>$1 AND listener.protocol=$2 AND
			      int4range(listener.port, COALESCE(listener.port_end, listener.port), '[]') && int4range($3, $4, '[]') AND
			      (listener.port_end IS NOT NULL OR $5 OR (NOT listener.tls_passthrough AND NOT $6))
			ORDER BY listener.port, listener.id LIMIT 1`,
			streamID, socket.Protocol, int(socket.Port), int(max(socket.Port, socket.PortEnd)), ranged, fields.TLSPassthrough,
		).Scan(&port, &end, &name, &otherScope)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		start, stop, _ := overlap(socket.Port, socket.PortEnd, uint16(port), uint16(end))
		conflict := &PortConflictError{Protocol: socket.Protocol, Port: start, With: PortConflictStream}
		if stop > start {
			conflict.PortEnd = stop
		}
		if otherScope == scopeID {
			conflict.Name = name
		}
		return conflict
	}
	return nil
}
