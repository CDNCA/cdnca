package l4forward

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func normalizeAdditionalListeners(fields *Fields) error {
	if fields.AdditionalListeners == nil {
		return nil
	}
	listeners := append([]AdditionalListener{}, (*fields.AdditionalListeners)...)
	if len(listeners) > 63 {
		return ErrInvalidInput
	}
	ids := make(map[uuid.UUID]bool, len(listeners))
	// Overlapping ranges are refused later (normalizePortRanges).
	sockets := map[RuntimeListener]bool{{Protocol: fields.Protocol, Address: fields.ListenAddress, Port: fields.ListenPort}: true}
	for _, listener := range listeners {
		socket := RuntimeListener{Protocol: listener.Protocol, Address: listener.Address, Port: listener.Port}
		if listener.ID == uuid.Nil || ids[listener.ID] || sockets[socket] || listener.Address != "*" || listener.Port == 0 ||
			(listener.Protocol != ProtocolTCP && listener.Protocol != ProtocolUDP) ||
			(listener.Protocol == ProtocolUDP && (fields.ProxyProtocolInbound || fields.ProxyProtocolV1 || fields.TOA)) {
			return ErrInvalidInput
		}
		ids[listener.ID], sockets[socket] = true, true
	}
	sort.Slice(listeners, func(i, j int) bool { return listeners[i].ID.String() < listeners[j].ID.String() })
	fields.AdditionalListeners = &listeners
	return nil
}

// The primary row is maintained by the database; application writes only extra listeners.
func releaseAdditionalListeners(ctx context.Context, tx pgx.Tx, streamID uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE l4_forward_listeners SET retired_at=clock_timestamp()
		WHERE stream_id=$1 AND id<>stream_id AND retired_at IS NULL`, streamID)
	return err
}

func writeAdditionalListeners(ctx context.Context, tx pgx.Tx, item *Forward, listeners *[]AdditionalListener) error {
	if listeners == nil {
		return nil
	}
	for _, listener := range *listeners {
		if listener.ID == item.ID {
			return ErrInvalidInput
		}
		command, err := tx.Exec(ctx, `INSERT INTO l4_forward_listeners(id,stream_id,protocol,address,port,port_end)
			VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE
			SET protocol=EXCLUDED.protocol,address=EXCLUDED.address,port=EXCLUDED.port,port_end=EXCLUDED.port_end,retired_at=NULL
			WHERE l4_forward_listeners.stream_id=EXCLUDED.stream_id AND l4_forward_listeners.id<>l4_forward_listeners.stream_id`,
			listener.ID, item.ID, listener.Protocol, listener.Address, listener.Port, nullablePort(listener.PortEnd))
		if err != nil {
			return classifyConflict(err)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidInput
		}
	}
	item.AdditionalListeners = append([]AdditionalListener(nil), (*listeners)...)
	return nil
}

const additionalListenersJSON = `COALESCE((SELECT jsonb_agg(jsonb_build_object(
	'id',listener.id,'protocol',listener.protocol,'address',listener.address,'port',listener.port) ||
	CASE WHEN listener.port_end IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('port_end',listener.port_end) END ORDER BY listener.id)
	FROM l4_forward_listeners listener WHERE listener.stream_id=f.id AND listener.id<>listener.stream_id
	AND listener.retired_at IS NULL),'[]'::jsonb)`

func loadAdditionalListeners(ctx context.Context, tx pgx.Tx, item *Forward) error {
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT `+additionalListenersJSON+` FROM l4_forwards f WHERE f.id=$1`, item.ID).Scan(&raw); err != nil {
		return err
	}
	return json.Unmarshal(raw, &item.AdditionalListeners)
}
