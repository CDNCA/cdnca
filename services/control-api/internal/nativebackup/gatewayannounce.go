package nativebackup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Announce the new Gateway address before a migration freezes this host
//. Nodes learn the endpoint list from GatewayHello and keep it
// (gateway-journal/gateway-endpoints.json); a node whose primary address no
// longer answers dials the next entries in order. Adding the new host as an
// extra entry point (agent_gateway_entrypoints, the Gateway settings page
// list) and restarting the local Gateway makes every online node reconnect
// and learn it now, so after the migration they follow the new host with no
// DNS involved. The node verifies the new Gateway with its Gateway CA (the
// migrated PKI) and the server name, which RetargetGatewayHost adds to the
// new host's certificate SAN.

// AnnounceRequest is one `native-backup announce-gateway`.
type AnnounceRequest struct {
	Host string // the new host (IP or name), as nodes will reach it
	// Wait bounds the wait for online nodes to reconnect after the restart.
	Wait time.Duration
}

// AnnounceResult reports the entry and how many nodes reconnected.
type AnnounceResult struct {
	Address     string `json:"address"`
	ServerName  string `json:"server_name"`
	Added       bool   `json:"added"`
	OnlineNodes int    `json:"online_nodes"`
	Reconnected int    `json:"reconnected_nodes"`
}

// AnnounceGateway adds host:<agent port> (grpc, server name host) as the
// first extra entry point and restarts cdnca-agent-gateway. It is a no-op
// when the entry exists or when this host has no co-located Gateway.
func AnnounceGateway(ctx context.Context, host *Host, request AnnounceRequest, now func() time.Time) (AnnounceResult, error) {
	target := strings.ToLower(strings.TrimSpace(request.Host))
	if !ValidGatewayHost(target) {
		return AnnounceResult{}, fmt.Errorf("invalid Gateway host %q", request.Host)
	}
	gateway, err := ReadEnvironmentFile(host.Layout.Path(gatewayEnvFile))
	if err != nil {
		return AnnounceResult{}, fmt.Errorf("read gateway.env: %w", err)
	}
	_, port, err := net.SplitHostPort(gateway[gatewayPublicKey])
	if err != nil {
		return AnnounceResult{}, fmt.Errorf("gateway.env %s is invalid", gatewayPublicKey)
	}
	address := net.JoinHostPort(target, port)
	result := AnnounceResult{Address: address, ServerName: target}
	db := postgresComponent{}
	name := host.Database.Name
	query := func(sql string) (string, error) { return db.psql(ctx, host, name, sql) }
	// Values are validated above (a canonical IP or a DNS name and a port);
	// they are still passed as quoted literals only.
	literal := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
	existing, err := query("SELECT count(*) FROM agent_gateway_entrypoints WHERE address=" + literal(address))
	if err != nil {
		return result, fmt.Errorf("read the Gateway entry points: %w", err)
	}
	if existing == "0" {
		// Shift the page-edited entries down one position and put the new
		// host first; the list is capped at 16 (MaxEntrypoints).
		count, err := query("SELECT count(*) FROM agent_gateway_entrypoints")
		if err != nil {
			return result, err
		}
		if number, _ := strconv.Atoi(count); number >= 16 {
			return result, errors.New("the Gateway entry point list is full (16); remove one on the Gateway settings page first")
		}
		// position is CHECKed to 1..16, so the list is re-inserted in one
		// transaction instead of being shifted in place.
		if _, err := query("BEGIN; LOCK TABLE agent_gateway_entrypoints IN EXCLUSIVE MODE; " +
			"CREATE TEMP TABLE cdnca_announce ON COMMIT DROP AS SELECT * FROM agent_gateway_entrypoints; " +
			"DELETE FROM agent_gateway_entrypoints; " +
			"INSERT INTO agent_gateway_entrypoints(position,address,server_name,transport,tunnel_host) VALUES(1," +
			literal(address) + "," + literal(target) + ",'grpc',''); " +
			"INSERT INTO agent_gateway_entrypoints(position,address,server_name,transport,tunnel_host) " +
			"SELECT position+1,address,server_name,transport,tunnel_host FROM cdnca_announce ORDER BY position; COMMIT;"); err != nil {
			return result, fmt.Errorf("add the new Gateway entry point: %w", err)
		}
		result.Added = true
	}
	since := now().UTC()
	online, err := query("SELECT count(*) FROM node_presence WHERE status='online'")
	if err == nil {
		result.OnlineNodes, _ = strconv.Atoi(online)
	}
	// The Gateway reads the list at startup; the restart closes every session
	// and nodes reconnect with a GatewayHello that names the new host.
	if err := host.Systemd.Stop(ctx, hostBindGatewayUnit); err != nil {
		return result, err
	}
	if err := host.Systemd.Start(ctx, hostBindGatewayUnit); err != nil {
		return result, err
	}
	deadline := since.Add(request.Wait)
	for {
		value, err := query("SELECT count(*) FROM node_presence WHERE status='online' AND last_seen_at > '" + since.Format(time.RFC3339Nano) + "'")
		if err == nil {
			result.Reconnected, _ = strconv.Atoi(value)
		}
		if result.Reconnected >= result.OnlineNodes || !now().Before(deadline) || !sleepContext(ctx, 5*time.Second) {
			return result, nil
		}
	}
}
