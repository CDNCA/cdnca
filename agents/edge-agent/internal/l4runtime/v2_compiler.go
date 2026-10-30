package l4runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

type geoRuntimeConfigV2 struct {
	SchemaVersion string                 `json:"schema_version"`
	VersionID     string                 `json:"version_id"`
	Revision      int64                  `json:"revision"`
	Listeners     []geoRuntimeListenerV2 `json:"listeners"`
}

type geoRuntimeListenerV2 struct {
	ID               string      `json:"id"`
	ResourceRevision int64       `json:"resource_revision,omitempty"`
	TenantID         string      `json:"tenant_id"`
	SiteID           string      `json:"site_id"`
	StreamID         string      `json:"stream_id"`
	Geo              GeoPolicyV2 `json:"geo"`
	// Guard holds the stream's guard rules for cdnca_l4_geo guard()
	// (tcp/udp v10); omitted for streams without rules.
	Guard []guardRuntimeRuleV2 `json:"guard,omitempty"`
}

// guardRuntimeRuleV2 is one guard rule as the stream module reads it: geo
// conditions are cdnca_iplib condition specs (edgeconfig.IPIntelConditionSpec).
type guardRuntimeRuleV2 struct {
	ID            string                         `json:"id"`
	Action        string                         `json:"action"`
	FirstPacket   *edgeconfig.L4GuardFirstPacket `json:"first_packet,omitempty"`
	ServerNames   []string                       `json:"server_names,omitempty"`
	ClientIP      *edgeconfig.L4GuardClientIP    `json:"client_ip,omitempty"`
	Geo           []string                       `json:"geo,omitempty"`
	BanSeconds    int                            `json:"ban_seconds,omitempty"`
	Threshold     int                            `json:"threshold,omitempty"`
	WindowSeconds int                            `json:"window_seconds,omitempty"`
}

func guardRuntimeRulesV2(rules []GuardRuleV2) []guardRuntimeRuleV2 {
	if len(rules) == 0 {
		return nil
	}
	result := make([]guardRuntimeRuleV2, len(rules))
	for index, rule := range rules {
		result[index] = guardRuntimeRuleV2{ID: rule.ID, Action: rule.Action, FirstPacket: rule.FirstPacket,
			ServerNames: rule.ServerNames, ClientIP: rule.ClientIP,
			BanSeconds: rule.BanSeconds, Threshold: rule.Threshold, WindowSeconds: rule.WindowSeconds}
		for _, condition := range rule.Geo {
			result[index].Geo = append(result[index].Geo, edgeconfig.IPIntelConditionSpec(condition))
		}
	}
	return result
}

func CompileV2(config ConfigV2, addressSets map[string][]netip.Addr) (CompiledConfigV2, error) {
	normalized, err := normalizeConfigV2(config)
	if err != nil {
		return CompiledConfigV2{}, err
	}
	canonical, err := CanonicalV2(normalized)
	if err != nil {
		return CompiledConfigV2{}, err
	}
	resolved := make(map[string][]netip.Addr, len(normalized.Listeners))
	for _, listener := range normalized.Listeners {
		addresses := addressSets[listener.StreamID]
		if len(listener.Endpoint.Origins) != 0 {
			// 源站列表 (tcp/udp v11): every origin, in order, down ones included
			// (rendered "down" so a later "up" keeps the ip_hash mapping).
			addresses = make([]netip.Addr, len(listener.Endpoint.Origins))
			for index, origin := range listener.Endpoint.Origins {
				addresses[index] = netip.MustParseAddr(origin.Address)
			}
		} else if listener.Endpoint.Address != "" {
			// Explicit addresses already passed the static endpoint contract in
			// normalizeConfigV2. DNS rebinding filters apply only to host answers.
			addresses = []netip.Addr{netip.MustParseAddr(listener.Endpoint.Address)}
		} else {
			addresses, err = normalizeResolvedAddresses(addresses, false)
		}
		if err != nil || len(addresses) == 0 {
			return CompiledConfigV2{}, ErrDNSUnavailable
		}
		resolved[listener.StreamID] = addresses
	}
	resolvedCanonical := make([]struct {
		StreamID  string   `json:"stream_id"`
		Addresses []string `json:"addresses"`
	}, 0, len(normalized.Listeners))
	for _, listener := range normalized.Listeners {
		item := struct {
			StreamID  string   `json:"stream_id"`
			Addresses []string `json:"addresses"`
		}{StreamID: listener.StreamID}
		for _, address := range resolved[listener.StreamID] {
			item.Addresses = append(item.Addresses, address.String())
		}
		resolvedCanonical = append(resolvedCanonical, item)
	}
	encodedResolved, err := json.Marshal(resolvedCanonical)
	if err != nil {
		return CompiledConfigV2{}, ErrInvalidConfig
	}
	digestInput := append(append([]byte(nil), canonical...), encodedResolved...)
	digestBytes := sha256.Sum256(digestInput)
	digest := hex.EncodeToString(digestBytes[:])
	geoConfig := geoRuntimeConfigV2{SchemaVersion: SchemaVersionV2, VersionID: normalized.VersionID, Revision: normalized.Revision}
	for _, listener := range normalized.Listeners {
		geoConfig.Listeners = append(geoConfig.Listeners, geoRuntimeListenerV2{
			ID: listener.StreamID, TenantID: listener.TenantID, SiteID: listener.SiteID, StreamID: listener.StreamID, Geo: listener.Geo,
			ResourceRevision: listener.ResourceRevision, Guard: guardRuntimeRulesV2(listener.GuardRules),
		})
	}
	geoJSON, err := json.Marshal(geoConfig)
	if err != nil {
		return CompiledConfigV2{}, ErrInvalidConfig
	}
	nginxConfig, err := renderV2(normalized, resolved, digest)
	if err != nil {
		return CompiledConfigV2{}, err
	}
	return CompiledConfigV2{
		Config: normalized, Digest: digest, CanonicalJSON: canonical, NginxConfig: nginxConfig,
		GeoJSON: append(geoJSON, '\n'), ResolvedAddressSets: cloneAddressSets(resolved),
	}, nil
}

func normalizeResolvedAddresses(values []netip.Addr, allowPrivate bool) ([]netip.Addr, error) {
	if len(values) == 0 || len(values) > maxEndpointsPerPool {
		return nil, ErrDNSUnavailable
	}
	normalized := make([]netip.Addr, 0, len(values))
	seen := make(map[netip.Addr]struct{}, len(values))
	class := ""
	for _, address := range values {
		address = address.Unmap()
		if !safeResolvedAddress(address, allowPrivate) {
			return nil, ErrDNSUnavailable
		}
		if class == "" {
			class = addressClass(address)
		} else if class != addressClass(address) {
			return nil, ErrDNSUnavailable
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		normalized = append(normalized, address)
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].Compare(normalized[j]) < 0 })
	return normalized, nil
}

// The version directory is sealed 0500/0400 for the agent, so workers running
// as the unprivileged nginx user cannot open config.json; the master reads it
// before forking.
const geoPreloadDirectiveV2 = "    init_by_lua_block { require(\"cdnca_l4_geo\").preload() }\n"

func renderV2(config ConfigV2, addressSets map[string][]netip.Addr, digest string) ([]byte, error) {
	var sockets []ListenerV2
	for _, listener := range config.Listeners {
		for _, socket := range listenerSocketsV2(listener) {
			physical := listener
			physical = physical.onSocket(socket)
			sockets = append(sockets, physical)
		}
	}
	shared, err := planSharedSocketsV2(sockets, config.SiteSockets, config.dispatchDirectory())
	if err != nil {
		return nil, err
	}
	var output strings.Builder
	output.WriteString("# Generated by CDNCA edge-agent; do not edit.\n")
	fmt.Fprintf(&output, "# schema=%s version=%s revision=%d digest=%s\n", config.SchemaVersion, config.VersionID, config.Revision, digest)
	output.WriteString("worker_processes auto;\n")
	output.WriteString("error_log stderr notice;\n")
	output.WriteString("events {\n    worker_connections 65535;\n}\n")
	output.WriteString("stream {\n")
	output.WriteString("    lua_package_path '/opt/cdnca/l4geo/?.lua;/opt/cdnca/?.lua;;';\n")
	output.WriteString(geoPreloadDirectiveV2)
	output.WriteString("    log_format l4_session_v1 escape=json '{\"time\":\"$time_iso8601\",\"connection\":\"$connection\",\"pid\":\"$pid\",\"protocol\":\"$protocol\",\"server_port\":\"$server_port\",\"status\":\"$status\",\"bytes_sent\":$bytes_sent,\"bytes_received\":$bytes_received,\"session_time\":$session_time}';\n")
	if shared.dispatched() {
		// Behind a dispatcher $server_port is empty: the PROXY header carries it.
		output.WriteString("    log_format l4_session_dispatched_v1 escape=json '{\"time\":\"$time_iso8601\",\"connection\":\"$connection\",\"pid\":\"$pid\",\"protocol\":\"$protocol\",\"server_port\":\"$proxy_protocol_server_port\",\"status\":\"$status\",\"bytes_sent\":$bytes_sent,\"bytes_received\":$bytes_received,\"session_time\":$session_time}';\n")
	}
	output.WriteString("    limit_conn_zone \"$server_addr:$server_port:$protocol:$binary_remote_addr\" zone=l4_v2_limit_clients:16m;\n")
	for _, mode := range shared.modes {
		if mode == socketPassthrough {
			// A passthrough socket alone on its port maps SNI into
			// $cdnca_l4_passthrough_<32 hex> (54 bytes): with the stream
			// default of 64 nginx cannot build the variables hash and refuses
			// the configuration.
			output.WriteString("    variables_hash_bucket_size 128;\n")
			break
		}
	}
	logging := slices.ContainsFunc(config.Listeners, func(listener ListenerV2) bool { return listener.SessionLog })
	tracking := slices.ContainsFunc(config.Listeners, tracksLiveSessions)
	if logging {
		// session_log (tcp/udp v7): v1 plus the client, the socket peer, the
		// upstream and the end reason; declared only when a stream logs.
		output.WriteString(sessionLogFormatV2("l4_session_v2", "$server_port"))
		if shared.dispatched() {
			output.WriteString(sessionLogFormatV2("l4_session_dispatched_v2", "$proxy_protocol_server_port"))
		}
	}
	if tracking {
		// Live TCP sessions (cdnca_l4_geo session_track), read by the agent
		// through the control socket: the live connection list and the
		// in-progress usage checkpoints (L4-USAGE-01, internal/l4usage).
		output.WriteString("    lua_shared_dict l4_v2_live 64m;\n")
	}
	if slices.ContainsFunc(config.Listeners, func(listener ListenerV2) bool { return listener.NewConnRate != nil || len(listener.GuardRules) != 0 }) {
		// Per-client new connection buckets and bans (cdnca_l4_geo
		// limit_new_connections), guard rule hit counters and the kernel ban
		// queue (guard), shared by the workers; declared only when a stream
		// is limited or guarded so other releases render as before.
		output.WriteString("    lua_shared_dict l4_v2_rate 16m;\n")
	}
	if slices.ContainsFunc(config.Listeners, func(listener ListenerV2) bool { return listener.SubscriptionLimits != nil }) {
		// Market supply limits per subscription (cdnca_l4_geo
		// subscription_enter, SUBSCRIPTION_LIMITS v1): session counts and the
		// per second windows, shared by the workers.
		output.WriteString("    lua_shared_dict l4_v2_subscriptions 4m;\n")
	}
	if slices.ContainsFunc(config.Listeners, func(listener ListenerV2) bool { return guardMatches(listener, edgeconfig.L4GuardMatchRegex) }) {
		// First packet regular expressions run on client data: bound PCRE
		// backtracking (a failed match is a non-match).
		output.WriteString("    lua_regex_match_limit 100000;\n")
	}
	output.WriteString("\n")
	shared.writeDispatchers(&output)
	for _, listener := range config.Listeners {
		upstream := internalName("l4_v2_upstream", listener.TenantID+"/"+listener.SiteID+"/"+listener.StreamID)
		fmt.Fprintf(&output, "    upstream %s {\n", upstream)
		if listener.Endpoint.FollowPort {
			writeFollowPortBalancer(&output, addressSets[listener.StreamID], listener.Endpoint.Balance)
		} else {
			fmt.Fprintf(&output, "        zone %s 64k;\n", upstream)
			if listener.Endpoint.Balance == edgeconfig.L4BalanceIPHash {
				// 定源: one client address always reaches the same origin.
				output.WriteString("        hash $remote_addr consistent;\n")
			}
			for index, address := range addressSets[listener.StreamID] {
				fmt.Fprintf(&output, "        server %s%s;\n", nginxAddress(address.String(), listener.Endpoint.Port),
					originServerParameters(listener.Endpoint, index))
			}
		}
		output.WriteString("    }\n\n")
		for _, socket := range listenerSocketsV2(listener) {
			listener := listener
			listener = listener.onSocket(socket)
			mode := shared.modes[listener.ID]
			target := upstream
			if mode == socketPassthrough {
				target = shared.passthroughTarget(&output, listener, upstream)
			}
			output.WriteString("    server {\n")
			if mode == socketDispatched {
				fmt.Fprintf(&output, "        listen unix:%s proxy_protocol;\n", shared.socketPath(listener.ID))
				output.WriteString("        set_real_ip_from unix:;\n")
			} else {
				addresses := []string{listener.Address}
				if listener.ListenIPv6 && listener.Address == "0.0.0.0" {
					// IPv6开启 (tcp/udp v11): the same socket on [::] too.
					addresses = append(addresses, "::")
				}
				for _, address := range addresses {
					fmt.Fprintf(&output, "        listen %s", nginxListenAddress(address, listener.Port, listener.PortEnd))
					if netip.MustParseAddr(address).Is6() {
						output.WriteString(" ipv6only=on")
					}
					if listener.Protocol == ProtocolUDP {
						output.WriteString(" udp")
					}
					if listener.ProxyProtocolInbound {
						output.WriteString(" proxy_protocol")
					}
					output.WriteString(";\n")
				}
			}
			if mode == socketPassthrough || mode == socketDispatched && guardUsesSNI(listener) {
				// Behind a dispatcher the ClientHello follows the PROXY header:
				// guard rules on SNI read it again.
				output.WriteString("        ssl_preread on;\n")
			}
			if guardMatches(listener, "") {
				// guard waits at most guardFirstPacketWait for the client's
				// first data; the session must outlive the wait.
				output.WriteString("        preread_timeout 3s;\n")
			}
			guard := ""
			if len(listener.GuardRules) != 0 {
				// A ban may become a kernel ban only where the socket peer is
				// the node's own client (not behind a shared port's dispatcher).
				guard = fmt.Sprintf(" if not geo.guard(\"%s\", client, %t, %t) then return end;", listener.StreamID, listener.SessionLog,
					mode != socketDispatched)
			}
			track := listener.Protocol == ProtocolTCP
			subscription := ""
			if listener.SubscriptionLimits != nil {
				// last in preread (after the Geo, guard and per-client
				// checks): a refused session is not counted
				output.WriteString("        set $cdnca_l4_subscription \"\";\n        set $cdnca_l4_subscription_rate 0;\n")
				subscription = subscriptionCall(listener)
			}
			if listener.SessionLog {
				output.WriteString("        set $cdnca_l4_client \"\";\n        set $cdnca_l4_end_reason \"\";\n")
				if track {
					output.WriteString("        set $cdnca_l4_live_key \"\";\n        set $cdnca_l4_live_token \"\";\n")
				}
				writeSessionLogPreread(&output, listener, track, mode == socketDispatched, guard, subscription)
			} else if rate := listener.NewConnRate; rate != nil || guard != "" || subscription != "" || track {
				if track {
					output.WriteString("        set $cdnca_l4_live_key \"\";\n        set $cdnca_l4_live_token \"\";\n")
				}
				// The bucket is the stream's (StreamID), so its sockets share it;
				// the client is the one the Geo decision used.
				fmt.Fprintf(&output, "        preread_by_lua_block { local geo = require(\"cdnca_l4_geo\"); local ok, reason, client = geo.enforce(\"%s\"); if not ok then ngx.log(ngx.WARN, \"l4_geo \", reason) return end;%s",
					listener.StreamID, guard)
				if rate != nil {
					// closes the session over the limit (ngx.exit): nothing after it runs
					fmt.Fprintf(&output, " geo.limit_new_connections(\"%s\", client, %d, %d, %d)", listener.StreamID, rate.RatePerSecond, rate.Burst, rate.BanSeconds)
				}
				output.WriteString(subscription)
				if track {
					fmt.Fprintf(&output, " geo.session_track(\"%s\", \"%s\", client, %t);", listener.StreamID, listener.ID, mode == socketDispatched)
				}
				output.WriteString(" }\n")
			} else {
				fmt.Fprintf(&output, "        preread_by_lua_block { local ok, reason = require(\"cdnca_l4_geo\").enforce(\"%s\"); if not ok then ngx.log(ngx.WARN, \"l4_geo \", reason) end }\n", listener.StreamID)
			}
			fmt.Fprintf(&output, "        proxy_pass %s;\n", target)
			fmt.Fprintf(&output, "        proxy_connect_timeout %dms;\n", listener.ConnectTimeoutMS)
			fmt.Fprintf(&output, "        proxy_timeout %dms;\n", listener.ResponseTimeoutMS)
			output.WriteString("        proxy_next_upstream on;\n")
			fmt.Fprintf(&output, "        proxy_next_upstream_tries %d;\n", upOrigins(listener.Endpoint, addressSets[listener.StreamID]))
			if listener.Protocol == ProtocolUDP {
				output.WriteString("        proxy_responses 1;\n")
			}
			if listener.ProxyProtocolOutbound {
				output.WriteString("        proxy_protocol on;\n")
			}
			if listener.TOA {
				output.WriteString("        proxy_toa on;\n")
			}
			fmt.Fprintf(&output, "        limit_conn l4_v2_limit_clients %d;\n", listener.MaxConnectionsPerClient)
			if limits := listener.SubscriptionLimits; limits != nil && limits.BandwidthBPS > 0 {
				// the subscription's bandwidth, one budget for all of its
				// sessions on the node (native patch 28: a token bucket per
				// subscription in shared memory; subscription_enter writes
				// both variables in preread)
				output.WriteString("        proxy_download_rate $cdnca_l4_subscription_rate;\n")
				output.WriteString("        proxy_download_rate_shared " + subscriptionRateZone + " $cdnca_l4_subscription;\n")
			}
			fmt.Fprintf(&output, "        set $cdnca_l4_tenant_id \"%s\";\n", listener.TenantID)
			fmt.Fprintf(&output, "        set $cdnca_l4_site_id \"%s\";\n", listener.SiteID)
			fmt.Fprintf(&output, "        set $cdnca_l4_stream_id \"%s\";\n", listener.StreamID)
			fmt.Fprintf(&output, "        set $cdnca_l4_listener_id \"%s\";\n", listener.ID)
			versionID, revision := listener.telemetryIdentity(config)
			fmt.Fprintf(&output, "        set $cdnca_l4_config_version_id \"%s\";\n", versionID)
			fmt.Fprintf(&output, "        set $cdnca_l4_config_revision \"%d\";\n", revision)
			telemetryPath, err := L4TelemetryLogPathForConfigListener("/var/lib/cdnca-edge", versionID, listener)
			if err != nil {
				return nil, fmt.Errorf("%w: L4 listener telemetry path", ErrInvalidConfig)
			}
			format := "l4_session_v1"
			if mode == socketDispatched {
				format = "l4_session_dispatched_v1"
			}
			if listener.SessionLog {
				format = strings.Replace(format, "_v1", "_v2", 1)
			}
			fmt.Fprintf(&output, "        access_log \"%s\" %s;\n", telemetryPath, format)
			switch {
			case track && listener.SubscriptionLimits != nil:
				output.WriteString("        log_by_lua_block { local geo = require(\"cdnca_l4_geo\"); geo.subscription_leave(); geo.session_end() }\n")
			case track:
				// Runs before the access log, so a killed session logs "killed".
				output.WriteString("        log_by_lua_block { require(\"cdnca_l4_geo\").session_end() }\n")
			case listener.SubscriptionLimits != nil:
				output.WriteString("        log_by_lua_block { require(\"cdnca_l4_geo\").subscription_leave() }\n")
			}
			output.WriteString("    }\n\n")
		}
	}
	if tracking || slices.ContainsFunc(config.Listeners, bansClients) {
		// The live session registry (session_log) and the guard kernel ban
		// queue (guard). Only the agent may connect: nginx makes unix sockets 0666, so the
		// directory (prepareControlDirectory) is the agent's, mode 0700.
		fmt.Fprintf(&output, "    server {\n        listen unix:%s;\n        access_log off;\n"+
			"        content_by_lua_block { require(\"cdnca_l4_geo\").control() }\n    }\n\n", L4ControlSocketPath)
	}
	output.WriteString("}\n")
	return []byte(output.String()), nil
}

// originServerParameters are the "server" parameters of the index-th origin
// of a multi-origin endpoint: weight (when not 1) and down.
func originServerParameters(endpoint EndpointV2, index int) string {
	if index >= len(endpoint.Origins) {
		return ""
	}
	origin := endpoint.Origins[index]
	parameters := ""
	if origin.Weight != 1 {
		parameters += fmt.Sprintf(" weight=%d", origin.Weight)
	}
	if origin.Down {
		parameters += " down"
	}
	return parameters
}

// nginxListenAddress is the listen address of a socket: a port range
// (nginx 1.15.10+) as "first-last".
func nginxListenAddress(address string, port, portEnd int) string {
	if portEnd == 0 {
		return nginxAddress(address, port)
	}
	if netip.MustParseAddr(address).Is6() {
		return fmt.Sprintf("[%s]:%d-%d", address, port, portEnd)
	}
	return fmt.Sprintf("%s:%d-%d", address, port, portEnd)
}

// writeFollowPortBalancer renders the upstream of a follow_port stream
// (tcp/udp v9): the origin is the stream's resolved addresses (the agent's
// L4 DNS policy, as for other streams) on the port the client connected to,
// $server_port, or behind a dispatcher the public port the PROXY header
// names. The first try picks an address by connection number (round robin)
// or, for 定源 (ip_hash), by a hash of the client address ($remote_addr, the
// PROXY client behind a dispatcher) so one client keeps one origin while the
// sorted address set is unchanged; retries walk the rest
// (proxy_next_upstream_tries). The placeholder server is never connected to:
// the balancer sets every peer.
func writeFollowPortBalancer(output *strings.Builder, addresses []netip.Addr, balance string) {
	peers := make([]string, 0, len(addresses))
	for _, address := range addresses {
		host := address.String()
		if address.Is6() {
			host = "[" + host + "]" // ngx_parse_url needs brackets around IPv6
		}
		peers = append(peers, fmt.Sprintf("%q", host))
	}
	first := "tonumber(ngx.var.connection)"
	if balance == edgeconfig.L4BalanceIPHash {
		first = "ngx.crc32_long(ngx.var.remote_addr)"
	}
	output.WriteString("        server 0.0.0.1:1;\n")
	fmt.Fprintf(output, "        balancer_by_lua_block { local balancer = require(\"ngx.balancer\"); local peers = {%s}; "+
		"local port = tonumber(ngx.var.server_port) or tonumber(ngx.var.proxy_protocol_server_port); "+
		"if not port then ngx.log(ngx.ERR, \"l4_follow_port no client port\") return ngx.exit(ngx.ERROR) end; "+
		"local ctx = ngx.ctx; local try = (ctx.cdnca_l4_follow_try or 0) + 1; ctx.cdnca_l4_follow_try = try; "+
		"if try == 1 and #peers > 1 then balancer.set_more_tries(#peers - 1) end; "+
		"local first = %s; local peer = peers[(first + try - 1) %% #peers + 1]; "+
		"local ok, err = balancer.set_current_peer(peer, port); "+
		"if not ok then ngx.log(ngx.ERR, \"l4_follow_port \", err) return ngx.exit(ngx.ERROR) end }\n",
		strings.Join(peers, ", "), first)
}

// guardMatches reports whether a guard rule of listener has a first packet
// condition (of kind match; "" any kind).
func guardMatches(listener ListenerV2, match string) bool {
	return slices.ContainsFunc(listener.GuardRules, func(rule GuardRuleV2) bool {
		return rule.FirstPacket != nil && (match == "" || rule.FirstPacket.Match == match)
	})
}

// guardUsesSNI reports whether a guard rule of listener matches the SNI.
func guardUsesSNI(listener ListenerV2) bool {
	return slices.ContainsFunc(listener.GuardRules, func(rule GuardRuleV2) bool { return len(rule.ServerNames) != 0 })
}

// bansClients reports whether a guard rule of listener bans.
func bansClients(listener ListenerV2) bool {
	return slices.ContainsFunc(listener.GuardRules, func(rule GuardRuleV2) bool { return rule.Action == edgeconfig.L4GuardActionBan })
}

// tracksLiveSessions: the live session registry covers every TCP socket
// (usage checkpoints, L4-USAGE-01; the live list reads it for logging
// streams); UDP sessions end with their reply.
func tracksLiveSessions(listener ListenerV2) bool {
	return slices.ContainsFunc(listenerSocketsV2(listener), func(socket AdditionalListenerV2) bool { return socket.Protocol == ProtocolTCP })
}

// sessionLogFormatV2 is l4_session_v1 plus the session log fields; port is
// the variable naming the listening port.
func sessionLogFormatV2(name, port string) string {
	return "    log_format " + name + ` escape=json '{"time":"$time_iso8601","connection":"$connection","pid":"$pid","protocol":"$protocol",` +
		`"server_port":"` + port + `","status":"$status","bytes_sent":$bytes_sent,"bytes_received":$bytes_received,` +
		`"session_time":$session_time,"client":"$cdnca_l4_client","remote_addr":"$remote_addr","remote_port":"$remote_port",` +
		`"proxy_protocol_port":"$proxy_protocol_port","upstream_addr":"$upstream_addr",` +
		`"upstream_connect_time":"$upstream_connect_time","end_reason":"$cdnca_l4_end_reason"}';` + "\n"
}

// writeSessionLogPreread renders the preread of a logging socket: the Geo
// and rate checks record a refusal's reason and the client, then an admitted
// TCP session is registered as live.
func writeSessionLogPreread(output *strings.Builder, listener ListenerV2, track, dispatched bool, guard, subscription string) {
	fmt.Fprintf(output, "        preread_by_lua_block { local geo = require(\"cdnca_l4_geo\"); local ok, reason, client = geo.enforce(\"%s\", true); "+
		"if not ok then ngx.log(ngx.WARN, \"l4_geo \", reason) return end;%s", listener.StreamID, guard)
	if rate := listener.NewConnRate; rate != nil {
		fmt.Fprintf(output, " if not geo.limit_new_connections(\"%s\", client, %d, %d, %d, true) then return end;",
			listener.StreamID, rate.RatePerSecond, rate.Burst, rate.BanSeconds)
	}
	output.WriteString(subscription)
	if track {
		fmt.Fprintf(output, " geo.session_track(\"%s\", \"%s\", client, %t);", listener.StreamID, listener.ID, dispatched)
	}
	output.WriteString(" }\n")
}

// upOrigins is how many of addresses the stream may connect to (origins not
// marked down).
func upOrigins(endpoint EndpointV2, addresses []netip.Addr) int {
	count := len(addresses)
	for _, origin := range endpoint.Origins {
		if origin.Down {
			count--
		}
	}
	return count
}

func cloneAddressSets(values map[string][]netip.Addr) map[string][]netip.Addr {
	cloned := make(map[string][]netip.Addr, len(values))
	for key, addresses := range values {
		cloned[key] = append([]netip.Addr(nil), addresses...)
	}
	return cloned
}

// subscriptionRateZone is the shared memory of the subscription bandwidth
// buckets (proxy_download_rate_shared); every server names the same zone.
const subscriptionRateZone = "l4_v2_subscription_rate:4m"

// subscriptionCall is the preread call of a stream's market supply limits.
func subscriptionCall(listener ListenerV2) string {
	limits := listener.SubscriptionLimits
	return fmt.Sprintf(" if not geo.subscription_enter(\"%s\", %d, %d, %d, %t, %t) then return end;",
		limits.SubscriptionID, limits.MaxConnections, limits.NewPerSecond, limits.BandwidthBPS, limits.Stopped, listener.SessionLog)
}
