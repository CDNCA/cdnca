package l4runtime

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Sockets of split ports. A TCP port with more than one consumer (streams,
// and websites handed over by SiteSockets) is owned by a dispatcher: it reads
// the ClientHello (ssl_preread) and passes the connection with PROXY
// protocol to the internal unix socket of the consumer it belongs to, where
// stream realip restores the client address for Geo, limits and telemetry.
const (
	L4DispatchDirectory = "/var/lib/cdnca-edge/shared/l4mux"
	// L4RejectSocketPath is never listened on: connections sent there (TLS
	// for an unknown server name) are closed.
	L4RejectSocketPath = L4DispatchDirectory + "/reject.sock"
	maxServerNames     = 32
	// L4ControlDirectory holds the socket the agent reads the live session
	// registry through (session_log streams).
	L4ControlDirectory  = "/var/lib/cdnca-edge/shared/l4ctl"
	L4ControlSocketPath = L4ControlDirectory + "/control.sock"
)

// L4DispatchSocketPath is the internal socket of one listener socket (a
// stream's primary or additional listener) on a split port.
func L4DispatchSocketPath(socketID string) string {
	return filepath.Join(L4DispatchDirectory, socketID+".sock")
}

// dispatchDirectory is the config's internal socket directory.
func (config ConfigV2) dispatchDirectory() string {
	if config.DispatchDirectory != "" {
		return config.DispatchDirectory
	}
	return L4DispatchDirectory
}

func validDispatchDirectory(path string) bool {
	return path == "" || path != "/" && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		!strings.ContainsAny(path, " \t\r\n;{}\"'$\\")
}

func normalizeL4ServerName(value string) bool {
	base := strings.TrimPrefix(value, "*.")
	host, err := canonicalDNSHost(base)
	return err == nil && host == base
}

// normalizeL4ServerNamesV2 checks a TLS passthrough stream: TCP on every
// listener and 1-32 distinct server names, returned sorted.
func normalizeL4ServerNamesV2(listener ListenerV2) ([]string, error) {
	if !listener.TLSPassthrough {
		if len(listener.ServerNames) != 0 {
			return nil, ErrInvalidConfig
		}
		return nil, nil
	}
	if listener.Protocol != ProtocolTCP || len(listener.ServerNames) == 0 || len(listener.ServerNames) > maxServerNames {
		return nil, ErrInvalidConfig
	}
	for _, socket := range listener.AdditionalListeners {
		if socket.Protocol != ProtocolTCP {
			return nil, ErrInvalidConfig
		}
	}
	names := append([]string(nil), listener.ServerNames...)
	sort.Strings(names)
	for index, name := range names {
		if !normalizeL4ServerName(name) || index > 0 && names[index-1] == name {
			return nil, ErrInvalidConfig
		}
	}
	return names, nil
}

func validDispatchSocket(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) <= 107 &&
		strings.HasSuffix(path, ".sock") && !strings.ContainsAny(path, " \t\r\n;{}\"'$\\")
}

func normalizeSiteSocketsV2(values []SiteSocketsV2) ([]SiteSocketsV2, error) {
	if len(values) == 0 {
		return nil, nil
	}
	result := make([]SiteSocketsV2, 0, len(values))
	ports := map[int]struct{}{}
	for _, value := range values {
		if !validPort(value.Port) || value.PlainSocket == "" && value.TLSSocket == "" ||
			value.PlainSocket != "" && !validDispatchSocket(value.PlainSocket) ||
			value.TLSSocket != "" && !validDispatchSocket(value.TLSSocket) ||
			(value.TLSSocket == "") != (len(value.TLSServerNames) == 0) || len(value.TLSServerNames) > 4096 {
			return nil, ErrInvalidConfig
		}
		if _, duplicate := ports[value.Port]; duplicate {
			return nil, ErrInvalidConfig
		}
		ports[value.Port] = struct{}{}
		names := append([]string(nil), value.TLSServerNames...)
		sort.Strings(names)
		for index, name := range names {
			if !normalizeL4ServerName(name) || index > 0 && names[index-1] == name {
				return nil, ErrInvalidConfig
			}
		}
		value.TLSServerNames = names
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Port < result[j].Port })
	return result, nil
}

type socketMode int

const (
	socketExclusive   socketMode = iota // rendered as before
	socketPassthrough                   // alone on its port, chosen by SNI
	socketDispatched                    // behind the port's dispatcher
)

// sharedPortV2 is one split port and how its consumers are told apart.
type sharedPortV2 struct {
	address string
	port    int
	// plain is the one consumer of non-TLS connections: an internal socket
	// path, empty when none.
	plain string
	// names maps a TLS server name to its consumer's socket.
	names map[string]string
	// tlsDefault receives TLS for an unknown name: the websites' TLS socket
	// (their default server), else the reject socket.
	tlsDefault string
}

type sharedSocketPlanV2 struct {
	modes map[string]socketMode // by socket ID
	ports []sharedPortV2
	// directory holds the internal sockets (ConfigV2.dispatchDirectory).
	directory string
}

func (plan sharedSocketPlanV2) socketPath(socketID string) string {
	return filepath.Join(plan.directory, socketID+".sock")
}

func (plan sharedSocketPlanV2) rejectPath() string {
	return filepath.Join(plan.directory, "reject.sock")
}

// planSharedSocketsV2 applies the port-sharing rules (FindPortConflicts) and
// decides how each socket is rendered. sockets are the physical listener
// sockets (ID set to the socket's ID).
func planSharedSocketsV2(sockets []ListenerV2, sites []SiteSocketsV2, directory string) (sharedSocketPlanV2, error) {
	plan := sharedSocketPlanV2{modes: map[string]socketMode{}, directory: directory}
	type groupKey struct {
		protocol Protocol
		port     int
	}
	groups := map[groupKey][]ListenerV2{}
	// A port range (tcp/udp v9) is exclusive: no other socket of its protocol
	// and no website hand-over may overlap it.
	var ranged []ListenerV2
	for _, socket := range sockets {
		if socket.PortEnd != 0 {
			ranged = append(ranged, socket)
			continue
		}
		key := groupKey{protocol: socket.Protocol, port: socket.Port}
		groups[key] = append(groups[key], socket)
	}
	for _, socket := range ranged {
		for _, other := range sockets {
			if other.ID != socket.ID && listenerV2BindsOverlap(socket, other) {
				return plan, ErrInvalidConfig
			}
		}
		for _, site := range sites {
			if socket.Protocol == ProtocolTCP && site.Port >= socket.Port && site.Port <= socket.PortEnd {
				return plan, ErrInvalidConfig
			}
		}
		plan.modes[socket.ID] = socketExclusive
	}
	siteByPort := map[int]SiteSocketsV2{}
	for _, site := range sites {
		siteByPort[site.Port] = site
		if len(groups[groupKey{protocol: ProtocolTCP, port: site.Port}]) == 0 {
			return plan, ErrInvalidConfig // a site hand-over without a stream to own the port
		}
	}
	keys := make([]groupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].port != keys[j].port {
			return keys[i].port < keys[j].port
		}
		return keys[i].protocol < keys[j].protocol
	})
	for _, key := range keys {
		group := groups[key]
		site, hasSite := siteByPort[key.port]
		hasSite = hasSite && key.protocol == ProtocolTCP
		shareable := hasSite
		for _, socket := range group {
			shareable = shareable || socket.TLSPassthrough
		}
		if !shareable {
			// Exclusive sockets keep the original rule: no overlapping binds.
			for left := 0; left < len(group); left++ {
				for right := left + 1; right < len(group); right++ {
					if listenerV2BindsOverlap(group[left], group[right]) {
						return plan, ErrInvalidConfig
					}
				}
				plan.modes[group[left].ID] = socketExclusive
			}
			continue
		}
		// One bind for the whole port, as the control plane publishes it.
		var claims []edgeconfig.PortClaim
		streams := map[string]struct{}{}
		for _, socket := range group {
			if socket.Address != group[0].Address || !netip.MustParseAddr(socket.Address).IsUnspecified() {
				return plan, ErrInvalidConfig
			}
			if _, duplicate := streams[socket.StreamID]; duplicate {
				return plan, ErrInvalidConfig // one stream twice on one socket
			}
			streams[socket.StreamID] = struct{}{}
			kind := edgeconfig.PortClaimPlainL4
			if socket.TLSPassthrough {
				kind = edgeconfig.PortClaimTLSL4
			}
			claims = append(claims, edgeconfig.PortClaim{Owner: socket.TenantID, ID: socket.StreamID, Kind: kind,
				Protocol: edgeconfig.StreamProtocol(socket.Protocol), Port: uint16(socket.Port), Names: socket.ServerNames})
		}
		if hasSite {
			if site.PlainSocket != "" {
				claims = append(claims, edgeconfig.PortClaim{Owner: "site", ID: "plain", Kind: edgeconfig.PortClaimPlainHTTP,
					Protocol: edgeconfig.StreamProtocolTCP, Port: uint16(site.Port)})
			}
			if site.TLSSocket != "" {
				claims = append(claims, edgeconfig.PortClaim{Owner: "site", ID: "tls", Kind: edgeconfig.PortClaimTLSSite,
					Protocol: edgeconfig.StreamProtocolTCP, Port: uint16(site.Port), Names: site.TLSServerNames})
			}
		}
		if len(edgeconfig.FindPortConflicts(claims)) != 0 {
			return plan, ErrInvalidConfig
		}
		if len(claims) == 1 {
			plan.modes[group[0].ID] = socketPassthrough
			continue
		}
		shared := sharedPortV2{address: group[0].Address, port: key.port, names: map[string]string{},
			tlsDefault: plan.rejectPath()}
		for _, socket := range group {
			// After the internal hop the local address is a unix socket: an
			// outbound PROXY header could not name the public address, and an
			// inbound one is already read by the dispatcher.
			if socket.ProxyProtocolInbound || socket.ProxyProtocolOutbound {
				return plan, ErrInvalidConfig
			}
			plan.modes[socket.ID] = socketDispatched
			path := plan.socketPath(socket.ID)
			if !validDispatchSocket(path) {
				return plan, ErrInvalidConfig // sun_path holds 107 bytes
			}
			if !socket.TLSPassthrough {
				shared.plain = path
				continue
			}
			for _, name := range socket.ServerNames {
				shared.names[name] = path
			}
		}
		if hasSite {
			if site.PlainSocket != "" {
				shared.plain = site.PlainSocket
			}
			if site.TLSSocket != "" {
				shared.tlsDefault = site.TLSSocket
				for _, name := range site.TLSServerNames {
					shared.names[name] = site.TLSSocket
				}
			}
		}
		plan.ports = append(plan.ports, shared)
	}
	return plan, nil
}

// writeDispatchers renders each split port's dispatcher: SNI picks a TLS
// consumer (hostnames: exact names win over "*." wildcards), plaintext goes
// to the port's one plain consumer, anything else to the reject socket.
func (plan sharedSocketPlanV2) writeDispatchers(output *strings.Builder) {
	for _, shared := range plan.ports {
		sni := fmt.Sprintf("cdnca_l4_sni_%d", shared.port)
		target := fmt.Sprintf("cdnca_l4_dispatch_%d", shared.port)
		fmt.Fprintf(output, "    map $ssl_preread_server_name $%s {\n        hostnames;\n        default \"\";\n", sni)
		names := make([]string, 0, len(shared.names))
		for name := range shared.names {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(output, "        %q \"=unix:%s\";\n", name, shared.names[name])
		}
		output.WriteString("    }\n")
		fmt.Fprintf(output, "    map \"$ssl_preread_protocol|$%s\" $%s {\n", sni, target)
		plain := plan.rejectPath()
		if shared.plain != "" {
			plain = shared.plain
		}
		fmt.Fprintf(output, "        \"|\" \"unix:%s\";\n", plain)
		output.WriteString("        \"~^.+\\|=(?<socket>.+)$\" $socket;\n")
		fmt.Fprintf(output, "        default \"unix:%s\";\n    }\n", shared.tlsDefault)
		output.WriteString("    server {\n")
		fmt.Fprintf(output, "        listen %s;\n", nginxAddress(shared.address, shared.port))
		// ssl_preread decides on the client's first 5 bytes: a plain
		// consumer sharing the port must speak a client-first protocol (a
		// server-first one, such as SMTP or MySQL, waits until the preread
		// timeout closes it). Exclusive ports are not affected.
		output.WriteString("        ssl_preread on;\n        proxy_protocol on;\n        access_log off;\n")
		fmt.Fprintf(output, "        proxy_pass $%s;\n    }\n\n", target)
	}
}

// passthroughTarget renders the SNI check of a TLS passthrough stream alone
// on its port and returns the proxy_pass target.
func (plan sharedSocketPlanV2) passthroughTarget(output *strings.Builder, listener ListenerV2, upstream string) string {
	variable := internalName("cdnca_l4_passthrough", listener.ID)
	fmt.Fprintf(output, "    map $ssl_preread_server_name $%s {\n        hostnames;\n        default \"unix:%s\";\n", variable, plan.rejectPath())
	for _, name := range listener.ServerNames {
		fmt.Fprintf(output, "        %q %q;\n", name, upstream)
	}
	output.WriteString("    }\n\n")
	return "$" + variable
}

func (plan sharedSocketPlanV2) dispatched() bool {
	return len(plan.ports) != 0
}

// prepareDispatchDirectory creates the directory of the internal sockets and
// removes socket files nothing listens on, which a crashed OpenResty leaves
// behind and which would make the next start fail to bind. The directory is
// traversable (workers connect to the sockets) but not listable.
// Workers of a root OpenResty run as nobody (L4F-E04): every parent must be
// traversable by others, or each dispatched connection is reset while the
// workers look healthy; such a directory is refused at apply time.
var prepareDispatchDirectory = func(directory string) error {
	return prepareSocketDirectoryFor(directory, 0o711, os.Geteuid() == 0, "/")
}

// prepareSocketDirectoryFor checks, after the creation (parents MkdirAll
// makes under the agent's umask, 0077 in its unit, are 0700 too), that with
// othersTraverse every parent of directory up to top lets others traverse.
func prepareSocketDirectoryFor(directory string, mode os.FileMode, othersTraverse bool, top string) error {
	if err := prepareSocketDirectory(directory, mode); err != nil || !othersTraverse {
		return err
	}
	for parent := filepath.Dir(directory); ; parent = filepath.Dir(parent) {
		info, err := os.Stat(parent)
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o001 == 0 {
			return fmt.Errorf("%w: L4 socket directory parent %s is not traversable by the OpenResty workers", ErrInvalidConfig, parent)
		}
		if parent == top || parent == filepath.Dir(parent) {
			return nil
		}
	}
}

// prepareControlDirectory creates the directory of the live session control
// socket (L4ControlSocketPath): nginx makes unix sockets 0666, so only this
// directory, the agent's with mode 0700, keeps others from connecting.
var prepareControlDirectory = func() error { return prepareSocketDirectory(L4ControlDirectory, 0o700) }

// UseControlDirectoryForTesting makes replays prepare directory instead of
// L4ControlDirectory (every TCP configuration renders the control socket,
// L4-USAGE-01; tests do not run as root). Tests only; restore undoes it.
func UseControlDirectoryForTesting(directory string) (restore func()) {
	previous := prepareControlDirectory
	prepareControlDirectory = func() error { return prepareSocketDirectory(directory, 0o700) }
	return func() { prepareControlDirectory = previous }
}

// prepareSocketDirectory creates directory with mode and removes socket files
// nothing listens on, which a crashed OpenResty leaves behind and which would
// make the next start fail to bind.
func prepareSocketDirectory(directory string, mode os.FileMode) error {
	if err := os.MkdirAll(directory, mode); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: L4 socket directory %s is unsafe", ErrInvalidConfig, directory)
	}
	if err := os.Chmod(directory, mode); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		if entry.Type()&os.ModeSocket == 0 {
			continue
		}
		connection, dialErr := net.DialTimeout("unix", path, time.Second)
		if dialErr == nil {
			_ = connection.Close()
			continue
		}
		if errors.Is(dialErr, syscall.ECONNREFUSED) {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}
