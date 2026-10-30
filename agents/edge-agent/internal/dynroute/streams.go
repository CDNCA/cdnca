package dynroute

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
)

// L4 forwards on a dynamic routing node (D13-c0). Every scope's v2 streams
// run in the node's L4 runtime (l4runtime.Manager) as one configuration; a
// TCP port a stream shares with websites belongs to the L4 runtime on IPv4,
// whose dispatcher hands the website connections to the skeleton's internal
// socket of that port (edgeskeleton.DispatchedPorts, PROXY protocol).

// ScopeStreams is one scope's L4 forwards.
type ScopeStreams struct {
	ScopeID         string
	ConfigVersionID string
	Revision        int64
	Runtime         edgeconfig.StreamRuntime
}

// L4Runtime is the node's L4 runtime. Begin opens a release (the previous
// configuration is kept until Finish), Apply activates config (nil: no
// streams), Finish(false) returns to the release's previous configuration.
type L4Runtime interface {
	Begin(ctx context.Context, versionID string) error
	Apply(ctx context.Context, versionID string, config *l4runtime.ConfigV2) error
	Finish(ctx context.Context, versionID string, succeeded bool) error
}

// L4TrafficStopper is an L4Runtime that can close the open sessions of
// forwards the release just finished withdrew (L4_TRAFFIC_STOP); without it
// they drain.
type L4TrafficStopper interface {
	CloseTrafficStopped(ctx context.Context, streamIDs []string) error
}

const l4StreamSetSchema = "cdnca.edge.l4-stream-set/v2"

// l4Plan is what one Apply gives the L4 runtime.
type l4Plan struct {
	versionID  string             // "" = no L4 configuration (nothing to apply)
	config     *l4runtime.ConfigV2 // nil = no streams
	dispatched map[int]bool        // ports whose IPv4 websites the L4 dispatcher hands over
	tcp        []ddos.PortRange    // the streams' TCP ports
}

type scopedL4Document struct {
	SchemaVersion string                          `json:"schema_version"`
	VersionID     string                          `json:"version_id"`
	Revision      int64                           `json:"revision"`
	Streams       []l4runtime.StreamRuntimeSpecV2 `json:"streams"`
}

// planStreams merges the scopes' streams under the port sharing rules
// (edgeconfig.FindPortConflicts across every site and stream of the node, as
// the composed v8 runtime does) and decides which ports are dispatched.
func (runtime *Runtime) planStreams(sites []edgesite.Site, scopes []ScopeStreams) (l4Plan, error) {
	if len(scopes) == 0 {
		if runtime.state.L4 == "" {
			return l4Plan{}, nil
		}
		return l4Plan{versionID: "dynroute-l4-none"}, nil
	}
	if runtime.config.L4 == nil {
		return l4Plan{}, fmt.Errorf("%w: L4 forwards and the node has no L4 runtime", ErrInvalid)
	}
	siteClaims := map[string][]edgeconfig.PortClaim{}
	var claims []edgeconfig.PortClaim
	if runtime.config.HealthPort != 0 {
		claims = append(claims, edgeconfig.PortClaim{Kind: edgeconfig.PortClaimReserved,
			Protocol: edgeconfig.StreamProtocolTCP, Port: uint16(runtime.config.HealthPort)})
	}
	sitePorts := map[int]bool{}
	for _, site := range sites {
		names := append([]string{site.Hosts.Primary}, site.Hosts.Aliases...)
		for _, listener := range site.Listeners {
			own := edgeconfig.SiteListenerPortClaims(site.ConfigurationScopeID, site.SiteID, uint16(listener.Port),
				listener.TLS != nil, listener.HTTP3, names)
			siteClaims[site.ConfigurationScopeID] = append(siteClaims[site.ConfigurationScopeID], own...)
			claims = append(claims, own...)
			if listener.AddressFamily != edgesite.FamilyIPv6 {
				sitePorts[listener.Port] = true
			}
		}
	}
	plan := l4Plan{dispatched: map[int]bool{}}
	var specs []l4runtime.StreamRuntimeSpecV2
	revision := int64(1)
	for _, scope := range scopes {
		if len(scope.Runtime.StreamsV2) == 0 {
			return l4Plan{}, fmt.Errorf("%w: scope %s: no L4 forwards", ErrInvalid, scope.ScopeID)
		}
		for _, stream := range scope.Runtime.StreamsV2 {
			for _, claim := range edgeconfig.L4StreamPortClaims(scope.ScopeID, stream) {
				claims = append(claims, claim)
				if claim.Protocol != edgeconfig.StreamProtocolTCP {
					continue
				}
				plan.tcp = append(plan.tcp, ddos.PortRange{First: claim.Port, Last: claim.LastPort()})
				for port := range sitePorts {
					if port >= int(claim.Port) && port <= int(claim.LastPort()) {
						plan.dispatched[port] = true
					}
				}
			}
		}
		// the scope's own artifact: the stream set the v8 document's L4
		// sidecar would carry (normalized, validated within the scope)
		_, files, err := edgeconfig.RenderSharedStreamFragment(scope.ConfigVersionID, uint64(scope.Revision), scope.Runtime,
			uint16(runtime.config.HealthPort), siteClaims[scope.ScopeID])
		if err != nil {
			return l4Plan{}, fmt.Errorf("%w: scope %s L4 forwards: %v", ErrInvalid, scope.ScopeID, err)
		}
		document, err := decodeScopedL4(files[edgeconfig.L4RuntimeV2ArtifactPath])
		if err != nil {
			return l4Plan{}, fmt.Errorf("%w: scope %s: %v", ErrInvalid, scope.ScopeID, err)
		}
		for _, spec := range document.Streams {
			spec.ConfigVersionID, spec.ConfigRevision = document.VersionID, document.Revision
			specs = append(specs, spec)
		}
		revision = max(revision, document.Revision)
	}
	if conflicts := edgeconfig.FindPortConflicts(claims); len(conflicts) != 0 {
		conflict := conflicts[0]
		return l4Plan{}, fmt.Errorf("%w: %s port %d: %s %s (scope %s) and %s %s (scope %s) cannot share it", ErrInvalid,
			conflict.Claim.Protocol, conflict.Claim.Port, conflict.Claim.Kind, conflict.Claim.ID, conflict.Claim.Owner,
			conflict.Other.Kind, conflict.Other.ID, conflict.Other.Owner)
	}
	plan.tcp = ddos.MergePorts(plan.tcp)
	handed := runtime.siteSockets(sites, plan.dispatched)
	// The L4 runtime's own internal sockets (a split port's streams) sit
	// beside the skeleton's: the default under the deployment root is
	// private to the agent, so the L4 workers could not connect to them.
	directory := filepath.Join(runtime.muxRoot(), "l4")
	// The version is the content: the L4 runtime keys releases by version
	// and refuses one version with two digests.
	content, err := json.Marshal(struct {
		Revision  int64                           `json:"revision"`
		Streams   []l4runtime.StreamRuntimeSpecV2 `json:"streams"`
		Sites     []l4runtime.SiteSocketsV2       `json:"sites"`
		Directory string                          `json:"directory"`
	}{revision, specs, handed, directory})
	if err != nil {
		return l4Plan{}, err
	}
	sum := sha256.Sum256(content)
	plan.versionID = "dynroute-l4-" + hex.EncodeToString(sum[:])[:32]
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2(plan.versionID, revision, specs, handed...)
	if err != nil {
		return l4Plan{}, fmt.Errorf("%w: L4 runtime: %v", ErrInvalid, err)
	}
	config.DispatchDirectory = directory
	plan.config = &config
	return plan, nil
}

// siteSockets hands each dispatched port's IPv4 websites to its internal
// socket: plaintext, or TLS with the names the L4 dispatcher sends there
// (every site on a port agrees on TLS, edgesite.PortProfiles).
func (runtime *Runtime) siteSockets(sites []edgesite.Site, dispatched map[int]bool) []l4runtime.SiteSocketsV2 {
	var result []l4runtime.SiteSocketsV2
	for _, port := range sortedPorts(dispatched) {
		hand := l4runtime.SiteSocketsV2{Port: port}
		for _, site := range sites {
			for _, listener := range site.Listeners {
				if listener.Port != port || listener.AddressFamily == edgesite.FamilyIPv6 {
					continue
				}
				if listener.TLS == nil {
					hand.PlainSocket = edgeskeleton.DispatchSocket(runtime.muxRoot(), port, false)
					continue
				}
				hand.TLSSocket = edgeskeleton.DispatchSocket(runtime.muxRoot(), port, true)
				for _, name := range append([]string{site.Hosts.Primary}, site.Hosts.Aliases...) {
					hand.TLSServerNames = append(hand.TLSServerNames, strings.ToLower(name))
				}
			}
		}
		slices.Sort(hand.TLSServerNames)
		hand.TLSServerNames = slices.Compact(hand.TLSServerNames)
		result = append(result, hand)
	}
	return result
}

func decodeScopedL4(raw []byte) (scopedL4Document, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document scopedL4Document
	if err := decoder.Decode(&document); err != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) ||
		document.SchemaVersion != l4StreamSetSchema || len(document.Streams) == 0 {
		return scopedL4Document{}, errors.New("scope L4 stream set is invalid")
	}
	return document, nil
}

func sortedPorts(set map[int]bool) []int {
	var ports []int
	for port, on := range set {
		if on {
			ports = append(ports, port)
		}
	}
	slices.Sort(ports)
	return ports
}

func portSet(ports []int) map[int]bool {
	set := make(map[int]bool, len(ports))
	for _, port := range ports {
		set[port] = true
	}
	return set
}

func unionPorts(a, b map[int]bool) map[int]bool {
	result := make(map[int]bool, len(a)+len(b))
	for port, on := range a {
		result[port] = on
	}
	for port, on := range b {
		if on {
			result[port] = true
		}
	}
	return result
}

// muxRoot holds the skeleton's internal sockets of dispatched ports.
func (runtime *Runtime) muxRoot() string {
	if runtime.config.MuxRoot != "" {
		return runtime.config.MuxRoot
	}
	return filepath.Join(runtime.config.SharedRoot, "mux")
}

// prepareMux creates the socket directory (traversal for the L4 workers)
// and removes socket files nothing listens on (a crashed OpenResty's):
// nginx cannot bind an existing path. A socket the running skeleton still
// serves is kept; its reload inherits it.
func (runtime *Runtime) prepareMux(dispatched map[int]bool) error {
	if len(sortedPorts(dispatched)) == 0 {
		return nil
	}
	root := runtime.muxRoot()
	if err := os.MkdirAll(root, 0o711); err != nil {
		return err
	}
	if info, err := os.Lstat(root); err != nil || !info.IsDir() {
		return fmt.Errorf("%w: mux root %s", ErrInvalid, root)
	}
	if err := os.Chmod(root, 0o711); err != nil {
		return err
	}
	for _, port := range sortedPorts(dispatched) {
		for _, tls := range []bool{false, true} {
			path := edgeskeleton.DispatchSocket(root, port, tls)
			info, err := os.Lstat(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || info.Mode()&os.ModeSocket == 0 {
				return fmt.Errorf("%w: mux socket %s is not a socket", ErrInvalid, path)
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
	}
	return nil
}

// ddosPorts are the TCP ports the node's OpenResty runtimes listen on: the
// sites' and the streams' (the table counts TCP connections only).
func ddosPorts(sites []edgesite.Site, streams []ddos.PortRange) []ddos.PortRange {
	return ddos.MergePorts(append(sitePorts(sites), streams...))
}

// installL4 activates plan in the L4 runtime. A port the L4 dispatcher
// takes over is first given up by the skeleton (rendered with the old and
// the new dispatched ports: the internal socket listens before the
// dispatcher sends to it, and 0.0.0.0 is free for the L4 runtime); a port
// it gives back is bound by the skeleton's final render after the L4 runtime
// released it. Either way new connections to that one port are refused for
// the duration of one reload. The release stays open until Apply's health
// check passes (Finish) or fails (abortL4).
func (runtime *Runtime) installL4(ctx context.Context, result *Result, sites []edgesite.Site, waf dynwaf.Result,
	system *edgeconfig.SiteRuntimeSystem, plan l4Plan, pages []nodePageRecord) error {
	previous := portSet(runtime.state.L4Ports)
	union := unionPorts(previous, plan.dispatched)
	if err := runtime.prepareMux(union); err != nil {
		return err
	}
	if len(sortedPorts(union)) != len(sortedPorts(previous)) {
		// both releases' streams hold their ports during the hand-over
		conf, err := runtime.render(sites, waf, system, union, append(slices.Clone(runtime.state.L4TCP), plan.tcp...), pages)
		if err != nil {
			return err
		}
		reloaded, started, old, err := runtime.install(ctx, conf)
		if err != nil {
			return err
		}
		runtime.state.Skeleton = skeletonDigest(conf)
		result.Reloaded, result.Started = result.Reloaded || reloaded, result.Started || started
		result.OldWorkers = append(result.OldWorkers, old...)
	}
	// the replaced workers close their listeners on the reload's signal;
	// the L4 runtime's port precheck binds them
	if err := waitPortsFree(ctx, changedPorts(plan.dispatched, previous)); err != nil {
		return err
	}
	if err := runtime.config.L4.Begin(ctx, plan.versionID); err != nil {
		return fmt.Errorf("L4 runtime: %w", err)
	}
	if err := runtime.config.L4.Apply(ctx, plan.versionID, plan.config); err != nil {
		runtime.abortL4(plan)
		return fmt.Errorf("L4 runtime: %w", err)
	}
	// ports given back: the skeleton's final render binds them
	if err := waitPortsFree(ctx, changedPorts(previous, plan.dispatched)); err != nil {
		runtime.abortL4(plan)
		return err
	}
	return nil
}

func portIn(ranges []ddos.PortRange, port int) bool {
	return slices.ContainsFunc(ranges, func(r ddos.PortRange) bool { return int(r.First) <= port && port <= int(r.Last) })
}

// changedPorts are the ports of to not in from.
func changedPorts(to, from map[int]bool) []int {
	var ports []int
	for _, port := range sortedPorts(to) {
		if !from[port] {
			ports = append(ports, port)
		}
	}
	return ports
}

// waitPortsFree waits until the IPv4 wildcard of every port can be bound
// (at most 10 s).
func waitPortsFree(ctx context.Context, ports []int) error {
	deadline := time.Now().Add(10 * time.Second)
	for _, port := range ports {
		for {
			listener, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
			if err == nil {
				_ = listener.Close()
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("port %d is not released for the L4 hand-over: %w", port, err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	return nil
}

// abortL4 returns the L4 runtime to the configuration before plan's
// release (no-op when plan changed nothing).
func (runtime *Runtime) abortL4(plan l4Plan) {
	if plan.versionID == "" || plan.versionID == runtime.state.L4 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := runtime.config.L4.Finish(ctx, plan.versionID, false); err != nil {
		log.Printf("dynamic routing: L4 release %s not reverted: %v", plan.versionID, err)
	}
}
