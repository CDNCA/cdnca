package l4runtime

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
)

func L4TelemetryLogPath(deploymentRoot, configVersionID, siteID string, listenPort int) string {
	return filepath.Join(deploymentRoot, "shared", "telemetry", configVersionID, siteID, strconv.Itoa(listenPort), "l4.jsonl")
}

var ErrInvalidTelemetryPath = errors.New("invalid L4 telemetry path identity")

func L4TelemetryLogPathForRuntimeStream(deploymentRoot, configVersionID string, listener StreamRuntimeSpecV2) (string, error) {
	// v12: the stream is its own partition (StreamRuntimeSpecV2).
	return L4TelemetryLogPathForIdentity(deploymentRoot, configVersionID, listener.StreamID, listener.StreamID,
		listener.StreamID, listener.Listener.Protocol, listener.Listener.Address, listener.Listener.Port)
}

func L4TelemetryLogPathForConfigListener(deploymentRoot, configVersionID string, listener ListenerV2) (string, error) {
	return L4TelemetryLogPathForIdentity(deploymentRoot, configVersionID, listener.SiteID, listener.StreamID,
		listener.ID, listener.Protocol, listener.Address, listener.Port)
}

func L4TelemetryLogPathForIdentity(deploymentRoot, configVersionID, siteID, streamID, listenerID string,
	protocol Protocol, address string, listenPort int) (string, error) {
	if !filepath.IsAbs(deploymentRoot) || filepath.Clean(deploymentRoot) != deploymentRoot || deploymentRoot == string(filepath.Separator) ||
		!safeTelemetryPathComponent(configVersionID) || !safeTelemetryPathComponent(siteID) ||
		!safeTelemetryPathComponent(streamID) || !safeTelemetryPathComponent(listenerID) ||
		(protocol != ProtocolTCP && protocol != ProtocolUDP) ||
		listenPort < 1 || listenPort > 65535 {
		return "", ErrInvalidTelemetryPath
	}
	parsedAddress, err := netip.ParseAddr(address)
	if err != nil {
		return "", ErrInvalidTelemetryPath
	}
	addressComponent := strings.NewReplacer(":", "_", ".", "_").Replace(parsedAddress.String())
	name := fmt.Sprintf("stream-%s--listener-%s--%s--addr-%s.l4.jsonl", streamID, listenerID, protocol, addressComponent)
	return filepath.Join(deploymentRoot, "shared", "telemetry", configVersionID, siteID,
		strconv.Itoa(listenPort), name), nil
}

func L4TelemetryPathIdentityPrefix(streamID, listenerID string) string {
	if !safeTelemetryPathComponent(streamID) || !safeTelemetryPathComponent(listenerID) {
		return ""
	}
	return fmt.Sprintf("stream-%s--listener-%s--", streamID, listenerID)
}

func IsL4TelemetryLogNameForIdentity(name, streamID, listenerID string) bool {
	prefix := L4TelemetryPathIdentityPrefix(streamID, listenerID)
	if prefix == "" || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".l4.jsonl") {
		return false
	}
	suffix := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".l4.jsonl")
	parts := strings.Split(suffix, "--")
	return len(parts) == 2 && (parts[0] == string(ProtocolTCP) || parts[0] == string(ProtocolUDP)) &&
		strings.HasPrefix(parts[1], "addr-") && safeTelemetryPathComponent(parts[1])
}

func IsSafeTelemetryPathComponent(value string) bool { return safeTelemetryPathComponent(value) }

func safeTelemetryPathComponent(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character != '-' && character != '_' && character != '.' &&
			(character < '0' || character > '9') && (character < 'A' || character > 'Z') &&
			(character < 'a' || character > 'z') {
			return false
		}
	}
	return true
}
