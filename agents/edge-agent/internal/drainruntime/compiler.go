package drainruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func Compile(plan Plan) (CompiledPlan, error) {
	normalized, err := normalizePlan(plan)
	if err != nil {
		return CompiledPlan{}, err
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return CompiledPlan{}, fmt.Errorf("marshal normalized drain plan: %w", err)
	}
	sum := sha256.Sum256(canonical)
	digest := hex.EncodeToString(sum[:])
	candidate := candidateListeners(normalized.Old.Listeners, normalized.New.Listeners)
	return CompiledPlan{
		Plan: normalized, Digest: digest, CanonicalJSON: canonical,
		CandidateNginx: renderFixture(normalized, digest, "candidate", candidate),
		DrainingNginx:  renderFixture(normalized, digest, "draining", normalized.New.Listeners),
		RollbackNginx:  renderFixture(normalized, digest, "rollback", normalized.Old.Listeners),
	}, nil
}

func normalizePlan(plan Plan) (Plan, error) {
	if plan.SchemaVersion != SchemaVersionV1 || !validIdentifier(plan.PlanID) || plan.Revision == 0 {
		return Plan{}, ErrInvalidPlan
	}
	oldVersion, err := normalizeVersion(plan.Old, false)
	if err != nil {
		return Plan{}, fmt.Errorf("%w: old version: %v", ErrInvalidPlan, err)
	}
	newVersion, err := normalizeVersion(plan.New, true)
	if err != nil {
		return Plan{}, fmt.Errorf("%w: new version: %v", ErrInvalidPlan, err)
	}
	if oldVersion.VersionID == newVersion.VersionID {
		return Plan{}, fmt.Errorf("%w: old and new version IDs must differ", ErrInvalidPlan)
	}
	if plan.HealthTimeoutSeconds < 1 || plan.HealthTimeoutSeconds > maxHealthTimeoutSeconds {
		return Plan{}, fmt.Errorf("%w: health timeout must be between 1 and %d seconds", ErrInvalidPlan, maxHealthTimeoutSeconds)
	}
	checks, err := normalizeHealthChecks(plan.HealthChecks, newVersion.Listeners)
	if err != nil {
		return Plan{}, err
	}
	if plan.Drain.MaxDrainSeconds < 1 || plan.Drain.MaxDrainSeconds > maxDrainTimeoutSeconds {
		return Plan{}, fmt.Errorf("%w: max drain timeout must be between 1 and %d seconds", ErrInvalidPlan, maxDrainTimeoutSeconds)
	}
	switch plan.Drain.Force {
	case ForceNever:
		if plan.Drain.ForceReason != "" {
			return Plan{}, fmt.Errorf("%w: force reason is forbidden when force termination is disabled", ErrInvalidPlan)
		}
	case ForceAfterDeadline:
		if !validReason(plan.Drain.ForceReason) {
			return Plan{}, fmt.Errorf("%w: force termination requires a bounded printable reason", ErrInvalidPlan)
		}
	default:
		return Plan{}, fmt.Errorf("%w: unknown force termination policy", ErrInvalidPlan)
	}
	plan.Old = oldVersion
	plan.New = newVersion
	plan.HealthChecks = checks
	return plan, nil
}

func normalizeVersion(version Version, allowEmpty bool) (Version, error) {
	if !validIdentifier(version.VersionID) {
		return Version{}, fmt.Errorf("invalid version ID")
	}
	if len(version.Listeners) > maxListeners || !allowEmpty && len(version.Listeners) == 0 {
		return Version{}, fmt.Errorf("listener count is invalid")
	}
	listeners := append([]Listener{}, version.Listeners...)
	seenIDs := make(map[string]struct{}, len(listeners))
	seenBinds := make([]Listener, 0, len(listeners))
	for index := range listeners {
		listener := &listeners[index]
		if !validIdentifier(listener.ID) {
			return Version{}, fmt.Errorf("listener %d has invalid ID", index)
		}
		if listener.Protocol != ProtocolHTTP && listener.Protocol != ProtocolTCP {
			return Version{}, fmt.Errorf("listener %s has unsupported protocol", listener.ID)
		}
		address, err := normalizeAddress(listener.Address, true)
		if err != nil {
			return Version{}, fmt.Errorf("listener %s address: %v", listener.ID, err)
		}
		upstream, err := normalizeAddress(listener.UpstreamAddress, false)
		if err != nil {
			return Version{}, fmt.Errorf("listener %s upstream address: %v", listener.ID, err)
		}
		if !validPort(listener.Port) || !validPort(listener.UpstreamPort) {
			return Version{}, fmt.Errorf("listener %s has invalid port", listener.ID)
		}
		listener.Address = address
		listener.UpstreamAddress = upstream
		if _, exists := seenIDs[listener.ID]; exists {
			return Version{}, fmt.Errorf("duplicate listener ID %s", listener.ID)
		}
		seenIDs[listener.ID] = struct{}{}
		for _, existing := range seenBinds {
			if bindsOverlap(existing, *listener) {
				return Version{}, fmt.Errorf("overlapping listener bind %s", bindKey(*listener))
			}
		}
		seenBinds = append(seenBinds, *listener)
	}
	sortListeners(listeners)
	return Version{VersionID: version.VersionID, Listeners: listeners}, nil
}

func normalizeHealthChecks(checks []HealthCheck, listeners []Listener) ([]HealthCheck, error) {
	if len(listeners) == 0 {
		if len(checks) != 0 {
			return nil, fmt.Errorf("%w: an empty new version cannot have health checks", ErrInvalidPlan)
		}
		return []HealthCheck{}, nil
	}
	if len(checks) == 0 || len(checks) > maxHealthChecks || len(checks) != len(listeners) {
		return nil, fmt.Errorf("%w: exactly one health check is required for every new listener", ErrInvalidPlan)
	}
	byID := make(map[string]Listener, len(listeners))
	for _, listener := range listeners {
		byID[listener.ID] = listener
	}
	normalized := append([]HealthCheck(nil), checks...)
	seen := make(map[string]struct{}, len(checks))
	for index := range normalized {
		check := &normalized[index]
		listener, exists := byID[check.ListenerID]
		if !exists {
			return nil, fmt.Errorf("%w: health check references unknown listener", ErrInvalidPlan)
		}
		if _, exists := seen[check.ListenerID]; exists {
			return nil, fmt.Errorf("%w: duplicate health check", ErrInvalidPlan)
		}
		seen[check.ListenerID] = struct{}{}
		if !validProbeText(check.ExpectedBodyPrefix, false) {
			return nil, fmt.Errorf("%w: health check has invalid expected prefix", ErrInvalidPlan)
		}
		switch listener.Protocol {
		case ProtocolHTTP:
			if !validHTTPPath(check.Path) || check.ExpectedStatus < 100 || check.ExpectedStatus > 599 || check.Payload != "" {
				return nil, fmt.Errorf("%w: invalid HTTP health check for %s", ErrInvalidPlan, listener.ID)
			}
		case ProtocolTCP:
			if check.Path != "" || check.ExpectedStatus != 0 || !validProbeText(check.Payload, true) {
				return nil, fmt.Errorf("%w: invalid TCP health check for %s", ErrInvalidPlan, listener.ID)
			}
		}
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].ListenerID < normalized[j].ListenerID })
	return normalized, nil
}

func candidateListeners(oldListeners, newListeners []Listener) []Listener {
	result := append([]Listener(nil), newListeners...)
	for _, listener := range oldListeners {
		replaced := false
		for _, candidate := range newListeners {
			if bindsOverlap(listener, candidate) {
				replaced = true
				break
			}
		}
		if !replaced {
			result = append(result, listener)
		}
	}
	sortListeners(result)
	return result
}

func renderFixture(plan Plan, digest, mode string, listeners []Listener) []byte {
	var output strings.Builder
	output.WriteString("# Generated by CDNCA edge-agent drain runtime; do not edit.\n")
	fmt.Fprintf(&output, "# schema=%s plan=%s revision=%d digest=%s mode=%s\n", plan.SchemaVersion, plan.PlanID, plan.Revision, digest, mode)
	output.WriteString("worker_processes 1;\n")
	output.WriteString("error_log logs/error.log notice;\n")
	output.WriteString("events { worker_connections 4096; }\n")

	var httpListeners, tcpListeners []Listener
	for _, listener := range listeners {
		if listener.Protocol == ProtocolHTTP {
			httpListeners = append(httpListeners, listener)
		} else {
			tcpListeners = append(tcpListeners, listener)
		}
	}
	if len(httpListeners) > 0 {
		output.WriteString("http {\n")
		output.WriteString("    map $http_upgrade $drain_connection_upgrade { default upgrade; '' close; }\n")
		output.WriteString("    access_log /dev/stdout combined;\n")
		for _, listener := range httpListeners {
			name := upstreamName(listener)
			fmt.Fprintf(&output, "    upstream %s { server %s; }\n", name, nginxAddress(listener.UpstreamAddress, listener.UpstreamPort))
			fmt.Fprintf(&output, "    # listener id=%s protocol=%s\n", listener.ID, listener.Protocol)
			output.WriteString("    server {\n")
			fmt.Fprintf(&output, "        listen %s;\n", nginxAddress(listener.Address, listener.Port))
			output.WriteString("        server_tokens off;\n")
			output.WriteString("        location / {\n")
			fmt.Fprintf(&output, "            proxy_pass http://%s;\n", name)
			output.WriteString("            proxy_http_version 1.1;\n")
			output.WriteString("            proxy_set_header Host $host;\n")
			output.WriteString("            proxy_set_header Upgrade $http_upgrade;\n")
			output.WriteString("            proxy_set_header Connection $drain_connection_upgrade;\n")
			output.WriteString("            proxy_connect_timeout 2s;\n")
			fmt.Fprintf(&output, "            proxy_read_timeout %ds;\n", maxDrainTimeoutSeconds)
			fmt.Fprintf(&output, "            proxy_send_timeout %ds;\n", maxDrainTimeoutSeconds)
			output.WriteString("        }\n")
			output.WriteString("    }\n")
		}
		output.WriteString("}\n")
	}
	if len(tcpListeners) > 0 {
		output.WriteString("stream {\n")
		output.WriteString("    log_format drain_audit escape=json '{\"time\":\"$time_iso8601\",\"connection\":\"$connection\",\"remote_addr\":\"$remote_addr\",\"server_port\":\"$server_port\",\"status\":\"$status\",\"session_time\":\"$session_time\",\"upstream_addr\":\"$upstream_addr\"}';\n")
		for _, listener := range tcpListeners {
			name := upstreamName(listener)
			fmt.Fprintf(&output, "    upstream %s { server %s; }\n", name, nginxAddress(listener.UpstreamAddress, listener.UpstreamPort))
			fmt.Fprintf(&output, "    # listener id=%s protocol=%s\n", listener.ID, listener.Protocol)
			output.WriteString("    server {\n")
			fmt.Fprintf(&output, "        listen %s;\n", nginxAddress(listener.Address, listener.Port))
			fmt.Fprintf(&output, "        proxy_pass %s;\n", name)
			output.WriteString("        proxy_connect_timeout 2s;\n")
			fmt.Fprintf(&output, "        proxy_timeout %ds;\n", maxDrainTimeoutSeconds)
			output.WriteString("        access_log /dev/stdout drain_audit;\n")
			output.WriteString("    }\n")
		}
		output.WriteString("}\n")
	}
	return []byte(output.String())
}

func upstreamName(listener Listener) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s|%d", listener.Protocol, listener.Address, listener.Port, listener.UpstreamAddress, listener.UpstreamPort)))
	return fmt.Sprintf("drain_upstream_%x", sum[:12])
}

func sortListeners(listeners []Listener) {
	sort.Slice(listeners, func(i, j int) bool {
		a, b := listeners[i], listeners[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.UpstreamAddress != b.UpstreamAddress {
			return a.UpstreamAddress < b.UpstreamAddress
		}
		return a.UpstreamPort < b.UpstreamPort
	})
}

func normalizeAddress(value string, listener bool) (string, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" || address.Is4In6() || address.IsMulticast() {
		return "", fmt.Errorf("must be an unzoned IPv4 or IPv6 literal")
	}
	if !listener && address.IsUnspecified() {
		return "", fmt.Errorf("upstream must not be unspecified")
	}
	return address.String(), nil
}

func bindKey(listener Listener) string {
	return fmt.Sprintf("%s:%d", listener.Address, listener.Port)
}

func bindsOverlap(left, right Listener) bool {
	if left.Port != right.Port {
		return false
	}
	leftAddress := netip.MustParseAddr(left.Address)
	rightAddress := netip.MustParseAddr(right.Address)
	if leftAddress.BitLen() != rightAddress.BitLen() {
		return false
	}
	return leftAddress == rightAddress || leftAddress.IsUnspecified() || rightAddress.IsUnspecified()
}

func nginxAddress(address string, port int) string {
	parsed := netip.MustParseAddr(address)
	if parsed.Is6() {
		return fmt.Sprintf("[%s]:%d", address, port)
	}
	return fmt.Sprintf("%s:%d", address, port)
}

func validIdentifier(value string) bool {
	return value != "" && len(value) <= maxIdentifierBytes && utf8.ValidString(value) && identifierPattern.MatchString(value)
}

func validPort(value int) bool { return value >= 1 && value <= 65535 }

func validReason(value string) bool {
	if value == "" || len(value) > maxReasonBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validProbeText(value string, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > maxProbeBytes || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsAny(value, "\r\n\x00")
}

func validHTTPPath(value string) bool {
	if value == "" || len(value) > maxProbeBytes || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.IsAbs() == false && strings.HasPrefix(value, "/")
}
