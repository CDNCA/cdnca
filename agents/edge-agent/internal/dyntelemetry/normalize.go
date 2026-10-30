package dyntelemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

type siteobjectCapture = siteobject.TelemetryCapture

// Attribution is the "cdnca" object of a line.
type Attribution struct {
	Generation uint64 `json:"generation"`
	Scope      string `json:"scope"`
	Digest     string `json:"digest"`
	Port       uint16 `json:"port"`
	// L2: the line is an L1's hop this node served as its L2 (fix-l2trust,
	// cdnca_telemetry): the L1 logged the visitor's request.
	L2 bool `json:"l2,omitempty"`
}

// SiteResolver returns the site object of a digest (verified against it).
type SiteResolver interface {
	Site(digest string) (edgesite.Site, error)
}

// Result is a line turned back into the v7 line of its site.
type Result struct {
	Line          []byte
	Identity      eventspool.TrustedIdentity
	CapturePolicy eventspool.CapturePolicy
	Attribution   Attribution
}

const attributionKey = `,"` + edgeconfig.DynamicRoutingAttribution + `":{`

// lineIdentity is what Normalize checks in the v7 part of a line.
type lineIdentity struct {
	TenantID        *string `json:"tenant_id"`
	SiteID          *string `json:"site_id"`
	ConfigVersionID *string `json:"config_version_id"`
	Host            *string `json:"host"`
	ListenPort      *uint16 `json:"listen_port"`
	Type            string  `json:"type"`
}

// Split separates the v7 line and the attribution of a dynamic routing line
// (both strictly checked).
func Split(line []byte) ([]byte, Attribution, error) {
	position := bytes.LastIndex(line, []byte(attributionKey))
	if position < 0 || !bytes.HasSuffix(line, []byte("}}")) || bytes.IndexAny(line, "\r\n") >= 0 {
		return nil, Attribution{}, fmt.Errorf("%w: no attribution", ErrInvalid)
	}
	v7 := append(append([]byte(nil), line[:position]...), '}')
	object := line[position+len(attributionKey)-1 : len(line)-1]
	if !json.Valid(v7) || edgeconfig.RejectDuplicateJSONKeys(v7) != nil {
		return nil, Attribution{}, fmt.Errorf("%w: line is not a JSON object", ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(object))
	decoder.DisallowUnknownFields()
	var attribution Attribution
	if err := decoder.Decode(&attribution); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		attribution.Generation == 0 || attribution.Generation > 1<<53-1 || !canonicalUUID(attribution.Scope) ||
		!hexDigest(attribution.Digest) || attribution.Port == 0 {
		return nil, Attribution{}, fmt.Errorf("%w: attribution", ErrInvalid)
	}
	return v7, attribution, nil
}

// Normalize turns one dynamic routing line into the v7 line of its site.
func Normalize(line []byte, registry *Registry, sites SiteResolver, nodeID string) (Result, error) {
	v7, attribution, err := Split(line)
	if err != nil {
		return Result{}, err
	}
	if attribution.L2 {
		// the L1 logged (and meters) the visitor's request; the L2's line
		// would count its traffic twice
		return Result{}, ErrL2Hop
	}
	version, ok := registry.ConfigVersion(attribution.Generation, attribution.Scope)
	if !ok {
		return Result{}, fmt.Errorf("%w: generation %d scope %s", ErrUnattributed, attribution.Generation, attribution.Scope)
	}
	site, err := sites.Site(attribution.Digest)
	if err != nil {
		return Result{}, fmt.Errorf("%w: site object %s: %v", ErrUnattributed, attribution.Digest, err)
	}
	var fields lineIdentity
	if err := json.Unmarshal(v7, &fields); err != nil || fields.TenantID == nil || fields.SiteID == nil ||
		fields.ConfigVersionID == nil || fields.Host == nil {
		return Result{}, fmt.Errorf("%w: identity fields", ErrInvalid)
	}
	switch {
	case site.Telemetry == nil:
		return Result{}, fmt.Errorf("%w: site %s has no telemetry", ErrInvalid, site.SiteID)
	case site.ConfigurationScopeID != attribution.Scope || *fields.TenantID != site.TenantID || *fields.SiteID != site.SiteID:
		return Result{}, fmt.Errorf("%w: line identity is not its site object's", ErrInvalid)
	case *fields.ConfigVersionID != "":
		return Result{}, fmt.Errorf("%w: config_version_id is the Agent's to fill", ErrInvalid)
	case !servesPort(site, attribution.Port) || !servesHost(site, *fields.Host):
		return Result{}, fmt.Errorf("%w: site %s does not serve %s:%d", ErrInvalid, site.SiteID, *fields.Host, attribution.Port)
	case fields.Type == string(eventspool.EventSecurity) && (fields.ListenPort == nil || *fields.ListenPort != attribution.Port):
		return Result{}, fmt.Errorf("%w: security listen_port", ErrInvalid)
	}
	filled, err := fillConfigVersion(v7, version)
	if err != nil {
		return Result{}, err
	}
	capture := site.Telemetry.Capture
	policy, err := capturePolicy(capture)
	if err != nil {
		return Result{}, err
	}
	return Result{Line: filled, Attribution: attribution, CapturePolicy: policy, Identity: eventspool.TrustedIdentity{
		ListenPort: attribution.Port, EnrollmentNodeID: nodeID, TenantID: site.TenantID, SiteID: site.SiteID,
		ConfigVersionID: version, CapturePolicyRevision: capture.Revision, CapturePolicyDigest: capture.EvidenceDigest,
	}}, nil
}

// fillConfigVersion sets the top-level config_version_id (written empty by
// the node). The value is a validated identifier (no quote or backslash).
func fillConfigVersion(v7 []byte, version string) ([]byte, error) {
	if strings.ContainsAny(version, "\"\\") {
		return nil, fmt.Errorf("%w: config version %q", ErrInvalid, version)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(v7, &top); err != nil {
		return nil, fmt.Errorf("%w: line", ErrInvalid)
	}
	top["config_version_id"] = json.RawMessage(`"` + version + `"`)
	// Field order does not matter downstream (the event spool decodes into
	// its envelope); encoding/json sorts the keys, so the result is
	// deterministic. Only the top level is touched: a captured body may hold
	// a field of the same name.
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(top); err != nil {
		return nil, fmt.Errorf("%w: line", ErrInvalid)
	}
	return bytes.TrimRight(output.Bytes(), "\n"), nil
}

func servesPort(site edgesite.Site, port uint16) bool {
	for _, listener := range site.Listeners {
		if listener.Port == int(port) {
			return true
		}
	}
	return false
}

// servesHost: the logged $host is one of the site's names by the routing
// rule (exact, or a leading wildcard covering at least one more label).
func servesHost(site edgesite.Site, host string) bool {
	for _, name := range append([]string{site.Hosts.Primary}, site.Hosts.Aliases...) {
		if host == name {
			return true
		}
		if suffix, ok := strings.CutPrefix(name, "*"); ok && strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return true
		}
	}
	return false
}

// capturePolicy is the event spool policy of a site object capture (the
// v7 manifest conversion, telemetry_sources.go eventspoolCapturePolicy).
func capturePolicy(capture siteobjectCapture) (eventspool.CapturePolicy, error) {
	if !capture.Enabled {
		return eventspool.CapturePolicy{}, nil
	}
	clone := func(values []string) []string { return append([]string{}, values...) }
	value, body, event := capture.MaxValueBytes, capture.MaxBodyBytes, capture.MaxEventBytes
	if value == 0 {
		value = edgeconfig.DefaultCaptureValueBytes
	}
	if body == 0 {
		body = edgeconfig.DefaultCaptureBodyBytes
	}
	if event == 0 {
		event = edgeconfig.DefaultCaptureEventBytes
	}
	return eventspool.CapturePolicy{Enabled: true, Methods: clone(capture.Methods), URIPrefixes: clone(capture.URIPrefixes),
		RequestHeaders: clone(capture.RequestHeaderAllowlist), ResponseHeaders: clone(capture.ResponseHeaderAllowlist),
		RequestBodyFields: clone(capture.RequestBodyFieldAllowlist), ResponseBodyFields: clone(capture.ResponseBodyFieldAllowlist),
		MaxHeaderValueBytes: value, MaxBodyBytes: body, MaxEventBytes: event}, nil
}

func hexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
