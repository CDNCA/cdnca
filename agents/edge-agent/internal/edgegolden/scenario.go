// Package edgegolden records what an edge runtime does for a fixed corpus of
// site facts and requests (the v7 behaviour golden, ADR 0009 §5) and compares
// another runtime's answers with it. Nothing here depends on how a runtime is
// built: a Renderer turns a scenario's site facts into a running runtime, the
// runner drives the requests and normalizes what clients, origins and logs saw.
package edgegolden

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Scenario is one case of the corpus: site facts, mock origins and the
// requests sent through the edge, in order.
type Scenario struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Covers      []string `json:"covers"`
	// Requires names optional environment pieces ("managed_waf"); a run
	// without one skips the scenario and says so.
	Requires []string `json:"requires,omitempty"`
	Facts    Facts    `json:"facts"`
	Origins  []Origin `json:"origins"`
	Steps    []Step   `json:"steps"`
	Mask     Mask     `json:"mask,omitempty"`

	digest string
}

// Facts are the published site facts. Document is the signed site runtime
// document and the files beside it as the control plane emits them today
// (cdnca.edge.site-runtime/v2); a renderer of another runtime converts them.
// String values may name ${placeholders} (Expand).
type Facts struct {
	Document   json.RawMessage `json:"document"`
	HTTPPolicy json.RawMessage `json:"http_policy,omitempty"`
	// OriginRoute is the conditional origin route bundle (origin-route.v1.json).
	OriginRoute json.RawMessage `json:"origin_route,omitempty"`
	// OriginTrust names the CAs (Env.PKI) published as origin trust anchors.
	OriginTrust []string `json:"origin_trust,omitempty"`
	// ClientCAs names the CAs (Env.PKI) published as client CA bundles
	// (client-ca/<digest>.pem); a listener references one as
	// "client_ca_ref": "${trust:<ca>}".
	ClientCAs []string `json:"client_cas,omitempty"`
	// CRS: the release carries the OWASP CRS rule text its managed WAF loads.
	CRS       bool       `json:"crs,omitempty"`
	Telemetry *Telemetry `json:"telemetry,omitempty"`
	Node      Node       `json:"node"`
}

// Telemetry is the scope's signed telemetry identity: every listener of every
// site logs under it.
type Telemetry struct {
	TenantID       string `json:"tenant_id"`
	InstallationID string `json:"installation_id,omitempty"`
	// Subscriptions maps site ID to its package subscription.
	Subscriptions map[string]string `json:"subscriptions,omitempty"`
	// Capture maps site ID to its capture policy (edgeconfig shape).
	Capture map[string]json.RawMessage `json:"capture,omitempty"`
}

// Node is node-local state the runtime reads beside the signed release.
type Node struct {
	ID     string `json:"id,omitempty"`
	Region string `json:"region,omitempty"`
	// HealthPort is the loopback health/prewarm listener.
	HealthPort int `json:"health_port"`
	// Workers pins worker_processes (0: one worker on the run's one CPU);
	// several workers share the dictionaries but each has its own LRUs.
	Workers      int           `json:"workers,omitempty"`
	Certificates []Certificate `json:"certificates,omitempty"`
	Challenges   []Challenge   `json:"challenges,omitempty"`
	// ErrorPages is the published error page policy (cdnca.error-pages/v1);
	// inline resources may omit size_bytes and sha256.
	ErrorPages json.RawMessage `json:"error_pages,omitempty"`
	// Schedule302Table is the node's HTTP 302 scheduling table
	// (cdnca.edge.sched302-table/v1) without revision and generated_at,
	// which the renderer fills in (1, the start time).
	Schedule302Table json.RawMessage `json:"schedule302_table,omitempty"`
}

// Challenge is a published JS challenge policy (cdnca.edge.challenge/v1)
// without current_key: the renderer installs a fresh key.
type Challenge struct {
	PolicyID string          `json:"policy_id"`
	Policy   json.RawMessage `json:"policy"`
}

// Certificate is an activated site certificate version, issued at run time by
// Env.PKI's "site" CA for Names with Serial.
type Certificate struct {
	SiteID    string   `json:"site_id"`
	VersionID string   `json:"version_id"`
	Revision  uint64   `json:"revision"`
	Serial    int64    `json:"serial"`
	Names     []string `json:"names"`
}

// Origin is a mock origin. Every request is recorded; the first route whose
// path matches answers it, else the default echo answer
// ("<name> <host> <request-uri>").
type Origin struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	// Stream "tcp" / "udp": an L4 echo origin instead of HTTP, answering
	// "<name>:<first line>" (tcp, behind TLS when TLS is set) or
	// "<name>:<datagram>" (udp).
	Stream string `json:"stream,omitempty"`
	// TLS: the origin serves HTTPS with a certificate of CA for Names.
	TLS    *OriginTLS    `json:"tls,omitempty"`
	Routes []OriginRoute `json:"routes,omitempty"`
	// WebSocket: GET with Upgrade: websocket on any path is echoed.
	WebSocket bool `json:"websocket,omitempty"`
}

type OriginTLS struct {
	CA    string   `json:"ca"`
	Names []string `json:"names"`
}

type OriginRoute struct {
	Path   string `json:"path,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Status int    `json:"status,omitempty"`
	// Body is the answer; "${request}" is replaced by "<name> <host> <uri>".
	Body    string            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	DelayMS int               `json:"delay_ms,omitempty"`
	// Truncate announces Content-Length len(Body)+Truncate and closes after Body.
	Truncate int `json:"truncate,omitempty"`
	// Gzip encodes Body with gzip (Content-Encoding: gzip).
	Gzip bool `json:"gzip,omitempty"`
	// Ranges answers Range / If-Range requests on Body (net/http ServeContent).
	Ranges bool `json:"ranges,omitempty"`
}

// Step is one action against the running edge.
type Step struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // http (default), tls, websocket, tcp, udp, task, logs, cache_entries, sleep, publish
	Note string `json:"note,omitempty"`

	// http / tls / websocket
	Method string `json:"method,omitempty"`
	// Scheme http (default) or https.
	Scheme  string            `json:"scheme,omitempty"`
	Address string            `json:"address,omitempty"` // default 127.0.0.1
	Port    int               `json:"port,omitempty"`
	Host    string            `json:"host,omitempty"`
	SNI     *string           `json:"sni,omitempty"` // default Host; "" sends none
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	// BodyBytes sends that many "x" instead of Body.
	BodyBytes int `json:"body_bytes,omitempty"`
	// Chunked sends the body without Content-Length.
	Chunked bool `json:"chunked,omitempty"`
	// ALPN offered over TLS; default ["h2", "http/1.1"].
	ALPN []string `json:"alpn,omitempty"`
	// TLSMin / TLSMax: "1.0", "1.1", "1.2" or "1.3".
	TLSMin string `json:"tls_min,omitempty"`
	TLSMax string `json:"tls_max,omitempty"`
	// Ciphers restricts the TLS 1.2-and-older suites offered (Go names).
	Ciphers []string `json:"ciphers,omitempty"`
	// ClientCert presents a client certificate issued by this CA (Env.PKI).
	ClientCert        string `json:"client_cert,omitempty"`
	clientCertificate *tls.Certificate
	// Source is the client's local address (ACL source rules).
	Source string `json:"source,omitempty"`
	// Repeat sends the request Repeat times; Summary records only the status
	// counts and the distinct origins (algorithms with random choice).
	Repeat  int  `json:"repeat,omitempty"`
	Summary bool `json:"summary,omitempty"`
	// Concurrent sends Repeat requests at once; responses are sorted.
	Concurrent bool `json:"concurrent,omitempty"`
	// Message is the websocket text frame sent and expected back (tcp: the
	// line sent, udp: the datagram).
	Message string `json:"message,omitempty"`
	// Proto "h3" sends the request over HTTP/3 (QUIC, scheme https) with the
	// run's HTTP/3 client (Env "http3").
	Proto string `json:"proto,omitempty"`
	// Connection names a kept-alive client connection: every http step
	// naming it reuses the one connection while the edge keeps it open
	// (Response.Reused), e.g. across a publish.
	Connection string `json:"connection,omitempty"`
	// FollowLocation: after a 3xx, the plain HTTP Location (an absolute
	// http:// URL to a loopback address) is requested once more from the
	// same source, as a client would (HTTP 302 scheduling); recorded as
	// Response.Followed.
	FollowLocation bool `json:"follow_location,omitempty"`

	// task: a cache task (purge_exact, purge_prefix, purge_site, prewarm).
	Task *TaskSpec `json:"task,omitempty"`
	// logs: drain the access/security logs written since the last logs step.
	// cache_entries: the site's cache objects (SiteID).
	SiteID string `json:"site_id,omitempty"`
	// sleep
	DelayMS int `json:"delay_ms,omitempty"`
	// publish: a new publication of the scope activated in place (no
	// reload), as the agent activates an index-only change.
	Publish *Publication `json:"publish,omitempty"`
}

// Publication replaces the facts' document (and, when given, the activated
// certificate versions; previous versions stay in the node's pool).
type Publication struct {
	Document     json.RawMessage `json:"document"`
	Certificates []Certificate   `json:"certificates,omitempty"`
}

// TaskSpec is a cache purge or prewarm as the control plane sends it.
type TaskSpec struct {
	Action  string   `json:"action"`
	SiteID  string   `json:"site_id"`
	Targets []string `json:"targets,omitempty"`
}

// Mask lists what differs from run to run in this scenario and is masked
// before recording (in addition to DefaultMask).
type Mask struct {
	ResponseHeaders []string `json:"response_headers,omitempty"`
	OriginHeaders   []string `json:"origin_headers,omitempty"`
	LogFields       []string `json:"log_fields,omitempty"`
	// Patterns are regular expressions replaced by "<masked>" in bodies and
	// header values.
	Patterns []string `json:"patterns,omitempty"`

	compiled []*regexp.Regexp
}

// DefaultMask: values no runtime can reproduce (clock, request IDs,
// connection serials, timing).
var DefaultMask = Mask{
	ResponseHeaders: []string{"date", "age"},
	OriginHeaders:   []string{"x-request-id"},
	LogFields: []string{"occurred_at", "request_id", "connection", "connection_requests", "duration_us",
		"origin_connect_us", "origin_first_byte_us", "origin_total_us", "request_time", "upstream_response_time"},
}

var stepKinds = map[string]bool{"http": true, "tls": true, "websocket": true, "tcp": true, "udp": true, "task": true, "logs": true,
	"cache_entries": true, "sleep": true, "publish": true}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// LoadScenario reads and checks one scenario file.
func LoadScenario(path string) (*Scenario, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var scenario Scenario
	if err := decoder.Decode(&scenario); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := scenario.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if want := strings.TrimSuffix(filepath.Base(path), ".json"); want != scenario.Name {
		return nil, fmt.Errorf("%s: name %q differs from the file name", path, scenario.Name)
	}
	sum := sha256.Sum256(raw)
	scenario.digest = hex.EncodeToString(sum[:])
	return &scenario, nil
}

// LoadScenarios reads every *.json under directory, sorted by name; only
// names (without .json) are read when given.
func LoadScenarios(directory string, only ...string) ([]*Scenario, error) {
	paths, err := filepath.Glob(filepath.Join(directory, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	wanted := map[string]bool{}
	for _, name := range only {
		wanted[name] = true
	}
	var scenarios []*Scenario
	for _, path := range paths {
		if len(wanted) != 0 && !wanted[strings.TrimSuffix(filepath.Base(path), ".json")] {
			continue
		}
		scenario, err := LoadScenario(path)
		if err != nil {
			return nil, err
		}
		scenarios = append(scenarios, scenario)
	}
	if len(scenarios) == 0 {
		return nil, fmt.Errorf("no scenarios under %s", directory)
	}
	return scenarios, nil
}

// Digest is the SHA-256 of the scenario file: a golden recorded for another
// version of the scenario is not compared.
func (scenario *Scenario) Digest() string { return scenario.digest }

func (scenario *Scenario) validate() error {
	if !namePattern.MatchString(scenario.Name) || scenario.Description == "" || len(scenario.Covers) == 0 {
		return fmt.Errorf("name, description and covers are required")
	}
	if len(scenario.Facts.Document) == 0 || scenario.Facts.Node.HealthPort <= 0 {
		return fmt.Errorf("facts.document and facts.node.health_port are required")
	}
	origins := map[string]bool{}
	for _, origin := range scenario.Origins {
		if !namePattern.MatchString(origin.Name) || origins[origin.Name] || origin.Address == "" {
			return fmt.Errorf("origin %q: unique name and address are required", origin.Name)
		}
		if origin.Stream != "" && (origin.Stream != "tcp" && origin.Stream != "udp" || origin.Stream == "udp" && origin.TLS != nil ||
			len(origin.Routes) != 0 || origin.WebSocket) {
			return fmt.Errorf("origin %q: stream is tcp (tls allowed: a TLS passthrough origin) or udp, without routes", origin.Name)
		}
		origins[origin.Name] = true
	}
	ids := map[string]bool{}
	for index := range scenario.Steps {
		step := &scenario.Steps[index]
		if step.Kind == "" {
			step.Kind = "http"
		}
		if !namePattern.MatchString(step.ID) || ids[step.ID] || !stepKinds[step.Kind] {
			return fmt.Errorf("step %d (%q): unique id and a known kind are required", index, step.ID)
		}
		ids[step.ID] = true
		switch step.Kind {
		case "http", "tls", "websocket", "tcp", "udp":
			if step.Port <= 0 {
				return fmt.Errorf("step %s: port is required", step.ID)
			}
			if step.Proto != "" && (step.Proto != "h3" || step.Kind != "http" || step.Scheme != "https" || step.Connection != "") {
				return fmt.Errorf("step %s: proto h3 is an https http step without connection", step.ID)
			}
			if step.Connection != "" && (step.Kind != "http" || step.Concurrent || !namePattern.MatchString(step.Connection)) {
				return fmt.Errorf("step %s: connection names a sequential http step's connection", step.ID)
			}
		case "publish":
			if step.Publish == nil || len(step.Publish.Document) == 0 {
				return fmt.Errorf("step %s: publish with document is required", step.ID)
			}
		case "task":
			if step.Task == nil || step.Task.SiteID == "" {
				return fmt.Errorf("step %s: task with site_id is required", step.ID)
			}
		case "cache_entries":
			if step.SiteID == "" {
				return fmt.Errorf("step %s: site_id is required", step.ID)
			}
		}
	}
	mask, err := DefaultMask.merge(scenario.Mask)
	if err != nil {
		return err
	}
	scenario.Mask = mask
	return nil
}

func (mask Mask) merge(extra Mask) (Mask, error) {
	merged := Mask{
		ResponseHeaders: lowerUnion(mask.ResponseHeaders, extra.ResponseHeaders),
		OriginHeaders:   lowerUnion(mask.OriginHeaders, extra.OriginHeaders),
		LogFields:       union(mask.LogFields, extra.LogFields),
		Patterns:        union(mask.Patterns, extra.Patterns),
	}
	for _, pattern := range merged.Patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return Mask{}, fmt.Errorf("mask pattern %q: %w", pattern, err)
		}
		merged.compiled = append(merged.compiled, compiled)
	}
	return merged, nil
}

func (mask Mask) text(value string) (string, bool) {
	masked := value
	for _, pattern := range mask.compiled {
		masked = pattern.ReplaceAllString(masked, "<masked>")
	}
	return masked, masked != value
}

func lowerUnion(left, right []string) []string {
	var values []string
	for _, value := range append(append([]string(nil), left...), right...) {
		values = append(values, strings.ToLower(value))
	}
	return union(values)
}

func union(lists ...[]string) []string {
	seen := map[string]bool{}
	var values []string
	for _, list := range lists {
		for _, value := range list {
			if !seen[value] {
				seen[value] = true
				values = append(values, value)
			}
		}
	}
	sort.Strings(values)
	return values
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

var placeholder = regexp.MustCompile(`\$\{([a-z0-9_.:-]+)\}`)

// Expand replaces every ${name} in raw with values[name]; an unknown name is
// an error. Values are inserted verbatim (they must not need JSON escaping).
func Expand(raw []byte, values map[string]string) ([]byte, error) {
	var missing []string
	result := placeholder.ReplaceAllFunc(raw, func(match []byte) []byte {
		name := string(placeholder.FindSubmatch(match)[1])
		value, ok := values[name]
		if !ok {
			missing = append(missing, name)
			return match
		}
		return []byte(value)
	})
	if len(missing) != 0 {
		return nil, fmt.Errorf("unknown placeholders %v", union(missing))
	}
	return result, nil
}

// Placeholders lists the ${names} raw uses.
func Placeholders(raw []byte) []string {
	var names []string
	for _, match := range placeholder.FindAllSubmatch(raw, -1) {
		names = append(names, string(match[1]))
	}
	return union(names)
}
