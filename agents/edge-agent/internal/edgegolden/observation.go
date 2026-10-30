package edgegolden

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// ObservationSchema names the golden file format.
const ObservationSchema = "cdnca.edge-golden.observation/v1"

// Observation is what one scenario produced, normalized: equal behaviour
// gives byte-identical files.
type Observation struct {
	Schema   string       `json:"schema"`
	Scenario string       `json:"scenario"`
	Digest   string       `json:"scenario_sha256"`
	Steps    []StepResult `json:"steps"`
}

type StepResult struct {
	ID        string           `json:"id"`
	Kind      string           `json:"kind"`
	Responses []Response       `json:"responses,omitempty"`
	Summary   *RepeatSummary   `json:"summary,omitempty"`
	TLS       *TLSResult       `json:"tls,omitempty"`
	WebSocket *WebSocketResult `json:"websocket,omitempty"`
	Task      *TaskResult      `json:"task,omitempty"`
	Logs      []LogRecord      `json:"logs,omitempty"`
	Cache     *CacheEntries    `json:"cache,omitempty"`
	Stream    *StreamResult    `json:"stream,omitempty"`
}

// StreamResult is an L4 exchange (tcp / udp step): the reply line or
// datagram, the TLS the client saw (TLS passthrough), what failed.
type StreamResult struct {
	Error string     `json:"error,omitempty"`
	Reply string     `json:"reply,omitempty"`
	TLS   *TLSResult `json:"tls,omitempty"`
}

type Response struct {
	// Error is the client-side failure class; empty when a response arrived.
	Error   string            `json:"error,omitempty"`
	Status  int               `json:"status,omitempty"`
	Proto   string            `json:"proto,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    *Body             `json:"body,omitempty"`
	TLS     *TLSResult        `json:"tls,omitempty"`
	// Origin is every request the mock origins received for this request,
	// in arrival order (retries and fallbacks included).
	Origin []OriginRequest `json:"origin"`
	// Followed is the response to the Location of a 3xx (Step.FollowLocation).
	Followed *Response `json:"followed,omitempty"`
	// Reused: a named connection's request went over the connection an
	// earlier step opened (Step.Connection).
	Reused bool `json:"reused,omitempty"`

	// location is the raw Location header (before masking), for Followed.
	location string
}

// Body is a response or origin request body after masking.
type Body struct {
	Length int    `json:"length"`
	SHA256 string `json:"sha256"`
	// Text is the masked body when it is short UTF-8.
	Text   string `json:"text,omitempty"`
	Masked bool   `json:"masked,omitempty"`
}

type OriginRequest struct {
	Origin  string            `json:"origin"`
	Method  string            `json:"method"`
	URI     string            `json:"uri"`
	Host    string            `json:"host"`
	Proto   string            `json:"proto"`
	Headers map[string]string `json:"headers"`
	Body    *Body             `json:"body,omitempty"`
	// Peer is the address the edge connected from (no port).
	Peer string `json:"peer"`
	SNI  string `json:"sni,omitempty"`
}

type TLSResult struct {
	Error   string `json:"error,omitempty"`
	Version string `json:"version,omitempty"`
	ALPN    string `json:"alpn,omitempty"`
	// Certificate the edge presented.
	Subject string   `json:"subject,omitempty"`
	Names   []string `json:"names,omitempty"`
	Serial  int64    `json:"serial,omitempty"`
	Issuer  string   `json:"issuer,omitempty"`
	// Verified: the chain verifies against the site CA for the SNI.
	Verified bool `json:"verified,omitempty"`
}

type RepeatSummary struct {
	Count    int            `json:"count"`
	Statuses map[string]int `json:"statuses"`
	Errors   map[string]int `json:"errors,omitempty"`
	// Origins are the distinct origins that answered, sorted.
	Origins []string `json:"origins"`
	// OriginRequests counts what the origins received in total.
	OriginRequests int `json:"origin_requests"`
}

type WebSocketResult struct {
	Error  string          `json:"error,omitempty"`
	Status int             `json:"status"`
	Echo   string          `json:"echo,omitempty"`
	Origin []OriginRequest `json:"origin"`
}

// TaskResult is a cache task's outcome as the control plane would see it.
type TaskResult struct {
	Error  string          `json:"error,omitempty"`
	State  string          `json:"state,omitempty"`
	Items  []TaskItem      `json:"items,omitempty"`
	Origin []OriginRequest `json:"origin"`
}

type TaskItem struct {
	Target   string `json:"target"`
	Status   string `json:"status"`
	Code     string `json:"code"`
	Affected int    `json:"affected"`
}

// LogRecord is one access or security log line after masking.
type LogRecord struct {
	Stream string         `json:"stream"` // access, security
	Fields map[string]any `json:"fields"`
}

// CacheEntries are the site's cache objects on disk.
type CacheEntries struct {
	Count int      `json:"count"`
	Keys  []string `json:"keys"`
}

// Encode is the golden encoding: indented, sorted keys, trailing newline.
func (observation *Observation) Encode() ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(observation); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// WriteObservation writes directory/<scenario>.json.
func WriteObservation(directory string, observation *Observation) error {
	encoded, err := observation.Encode()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, observation.Scenario+".json"), encoded, 0o644)
}

// ReadObservation reads directory/<name>.json; ok is false when it is absent.
func ReadObservation(directory, name string) (*Observation, bool, error) {
	raw, err := os.ReadFile(filepath.Join(directory, name+".json"))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var observation Observation
	if err := decoder.Decode(&observation); err != nil {
		return nil, false, fmt.Errorf("%s: %w", name, err)
	}
	if observation.Schema != ObservationSchema || observation.Scenario != name {
		return nil, false, fmt.Errorf("%s: not a %s observation of this scenario", name, ObservationSchema)
	}
	return &observation, true, nil
}

const maxBodyText = 8192

func newBody(mask Mask, raw []byte) *Body {
	if len(raw) == 0 {
		return nil
	}
	text := string(raw)
	masked := false
	if utf8.Valid(raw) {
		text, masked = mask.text(text)
	}
	sum := sha256.Sum256([]byte(text))
	body := &Body{Length: len(raw), SHA256: hex.EncodeToString(sum[:]), Masked: masked}
	if utf8.ValidString(text) && len(text) <= maxBodyText {
		body.Text = text
	}
	return body
}

// headerMap lowercases names, joins repeated values with "\n" and masks.
func headerMap(mask Mask, names []string, header map[string][]string, skip ...string) map[string]string {
	result := make(map[string]string, len(header))
	for name, values := range header {
		lower := strings.ToLower(name)
		if contains(skip, lower) {
			continue
		}
		if contains(names, lower) {
			result[lower] = "<masked>"
			continue
		}
		joined := strings.Join(values, "\n")
		joined, _ = mask.text(joined)
		result[lower] = joined
	}
	return result
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
