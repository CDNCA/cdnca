package eventspool

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// sanitizeSecurityEvidence is the Agent's second guard over a security
// event's evidence (TF-E01): the node writes a body excerpt only for a site
// whose capture policy collects request body fields and redacts sensitive
// names, but an older node or odd input must not carry a raw body or secret
// value into the spool. Without request body capture for this request the
// excerpt is dropped; otherwise a JSON or form excerpt is re-redacted and any
// other text is dropped. The matched fragment keeps its text with sensitive
// name=value / "name":"value" values replaced. Rule, detector and action are
// untouched.
func sanitizeSecurityEvidence(envelope Envelope, policy CapturePolicy) Envelope {
	if envelope.Type != EventSecurity {
		return envelope
	}
	envelope.Matched = truncateUTF8(scrubEvidenceText(envelope.Matched), 256)
	if len(policy.RequestBodyFields) == 0 || !capturePolicyMatches(envelope.Method, envelope.Path, policy) {
		envelope.RequestBodyExcerpt = ""
		return envelope
	}
	envelope.RequestBodyExcerpt = redactEvidenceBody(envelope.RequestBodyExcerpt)
	return envelope
}

func redactEvidenceBody(excerpt string) string {
	trimmed := strings.TrimSpace(excerpt)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var decoded any
		decoder := json.NewDecoder(strings.NewReader(trimmed))
		decoder.UseNumber()
		if decoder.Decode(&decoded) != nil || decoder.More() {
			return ""
		}
		encoded, err := json.Marshal(redactEvidenceJSON(decoded, 0))
		if err != nil || len(encoded) > 1024 || !utf8.Valid(encoded) {
			return ""
		}
		return string(encoded)
	}
	if strings.ContainsAny(trimmed, " \t\r\n<>{}") {
		return ""
	}
	parts := strings.Split(trimmed, "&")
	for index, pair := range parts {
		name, _, _ := strings.Cut(pair, "=")
		decoded, err := url.QueryUnescape(name)
		if err != nil {
			return ""
		}
		if sensitiveName(decoded) {
			parts[index] = name + "=" + redactedValue
		}
	}
	result := strings.Join(parts, "&")
	if len(result) > 1024 {
		return ""
	}
	return result
}

func redactEvidenceJSON(value any, depth int) any {
	if depth > 16 {
		return nil
	}
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for name, item := range typed {
			if sensitiveName(name) {
				result[name] = redactedValue
				continue
			}
			result[name] = redactEvidenceJSON(item, depth+1)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = redactEvidenceJSON(item, depth+1)
		}
		return result
	default:
		return typed
	}
}

var (
	evidenceJSONPair = regexp.MustCompile(`"([^"]*)"(\s*:\s*)"[^"]*"?`)
	evidenceFormPair = regexp.MustCompile(`([A-Za-z0-9_.\[\]-]+)=([^&;\s]*)`)
)

// scrubEvidenceText replaces the value after a sensitive name in a fragment
// cut from a body, query or header (same patterns as cdnca_waf
// evidence.scrub).
func scrubEvidenceText(text string) string {
	if text == "" {
		return ""
	}
	text = evidenceJSONPair.ReplaceAllStringFunc(text, func(match string) string {
		parts := evidenceJSONPair.FindStringSubmatch(match)
		if !sensitiveName(parts[1]) {
			return match
		}
		return `"` + parts[1] + `"` + parts[2] + `"` + redactedValue + `"`
	})
	return evidenceFormPair.ReplaceAllStringFunc(text, func(match string) string {
		parts := evidenceFormPair.FindStringSubmatch(match)
		if !sensitiveName(parts[1]) {
			return match
		}
		return parts[1] + "=" + redactedValue
	})
}

// truncateUTF8 cuts value to at most limit bytes on a rune boundary (a
// redacted value can be longer than the one it replaced).
func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for len(value) > 0 && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return strings.TrimSpace(value)
}

// aggregateEventID identifies an aggregated security line (TF-E03) by its
// source, node and bytes, not by where it was appended: the node keeps a
// finished minute's line until the flush server answers 204, so a lost
// acknowledgement makes it write the same line again at another offset (or
// file after rotation). The same ID lets the spool (and ClickHouse's
// ReplacingMergeTree on event_id) count it once.
func aggregateEventID(sourcePath, nodeID string, line []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.security.aggregate.v1\x00" + sourcePath + "\x00" + nodeID + "\x00"))
	lineDigest := sha256.Sum256(line)
	_, _ = hash.Write(lineDigest[:])
	return "evt_" + hex.EncodeToString(hash.Sum(nil))
}
