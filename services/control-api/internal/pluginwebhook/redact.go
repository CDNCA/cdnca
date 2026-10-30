package pluginwebhook

import (
	"encoding/json"
	"net/http"
	"strings"
	"unicode/utf8"
)

const redactedValue = "[REDACTED]"

func sanitizePreview(payload []byte, contentType string, limit int) string {
	if limit <= 0 || len(payload) == 0 {
		return ""
	}
	preview := "[non-json response omitted]"
	if strings.Contains(strings.ToLower(contentType), "json") && json.Valid(payload) {
		var value any
		if json.Unmarshal(payload, &value) == nil {
			redactJSON(value)
			if encoded, err := json.Marshal(value); err == nil {
				preview = string(encoded)
			}
		}
	}
	return truncateUTF8(preview, limit)
}

func sanitizeHeaders(headers http.Header) map[string]string {
	result := make(map[string]string, len(headers))
	for name, values := range headers {
		canonical := http.CanonicalHeaderKey(name)
		if sensitiveName(canonical) {
			result[canonical] = redactedValue
			continue
		}
		switch canonical {
		case "Content-Type", "Retry-After":
			result[canonical] = truncateUTF8(strings.Join(values, ","), 256)
		default:
			result[canonical] = redactedValue
		}
	}
	return result
}

func redactJSON(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if sensitiveName(key) {
				typed[key] = redactedValue
				continue
			}
			redactJSON(child)
		}
	case []any:
		for _, child := range typed {
			redactJSON(child)
		}
	}
}

func sensitiveName(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, "-", "_"), ".", "_"))
	for _, marker := range []string{"authorization", "cookie", "password", "passwd", "secret", "token", "signature", "private_key", "api_key"} {
		if normalized == marker || strings.HasSuffix(normalized, "_"+marker) || strings.HasPrefix(normalized, marker+"_") {
			return true
		}
	}
	compact := strings.ReplaceAll(normalized, "_", "")
	for _, marker := range []string{"authorization", "cookie", "password", "passwd", "secret", "token", "signature", "privatekey", "apikey", "credential"} {
		if strings.Contains(compact, marker) {
			return true
		}
	}
	return false
}

func truncateUTF8(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) && len(value) > 0 {
		value = value[:len(value)-1]
	}
	return value
}
