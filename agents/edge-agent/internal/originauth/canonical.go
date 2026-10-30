package originauth

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

var rangePattern = regexp.MustCompile(`^bytes=(?:[0-9]+-[0-9]*|-[0-9]+)$`)

type queryPair struct {
	name  string
	value string
}

func canonicalPath(raw string) (string, error) {
	if raw == "" {
		raw = "/"
	}
	if len(raw) > 4096 || raw[0] != '/' || strings.Contains(raw, "\\") || strings.Contains(strings.ToLower(raw), "%2f") || strings.Contains(strings.ToLower(raw), "%5c") {
		return "", reject("PATH_INVALID")
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil || !utf8.ValidString(decoded) || hasControl(decoded) || strings.Contains(decoded, "\\") {
		return "", reject("PATH_INVALID")
	}
	segments := strings.Split(decoded, "/")
	for index, segment := range segments {
		if index == 0 {
			continue
		}
		if segment == "." || segment == ".." || (segment == "" && index != len(segments)-1) {
			return "", reject("PATH_INVALID")
		}
	}
	return percentEncode(decoded, true), nil
}

func parseQuery(raw string) ([]queryPair, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 8192 || strings.ContainsAny(raw, ";+#") {
		return nil, reject("QUERY_INVALID")
	}
	parts := strings.Split(raw, "&")
	if len(parts) > 128 {
		return nil, reject("QUERY_INVALID")
	}
	result := make([]queryPair, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, reject("QUERY_INVALID")
		}
		nameRaw, valueRaw, found := strings.Cut(part, "=")
		if !found {
			valueRaw = ""
		}
		name, err := url.PathUnescape(nameRaw)
		if err != nil || name == "" || !utf8.ValidString(name) || hasControl(name) {
			return nil, reject("QUERY_INVALID")
		}
		value, err := url.PathUnescape(valueRaw)
		if err != nil || !utf8.ValidString(value) || hasControl(value) {
			return nil, reject("QUERY_INVALID")
		}
		if _, exists := seen[name]; exists {
			return nil, reject("QUERY_AMBIGUOUS")
		}
		seen[name] = struct{}{}
		if credentialQueryName(name) {
			return nil, reject("CREDENTIAL_IN_QUERY")
		}
		result = append(result, queryPair{name: name, value: value})
	}
	return result, nil
}

func canonicalQuery(pairs []queryPair) string {
	values := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		values = append(values, percentEncode(pair.name, false)+"="+percentEncode(pair.value, false))
	}
	sort.Strings(values)
	return strings.Join(values, "&")
}

func canonicalOSSQuery(pairs []queryPair) string {
	values := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		value := percentEncode(pair.name, false)
		if pair.value != "" {
			value += "=" + percentEncode(pair.value, false)
		}
		values = append(values, value)
	}
	sort.Strings(values)
	return strings.Join(values, "&")
}

func cosCanonicalQuery(pairs []queryPair) (string, string) {
	type encoded struct{ name, value string }
	values := make([]encoded, 0, len(pairs))
	for _, pair := range pairs {
		values = append(values, encoded{name: strings.ToLower(percentEncode(pair.name, false)), value: percentEncode(pair.value, false)})
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].name != values[j].name {
			return values[i].name < values[j].name
		}
		return values[i].value < values[j].value
	})
	formatted := make([]string, len(values))
	names := make([]string, len(values))
	for index, value := range values {
		formatted[index] = value.name + "=" + value.value
		names[index] = value.name
	}
	return strings.Join(formatted, "&"), strings.Join(names, ";")
}

func percentEncode(value string, preserveSlash bool) string {
	const hex = "0123456789ABCDEF"
	var output strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("-._~", rune(character)) || preserveSlash && character == '/' {
			output.WriteByte(character)
			continue
		}
		output.WriteByte('%')
		output.WriteByte(hex[character>>4])
		output.WriteByte(hex[character&15])
	}
	return output.String()
}

func credentialQueryName(name string) bool {
	value := strings.ToLower(name)
	if strings.HasPrefix(value, "x-amz-") || strings.HasPrefix(value, "x-oss-") || strings.HasPrefix(value, "q-sign-") || strings.HasPrefix(value, "q-key-") {
		return true
	}
	switch value {
	case "authorization", "signature", "ossaccesskeyid", "security-token", "x-cos-security-token", "q-ak", "q-header-list", "q-url-param-list":
		return true
	default:
		return false
	}
}

func validateRange(values []string) (string, error) {
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 || len(values[0]) > 128 || !rangePattern.MatchString(values[0]) {
		return "", reject("RANGE_INVALID")
	}
	return values[0], nil
}

func normalizedHeaderValue(value string) (string, error) {
	if len(value) == 0 || len(value) > 4096 || hasControl(value) {
		return "", reject("HEADER_INVALID")
	}
	return strings.Join(strings.Fields(value), " "), nil
}

func canonicalHeaders(headers map[string]string) (string, string, error) {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)
	var output strings.Builder
	for _, name := range names {
		value, err := normalizedHeaderValue(headers[name])
		if err != nil {
			return "", "", err
		}
		fmt.Fprintf(&output, "%s:%s\n", name, value)
	}
	return output.String(), strings.Join(names, ";"), nil
}
