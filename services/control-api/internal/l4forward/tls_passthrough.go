package l4forward

import (
	"regexp"
	"sort"
	"strings"
)

// maxServerNames bounds the SNI list of one TLS passthrough stream
// (edgeconfig.L4ServerNamesMax, migration 293).
const maxServerNames = 32

var serverNamePattern = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// normalizeTLSPassthrough lower-cases and sorts the SNI list. Passthrough
// streams are TCP only and name 1-32 exact host names or leading "*."
// wildcards; plain streams name none. Additional listeners inherit the
// stream's passthrough and must be TCP as well (the database checks it too).
func normalizeTLSPassthrough(fields *Fields) error {
	if !fields.TLSPassthrough {
		if len(fields.ServerNames) != 0 {
			return ErrInvalidInput
		}
		fields.ServerNames = []string{}
		return nil
	}
	if fields.Protocol != ProtocolTCP || len(fields.ServerNames) == 0 || len(fields.ServerNames) > maxServerNames {
		return ErrInvalidInput
	}
	if fields.AdditionalListeners != nil {
		for _, listener := range *fields.AdditionalListeners {
			if listener.Protocol != ProtocolTCP {
				return ErrInvalidInput
			}
		}
	}
	names := make([]string, 0, len(fields.ServerNames))
	seen := make(map[string]struct{}, len(fields.ServerNames))
	for _, value := range fields.ServerNames {
		name := strings.ToLower(strings.TrimSpace(value))
		if len(strings.TrimPrefix(name, "*.")) > 253 || !serverNamePattern.MatchString(name) {
			return ErrInvalidInput
		}
		if _, duplicate := seen[name]; duplicate {
			return ErrInvalidInput
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	fields.ServerNames = names
	return nil
}
