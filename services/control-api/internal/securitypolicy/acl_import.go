package securitypolicy

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxACLImportBytes  = 64 << 10
	maxACLRules        = 100
	maxACLCommentBytes = 256
)

type ACLImportLineError struct {
	Line int    `json:"line"`
	Code string `json:"code"`
}

type ACLImportError struct {
	Lines []ACLImportLineError
}

func (err *ACLImportError) Error() string { return "ACL import contains invalid lines" }
func (err *ACLImportError) Unwrap() error { return ErrInvalidInput }

func ParseACLImport(raw string) ([]Rule, error) {
	if len(raw) == 0 || len(raw) > maxACLImportBytes || !utf8.ValidString(raw) {
		return nil, &ACLImportError{Lines: []ACLImportLineError{{Line: 1, Code: "invalid_size"}}}
	}
	type entry struct {
		line, action             int
		cidr, comment, expiresAt string
	}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	entries := make([]entry, 0, len(lines))
	failures := make([]ACLImportLineError, 0)
	seen := make(map[string]struct{})
	for index, rawLine := range lines {
		lineNumber := index + 1
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		content, comment, hasComment := line, "", false
		if marker := strings.IndexByte(line, '#'); marker >= 0 {
			content, comment, hasComment = strings.TrimSpace(line[:marker]), strings.TrimSpace(line[marker+1:]), true
		}
		fields := strings.Fields(content)
		if len(fields) < 2 || len(fields) > 3 {
			failures = append(failures, ACLImportLineError{Line: lineNumber, Code: "invalid_syntax"})
			continue
		}
		action := strings.ToLower(fields[0])
		if action != ActionAllow && action != ActionBlock {
			failures = append(failures, ACLImportLineError{Line: lineNumber, Code: "invalid_action"})
			continue
		}
		cidr, err := canonicalACLPrefix(fields[1])
		if err != nil {
			failures = append(failures, ACLImportLineError{Line: lineNumber, Code: "invalid_cidr"})
			continue
		}
		expiresAt := ""
		if len(fields) == 3 {
			if !strings.HasPrefix(fields[2], "expires=") || !validACLExpiry(strings.TrimPrefix(fields[2], "expires=")) {
				failures = append(failures, ACLImportLineError{Line: lineNumber, Code: "invalid_expiry"})
				continue
			}
			expiresAt = strings.TrimPrefix(fields[2], "expires=")
		}
		if hasComment && !validACLComment(comment) {
			failures = append(failures, ACLImportLineError{Line: lineNumber, Code: "invalid_comment"})
			continue
		}
		if _, duplicate := seen[cidr]; duplicate {
			failures = append(failures, ACLImportLineError{Line: lineNumber, Code: "duplicate_cidr"})
			continue
		}
		seen[cidr] = struct{}{}
		actionOrder := 1
		if action == ActionBlock {
			actionOrder = 2
		}
		entries = append(entries, entry{line: lineNumber, action: actionOrder, cidr: cidr, comment: comment, expiresAt: expiresAt})
		if len(entries) > maxACLRules {
			failures = append(failures, ACLImportLineError{Line: lineNumber, Code: "too_many_entries"})
		}
	}
	if len(failures) != 0 {
		return nil, &ACLImportError{Lines: failures}
	}
	if len(entries) == 0 {
		return nil, &ACLImportError{Lines: []ACLImportLineError{{Line: 1, Code: "empty_import"}}}
	}
	rules := make([]Rule, 0, len(entries))
	for actionOrder := 1; actionOrder <= 2; actionOrder++ {
		for _, item := range entries {
			if item.action != actionOrder {
				continue
			}
			action := ActionAllow
			if actionOrder == 2 {
				action = ActionBlock
			}
			rules = append(rules, Rule{
				Name: fmt.Sprintf("%s %s", action, item.cidr), Priority: len(rules) + 1, Enabled: true,
				Comment: item.comment, ExpiresAt: item.expiresAt, Action: action, Flow: FlowStop,
				Conditions: []Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{item.cidr}}},
			})
		}
	}
	return rules, nil
}

// canonicalACLPrefix reads a CIDR, address, dotted netmask or a range that is
// exactly one CIDR (ParseIPNetworks); an ACL rule holds one network.
func canonicalACLPrefix(value string) (string, error) {
	prefixes, err := ParseIPNetworks(value)
	if err != nil || len(prefixes) != 1 {
		return "", ErrInvalidInput
	}
	return prefixes[0].String(), nil
}

func validACLComment(value string) bool {
	return value != "" && len(value) <= maxACLCommentBytes && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}
