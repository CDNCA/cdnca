// Package fielderr locates a refused request field on a domain validation
// error, so the API can answer validation_error with details.field (the JSON
// path as sent: name, limits.domains, group_ids[0]) and details.reason (a
// machine code the pages translate). The error still unwraps to the domain's
// own invalid-input sentinel: errors.Is, the HTTP status and the code are
// unchanged.
package fielderr

import "errors"

// Reasons the pages have texts for (packages/cdnca-ui formErrors.tsx).
const (
	Required      = "required"
	TooLong       = "too_long"
	TooShort      = "too_short"
	InvalidFormat = "invalid_format"
	OutOfRange    = "out_of_range"
	Duplicate     = "duplicate"
	Invalid       = "invalid"
)

// Error is a validation refusal of one request field.
type Error struct {
	Field  string
	Reason string
	base   error
}

func (e *Error) Error() string {
	return e.base.Error() + ": field " + e.Field + " is " + e.Reason
}

func (e *Error) Unwrap() error { return e.base }

// New wraps base (the package's ErrInvalidInput) with the refused field.
func New(base error, field, reason string) error {
	return &Error{Field: field, Reason: reason, base: base}
}

// As returns the located field of err, if any.
func As(err error) (*Error, bool) {
	var located *Error
	if errors.As(err, &located) {
		return located, true
	}
	return nil, false
}

// Within prefixes the field path of err with prefix (a nested request body,
// e.g. "spec"); other errors are returned unchanged.
func Within(err error, prefix string) error {
	located, ok := As(err)
	if !ok || prefix == "" {
		return err
	}
	field := prefix + "." + located.Field
	if len(located.Field) > 0 && located.Field[0] == '[' {
		field = prefix + located.Field
	}
	return &Error{Field: field, Reason: located.Reason, base: located.base}
}
