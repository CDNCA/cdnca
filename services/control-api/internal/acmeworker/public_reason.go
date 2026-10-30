package acmeworker

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/acme"
)

// PublicReasonLimit bounds the CA reason kept on a certificate order (runes).
const PublicReasonLimit = 512

var (
	reasonURLPattern   = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]*[^\s"'<>.,:;)]`)
	reasonEmailPattern = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	// Account keys, nonces, challenge tokens and key authorizations are long
	// base64url runs; domain labels are at most 63 characters with dots.
	reasonTokenPattern = regexp.MustCompile(`[A-Za-z0-9_-]{32,}(\.[A-Za-z0-9_-]{16,})?`)
	reasonSpacePattern = regexp.MustCompile(`\s+`)
)

// PublicReason is the CA's own explanation of why err failed, fit to show the
// certificate owner next to the failure category: the
// ACME problem detail of the failed authorization or request, with URLs,
// e-mail addresses and token-like strings replaced, control characters
// removed and at most PublicReasonLimit runes. Empty for any cause that is
// not an ACME problem (those may quote local addresses or values).
func PublicReason(err error) string {
	var workerErr *Error
	if errors.As(err, &workerErr) {
		err = workerErr.cause
	}
	if err == nil {
		return ""
	}
	var parts []string
	var authorization *acme.AuthorizationError
	var problem *acme.Error
	switch {
	case errors.As(err, &authorization):
		for _, cause := range authorization.Errors {
			if errors.As(cause, &problem) && problem.Detail != "" {
				parts = append(parts, problemText(problem))
			}
		}
		if len(parts) > 0 && authorization.Identifier != "" {
			parts[0] = authorization.Identifier + ": " + parts[0]
		}
	case errors.As(err, &problem):
		parts = append(parts, problemText(problem))
	}
	return redactReason(strings.Join(parts, "; "))
}

func problemText(problem *acme.Error) string {
	text := problem.Detail
	for _, sub := range problem.Subproblems {
		if sub.Detail == "" {
			continue
		}
		if sub.Identifier != nil && sub.Identifier.Value != "" {
			text += "; " + sub.Identifier.Value + ": " + sub.Detail
		} else {
			text += "; " + sub.Detail
		}
	}
	return text
}

func redactReason(text string) string {
	text = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r == '\r' {
			return ' '
		}
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, text)
	text = reasonURLPattern.ReplaceAllString(text, "[url]")
	text = reasonEmailPattern.ReplaceAllString(text, "[email]")
	text = reasonTokenPattern.ReplaceAllString(text, "[token]")
	text = strings.TrimSpace(reasonSpacePattern.ReplaceAllString(text, " "))
	if utf8.RuneCountInString(text) > PublicReasonLimit {
		runes := []rune(text)
		text = strings.TrimSpace(string(runes[:PublicReasonLimit-1])) + "…"
	}
	return text
}

// TerminalFailure is an Error that settles its operation as failed, with the
// cause kept for FailureDetail and PublicReason (callers outside the worker,
// such as the runtime dispatcher tests).
func TerminalFailure(code ErrorCode, cause error) *Error {
	return &Error{Code: code, Terminal: true, cause: cause}
}
