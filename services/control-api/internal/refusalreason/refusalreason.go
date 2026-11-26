// Package refusalreason carries a stable internal reason code for a refused
// request to the "request refused" log line without putting it in the
// response: the response keeps its public error code and message, operators
// read the reason (problem 28: a built-in CAPTCHA refused as
// account_registration_human_invalid logged reason="").
//
// A reason is a fixed code such as "captcha_expired". It must never hold
// user input (answers, tokens) or other secrets.
package refusalreason

import (
	"context"
	"errors"
)

type reasonError struct {
	err    error
	reason string
}

func (e *reasonError) Error() string { return e.err.Error() }
func (e *reasonError) Unwrap() error { return e.err }

// Wrap attaches reason to err; errors.Is(Wrap(err, r), err) stays true.
// An empty reason or nil err returns err unchanged.
func Wrap(err error, reason string) error {
	if err == nil || reason == "" {
		return err
	}
	return &reasonError{err: err, reason: reason}
}

// Of returns the outermost reason attached to err, or "".
func Of(err error) string {
	var wrapped *reasonError
	if errors.As(err, &wrapped) {
		return wrapped.reason
	}
	return ""
}

type recorderKey struct{}

type recorder struct{ reason string }

// WithRecorder returns a context in which Record keeps a reason for the
// request; the refusal log installs it once per request.
func WithRecorder(ctx context.Context) context.Context {
	return context.WithValue(ctx, recorderKey{}, &recorder{})
}

// Record keeps reason for the refusal log of the request ctx belongs to. It
// is a no-op without a recorder or with an empty reason.
func Record(ctx context.Context, reason string) {
	if r, ok := ctx.Value(recorderKey{}).(*recorder); ok && reason != "" {
		r.reason = reason
	}
}

// Recorded returns the reason recorded for the request, or "".
func Recorded(ctx context.Context) string {
	if r, ok := ctx.Value(recorderKey{}).(*recorder); ok {
		return r.reason
	}
	return ""
}
