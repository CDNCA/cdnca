package cachecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestWithSessionAuthorizationStrictBoundaryAndRedaction(t *testing.T) {
	validToken := strings.Repeat("a", 8191)
	ctx, err := WithSessionAuthorization(context.Background(), validToken)
	if err != nil {
		t.Fatalf("8191-byte token: %v", err)
	}
	authorization, ok := ctx.Value(sessionAuthorizationContextKey{}).(sessionAuthorization)
	if !ok || authorization.rawToken != validToken {
		t.Fatal("8191-byte token was not stored in the private context value")
	}

	for _, test := range []struct {
		name  string
		ctx   context.Context
		token string
	}{
		{name: "nil context", token: "token"},
		{name: "empty token", ctx: context.Background()},
		{name: "whitespace token", ctx: context.Background(), token: "secret token"},
		{name: "8192-byte token", ctx: context.Background(), token: strings.Repeat("a", 8192)},
		{name: "over-limit token", ctx: context.Background(), token: strings.Repeat("a", 8193)},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := WithSessionAuthorization(test.ctx, test.token)
			if !errors.Is(err, ErrInvalidInput) || result != nil {
				t.Fatalf("context=%v err=%v, want nil context and ErrInvalidInput", result, err)
			}
		})
	}

	if got := fmt.Sprintf("%v %#v", authorization, authorization); strings.Contains(got, validToken) {
		t.Fatalf("formatted session authorization leaked token: %q", got)
	}
	encoded, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), validToken) {
		t.Fatalf("JSON session authorization leaked token: %s", encoded)
	}
}
