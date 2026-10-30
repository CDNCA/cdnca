package acmeworker

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/crypto/acme"
)

// 申请记录显示 CA 返回的具体原因，但去掉 URL、邮箱、令牌，限 512 字符。
func TestPublicReason(t *testing.T) {
	authorization := &acme.AuthorizationError{URI: "https://ca.test/acme/authz/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", Identifier: "www.example.test",
		Errors: []error{&acme.Error{StatusCode: 403, ProblemType: "urn:ietf:params:acme:error:unauthorized",
			Detail: "Invalid response from http://www.example.test/.well-known/acme-challenge/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-xyz: 404"}}}
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{"authorization", failure(CodeAuthorizationInvalid, authorization),
			"www.example.test: Invalid response from [url]: 404"},
		{"problem", failure(CodeOrderRejected, &acme.Error{StatusCode: 400, ProblemType: "urn:ietf:params:acme:error:dns",
			Detail: "DNS problem: NXDOMAIN looking up TXT for _acme-challenge.example.test\n- check that a DNS record exists"}),
			"DNS problem: NXDOMAIN looking up TXT for _acme-challenge.example.test - check that a DNS record exists"},
		{"contact", failure(CodeOrderRejected, &acme.Error{StatusCode: 400, ProblemType: "urn:ietf:params:acme:error:invalidContact",
			Detail: "Error validating contact(s) :: contact email \"ops@example.test\" has invalid domain"}),
			"Error validating contact(s) :: contact email \"[email]\" has invalid domain"},
		{"subproblems", failure(CodeOrderRejected, &acme.Error{StatusCode: 400, ProblemType: "urn:ietf:params:acme:error:rejectedIdentifier",
			Detail: "Error creating new order", Subproblems: []acme.Subproblem{{Type: "x", Detail: "Domain name contains an invalid character",
				Identifier: &acme.AuthzID{Type: "dns", Value: "bad_.example.test"}}}}),
			"Error creating new order; bad_.example.test: Domain name contains an invalid character"},
		{"non acme cause", failure(CodeChallengeUnavailable, errors.New("dial tcp 10.0.0.1:443: secret=abc")), ""},
		{"no cause", failure(CodeOrderRejected, nil), ""},
		{"plain", errors.New("boom"), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := PublicReason(test.err); got != test.want {
				t.Fatalf("PublicReason = %q, want %q", got, test.want)
			}
		})
	}
}

func TestPublicReasonIsBounded(t *testing.T) {
	long := failure(CodeOrderRejected, &acme.Error{Detail: strings.Repeat("报错原因 ", 300) + "\x00\x1b[31m"})
	got := PublicReason(long)
	if utf8.RuneCountInString(got) > PublicReasonLimit || strings.ContainsAny(got, "\x00\x1b\n") || !strings.HasSuffix(got, "…") {
		t.Fatalf("len=%d %q", utf8.RuneCountInString(got), got[len(got)-20:])
	}
}
