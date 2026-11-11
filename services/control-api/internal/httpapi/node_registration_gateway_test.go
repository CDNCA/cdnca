package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/node"
)

// The registration-credential response carries the direct Gateway
// entry the console writes into the node install command.
func TestNodeRegistrationCredentialResponseCarriesTheGateway(t *testing.T) {
	credential := node.RegistrationCredential{Credential: "nrk1.x"}
	gateway := NodeInstallGateway{EnrollmentAddress: "203.0.113.20:29402", Address: "203.0.113.20:20407", ServerName: "203.0.113.20"}
	encode := func(s *Server) string {
		body, err := json.Marshal(s.nodeRegistrationCredentialResponse(t.Context(), credential))
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	got := encode(&Server{logger: quiet, nodeInstallGateway: func(context.Context) (NodeInstallGateway, bool, error) { return gateway, true, nil }})
	if !strings.Contains(got, `"gateway":{"enrollment_address":"203.0.113.20:29402","address":"203.0.113.20:20407","server_name":"203.0.113.20"}`) ||
		!strings.Contains(got, `"credential":"nrk1.x"`) {
		t.Fatalf("body = %s", got)
	}
	for name, source := range map[string]func(context.Context) (NodeInstallGateway, bool, error){
		"ws console": func(context.Context) (NodeInstallGateway, bool, error) { return gateway, false, nil },
		"read error": func(context.Context) (NodeInstallGateway, bool, error) { return gateway, true, errors.New("db down") },
		"no source":  nil,
	} {
		if got := encode(&Server{logger: quiet, nodeInstallGateway: source}); strings.Contains(got, "gateway") {
			t.Errorf("%s: body = %s", name, got)
		}
	}
}

// 重装此节点: the issued enrollment token carries the same Gateway entry, so
// the console's reinstall command connects like the install command.
func TestIssuedEnrollmentTokenResponseCarriesTheGateway(t *testing.T) {
	issued := node.IssuedToken{TokenMetadata: node.TokenMetadata{Purpose: node.PurposeReEnrollment}, Token: "raw-token"}
	gateway := NodeInstallGateway{EnrollmentAddress: "203.0.113.20:29402", Address: "203.0.113.20:20407", ServerName: "203.0.113.20"}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	encode := func(source func(context.Context) (NodeInstallGateway, bool, error)) string {
		s := &Server{logger: quiet, nodeInstallGateway: source}
		body, err := json.Marshal(issuedEnrollmentTokenResponse{IssuedToken: issued, Gateway: s.installGateway(t.Context())})
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	got := encode(func(context.Context) (NodeInstallGateway, bool, error) { return gateway, true, nil })
	if !strings.Contains(got, `"token":"raw-token"`) || !strings.Contains(got, `"purpose":"re_enrollment"`) ||
		!strings.Contains(got, `"gateway":{"enrollment_address":"203.0.113.20:29402","address":"203.0.113.20:20407","server_name":"203.0.113.20"}`) {
		t.Fatalf("body = %s", got)
	}
	if got := encode(nil); strings.Contains(got, "gateway") || !strings.Contains(got, `"token":"raw-token"`) {
		t.Fatalf("without a Gateway entry body = %s", got)
	}
}

// A re_enrollment token takes the reinstall entry (a ws
// console's first grpc entry), an initial token the install command's.
func TestIssuedEnrollmentTokenResponsePicksTheReinstallGateway(t *testing.T) {
	install := NodeInstallGateway{EnrollmentAddress: "203.0.113.20:29402", Address: "203.0.113.20:20407", ServerName: "install.example"}
	reinstall := NodeInstallGateway{EnrollmentAddress: "203.0.113.20:29402", Address: "203.0.113.20:20407", ServerName: "reinstall.example"}
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		nodeInstallGateway:   func(context.Context) (NodeInstallGateway, bool, error) { return install, false, nil },
		nodeReinstallGateway: func(context.Context) (NodeInstallGateway, bool, error) { return reinstall, true, nil }}
	for purpose, want := range map[string]*NodeInstallGateway{node.PurposeReEnrollment: &reinstall, node.PurposeInitial: nil} {
		issued := node.IssuedToken{TokenMetadata: node.TokenMetadata{Purpose: purpose}, Token: "raw-token"}
		got := s.issuedEnrollmentTokenResponse(t.Context(), issued).Gateway
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("%s: gateway = %+v, want %+v", purpose, got, want)
		}
	}
	s.nodeReinstallGateway = nil
	reEnrollment := node.IssuedToken{TokenMetadata: node.TokenMetadata{Purpose: node.PurposeReEnrollment}}
	if got := s.issuedEnrollmentTokenResponse(t.Context(), reEnrollment).Gateway; got != nil {
		t.Fatalf("without a reinstall source gateway = %+v", got)
	}
}
