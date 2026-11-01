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
