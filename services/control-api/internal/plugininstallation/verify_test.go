package plugininstallation

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeauth"
	"github.com/google/uuid"
)

func TestRuntimeFactVerifierRequiresExactSignedCandidateAndCapabilitySubset(t *testing.T) {
	tenantID, installationID, authorizationID, verificationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	candidate := Candidate{TenantID: tenantID, ResourceScope: ResourceScopeTenant, EntrypointType: EntrypointExternalHTTPS, InstallationID: installationID, AuthorizationID: authorizationID,
		VerificationID: verificationID, PluginID: "acme.example", Version: "1.2.0", ManifestSHA256: digest("a"),
		ConfigurationSchemaSHA256: digest("1"), ManifestScopes: []string{"plugin.read", "plugin.write"},
		ApprovedScopes: []string{"plugin.read", "plugin.write"}}
	authorizer := &stubRuntimeAuthorizer{}
	verifier := RuntimeFactVerifier{Authorizer: authorizer}
	facts := []SignedRuntimeFact{
		{Scope: "plugin.read", RequestID: "scope-read", IdentityJSON: []byte("identity-read"), DecisionJSON: []byte("decision-read")},
		{Scope: "plugin.write", RequestID: "scope-write", IdentityJSON: []byte("identity-write"), DecisionJSON: []byte("decision-write")},
	}
	authorizer.result = pluginruntimeauth.Authorization{CustomerID: tenantID, InstallationID: installationID,
		AuthorizationID: authorizationID, VerificationID: verificationID, PluginID: "acme.example",
		PluginVersion: "1.2.0", ManifestSHA256: digest("a"), CapabilityKind: "scope"}
	if err := verifier.VerifyCandidate(context.Background(), candidate, facts); err != nil {
		t.Fatalf("verify exact facts: %v", err)
	}
	if authorizer.calls != 2 {
		t.Fatalf("authorize calls=%d want=2", authorizer.calls)
	}

	for name, mutate := range map[string]func(*pluginruntimeauth.Authorization){
		"tenant":        func(value *pluginruntimeauth.Authorization) { value.CustomerID = uuid.New() },
		"installation":  func(value *pluginruntimeauth.Authorization) { value.InstallationID = uuid.New() },
		"authorization": func(value *pluginruntimeauth.Authorization) { value.AuthorizationID = uuid.New() },
		"verification":  func(value *pluginruntimeauth.Authorization) { value.VerificationID = uuid.New() },
		"plugin":        func(value *pluginruntimeauth.Authorization) { value.PluginID = "other.example" },
		"version":       func(value *pluginruntimeauth.Authorization) { value.PluginVersion = "1.3.0" },
		"manifest":      func(value *pluginruntimeauth.Authorization) { value.ManifestSHA256 = digest("b") },
	} {
		t.Run(name, func(t *testing.T) {
			value := authorizer.result
			mutate(&value)
			authorizer.result = value
			if err := verifier.VerifyCandidate(context.Background(), candidate, facts); !errors.Is(err, ErrFactDenied) {
				t.Fatalf("error=%v", err)
			}
			authorizer.result = pluginruntimeauth.Authorization{CustomerID: tenantID, InstallationID: installationID,
				AuthorizationID: authorizationID, VerificationID: verificationID, PluginID: "acme.example",
				PluginVersion: "1.2.0", ManifestSHA256: digest("a"), CapabilityKind: "scope"}
		})
	}

	if err := verifier.VerifyCandidate(context.Background(), candidate, facts[:1]); !errors.Is(err, ErrFactDenied) {
		t.Fatalf("missing approved capability error=%v", err)
	}
	tamperedOrder := []SignedRuntimeFact{facts[1], facts[0]}
	if err := verifier.VerifyCandidate(context.Background(), candidate, tamperedOrder); !errors.Is(err, ErrFactDenied) {
		t.Fatalf("noncanonical capability order error=%v", err)
	}
	authorizer.err = pluginruntimeauth.ErrTrustUnavailable
	if err := verifier.VerifyCandidate(context.Background(), candidate, facts); !errors.Is(err, ErrFactUnavailable) {
		t.Fatalf("trust unavailable error=%v", err)
	}
}

type stubRuntimeAuthorizer struct {
	result pluginruntimeauth.Authorization
	err    error
	calls  int
}

func (authorizer *stubRuntimeAuthorizer) Authorize(_ []byte, _ []byte,
	expected pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
	authorizer.calls++
	if authorizer.err != nil {
		return pluginruntimeauth.Authorization{}, authorizer.err
	}
	result := authorizer.result
	result.RequestID = expected.RequestID
	result.Action = expected.Action
	result.CapabilityCode = expected.CapabilityCode
	return result, nil
}
