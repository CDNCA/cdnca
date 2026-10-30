package plugininstallation

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeauth"
)

type CandidateVerifier interface {
	VerifyCandidate(context.Context, Candidate, []SignedRuntimeFact) error
}

type RuntimeAuthorizer interface {
	Authorize(identityJSON, decisionJSON []byte,
		expected pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error)
}

type RuntimeFactVerifier struct {
	Authorizer RuntimeAuthorizer
}

func (verifier RuntimeFactVerifier) VerifyCandidate(ctx context.Context, candidate Candidate,
	facts []SignedRuntimeFact) error {
	if ctx == nil || verifier.Authorizer == nil || !validCandidate(candidate) {
		return ErrFactUnavailable
	}
	if len(candidate.ApprovedScopes) == 0 || len(facts) != len(candidate.ApprovedScopes) {
		return ErrFactDenied
	}
	for index, scope := range candidate.ApprovedScopes {
		fact := facts[index]
		if fact.Scope != scope || !validRequestID(fact.RequestID) {
			return ErrFactDenied
		}
		authorization, err := verifier.Authorizer.Authorize(fact.IdentityJSON, fact.DecisionJSON,
			pluginruntimeauth.ExpectedAction{CustomerID: candidate.TenantID,
				InstallationID: candidate.InstallationID, RequestID: fact.RequestID,
				CapabilityKind: "scope", CapabilityCode: scope, Action: scope})
		if err != nil {
			if errors.Is(err, pluginruntimeauth.ErrTrustUnavailable) {
				return ErrFactUnavailable
			}
			return ErrFactDenied
		}
		if authorization.CustomerID != candidate.TenantID || authorization.InstallationID != candidate.InstallationID ||
			authorization.AuthorizationID != candidate.AuthorizationID || authorization.VerificationID != candidate.VerificationID ||
			authorization.PluginID != candidate.PluginID || authorization.PluginVersion != candidate.Version ||
			authorization.ManifestSHA256 != candidate.ManifestSHA256 || authorization.CapabilityKind != "scope" ||
			authorization.CapabilityCode != scope || authorization.Action != scope || authorization.RequestID != fact.RequestID {
			return ErrFactDenied
		}
	}
	return nil
}
