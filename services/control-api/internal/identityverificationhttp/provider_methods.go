package identityverificationhttp

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/jackc/pgx/v5"
)

// providerMethodKinds is every kind StartSession accepts, in display order.
var providerMethodKinds = []string{"personal_initial", "personal_reverification", "enterprise"}

// ProviderMethodsView is what an applicant may start:
// whether the one configured verification service is ready, its name (sent
// back as the provider of a new session) and the kinds the platform turned on.
// It carries no endpoint, key or credential.
type ProviderMethodsView struct {
	Configured          bool     `json:"configured"`
	ProviderDisplayName string   `json:"provider_display_name"`
	Kinds               []string `json:"kinds"`
}

// Methods reads the applicant's startable verification methods under the
// same live session, membership and RBAC check as GET /status
// (identity_verification.self.manage in the applicant's own tenant scope).
func (workflow *ProviderWorkflow) Methods(ctx context.Context, actor identityverification.Actor) (ProviderMethodsView, error) {
	if workflow == nil || workflow.pool == nil || isNilDependency(workflow.authorizer) || ctx == nil || !actor.Valid() {
		return ProviderMethodsView{}, ErrProviderInvalid
	}
	if err := pgx.BeginFunc(ctx, workflow.pool, func(tx pgx.Tx) error {
		return workflow.authorizer.AuthorizeProviderWrite(ctx, tx, actor)
	}); err != nil {
		return ProviderMethodsView{}, err
	}
	return workflow.methods(ctx)
}

func (workflow *ProviderWorkflow) methods(ctx context.Context) (ProviderMethodsView, error) {
	off := ProviderMethodsView{Kinds: []string{}}
	if !workflow.Configured() {
		return off, nil
	}
	switch ready := workflow.provider.(type) {
	case runtimeConfiguredProvider:
		if err := ready.EnsureCredentials(ctx); err != nil {
			if errors.Is(err, ErrProviderNotConfigured) {
				return off, nil
			}
			return ProviderMethodsView{}, ErrProviderUnavailable
		}
	case interface{ CredentialsReady() bool }:
		if !ready.CredentialsReady() {
			return off, nil
		}
	}
	name := workflow.provider.Name()
	if !resolverNamePattern.MatchString(name) {
		return off, nil
	}
	kinds := make([]string, 0, len(providerMethodKinds))
	for _, kind := range providerMethodKinds {
		if workflow.kindEnabled != nil {
			enabled, err := workflow.kindEnabled(ctx, kind)
			if err != nil {
				return ProviderMethodsView{}, ErrProviderUnavailable
			}
			if !enabled {
				continue
			}
		}
		kinds = append(kinds, kind)
	}
	if len(kinds) == 0 {
		return off, nil
	}
	return ProviderMethodsView{Configured: true, ProviderDisplayName: name, Kinds: kinds}, nil
}
