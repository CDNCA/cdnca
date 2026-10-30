package httpapi

import (
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// modulesResponse is GET /v1/modules: the module, pack and theme codes the
// verified local lease grants, for menus (requiredModule). It is empty unless
// the lease is valid, so the menu agrees with the API entry and publication
// gates (ADR 0007 §3.1).
type modulesResponse struct {
	Status      string   `json:"status"`
	LeaseSerial uint64   `json:"lease_serial"`
	Modules     []string `json:"modules"`
}

func (s *Server) moduleGuard() *entitlementguard.Guard {
	return entitlementguard.NewGuard(s.pool, s.now, s.entitlementTrust)
}

func (s *Server) handleListModules(w http.ResponseWriter, r *http.Request) {
	if _, err := s.authenticatedSessionPrincipal(r); err != nil {
		s.writeError(w, r, err)
		return
	}
	var grants entitlementguard.ModuleGrants
	if err := pgx.BeginTxFunc(r.Context(), s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		grants, err = s.moduleGuard().GrantedModules(r.Context(), tx)
		return err
	}); err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, modulesResponse{Status: grants.Status, LeaseSerial: grants.LeaseSerial, Modules: grants.Codes})
}

// requireModule is the API entry gate of a module route: an authenticated
// session whose request the lease does not grant module for is refused with
// entitlement_feature_denied and audited (entitlement.guard.reject), the same
// CheckFeature path every other entitlement uses.
func (s *Server) requireModule(module, resourceType, operation string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := s.authenticatedSessionPrincipal(r)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		check := entitlementguard.ModuleCheck{
			TargetScopeID: principal.ScopeID, ActorScopeID: principal.ScopeID, ActorUserID: principal.UserID,
			ResourceType: resourceType, ResourceID: uuid.NewSHA1(principal.ScopeID, []byte(module)),
			RequestID: requestID(r.Context()), Operation: operation, Module: module,
		}
		if err := s.moduleGuard().AuthorizeModule(r.Context(), s.pool, check); err != nil {
			s.writeError(w, r, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}
