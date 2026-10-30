package httpapi

import (
	"net/http"
	"net/url"

	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func (s *Server) handleMaintenanceUpgradeStatus(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireControlUpgradeActor(w, r)
	if !ok {
		return
	}
	if err := identity.Authorize(principal, "control.upgrades.read"); err != nil {
		s.writeError(w, r, err)
		return
	}
	nodeIDs, err := parseMaintenanceUpgradeNodes(r.URL.RawQuery)
	if err != nil {
		s.writeControlUpgradeError(w, r, err)
		return
	}
	if len(nodeIDs) > 0 {
		if err := identity.Authorize(principal, "nodes.read"); err != nil {
			s.writeError(w, r, err)
			return
		}
	}
	status, err := s.controlUpgrades.ReadMaintenanceStatus(r.Context(), controlUpgradeActor(principal), s.maintenanceUpgradeRuntime, nodeIDs)
	if err != nil {
		s.writeControlUpgradeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, struct {
		Data controlupgrade.MaintenanceStatus `json:"data"`
	}{status})
}

func parseMaintenanceUpgradeNodes(raw string) ([]string, error) {
	values, err := url.ParseQuery(raw)
	if err != nil || len(raw) > 8192 {
		return nil, controlupgrade.ErrInvalidInput
	}
	for key := range values {
		if key != "node_id" {
			return nil, controlupgrade.ErrInvalidInput
		}
	}
	ids := values["node_id"]
	if len(ids) > 100 {
		return nil, controlupgrade.ErrInvalidInput
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id || seen[id] {
			return nil, controlupgrade.ErrInvalidInput
		}
		seen[id] = true
	}
	return ids, nil
}
