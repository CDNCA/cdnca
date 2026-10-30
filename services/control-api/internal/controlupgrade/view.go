package controlupgrade

import "encoding/json"

func (detail RolloutDetail) MarshalJSON() ([]byte, error) {
	summary := detail.RolloutSummary
	return json.Marshal(struct {
		ID                        string           `json:"id"`
		SchemaVersion             uint16           `json:"schema_version"`
		InstallationID            string           `json:"installation_id"`
		Component                 string           `json:"component"`
		CurrentVersion            string           `json:"current_version"`
		TargetVersion             string           `json:"target_version"`
		State                     PlanState        `json:"state"`
		Completion                PlanCompletion   `json:"completion"`
		Revision                  uint64           `json:"revision"`
		AutomaticRollback         bool             `json:"automatic_rollback"`
		ParentGrantID             string           `json:"parent_grant_id"`
		ArtifactID                string           `json:"artifact_id"`
		ArtifactSHA256            string           `json:"artifact_sha256"`
		ArtifactSizeBytes         int64            `json:"artifact_size_bytes"`
		RollbackArtifactID        string           `json:"rollback_artifact_id"`
		RollbackArtifactSHA256    string           `json:"rollback_artifact_sha256"`
		RollbackArtifactSizeBytes int64            `json:"rollback_artifact_size_bytes"`
		ActiveBatch               int              `json:"active_batch"`
		TotalNodes                int              `json:"total_nodes"`
		PendingNodes              int              `json:"pending_nodes"`
		DispatchedNodes           int              `json:"dispatched_nodes"`
		HealthyNodes              int              `json:"healthy_nodes"`
		FailedNodes               int              `json:"failed_nodes"`
		RolledBackNodes           int              `json:"rolled_back_nodes"`
		Blockers                  []RolloutBlocker `json:"blockers"`
		Batches                   []RolloutBatch   `json:"batches"`
		Nodes                     []RolloutNode    `json:"nodes"`
		Events                    []RolloutEvent   `json:"events"`
		CreatedAt                 any              `json:"created_at"`
		UpdatedAt                 any              `json:"updated_at"`
	}{summary.ID, summary.SchemaVersion, summary.InstallationID, summary.Component,
		summary.CurrentVersion, summary.TargetVersion, summary.State, summary.Completion,
		summary.Revision, summary.AutomaticRollback, summary.ParentGrantID, summary.ArtifactID,
		summary.ArtifactSHA256, summary.ArtifactSizeBytes, summary.RollbackArtifactID,
		summary.RollbackArtifactSHA256, summary.RollbackArtifactSizeBytes, summary.ActiveBatch,
		summary.TotalNodes, summary.PendingNodes, summary.DispatchedNodes, summary.HealthyNodes,
		summary.FailedNodes, summary.RolledBackNodes, summary.Blockers, detail.Batches, detail.Nodes,
		detail.Events, summary.CreatedAt, summary.UpdatedAt})
}
