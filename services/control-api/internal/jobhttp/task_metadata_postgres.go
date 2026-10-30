package jobhttp

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const completionDependenciesSQL = `
	SELECT target.job_id,child.id,child.state
	FROM cname_allocation_targets target
	JOIN background_jobs parent ON parent.tenant_id=target.tenant_id AND parent.id=target.job_id
	  AND parent.kind='dns.cname.allocation'
	JOIN dns_reconcile_tasks fact ON fact.tenant_id=target.tenant_id AND fact.job_id=target.child_task_id
	JOIN background_jobs child ON child.tenant_id=fact.tenant_id AND child.id=fact.job_id
	  AND child.kind='dns_reconcile'
	WHERE target.job_id=ANY($1::uuid[])
	  AND ($2::uuid IS NULL OR EXISTS (
	    SELECT 1 FROM access_scopes scope
	    WHERE scope.id=$2 AND scope.kind='tenant' AND scope.tenant_id=target.tenant_id))`

func attachCompletionDependencies(ctx context.Context, tx pgx.Tx, scope ReadScope, jobs []Job) error {
	ids := make([]uuid.UUID, 0)
	indexes := make(map[uuid.UUID]int)
	for index, job := range jobs {
		if job.Kind == "dns.cname.allocation" {
			ids = append(ids, job.TaskID)
			indexes[job.TaskID] = index
		}
	}
	if len(ids) == 0 {
		return nil
	}
	var available bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass(current_schema() || '.cname_allocation_targets') IS NOT NULL
		AND to_regclass(current_schema() || '.dns_reconcile_tasks') IS NOT NULL`).Scan(&available); err != nil {
		return err
	}
	if !available {
		return nil
	}
	var tenantScope *uuid.UUID
	if scope.Kind == ScopeTenant {
		tenantScope = &scope.ID
	}
	rows, err := tx.Query(ctx, completionDependenciesSQL, ids, tenantScope)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var parentID uuid.UUID
		var dependency TaskDependency
		if err := rows.Scan(&parentID, &dependency.TaskID, &dependency.Status); err != nil {
			return err
		}
		index, exists := indexes[parentID]
		if !exists || jobs[index].taskMetadata != nil {
			return ErrInvalidStoreResponse
		}
		metadata := derivedTaskMetadata(jobs[index])
		dependency.Relation = "completion"
		metadata.Dependencies = TaskDependencies{State: "observed", Items: []TaskDependency{dependency}}
		jobs[index].taskMetadata = &metadata
	}
	return rows.Err()
}
