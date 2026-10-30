package jobhttp

import (
	"context"

	"github.com/jackc/pgx/v5"
)

const platformCountSQL = `SELECT count(*)` + platformJobFilterSQL
const tenantCountSQL = `SELECT count(*)` + tenantJobFilterSQL
const platformNumberedSQL = jobListProjectionSQL + platformJobFilterSQL + `
	ORDER BY job.created_at DESC,job.id DESC LIMIT $8 OFFSET $9`
const tenantNumberedSQL = jobListProjectionSQL + tenantJobFilterSQL + `
	ORDER BY job.created_at DESC,job.id DESC LIMIT $8 OFFSET $9`

func (reader *PostgresReader) ListNumberedPage(ctx context.Context, scope ReadScope, query ListQuery) ([]Job, int64, error) {
	if ctx == nil || reader == nil || reader.pool == nil || !validReadScope(scope) ||
		query.Limit < 1 || query.Limit > maximumPageLimit || query.Offset < 0 ||
		query.AfterCreated != nil || query.AfterTaskID != nil || scope.Kind == ScopeTenant && query.TenantID != nil {
		return nil, 0, ErrInvalidRequest
	}
	countSQL, listSQL := platformCountSQL, platformNumberedSQL
	states := nullableSlice(stateStrings(query.States))
	arguments := []any{query.TenantID, query.TaskID, states, nullableString(query.Kind), nullableString(query.Resource), query.From, query.To}
	if scope.Kind == ScopeTenant {
		countSQL, listSQL = tenantCountSQL, tenantNumberedSQL
		arguments[0], arguments[1], arguments[2] = scope.ID, states, query.TaskID
	}
	jobs := make([]Job, 0, query.Limit)
	var total int64
	err := pgx.BeginTxFunc(ctx, reader.pool, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, countSQL, arguments...).Scan(&total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, listSQL, append(arguments, query.Limit, query.Offset)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			job, err := scanListJob(rows)
			if err != nil {
				return err
			}
			jobs = append(jobs, job)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		return attachCompletionDependencies(ctx, tx, scope, jobs)
	})
	if err != nil {
		return nil, 0, postgresError(ctx, "list numbered jobs")
	}
	return jobs, total, nil
}

var _ NumberedPageReader = (*PostgresReader)(nil)
