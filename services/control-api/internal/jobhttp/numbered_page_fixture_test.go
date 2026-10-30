package jobhttp

import "context"

func (reader *fixtureReader) ListNumberedPage(ctx context.Context, scope ReadScope, query ListQuery) ([]Job, int64, error) {
	all := query
	all.Limit = int(^uint(0) >> 1)
	jobs, err := reader.List(ctx, scope, all)
	if err != nil {
		return nil, 0, err
	}
	total := int64(len(jobs))
	start := min(query.Offset, total)
	end := min(start+int64(query.Limit), total)
	return jobs[start:end], total, nil
}
