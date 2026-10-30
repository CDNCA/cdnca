package jobhttp

import (
	"context"
	"time"
)

func (service *Service) numberedPage(ctx context.Context, scope ReadScope, request ListRequest, query ListQuery) (JobPage, error) {
	reader, ok := service.reader.(NumberedPageReader)
	if !ok {
		return JobPage{}, ErrStoreUnavailable
	}
	query.Limit = request.Limit
	query.Offset = int64(request.Page-1) * int64(request.Limit)
	jobs, total, err := reader.ListNumberedPage(ctx, scope, query)
	if err != nil {
		return JobPage{}, normalizeReaderError(ctx, err)
	}
	if err := validateJobPage(jobs, query); err != nil {
		return JobPage{}, err
	}
	expected := max(int64(0), min(int64(query.Limit), total-query.Offset))
	if total < 0 || int64(len(jobs)) != expected {
		return JobPage{}, ErrInvalidStoreResponse
	}
	pages := total / int64(query.Limit)
	if total%int64(query.Limit) != 0 {
		pages++
	}
	if jobs == nil {
		jobs = []Job{}
	}
	metadata, err := metadataForJobs(jobs)
	if err != nil {
		return JobPage{}, err
	}
	return JobPage{
		Data: jobs, TaskMetadata: &metadata,
		Page:  PageMeta{Number: request.Page, Limit: request.Limit, Total: &total, TotalPages: &pages, Consistency: "request_snapshot"},
		Query: QueryMeta{From: request.From.Format(time.RFC3339Nano), To: request.To.Format(time.RFC3339Nano)},
	}, nil
}
