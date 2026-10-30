package pgxscript

import (
	"context"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Enqueuer records every request a producer hands to the notification store.
type Enqueuer struct{ Requests []notification.EnqueueRequest }

func (e *Enqueuer) EnqueueTx(_ context.Context, _ pgx.Tx, request notification.EnqueueRequest) (notification.EnqueueResult, error) {
	e.Requests = append(e.Requests, request)
	return notification.EnqueueResult{EventID: uuid.New()}, nil
}

// SubjectSites lists each request's subject_site_id (uuid.Nil when absent).
func (e *Enqueuer) SubjectSites() []uuid.UUID {
	out := make([]uuid.UUID, 0, len(e.Requests))
	for _, request := range e.Requests {
		if request.SubjectSiteID == nil {
			out = append(out, uuid.Nil)
			continue
		}
		out = append(out, *request.SubjectSiteID)
	}
	return out
}
