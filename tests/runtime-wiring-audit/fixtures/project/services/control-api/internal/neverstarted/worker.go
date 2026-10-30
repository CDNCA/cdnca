package neverstarted

import "context"

type Worker struct{}

func NewWorker() *Worker { return &Worker{} }

func (w *Worker) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
