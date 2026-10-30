package asyncworker

import "context"

type Worker struct{}

func NewWorker() *Worker { return &Worker{} }

func (*Worker) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
