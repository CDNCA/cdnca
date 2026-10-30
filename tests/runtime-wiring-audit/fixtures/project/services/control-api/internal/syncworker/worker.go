package syncworker

import "context"

type Worker struct{}

func NewWorker() *Worker { return &Worker{} }

func (*Worker) Run(context.Context) error { return nil }
