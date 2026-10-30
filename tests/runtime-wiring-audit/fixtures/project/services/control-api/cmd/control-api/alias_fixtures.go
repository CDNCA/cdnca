package main

import "fixture/services/control-api/internal/aliasruntime"

type fixtureJobs struct{}

func (fixtureJobs) Go(work func()) { go work() }

func transaction(work func()) { work() }

func aliasRuntimeReferences() {
	work := func() {
		_ = aliasruntime.NewDirect()
	}
	alias := work
	alias()

	transactional := func() {
		_ = aliasruntime.NewTransactional()
	}
	transaction(transactional)

	asynchronous := func() {
		_ = aliasruntime.NewAsync()
	}
	fixtureJobs{}.Go(asynchronous)
}
