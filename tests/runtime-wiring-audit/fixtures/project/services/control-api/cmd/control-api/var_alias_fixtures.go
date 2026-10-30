package main

import "fixture/services/control-api/internal/aliasruntime"

func varAliasRuntimeReferences() {
	var work = func() {
		_ = aliasruntime.NewVarAlias()
	}
	if false {
		work = func() {}
	}
	var alias = work
	alias()
	alias = func() {}

	var transactional = func() {
		_ = aliasruntime.NewTransactional()
	}
	var transactionAlias = transactional
	transaction(transactionAlias)

	var async = func() {
		_ = aliasruntime.NewAsync()
	}
	var asyncAlias = async
	fixtureJobs{}.Go(asyncAlias)
}
