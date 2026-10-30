package main

import "fixture/services/control-api/internal/aliasruntime"

func init() {
	round8ParenthesizedRuntimeReferences()
}

func round8ParenthesizedRuntimeReferences() {
	work := (func() {
		_ = aliasruntime.NewParenDirect()
	})
	var alias = (work)
	(alias)()

	transactional := (func() {
		_ = aliasruntime.NewParenTransactional()
	})
	var transactionAlias = (transactional)
	transaction((transactionAlias))

	asynchronous := (func() {
		_ = aliasruntime.NewParenAsync()
	})
	var asyncAlias = (asynchronous)
	fixtureJobs{}.Go((asyncAlias))

	(func() {
		_ = aliasruntime.NewParenIIFE()
	})()
}
