package main

import "fixture/services/control-api/internal/nilescape"

func init() {
	_ = nilescape.NewImmediateClient(nil)
	_ = nilescape.NewClosureClient(nil)
	_ = nilescape.NewAliasClient(nil)
	_ = nilescape.NewHelperClient(nil)
}
