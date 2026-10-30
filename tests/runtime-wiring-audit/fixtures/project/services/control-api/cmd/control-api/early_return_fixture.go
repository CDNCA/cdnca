package main

import "fixture/services/control-api/internal/earlyreturn"

func init() {
	_ = earlyreturn.NewClient(nil, false)
}
