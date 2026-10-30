package main

import "fixture/services/control-api/internal/unmounted"

func buildUnusedHandler() any { return unmounted.NewHandler() }
