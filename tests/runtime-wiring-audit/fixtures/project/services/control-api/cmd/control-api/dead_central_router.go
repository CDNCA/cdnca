package main

import "fixture/services/control-api/internal/httpapi"

func deadCentralRouterReference() {
	if false {
		server := httpapi.New()
		_ = server.Handler()
	}
	unused := func() {
		server := httpapi.New()
		_ = server.Handler()
	}
	_ = unused
}
