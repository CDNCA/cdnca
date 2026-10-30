package main

import (
	"net/http"

	"fixture/services/control-api/internal/testonly"
)

func testMount() http.Handler {
	handler := testonly.NewHandler()
	mux := http.NewServeMux()
	mux.Handle("/v1/test-only", handler.Handler())
	return mux
}
