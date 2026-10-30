package futuremux

import "net/http"

type Registrar interface {
	Handle(string, http.Handler)
}

type Registry struct{}

func (*Registry) Handle(string, http.Handler) {}

func Register(handler http.Handler) Registrar {
	var registrar Registrar
	registrar = &Registry{}
	registrar.Handle("/v1/not-a-router", handler)
	registrar = http.NewServeMux()
	return registrar
}
