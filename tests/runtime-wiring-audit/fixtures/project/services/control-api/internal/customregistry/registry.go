package customregistry

import "net/http"

type Registry struct{}

func (Registry) Handle(string, http.Handler) {}

func NewRegistry(handler http.Handler) Registry {
	registry := Registry{}
	registry.Handle("/v1/not-registered", handler)
	return registry
}
