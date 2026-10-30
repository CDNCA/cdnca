package httpapi

import "net/http"

type Server struct{}

func New() *Server { return &Server{} }

func (*Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/central-dead", func(http.ResponseWriter, *http.Request) {})
	return mux
}
