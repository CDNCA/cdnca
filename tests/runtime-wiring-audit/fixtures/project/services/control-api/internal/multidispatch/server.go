package multidispatch

import "net/http"

type Server struct {
	alpha http.Handler
	beta  http.Handler
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	for _, pattern := range []string{
		"/v1/multi/alpha",
		"/v1/multi/alpha/{id}",
	} {
		mux.Handle(pattern, http.HandlerFunc(s.handleAlpha))
	}
	for _, pattern := range []string{
		"/v1/multi/beta",
		"/v1/multi/beta/{id}",
	} {
		mux.Handle(pattern, http.HandlerFunc(s.handleBeta))
	}
	return mux
}

func (s *Server) handleAlpha(w http.ResponseWriter, r *http.Request) {
	s.alpha.ServeHTTP(w, r)
}

func (s *Server) handleBeta(w http.ResponseWriter, r *http.Request) {
	s.beta.ServeHTTP(w, r)
}
