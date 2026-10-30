package httpapi

func (s *Server) mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /seller/v1/me", s.seller(s.me))
	mux.HandleFunc("GET /admin/v1/sellers", s.operator(s.listSellers))
	mux.HandleFunc("GET /admin/v1/unproxied", s.operator(s.unproxied))
	mux.HandleFunc("GET /v1/members/me", s.member(s.me))
}
