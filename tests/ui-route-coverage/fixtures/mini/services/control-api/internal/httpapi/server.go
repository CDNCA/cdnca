package httpapi

func (s *Server) Handler() {
	mux.HandleFunc("GET /v1/widgets", s.handleListWidgets)
	mux.HandleFunc("POST /v1/widgets", s.handleCreateWidget)
	mux.HandleFunc("DELETE /v1/widgets/{id}", s.handleDeleteWidget)
	mux.HandleFunc("GET /v1/gadgets", s.handleListGadgets)
	mux.HandleFunc("GET /v1/gadgets/{id}", s.handleGetGadget)
	mux.HandleFunc("GET /health/live", s.handleLive)
	for _, base := range []string{"/v1/bans", "/v1/admin/bans"} {
		mux.HandleFunc("GET "+base, s.handleListBans)
	}
	mux.Handle("/v1/reports/", reports)
}

func (s *Server) handleListWidgets(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "widgets.read")
}

func (s *Server) handleCreateWidget(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "widgets.manage")
}

func (s *Server) handleDeleteWidget(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "widgets.manage")
}

func (s *Server) handleListGadgets(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "gadgets.read")
}
