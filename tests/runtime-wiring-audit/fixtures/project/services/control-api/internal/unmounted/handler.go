package unmounted

import "net/http"

type Handler struct{}

func NewHandler() *Handler { return &Handler{} }

func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/unmounted", func(http.ResponseWriter, *http.Request) {})
	return mux
}
