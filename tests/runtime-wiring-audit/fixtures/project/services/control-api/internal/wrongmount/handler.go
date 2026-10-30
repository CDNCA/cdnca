package wrongmount

import "net/http"

type Handler struct{}

func NewHandler() *Handler { return &Handler{} }

func (*Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/wrong-mount", func(http.ResponseWriter, *http.Request) {})
	return mux
}
