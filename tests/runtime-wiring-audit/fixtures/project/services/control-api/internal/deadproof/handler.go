package deadproof

import "net/http"

type Handler struct{}

func NewHandler() *Handler { return &Handler{} }

func (*Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/dead-proof", func(http.ResponseWriter, *http.Request) {})
	return mux
}

func deadEvidence(request *http.Request) {
	_ = request.Header.Get("Idempotency-Key")
	_ = "INSERT INTO dead_idempotency (key) VALUES ($1)"
	appendAudit(nil)
}

func appendAudit(any) {}
