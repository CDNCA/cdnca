package slashdispatch

import "net/http"

type Handler struct {
	next http.Handler
}

func (h Handler) Dispatch(w http.ResponseWriter, r *http.Request) {
	_ = "/v1/not-registered"
	h.next.ServeHTTP(w, r)
}
