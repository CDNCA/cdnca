package fragmenthidden

import "net/http"

func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/fragment-hidden", func(http.ResponseWriter, *http.Request) {})
	return mux
}
