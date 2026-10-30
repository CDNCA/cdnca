package controlflowroutes

import "net/http"

func Round8ParenthesizedMuxBinding(handler http.Handler) {
	mux := (http.NewServeMux())
	(mux).Handle("/round8-paren-mux", handler)
}
