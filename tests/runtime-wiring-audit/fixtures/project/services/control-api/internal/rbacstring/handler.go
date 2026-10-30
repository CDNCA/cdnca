package rbacstring

import "net/http"

const PermissionManage = "rbac_string.manage"

type Handler struct{}

func NewHandler() *Handler { return &Handler{} }

func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/rbac-string", func(http.ResponseWriter, *http.Request) {})
	return mux
}
