package rbacdead

import "net/http"

const PermissionManage = "rbac_dead.manage"

type Handler struct{}

func NewHandler() *Handler { return &Handler{} }

func (*Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/rbac-dead", func(http.ResponseWriter, *http.Request) {})
	return mux
}

func deadAuthorizationHelper() {
	authorize()
	begin()
	_ = "SELECT permission FROM grants FOR UPDATE"
}

func authorize() {}

func begin() {}
