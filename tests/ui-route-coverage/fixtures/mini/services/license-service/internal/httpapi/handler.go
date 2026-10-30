package httpapi

func (api *API) routes() {
	api.router.HandleFunc("GET /healthz", api.health)
	api.router.Handle("GET /operator/v1/customers", api.requireSession(http.HandlerFunc(api.listCustomers), false))
	api.router.Handle("POST /activation/v1/activations", http.HandlerFunc(api.activate))
}
