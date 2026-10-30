package commentsfake

// NewHandler, mux.Handle and Idempotency-Key are documentation examples only.
type Core struct{}

func NewCore() *Core { return &Core{} }
