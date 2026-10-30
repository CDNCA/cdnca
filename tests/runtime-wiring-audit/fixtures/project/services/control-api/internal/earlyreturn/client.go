package earlyreturn

type Dependency interface {
	Ready() bool
}

type Real struct{}

func (*Real) Ready() bool { return true }

type Client struct {
	dependency Dependency
}

func NewClient(dependency Dependency, bypass bool) *Client {
	if bypass {
		return &Client{dependency: dependency}
	}
	if dependency == nil {
		dependency = &Real{}
	}
	return &Client{dependency: dependency}
}
